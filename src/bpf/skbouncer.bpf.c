// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "skbouncer.h"

/* The program attaches through tcx. A tcx link is removed when its process
 * exits, and a killed skbouncer leaves nothing attached. A pass returns
 * TCX_NEXT. TCX_PASS would end the chain before other instances on the same
 * hook run. */
#define SKB_PASS TCX_NEXT
#define SKB_DROP TCX_DROP

#define ETH_P_IP  0x0800
#define ETH_HLEN  14

#define IP_OFFMASK 0x1fff

#define TLS_CT_HANDSHAKE   0x16
#define TLS_HS_CLIENT_HELLO 0x01
#define TLS_RECORD_HLEN    5
#define TLS_RECORD_MAX     16384	/* RFC 8446 section 5.1, 2^14 bytes */
#define TLS_HS_HLEN        4		/* type + uint24 length */
#define TLS_RANDOM_LEN     32
#define TLS_SID_MAX        32
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b

/* The smallest ClientHello body holds a version, the random, an empty
 * session_id, one cipher suite and one compression method, with no
 * extensions (RFC 8446 section 4.1.2). */
#define TLS_HELLO_MIN (2 + TLS_RANDOM_LEN + 1 + 2 + 2 + 1 + 1)

/* The record header and the first byte of the handshake body identify a
 * ClientHello. The rest of the handshake header and legacy_version are
 * checked when the segment holds them. */
#define TLS_SNIFF_LEN (TLS_RECORD_HLEN + 1)
#define TLS_CHECK_LEN (TLS_RECORD_HLEN + TLS_HS_HLEN + 2)

/* Offsets into the payload of the handshake length (uint24) and of
 * legacy_version. */
#define OFF_HS_LEN     (TLS_RECORD_HLEN + 1)
#define OFF_LEGACY_VER (TLS_RECORD_HLEN + TLS_HS_HLEN)

char LICENSE[] SEC("license") = "GPL";

/* Enforce mode settings, set by the loader before the program loads. Only
 * sockets in the cgroup scope_id at depth scope_level, or below it, are
 * blocked. */
const volatile __u8  enforce = 0;
const volatile __u8  unknown_block = 0;	/* policy "on_unknown": "block" */
const volatile __u32 scope_level = 0;
const volatile __u64 scope_id = 0;

/* The compiled policy. Userspace fills both maps before attaching and
 * updates cgroup_rule as containers start. A cgroup missing from cgroup_rule
 * gets rules[0], the policy default. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SKB_MAX_CGROUPS);
	__type(key, __u64);
	__type(value, __u32);
} cgroup_rule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SKB_MAX_RULES + 1);
	__type(key, __u32);
	__type(value, struct skb_krule);
} rules SEC(".maps");

/* The event is built here when the ringbuf is full. Enforcement then works
 * without room to report. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct skb_event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);	/* 256 KiB */
} events SEC(".maps");

/* A plain array with atomic adds. ClientHellos arrive at handshake rate, and
 * the atomics cost little at that rate. Userspace reads one value per
 * counter. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SKB_STAT__MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 stat)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &stat);

	if (c)
		__sync_fetch_and_add(c, 1);
}

/* Every caller has checked off + 2 against the segment, which lies inside
 * the skb, so the load cannot fail. */
static __always_inline __u16 load16(struct __sk_buff *skb, __u32 off)
{
	__u8 b[2] = {};

	bpf_skb_load_bytes(skb, off, b, 2);
	return ((__u16)b[0] << 8) | b[1];
}

/* Copies a list of n two-byte entries at `off` into dst: at most `max` of
 * them, and none at or past `lim`. Returns how many it copied, or -1 if the
 * load failed. */
static __always_inline int copy_list(struct __sk_buff *skb, __u32 off, __u32 lim,
				     __u16 *dst, __u32 n, __u32 max)
{
	__u32 len = n > max ? max : n;

	if (off + len * 2 > lim)
		len = off < lim ? (lim - off) / 2 : 0;
	if (len == 0 || len > max)
		return 0;
	if (bpf_skb_load_bytes(skb, off, dst, len * 2) < 0)
		return -1;
	return len;
}

/* The supported_versions extension body at `off`: a one-byte length, then
 * two-byte versions. Nothing after it is extracted. The caller already has
 * the record length. */
static __always_inline __u8 read_versions(struct __sk_buff *skb,
					  struct skb_event *ev, __u32 off, __u32 lim)
{
	__u8 len;
	int got;

	if (off + 1 > lim)
		return SKB_TRUNC_SEGMENT;
	if (bpf_skb_load_bytes(skb, off, &len, 1) < 0)
		return SKB_TRUNC_PARSE;
	got = copy_list(skb, off + 1, lim, ev->versions, len / 2, SKB_MAX_VERSIONS);
	if (got < 0)
		return SKB_TRUNC_PARSE;
	ev->n_versions = got;
	if (got < len / 2)
		return SKB_TRUNC_SEGMENT;
	ev->seen |= SKB_SEEN_VERSIONS;
	return SKB_TRUNC_NONE;
}

/* Walks the extensions from `off` to `ext_end`, at most SKB_MAX_EXTS of them,
 * looking for supported_versions. */
static __always_inline __u8 walk_extensions(struct __sk_buff *skb,
					    struct skb_event *ev, __u32 off,
					    __u32 ext_end, __u32 end, __u32 lim)
{
	__u8 b[4];
	int i;

	for (i = 0; i < SKB_MAX_EXTS; i++) {
		__u16 type, elen;

		if (off >= ext_end) {
			if (ext_end > end)
				return SKB_TRUNC_SEGMENT;
			/* No extension was supported_versions, so
			 * legacy_version is the offer. */
			ev->seen |= SKB_SEEN_VERSIONS;
			return SKB_TRUNC_NONE;
		}
		if (off + 4 > lim)
			return SKB_TRUNC_SEGMENT;
		if (bpf_skb_load_bytes(skb, off, b, 4) < 0)
			return SKB_TRUNC_PARSE;
		type = ((__u16)b[0] << 8) | b[1];
		elen = ((__u16)b[2] << 8) | b[3];
		off += 4;
		if (type == TLS_EXT_SUPPORTED_VERSIONS)
			return read_versions(skb, ev, off, lim);
		off += elen;
	}
	return SKB_TRUNC_EXT_LIMIT;
}

/* Walks the ClientHello body from `hs`, the start of the handshake header.
 * The walk reads nothing at or past hs + ev->captured_len. Bytes past that
 * point reach the peer in a later segment. It returns SKB_TRUNC_SEGMENT when
 * it needed a byte it did not have, and the caller decides whether the
 * segment or the record ran out.
 *
 * bpf_skb_load_bytes() checks the offsets at run time. The verifier only
 * needs the copy lengths bounded. */
static __always_inline __u8 walk_hello(struct __sk_buff *skb,
				       struct skb_event *ev, __u32 hs)
{
	__u32 lim = hs + ev->captured_len;
	__u32 end = hs + ev->record_len;
	__u32 off, n;
	__u8 b[4];
	int got;

	if (hs + TLS_HS_HLEN + 2 > lim)
		return SKB_TRUNC_SEGMENT;
	if (bpf_skb_load_bytes(skb, hs, b, 4) < 0)
		return SKB_TRUNC_PARSE;
	n = ((__u32)b[1] << 16) | ((__u32)b[2] << 8) | b[3];
	ev->handshake_len = n > 0xffff ? 0xffff : n;
	off = hs + TLS_HS_HLEN;
	ev->legacy_version = load16(skb, off);
	off += 2 + TLS_RANDOM_LEN;

	/* session_id */
	if (off + 1 > lim)
		return SKB_TRUNC_SEGMENT;
	if (bpf_skb_load_bytes(skb, off, b, 1) < 0)
		return SKB_TRUNC_PARSE;
	if (b[0] > TLS_SID_MAX)
		return SKB_TRUNC_PARSE;
	off += 1 + b[0];

	/* cipher_suites */
	if (off + 2 > lim)
		return SKB_TRUNC_SEGMENT;
	n = load16(skb, off) / 2;
	off += 2;
	ev->ciphers_capped = n > SKB_MAX_CIPHERS;
	got = copy_list(skb, off, lim, ev->ciphers, n, SKB_MAX_CIPHERS);
	if (got < 0)
		return SKB_TRUNC_PARSE;
	ev->n_ciphers = got;
	if (got == n)
		ev->seen |= SKB_SEEN_CIPHERS;
	off += n * 2;

	/* compression_methods */
	if (off + 1 > lim)
		return SKB_TRUNC_SEGMENT;
	if (bpf_skb_load_bytes(skb, off, b, 1) < 0)
		return SKB_TRUNC_PARSE;
	off += 1 + b[0];

	/* TLS 1.2 allows a ClientHello with no extensions block. */
	if (off == end) {
		ev->seen |= SKB_SEEN_VERSIONS;
		return SKB_TRUNC_NONE;
	}
	if (off + 2 > lim)
		return SKB_TRUNC_SEGMENT;
	return walk_extensions(skb, ev, off + 2, off + 2 + load16(skb, off), end, lim);
}

/* The kernel copy of skb_policy_explain() in userspace. The two must agree. */
static __always_inline __u8 check_policy(const struct skb_event *ev)
{
	const struct skb_krule *r;
	__u32 zero = 0, *slot;
	int partial = 0, i;

	slot = bpf_map_lookup_elem(&cgroup_rule, &ev->cgroup_id);
	r = bpf_map_lookup_elem(&rules, slot ? slot : &zero);
	if (!r || !(r->flags & SKB_KRULE_VALID))
		return SKB_VERDICT_ALLOW;
	if (r->flags & SKB_KRULE_FIXED)
		return r->fixed;

	if (!(r->flags & SKB_KRULE_ANY_CIPHER)) {
		for (i = 0; i < SKB_MAX_CIPHERS && i < ev->n_ciphers; i++) {
			__u16 c = bpf_ntohs(ev->ciphers[i]);

			if (skb_cipher_ignored(c))
				continue;
			if (!((r->ciphers[c >> 6] >> (c & 63)) & 1))
				return SKB_VERDICT_VIOLATION;
		}
		if (!(ev->seen & SKB_SEEN_CIPHERS))
			partial = 1;
	}

	if (r->min_version) {
		if (ev->n_versions) {
			for (i = 0; i < SKB_MAX_VERSIONS && i < ev->n_versions; i++) {
				__u16 v = bpf_ntohs(ev->versions[i]);

				if (!skb_is_grease(v) && v < r->min_version)
					return SKB_VERDICT_VIOLATION;
			}
		} else if (ev->seen & SKB_SEEN_VERSIONS) {
			if (ev->legacy_version < r->min_version)
				return SKB_VERDICT_VIOLATION;
		}
		if (!(ev->seen & SKB_SEEN_VERSIONS))
			partial = 1;
	}
	return partial ? SKB_VERDICT_UNKNOWN : SKB_VERDICT_ALLOW;
}

/* Returns 1 for a record that cannot hold a ClientHello, whatever its first
 * six bytes say. A segment in the middle of a stream can start with any
 * bytes. Tracking flow state would not separate the two cases. A real
 * ClientHello can follow plaintext (STARTTLS). `avail` is the number of
 * payload bytes in this segment.
 *
 * The handshake length must cover the whole record body. A client sends
 * nothing else before the server answers. The handshake length may exceed
 * the record body when the ClientHello continues in the next record. */
static __always_inline int not_a_hello(struct __sk_buff *skb, __u32 pay_off,
				       __u32 avail, __u16 record_len)
{
	__u8 h[TLS_CHECK_LEN];
	__u32 n;

	if (avail >= TLS_CHECK_LEN) {
		if (bpf_skb_load_bytes(skb, pay_off, h, TLS_CHECK_LEN) < 0)
			return 1;
		if (h[OFF_LEGACY_VER] != 0x03)	/* legacy_version is 3.x */
			return 1;
	} else if (avail >= TLS_RECORD_HLEN + TLS_HS_HLEN) {
		if (bpf_skb_load_bytes(skb, pay_off, h, TLS_RECORD_HLEN + TLS_HS_HLEN) < 0)
			return 1;
	} else {
		return 0;
	}
	n = ((__u32)h[OFF_HS_LEN] << 16) | ((__u32)h[OFF_HS_LEN + 1] << 8) |
	    h[OFF_HS_LEN + 2];
	return n < TLS_HELLO_MIN || TLS_HS_HLEN + n < record_len;
}

/* Counts a segment of 1 to 5 bytes that starts like a handshake record. A
 * ClientHello whose record header was written on its own looks like this and
 * cannot be classified. The counter makes the miss visible. */
static __always_inline void count_short(struct __sk_buff *skb, __u32 pay_off,
					__u32 avail)
{
	__u8 b[2] = {};

	if (avail == 0 || avail >= TLS_SNIFF_LEN)
		return;
	if (bpf_skb_load_bytes(skb, pay_off, b, 1) < 0 || b[0] != TLS_CT_HANDSHAKE)
		return;
	if (avail >= 2 && (bpf_skb_load_bytes(skb, pay_off + 1, b + 1, 1) < 0 ||
			   b[1] != 0x03))
		return;
	bump(SKB_STAT_SHORT);
}

/* What read_headers() and is_client_hello() learn about one packet. */
struct pkt {
	struct skb_tuple tuple;
	__u32 pay_off;		/* where the TCP payload starts */
	__u32 avail;		/* payload bytes in the first wire segment */
	__u16 record_len;
	__u16 captured_len;	/* record bytes after the header in that segment */
};

/* Ethernet, IPv4 and TCP. The headers sit in the linear area, and direct
 * access to them is safe. The packet pointers stay inside this function,
 * where the verifier has seen them checked against data_end. */
static __always_inline bool read_headers(struct __sk_buff *skb, struct pkt *p)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u32 l4_off, seg_len;

	if ((void *)(eth + 1) > data_end)
		return false;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return false;

	ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end)
		return false;
	if (ip->protocol != IPPROTO_TCP)
		return false;
	/* Only the first fragment carries the TCP header. */
	if (ip->frag_off & bpf_htons(IP_OFFMASK))
		return false;
	if (ip->ihl < 5)
		return false;
	l4_off = ETH_HLEN + (__u32)ip->ihl * 4;	/* <= 14 + 60 */

	tcp = data + l4_off;
	if ((void *)(tcp + 1) > data_end)
		return false;
	if (tcp->doff < 5)
		return false;
	p->pay_off = l4_off + (__u32)tcp->doff * 4;	/* <= 134 */
	if (p->pay_off >= skb->len)
		return false;

	p->tuple.saddr = ip->saddr;
	p->tuple.daddr = ip->daddr;
	p->tuple.sport = tcp->source;
	p->tuple.dport = tcp->dest;

	/* The bytes of the record that the first wire segment carries. The
	 * hook runs before segmentation, and veth forwards GSO packets whole,
	 * so skb->len can span several wire segments. gso_size is the payload
	 * of one segment. Without this clamp every ClientHello would look
	 * whole. */
	p->avail = skb->len - p->pay_off;
	seg_len = skb->gso_size;
	if (seg_len >= TLS_SNIFF_LEN && seg_len < p->avail)
		p->avail = seg_len;
	return true;
}

/* The segment is assumed to start on a record boundary. A ClientHello can
 * appear later in a connection (STARTTLS), so any segment may start one.
 * not_a_hello() rejects segments that only resemble one. */
static __always_inline bool is_client_hello(struct __sk_buff *skb, struct pkt *p)
{
	__u8 tls[TLS_SNIFF_LEN];
	__u32 body_len;

	if (p->avail < TLS_SNIFF_LEN) {
		count_short(skb, p->pay_off, p->avail);
		return false;
	}
	if (bpf_skb_load_bytes(skb, p->pay_off, tls, sizeof(tls)) < 0)
		return false;
	if (tls[0] != TLS_CT_HANDSHAKE)
		return false;
	if (tls[1] != 0x03)		/* record layer version is always 3.x */
		return false;
	if (tls[5] != TLS_HS_CLIENT_HELLO)
		return false;

	p->record_len = ((__u16)tls[3] << 8) | tls[4];
	if (p->record_len < TLS_HS_HLEN || p->record_len > TLS_RECORD_MAX)
		return false;
	if (not_a_hello(skb, p->pay_off, p->avail, p->record_len))
		return false;

	/* avail >= TLS_SNIFF_LEN, so body_len is at least 1. skb->len can
	 * exceed 64 KiB. The result is bounded by record_len, at most
	 * TLS_RECORD_MAX, and fits a __u16. */
	body_len = p->avail - TLS_RECORD_HLEN;
	p->captured_len = body_len < p->record_len ? (__u16)body_len : p->record_len;
	return true;
}

static __always_inline void fill_event(struct __sk_buff *skb, const struct pkt *p,
				       struct skb_event *ev)
{
	/* Reserved ringbuf memory is not zeroed, and the walk may stop before
	 * filling every field. */
	__builtin_memset(ev, 0, sizeof(*ev));

	/* The container's cgroup. It is 0 on a forwarded skb, which has no
	 * socket. */
	ev->cgroup_id = bpf_skb_cgroup_id(skb);
	ev->ktime_ns = bpf_ktime_get_ns();
	ev->tuple = p->tuple;
	ev->ifindex = skb->ifindex;
	ev->record_len = p->record_len;
	ev->captured_len = p->captured_len;
	ev->event_version = SKB_EVENT_VERSION;

	/* A walk that runs out of segment is SEGMENT whatever field it was
	 * reading. These events form the fragmentation dataset. A walk that
	 * runs out of record with the whole record in hand is PARSE. */
	ev->trunc_reason = walk_hello(skb, ev, p->pay_off + TLS_RECORD_HLEN);
	if (p->captured_len < p->record_len)
		ev->trunc_reason = SKB_TRUNC_SEGMENT;
	else if (ev->trunc_reason == SKB_TRUNC_SEGMENT)
		ev->trunc_reason = SKB_TRUNC_PARSE;
}

/* Enforce mode. The kernel judges only in scope. cgroup_rule holds in-scope
 * cgroups only, and elsewhere there is no rule to judge by. */
static __always_inline int judge(struct __sk_buff *skb, struct skb_event *ev)
{
	ev->action = SKB_ACTION_PASS;
	ev->verdict = SKB_VERDICT_NONE;
	if (bpf_skb_ancestor_cgroup_id(skb, scope_level) == scope_id) {
		ev->verdict = check_policy(ev);
		if (ev->verdict == SKB_VERDICT_VIOLATION ||
		    (ev->verdict == SKB_VERDICT_UNKNOWN && unknown_block))
			ev->action = SKB_ACTION_BLOCK;
	}
	return ev->action == SKB_ACTION_BLOCK ? SKB_DROP : SKB_PASS;
}

/* Runs on tcx ingress of a container's veth, where the container's outgoing
 * traffic arrives.
 *
 * The name must stay within 15 characters. BPF_OBJ_NAME_LEN is 16 including
 * the NUL, and bpftool shows a longer name truncated. */
SEC("tcx/ingress")
int skb_tc(struct __sk_buff *skb)
{
	struct skb_event *ev;
	struct pkt p = {};
	int reported = 1, act;

	if (!read_headers(skb, &p) || !is_client_hello(skb, &p))
		return SKB_PASS;
	bump(SKB_STAT_DETECTED);

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		__u32 zero = 0;

		bump(SKB_STAT_DROPPED);
		if (!enforce)
			return SKB_PASS;
		/* Enforcement does not depend on room to report. */
		ev = bpf_map_lookup_elem(&scratch, &zero);
		if (!ev)
			return SKB_PASS;
		reported = 0;
	}
	fill_event(skb, &p, ev);
	act = enforce ? judge(skb, ev) : SKB_PASS;

	if (reported)
		bpf_ringbuf_submit(ev, 0);
	return act;
}
