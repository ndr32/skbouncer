// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "skbouncer.h"

/* tcx, not cls_bpf: the link dies with the process, so a killed skbouncer
 * leaves nothing behind. Passing is TCX_NEXT rather than TCX_PASS, which
 * would end the chain before any other instance on the hook runs. */
#define SKB_PASS TCX_NEXT
#define SKB_DROP TCX_DROP

#define ETH_P_IP  0x0800
#define ETH_HLEN  14

#define IP_OFFMASK 0x1fff

#define TLS_CT_HANDSHAKE   0x16
#define TLS_HS_CLIENT_HELLO 0x01
#define TLS_RECORD_HLEN    5
#define TLS_RECORD_MAX     16384	/* RFC 8446 5.1: 2^14 */
#define TLS_HS_HLEN        4		/* type + uint24 length */
#define TLS_RANDOM_LEN     32
#define TLS_SID_MAX        32
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b

/* The smallest ClientHello body: version, random, empty session_id, one
 * cipher suite, one compression method, no extensions (RFC 8446 4.1.2). */
#define TLS_HELLO_MIN (2 + TLS_RANDOM_LEN + 1 + 2 + 2 + 1 + 1)

/* Record header plus the first byte of the handshake body: enough to call
 * it a ClientHello. The rest of the handshake header and legacy_version are
 * checked when the segment holds them. */
#define TLS_SNIFF_LEN (TLS_RECORD_HLEN + 1)
#define TLS_CHECK_LEN (TLS_RECORD_HLEN + TLS_HS_HLEN + 2)

/* Payload offsets: record header, then the handshake header's uint24
 * length, then legacy_version. */
#define OFF_HS_LEN     (TLS_RECORD_HLEN + 1)
#define OFF_LEGACY_VER (TLS_RECORD_HLEN + TLS_HS_HLEN)

char LICENSE[] SEC("license") = "GPL";

/* Set by the loader before load, from --direction: the program cannot ask
 * the kernel which tcx hook it sits on. See enum skb_direction. */
const volatile __u8 attach_dir = SKB_DIR_EGRESS;

/* Enforce mode, set by the loader before load. Only sockets in the cgroup
 * scope_id, at scope_level, or below it are ever blocked. */
const volatile __u8  enforce = 0;
const volatile __u8  unknown_block = 0;	/* policy "on_unknown": "block" */
const volatile __u32 scope_level = 0;
const volatile __u64 scope_id = 0;

/* The compiled policy. Userspace fills both before attaching, and keeps
 * cgroup_rule current as containers appear. A cgroup not in it matched no
 * rule, so it gets rules[0], the policy default. */
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

/* Where the event is built when the ringbuf is full: enforcement must not
 * depend on there being room to report it. */
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

/* A plain array, not a per-CPU one: ClientHellos arrive at handshake rate,
 * so the atomic costs nothing and userspace reads one value per counter
 * instead of summing across CPUs. */
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

static __always_inline __u16 load16(struct __sk_buff *skb, __u32 off)
{
	__u8 b[2] = {};

	bpf_skb_load_bytes(skb, off, b, 2);
	return ((__u16)b[0] << 8) | b[1];
}

/* Walks the ClientHello body starting at `hs`, the handshake header, and
 * reading nothing at or past hs + ev->captured_len: bytes beyond that reach
 * the peer in a later segment. Returns SKB_TRUNC_SEGMENT when the walk
 * needed a byte it did not have, whichever limit caused it; the caller
 * decides which of segment and record that was.
 *
 * Offsets are skb offsets; bpf_skb_load_bytes() checks them at run time, so
 * the verifier only needs the copy lengths bounded. */
static __always_inline __u8 walk_hello(struct __sk_buff *skb,
				       struct skb_event *ev, __u32 hs)
{
	__u32 lim = hs + ev->captured_len;
	__u32 end = hs + ev->record_len;
	__u32 off, ext_end, n, len;
	__u8 b[4];
	int i;

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

	/* cipher_suites: one copy of up to SKB_MAX_CIPHERS entries, cut to
	 * what this segment holds. */
	if (off + 2 > lim)
		return SKB_TRUNC_SEGMENT;
	n = load16(skb, off) / 2;
	off += 2;
	if (n > SKB_MAX_CIPHERS) {
		ev->ciphers_capped = 1;
		len = SKB_MAX_CIPHERS;
	} else {
		len = n;
	}
	if (off + len * 2 > lim)
		len = off < lim ? (lim - off) / 2 : 0;
	if (len > 0 && len <= SKB_MAX_CIPHERS) {
		if (bpf_skb_load_bytes(skb, off, ev->ciphers, len * 2) < 0)
			return SKB_TRUNC_PARSE;
		ev->n_ciphers = len;
	}
	if (len == n)
		ev->seen |= SKB_SEEN_CIPHERS;
	off += n * 2;

	/* compression_methods */
	if (off + 1 > lim)
		return SKB_TRUNC_SEGMENT;
	if (bpf_skb_load_bytes(skb, off, b, 1) < 0)
		return SKB_TRUNC_PARSE;
	off += 1 + b[0];

	/* No extensions block at all is legal for TLS 1.2. */
	if (off == end) {
		ev->seen |= SKB_SEEN_VERSIONS;
		return SKB_TRUNC_NONE;
	}
	if (off + 2 > lim)
		return SKB_TRUNC_SEGMENT;
	ext_end = off + 2 + load16(skb, off);
	off += 2;

	for (i = 0; i < SKB_MAX_EXTS; i++) {
		__u16 type, elen;

		if (off >= ext_end) {
			if (ext_end > end)
				return SKB_TRUNC_SEGMENT;
			/* Every extension walked, none was 0x002b:
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

		if (type == TLS_EXT_SUPPORTED_VERSIONS) {
			if (off + 1 > lim)
				return SKB_TRUNC_SEGMENT;
			if (bpf_skb_load_bytes(skb, off, b, 1) < 0)
				return SKB_TRUNC_PARSE;
			n = b[0] / 2;
			len = n > SKB_MAX_VERSIONS ? SKB_MAX_VERSIONS : n;
			if (off + 1 + len * 2 > lim)
				len = off + 1 < lim ? (lim - off - 1) / 2 : 0;
			if (len > 0 && len <= SKB_MAX_VERSIONS) {
				if (bpf_skb_load_bytes(skb, off + 1, ev->versions,
						       len * 2) < 0)
					return SKB_TRUNC_PARSE;
				ev->n_versions = len;
			}
			/* Nothing further is extracted; the rest of the
			 * record only matters for its length, which the
			 * caller already has. */
			if (len < n)
				return SKB_TRUNC_SEGMENT;
			ev->seen |= SKB_SEEN_VERSIONS;
			return SKB_TRUNC_NONE;
		}
		off += elen;
	}
	return SKB_TRUNC_EXT_LIMIT;
}

/* skb_policy_explain() in userspace, which it must agree with. */
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

/* A record that cannot hold a ClientHello, whatever its first six bytes
 * say. A segment in the middle of a stream can start with anything, and
 * flow state would not help: a real ClientHello can follow plaintext
 * (STARTTLS). `avail` is how many payload bytes this segment holds.
 *
 * The handshake length must be at least the record body: a ClientHello is
 * the only thing the client sends before the server answers, so the record
 * holds nothing else. It may be longer, when the ClientHello continues in
 * the next record. */
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

/* A segment of 1-5 bytes that starts like a handshake record: a ClientHello
 * whose header was written on its own would look like this, and cannot be
 * classified. Counted so the miss is visible. */
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

/* One program for both tcx hooks - the parse is direction-agnostic, and
 * a container's outbound handshake arrives on the INGRESS side of its veth.
 *
 * Name must stay <= 15 chars: BPF_OBJ_NAME_LEN is 16 incl. NUL, and a
 * longer name shows truncated in bpftool. */
SEC("tcx/ingress")	/* the loader switches it to egress */
int skb_tc(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct skb_tuple tuple;
	struct skb_event *ev;
	__u32 l4_off, pay_off, avail, seg_len, body_len;
	__u16 record_len, captured_len;
	__u8 tls[TLS_SNIFF_LEN];
	int reported = 1, act;

	/* L2/L3/L4 headers are always in the linear area at either hook, so
	 * direct access is safe here. The payload is not: tcp_sendmsg parks it
	 * in page frags, hence bpf_skb_load_bytes() for the TLS bytes below. */
	if ((void *)(eth + 1) > data_end)
		return SKB_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return SKB_PASS;

	ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end)
		return SKB_PASS;
	if (ip->protocol != IPPROTO_TCP)
		return SKB_PASS;
	/* Only the first fragment carries the TCP header. */
	if (ip->frag_off & bpf_htons(IP_OFFMASK))
		return SKB_PASS;
	if (ip->ihl < 5)
		return SKB_PASS;
	l4_off = ETH_HLEN + (__u32)ip->ihl * 4;	/* <= 14 + 60 */

	tcp = data + l4_off;
	if ((void *)(tcp + 1) > data_end)
		return SKB_PASS;
	if (tcp->doff < 5)
		return SKB_PASS;
	pay_off = l4_off + (__u32)tcp->doff * 4;	/* <= 134 */

	if (pay_off >= skb->len)
		return SKB_PASS;

	/* Read the tuple before any helper call so the verifier keeps the
	 * packet pointers valid. */
	tuple.saddr = ip->saddr;
	tuple.daddr = ip->daddr;
	tuple.sport = tcp->source;
	tuple.dport = tcp->dest;

	/* How much of the record reaches the peer in the segment that
	 * carries its header.
	 *
	 * tc egress runs BEFORE segmentation offload, so on a GSO skb
	 * skb->len spans the whole super-packet rather than one wire segment
	 * and would overstate what the first segment holds. Measured here: a
	 * 1557-byte ClientHello arrived as a single skb with gso_size=1460
	 * and gso_segs=2, i.e. two segments on the wire. Without this clamp
	 * every handshake looks unfragmented and M7 measures nothing.
	 *
	 * The same holds at veth ingress: veth forwards GSO skbs whole, so the
	 * container's super-packet is still unsegmented when it lands here and
	 * gso_size carries the container's MSS. */
	avail = skb->len - pay_off;
	seg_len = skb->gso_size;
	if (seg_len >= TLS_SNIFF_LEN && seg_len < avail)
		avail = seg_len;

	if (avail < TLS_SNIFF_LEN) {
		count_short(skb, pay_off, avail);
		return SKB_PASS;
	}
	if (bpf_skb_load_bytes(skb, pay_off, tls, sizeof(tls)) < 0)
		return SKB_PASS;

	/* The segment is taken to start on a record boundary. A ClientHello
	 * can appear later in a connection (STARTTLS), so any segment may
	 * start one; not_a_hello() weeds out those that only look like it. */
	if (tls[0] != TLS_CT_HANDSHAKE)
		return SKB_PASS;
	if (tls[1] != 0x03)		/* record layer version is always 3.x */
		return SKB_PASS;
	if (tls[5] != TLS_HS_CLIENT_HELLO)
		return SKB_PASS;

	record_len = ((__u16)tls[3] << 8) | tls[4];
	if (record_len < TLS_HS_HLEN || record_len > TLS_RECORD_MAX)
		return SKB_PASS;
	if (not_a_hello(skb, pay_off, avail, record_len))
		return SKB_PASS;

	bump(SKB_STAT_DETECTED);

	/* avail >= TLS_SNIFF_LEN, so body_len is at least 1. skb->len can
	 * exceed 64 KiB, but the min() bounds the result by record_len,
	 * itself <= TLS_RECORD_MAX, so __u16 holds. */
	body_len = avail - TLS_RECORD_HLEN;
	captured_len = body_len < record_len ? (__u16)body_len : record_len;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		__u32 zero = 0;

		bump(SKB_STAT_DROPPED);
		if (!enforce)
			return SKB_PASS;
		ev = bpf_map_lookup_elem(&scratch, &zero);
		if (!ev)
			return SKB_PASS;
		reported = 0;
	}
	/* Reserved ringbuf memory is not zeroed, and the walk may stop before
	 * filling every field. */
	__builtin_memset(ev, 0, sizeof(*ev));

	/* Expected to be 0 on a forwarded skb, which has no local socket.
	 * Recorded rather than relied on: the interface is the identity. */
	ev->cgroup_id = bpf_skb_cgroup_id(skb);
	ev->ktime_ns = bpf_ktime_get_ns();
	ev->tuple = tuple;
	ev->ifindex = skb->ifindex;
	ev->direction = attach_dir;
	ev->record_len = record_len;
	ev->captured_len = captured_len;
	ev->event_version = SKB_EVENT_VERSION;

	/* A walk that runs out of segment is SEGMENT whatever it was reading:
	 * that is the fragmentation dataset. Only a walk that runs out of
	 * record with the whole record in hand is PARSE. */
	ev->trunc_reason = walk_hello(skb, ev, pay_off + TLS_RECORD_HLEN);
	if (captured_len < record_len)
		ev->trunc_reason = SKB_TRUNC_SEGMENT;
	else if (ev->trunc_reason == SKB_TRUNC_SEGMENT)
		ev->trunc_reason = SKB_TRUNC_PARSE;

	/* The kernel judges only in scope: cgroup_rule holds only in-scope
	 * cgroups, so anywhere else it has no rule to judge by. */
	if (enforce) {
		ev->action = SKB_ACTION_PASS;
		ev->verdict = SKB_VERDICT_NONE;
		if (bpf_skb_ancestor_cgroup_id(skb, scope_level) == scope_id) {
			ev->verdict = check_policy(ev);
			if (ev->verdict == SKB_VERDICT_VIOLATION ||
			    (ev->verdict == SKB_VERDICT_UNKNOWN && unknown_block))
				ev->action = SKB_ACTION_BLOCK;
		}
	}
	act = ev->action == SKB_ACTION_BLOCK ? SKB_DROP : SKB_PASS;

	if (reported)
		bpf_ringbuf_submit(ev, 0);
	return act;
}
