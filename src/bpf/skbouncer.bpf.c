// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "skbouncer.h"

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

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

/* Record header plus the first byte of the handshake body. */
#define TLS_SNIFF_LEN (TLS_RECORD_HLEN + 1)

char LICENSE[] SEC("license") = "GPL";

/* Set by the loader before load, from --direction. The program cannot ask
 * the kernel which clsact hook it sits on, and the answer matters: it is
 * what identifies the container. See enum skb_direction. */
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
	/* A ClientHello split across records is legal but not walked. */
	if (TLS_HS_HLEN + n < end - hs)
		end = hs + TLS_HS_HLEN + n;

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

static __always_inline int is_grease(__u16 v)
{
	return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

/* skb_policy_check() in userspace, which it must agree with. */
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

			if (is_grease(c) || c == 0x00ff || c == 0x5600)
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

				if (!is_grease(v) && v < r->min_version)
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

/* One program for both clsact hooks - the parse is direction-agnostic, and
 * a container's outbound handshake arrives on the INGRESS side of its veth.
 *
 * Name must stay <= 15 chars: BPF_OBJ_NAME_LEN is 16 incl. NUL, and a
 * longer name shows truncated in bpftool. */
SEC("tc")
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
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	/* Only the first fragment carries the TCP header. */
	if (ip->frag_off & bpf_htons(IP_OFFMASK))
		return TC_ACT_OK;
	if (ip->ihl < 5)
		return TC_ACT_OK;
	l4_off = ETH_HLEN + (__u32)ip->ihl * 4;	/* <= 14 + 60 */

	tcp = data + l4_off;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;
	if (tcp->doff < 5)
		return TC_ACT_OK;
	pay_off = l4_off + (__u32)tcp->doff * 4;	/* <= 134 */

	if (pay_off + TLS_SNIFF_LEN > skb->len)
		return TC_ACT_OK;

	/* Read the tuple before any helper call so the verifier keeps the
	 * packet pointers valid. */
	tuple.saddr = ip->saddr;
	tuple.daddr = ip->daddr;
	tuple.sport = tcp->source;
	tuple.dport = tcp->dest;

	if (bpf_skb_load_bytes(skb, pay_off, tls, sizeof(tls)) < 0)
		return TC_ACT_OK;

	/* Assumes the segment starts on a record boundary, which holds for the
	 * first data segment of a connection - the only place a ClientHello
	 * can appear. */
	if (tls[0] != TLS_CT_HANDSHAKE)
		return TC_ACT_OK;
	if (tls[1] != 0x03)		/* record layer version is always 3.x */
		return TC_ACT_OK;
	if (tls[5] != TLS_HS_CLIENT_HELLO)
		return TC_ACT_OK;

	record_len = ((__u16)tls[3] << 8) | tls[4];
	if (record_len < TLS_HS_HLEN || record_len > TLS_RECORD_MAX)
		return TC_ACT_OK;

	bump(SKB_STAT_DETECTED);

	/* How much of the record body reaches the peer in the segment that
	 * carries the record header.
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
	 * gso_size carries the container's MSS.
	 *
	 * avail >= TLS_SNIFF_LEN on both paths - the length check above for
	 * the unclamped one, the gso_size guard for the other - so body_len
	 * is at least 1. skb->len can exceed 64 KiB, but the min() bounds the
	 * result by record_len, itself <= TLS_RECORD_MAX, so __u16 holds. */
	avail = skb->len - pay_off;
	seg_len = skb->gso_size;
	if (seg_len >= TLS_SNIFF_LEN && seg_len < avail)
		avail = seg_len;

	body_len = avail - TLS_RECORD_HLEN;
	captured_len = body_len < record_len ? (__u16)body_len : record_len;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		__u32 zero = 0;

		bump(SKB_STAT_DROPPED);
		if (!enforce)
			return TC_ACT_OK;
		ev = bpf_map_lookup_elem(&scratch, &zero);
		if (!ev)
			return TC_ACT_OK;
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

	/* Out of scope still gets a verdict, so the event can say what
	 * would have happened, but always passes. */
	if (enforce) {
		ev->verdict = check_policy(ev);
		ev->action = SKB_ACTION_PASS;
		if (bpf_skb_ancestor_cgroup_id(skb, scope_level) == scope_id &&
		    (ev->verdict == SKB_VERDICT_VIOLATION ||
		     (ev->verdict == SKB_VERDICT_UNKNOWN && unknown_block)))
			ev->action = SKB_ACTION_BLOCK;
	}
	act = ev->action == SKB_ACTION_BLOCK ? TC_ACT_SHOT : TC_ACT_OK;

	if (reported)
		bpf_ringbuf_submit(ev, 0);
	return act;
}
