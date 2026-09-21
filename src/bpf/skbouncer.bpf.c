// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "skbouncer.h"

#define TC_ACT_OK 0

#define ETH_P_IP  0x0800
#define ETH_HLEN  14

#define IP_OFFMASK 0x1fff

#define TLS_CT_HANDSHAKE   0x16
#define TLS_HS_CLIENT_HELLO 0x01
#define TLS_RECORD_HLEN    5
#define TLS_RECORD_MAX     16384	/* RFC 8446 5.1: 2^14 */
#define TLS_HS_HLEN        4		/* type + uint24 length */

/* Record header plus the first byte of the handshake body. */
#define TLS_SNIFF_LEN (TLS_RECORD_HLEN + 1)

char LICENSE[] SEC("license") = "GPL";

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

/* Name must stay <= 15 chars: BPF_OBJ_NAME_LEN is 16 incl. NUL, and a
 * longer name shows truncated in bpftool. */
SEC("tc")
int skb_egress(struct __sk_buff *skb)
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

	/* L2/L3/L4 headers are always in the linear area at egress, so direct
	 * access is safe here. The payload is not: tcp_sendmsg parks it in page
	 * frags, hence bpf_skb_load_bytes() for the TLS bytes below. */
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

	/* Reserve the header only. The size must be a compile-time constant
	 * for the verifier, and `snapshot` stays empty until M3 fills it. */
	ev = bpf_ringbuf_reserve(&events, SKB_EVENT_HDR_LEN, 0);
	if (!ev) {
		bump(SKB_STAT_DROPPED);
		return TC_ACT_OK;
	}
	/* Reserved ringbuf memory is not zeroed and the M3 fields are not
	 * filled yet; clear the header rather than leak stale bytes. */
	__builtin_memset(ev, 0, SKB_EVENT_HDR_LEN);

	ev->cgroup_id = bpf_skb_cgroup_id(skb);
	ev->ktime_ns = bpf_ktime_get_ns();
	ev->tuple = tuple;
	ev->record_len = record_len;
	ev->captured_len = captured_len;
	ev->trunc_reason = captured_len < record_len ? SKB_TRUNC_SEGMENT
						     : SKB_TRUNC_NONE;
	ev->event_version = SKB_EVENT_VERSION;

	bpf_ringbuf_submit(ev, 0);
	return TC_ACT_OK;
}
