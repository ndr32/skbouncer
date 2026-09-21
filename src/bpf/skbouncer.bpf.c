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
	__uint(max_entries, 1 << 18);	/* 256 KiB; ~460 events */
} events SEC(".maps");

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
	__u32 l4_off, pay_off;
	__u16 record_len;
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

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return TC_ACT_OK;
	/* Reserved ringbuf memory is not zeroed and the M3 fields are not
	 * filled yet; clear the whole record rather than leak stale bytes. */
	__builtin_memset(ev, 0, sizeof(*ev));

	ev->cgroup_id = bpf_skb_cgroup_id(skb);
	ev->ktime_ns = bpf_ktime_get_ns();
	ev->tuple = tuple;
	ev->record_len = record_len;
	ev->event_version = SKB_EVENT_VERSION;

	bpf_ringbuf_submit(ev, 0);
	return TC_ACT_OK;
}
