/* SPDX-License-Identifier: GPL-2.0 */
/* Shared between the BPF program and userspace. Fixed-width types only. */
#ifndef SKBOUNCER_H
#define SKBOUNCER_H

/* vmlinux.h supplies these on the BPF side and defines this guard. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Bump on any layout change to struct skb_event. */
#define SKB_EVENT_VERSION 2

#define SKB_MAX_CIPHERS   64	/* verifier needs a bounded walk */
#define SKB_MAX_VERSIONS  8
#define SKB_MAX_SNAPSHOT  512

/* Kernel-side tallies. M7 needs a denominator: an event lost to a full
 * ringbuf must not look like a connection that never happened. */
enum skb_stat {
	SKB_STAT_DETECTED = 0,	/* ClientHello matched */
	SKB_STAT_DROPPED,	/* bpf_ringbuf_reserve() returned NULL */
	SKB_STAT__MAX,
};

enum skb_trunc_reason {
	SKB_TRUNC_NONE = 0,
	SKB_TRUNC_SEGMENT,	/* record continues in a later segment */
	SKB_TRUNC_SNAPSHOT,	/* exceeded SKB_MAX_SNAPSHOT */
	SKB_TRUNC_PARSE,	/* walk stopped early */
};

/* Everything here is in network byte order, as it sits on the wire. */
struct skb_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

/* Add fields at the tail; order avoids implicit padding on x86_64. */
struct skb_event {
	__u64 cgroup_id;
	__u64 ktime_ns;		/* monotonic; survives NTP steps */

	struct skb_tuple tuple;

	__u16 record_len;
	__u16 captured_len;
	__u16 handshake_len;
	__u16 legacy_version;

	__u8  trunc_reason;
	__u8  event_version;
	__u8  _pad[6];

	__u8  snapshot[SKB_MAX_SNAPSHOT];
};

/* Records carry the header plus however much of `snapshot` was filled, so
 * the tail is not sent while it is empty. Userspace must accept anything at
 * least this long: M3 starts filling the snapshot and the records grow
 * without a further format change. */
#define SKB_EVENT_HDR_LEN __builtin_offsetof(struct skb_event, snapshot)

#endif /* SKBOUNCER_H */
