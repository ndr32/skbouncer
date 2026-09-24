/* SPDX-License-Identifier: GPL-2.0 */
/* Shared between the BPF program and userspace. Fixed-width types only. */
#ifndef SKBOUNCER_H
#define SKBOUNCER_H

/* vmlinux.h supplies these on the BPF side and defines this guard. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Bump on any layout change to struct skb_event. */
#define SKB_EVENT_VERSION 7

#define SKB_MAX_CIPHERS   64	/* verifier needs a bounded walk */
#define SKB_MAX_VERSIONS  8
#define SKB_MAX_EXTS      32	/* extensions walked looking for 0x002b */
#define SKB_MAX_RULES     64	/* policy rules; map slot 0 is "no rule matched" */
#define SKB_MAX_CGROUPS   4096	/* cgroup id -> rule index entries */

/* Kernel-side tallies. M7 needs a denominator: an event lost to a full
 * ringbuf must not look like a connection that never happened. */
enum skb_stat {
	SKB_STAT_DETECTED = 0,	/* ClientHello matched */
	SKB_STAT_DROPPED,	/* bpf_ringbuf_reserve() returned NULL */
	SKB_STAT_SHORT,		/* 1-5 byte segment starting a handshake record: unclassifiable */
	SKB_STAT__MAX,
};

/* Which clsact hook the program sits on. Container identity comes from the
 * attachment point, not from cgroup_id: a bridged container's packet is
 * already forwarded and SNATed by the time it reaches the physical
 * interface, so it is watched as INGRESS on the host side of its veth. */
enum skb_direction {
	SKB_DIR_EGRESS = 0,
	SKB_DIR_INGRESS,
};

/* Which lists the walk read in full. trunc_reason says the record was cut;
 * these say whether the cut mattered. A verdict is only certain for a list
 * seen whole. */
enum skb_seen {
	SKB_SEEN_CIPHERS  = 1 << 0,	/* every offered cipher is in ciphers[] */
	SKB_SEEN_VERSIONS = 1 << 1,	/* supported_versions read whole, or known absent */
};

/* policy/README.md, Verdicts. Computed by userspace in every mode, and
 * by the kernel as well in enforce mode, since only it can drop in time. */
enum skb_verdict {
	SKB_VERDICT_ALLOW = 0,
	SKB_VERDICT_VIOLATION,
	SKB_VERDICT_UNKNOWN,	/* a constrained list was not seen in full */
	SKB_VERDICT_NONE,	/* kernel only: outside --cgroup, not judged */
};

/* What the kernel did with the ClientHello. NONE outside enforce mode. */
enum skb_action {
	SKB_ACTION_NONE = 0,
	SKB_ACTION_PASS,
	SKB_ACTION_BLOCK,
};

enum skb_krule_flags {
	SKB_KRULE_VALID      = 1 << 0,	/* written by userspace; unset fails open */
	SKB_KRULE_FIXED      = 1 << 1,	/* no rule matched: `fixed` is the verdict */
	SKB_KRULE_ANY_CIPHER = 1 << 2,	/* rule has no "ciphers" */
};

/* One policy rule as the kernel checks it. The cipher list is a bitmap over
 * all 2^16 code points, so a lookup is one load rather than a nested loop. */
struct skb_krule {
	__u16 min_version;	/* 0 = any */
	__u8  flags;		/* enum skb_krule_flags */
	__u8  fixed;		/* enum skb_verdict, with SKB_KRULE_FIXED */
	__u32 _pad;
	__u64 ciphers[65536 / 64];
};

enum skb_trunc_reason {
	SKB_TRUNC_NONE = 0,
	SKB_TRUNC_SEGMENT,	/* record continues in a later segment */
	SKB_TRUNC_EXT_LIMIT,	/* walked SKB_MAX_EXTS extensions without reaching the end */
	SKB_TRUNC_PARSE,	/* malformed: a length points past the record */
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

	__u32 ifindex;		/* device the hook is on; names the container */

	__u16 record_len;
	__u16 captured_len;
	__u16 handshake_len;
	__u16 legacy_version;

	__u8  trunc_reason;
	__u8  direction;	/* enum skb_direction */
	__u8  event_version;
	__u8  n_ciphers;	/* entries filled in ciphers[] */
	__u8  n_versions;	/* entries filled in versions[]; 0 = absent */
	__u8  ciphers_capped;	/* offered more than SKB_MAX_CIPHERS */
	__u8  seen;		/* enum skb_seen */
	__u8  action;		/* enum skb_action */

	/* Wire order, and still big-endian: userspace swaps. */
	__u16 ciphers[SKB_MAX_CIPHERS];
	__u16 versions[SKB_MAX_VERSIONS];

	__u8  verdict;		/* enum skb_verdict; the kernel's, enforce mode only */
	__u8  _pad[7];
};

#endif /* SKBOUNCER_H */
