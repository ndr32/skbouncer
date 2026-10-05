/* SPDX-License-Identifier: GPL-2.0 */
/* Shared by the kernel side and the userspace side. Fixed-width types only. */
#ifndef SKBOUNCER_H
#define SKBOUNCER_H

/* vmlinux.h supplies these on the BPF side and defines this guard. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Bump on any layout change to struct skb_event. */
#define SKB_EVENT_VERSION 8

#define SKB_MAX_CIPHERS   64	/* the verifier requires a bounded walk */
#define SKB_MAX_VERSIONS  8
#define SKB_MAX_EXTS      32	/* extensions walked in search of supported_versions (0x002b) */
#define SKB_MAX_RULES     64	/* policy rules. Map slot 0 holds the policy default. */
#define SKB_MAX_CGROUPS   4096	/* entries mapping a cgroup id to a rule slot */

/* Values in a ClientHello that offer nothing. Both policy checks skip them.
 * GREASE values (RFC 8701, 0x0a0a, 0x1a1a up to 0xfafa) appear in the cipher
 * and version lists, and the two signalling cipher suites appear in the
 * cipher list. */
#define SKB_SCSV_RENEGOTIATION 0x00ff
#define SKB_SCSV_FALLBACK      0x5600

static inline int skb_is_grease(__u16 v)
{
	return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

static inline int skb_cipher_ignored(__u16 c)
{
	return skb_is_grease(c) || c == SKB_SCSV_RENEGOTIATION || c == SKB_SCSV_FALLBACK;
}

/* Counters kept by the kernel side. They give the coverage denominator. An
 * event lost to a full ringbuf still counts as a detected ClientHello. */
enum skb_stat {
	SKB_STAT_DETECTED = 0,	/* ClientHello matched */
	SKB_STAT_DROPPED,	/* bpf_ringbuf_reserve() returned NULL */
	SKB_STAT_SHORT,		/* a 1 to 5 byte segment that starts a handshake record, too short to classify */
	SKB_STAT__MAX,
};

/* Lists the walk read in full. trunc_reason records that the record was cut.
 * These flags record which lists the cut left whole. A verdict on a list is
 * certain only when the walk read that list in full. */
enum skb_seen {
	SKB_SEEN_CIPHERS  = 1 << 0,	/* every offered cipher is in ciphers[] */
	SKB_SEEN_VERSIONS = 1 << 1,	/* supported_versions read in full, or proved absent */
};

/* Defined in policy/README.md under Verdicts. The userspace side computes a
 * verdict in every mode. In enforce mode the kernel side computes one as
 * well. Only the kernel can drop the packet before it leaves. */
enum skb_verdict {
	SKB_VERDICT_ALLOW = 0,
	SKB_VERDICT_VIOLATION,
	SKB_VERDICT_UNKNOWN,	/* a constrained list was not seen in full */
	SKB_VERDICT_NONE,	/* kernel side only. The cgroup is outside --cgroup and was not judged. */
};

/* What the kernel did with the ClientHello. NONE outside enforce mode. */
enum skb_action {
	SKB_ACTION_NONE = 0,
	SKB_ACTION_PASS,
	SKB_ACTION_BLOCK,
};

enum skb_krule_flags {
	SKB_KRULE_VALID      = 1 << 0,	/* set by userspace. Without it the kernel allows. */
	SKB_KRULE_FIXED      = 1 << 1,	/* no rule matched, and `fixed` holds the verdict */
	SKB_KRULE_ANY_CIPHER = 1 << 2,	/* rule has no "ciphers" */
};

/* One policy rule in the form the kernel checks. The permitted ciphers are a
 * bitmap over all 65,536 code points, and checking one cipher is a single
 * load. */
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
	SKB_TRUNC_PARSE,	/* malformed. A length field points past the record. */
};

/* All fields are in network byte order, as on the wire. */
struct skb_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

/* One ClientHello, seen as ingress on the host end of a container's veth. A
 * bridged container's outgoing traffic arrives there still carrying the
 * container's own address before NAT. At the physical interface the same
 * packet has been forwarded and SNATed, and it no longer carries a cgroup
 * id. Containers that share a network namespace share one veth, so
 * cgroup_id names the container.
 *
 * The field order leaves no implicit padding on x86_64. */
struct skb_event {
	__u64 cgroup_id;
	__u64 ktime_ns;		/* CLOCK_MONOTONIC, unaffected by NTP steps */

	struct skb_tuple tuple;

	__u32 ifindex;		/* the veth the program is attached to */

	__u16 record_len;
	__u16 captured_len;
	__u16 handshake_len;
	__u16 legacy_version;

	__u8  trunc_reason;
	__u8  event_version;
	__u8  n_ciphers;	/* entries filled in ciphers[] */
	__u8  n_versions;	/* entries filled in versions[]; 0 = absent */
	__u8  ciphers_capped;	/* offered more than SKB_MAX_CIPHERS */
	__u8  seen;		/* enum skb_seen */
	__u8  action;		/* enum skb_action */
	__u8  verdict;		/* enum skb_verdict. The kernel's, enforce mode only. */

	/* Wire order and big-endian. Userspace converts them. */
	__u16 ciphers[SKB_MAX_CIPHERS];
	__u16 versions[SKB_MAX_VERSIONS];
};

#endif /* SKBOUNCER_H */
