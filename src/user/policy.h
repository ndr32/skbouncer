/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_POLICY_H
#define SKB_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "skbouncer.h"

struct skb_policy;

/* Reasons can include a container name of any length. A longer reason is
 * cut at this size. */
#define SKB_REASON_MAX 256

struct skb_policy *skb_policy_load(const char *path, char *errbuf, size_t errlen);

/* `container` is the event's container name, or NULL for none. `why`
 * receives the reason and may be NULL. A list cut short never gives ALLOW. A
 * forbidden cipher may sit in the unseen part. */
enum skb_verdict skb_policy_explain(const struct skb_policy *pol,
				    const struct skb_event *ev,
				    const char *container, char *why, size_t len);

/* IANA name, or NULL if not in the table. */
const char *skb_cipher_name(uint16_t id);
/* "1.0" to "1.3", otherwise "0x" and four hex digits */
const char *skb_version_name(uint16_t v, char buf[8]);

/* Enforce mode. skb_policy_rule_slot() gives the rule `container` matches as
 * an index into the kernel's rule map, where 0 is the default.
 * skb_policy_compile() writes that rule in kernel form. */
unsigned skb_policy_rule_slot(const struct skb_policy *pol, const char *container);
size_t skb_policy_n_rules(const struct skb_policy *pol);
void skb_policy_compile(const struct skb_policy *pol, unsigned slot,
			struct skb_krule *out);
bool skb_policy_blocks_unknown(const struct skb_policy *pol);

/* The policy in plain words: one line per rule, then the default and the
 * on_unknown setting. */
void skb_policy_describe(const struct skb_policy *pol, FILE *out);

const char *skb_verdict_str(enum skb_verdict v);
void skb_policy_free(struct skb_policy *pol);

#endif /* SKB_POLICY_H */
