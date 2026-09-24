/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_POLICY_H
#define SKB_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "skbouncer.h"

struct skb_policy;

struct skb_policy *skb_policy_load(const char *path, char *errbuf, size_t errlen);

/* `container` is the event's container name, or NULL for none; `why` gets
 * the reason and may be NULL. Never ALLOW on a list cut short: the forbidden
 * cipher may be in the part not seen. */
enum skb_verdict skb_policy_explain(const struct skb_policy *pol,
				    const struct skb_event *ev,
				    const char *container, char *why, size_t len);

/* IANA name, or NULL if not in the table. */
const char *skb_cipher_name(uint16_t id);
/* "1.0".."1.3", else "0x...." */
const char *skb_version_name(uint16_t v, char buf[8]);

/* Enforce mode: the rule `container` matches, as an index into the kernel's
 * rule map (0 = none matched, i.e. the default), and that rule compiled. */
unsigned skb_policy_rule_slot(const struct skb_policy *pol, const char *container);
size_t skb_policy_n_rules(const struct skb_policy *pol);
void skb_policy_compile(const struct skb_policy *pol, unsigned slot,
			struct skb_krule *out);
bool skb_policy_blocks_unknown(const struct skb_policy *pol);

const char *skb_verdict_str(enum skb_verdict v);
void skb_policy_free(struct skb_policy *pol);

#endif /* SKB_POLICY_H */
