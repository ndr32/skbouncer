/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_POLICY_H
#define SKB_POLICY_H

#include <stdint.h>
#include "skbouncer.h"

enum skb_verdict {
	SKB_VERDICT_ALLOW = 0,
	SKB_VERDICT_VIOLATION,
	SKB_VERDICT_UNKNOWN,	/* a constrained list was not seen in full */
};

struct skb_policy;

struct skb_policy *skb_policy_load(const char *path, char *errbuf, size_t errlen);

/* `container` is the event's container name, or NULL for none. Never ALLOW
 * on a list cut short: the forbidden cipher may be in the part not seen. */
enum skb_verdict skb_policy_check(const struct skb_policy *pol,
				  const struct skb_event *ev,
				  const char *container);

const char *skb_verdict_str(enum skb_verdict v);
void skb_policy_free(struct skb_policy *pol);

#endif /* SKB_POLICY_H */
