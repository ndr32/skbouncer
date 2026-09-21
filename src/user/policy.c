// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#endif

struct skb_policy {
	int placeholder;
};

struct skb_policy *skb_policy_load(const char *path, char *errbuf, size_t errlen)
{
#ifdef HAVE_JANSSON
	snprintf(errbuf, errlen, "policy loading not implemented (%s)", path);
#else
	snprintf(errbuf, errlen,
		 "built without jansson; run: sudo apt install libjansson-dev");
#endif
	return NULL;
}

enum skb_verdict skb_policy_check(const struct skb_policy *pol,
				  const struct skb_event *ev)
{
	(void)pol;
	(void)ev;
	return SKB_VERDICT_UNKNOWN;
}

const char *skb_verdict_str(enum skb_verdict v)
{
	switch (v) {
	case SKB_VERDICT_ALLOW:     return "allow";
	case SKB_VERDICT_VIOLATION: return "violation";
	case SKB_VERDICT_UNKNOWN:   return "unknown";
	}
	return "invalid";
}

void skb_policy_free(struct skb_policy *pol)
{
	free(pol);
}
