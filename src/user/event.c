// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <stdint.h>

#include "event.h"

/* inet_ntop() into a caller slot: two calls per line need two buffers. */
static const char *ip4(char buf[INET_ADDRSTRLEN], uint32_t be_addr)
{
	struct in_addr a = { .s_addr = be_addr };

	return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) ? buf : "?";
}

/* Short enough to stay in one column; M3 adds the SNAPSHOT/PARSE cases. */
static const char *trunc_name(uint8_t reason)
{
	switch (reason) {
	case SKB_TRUNC_NONE:     return "none";
	case SKB_TRUNC_SEGMENT:  return "segment";
	case SKB_TRUNC_SNAPSHOT: return "snapshot";
	case SKB_TRUNC_PARSE:    return "parse";
	default:                 return "?";
	}
}

void skb_event_header(FILE *out)
{
	fprintf(out, "%-18s %-20s %-21s %-21s %6s %8s %s\n",
		"TIME(mono)", "CGROUP", "SOURCE", "DEST",
		"RECORD", "CAPTURED", "TRUNC");
}

void skb_event_print(FILE *out, const struct skb_event *ev)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	char sbuf[INET_ADDRSTRLEN + 8], dbuf[INET_ADDRSTRLEN + 8];

	snprintf(sbuf, sizeof(sbuf), "%s:%u", ip4(src, ev->tuple.saddr),
		 ntohs(ev->tuple.sport));
	snprintf(dbuf, sizeof(dbuf), "%s:%u", ip4(dst, ev->tuple.daddr),
		 ntohs(ev->tuple.dport));

	/* __u64 is unsigned long long here, so PRIu64 ("lu") would not match. */
	fprintf(out, "%6llu.%09llu %-20llu %-21s %-21s %6u %8u %s\n",
		(unsigned long long)(ev->ktime_ns / 1000000000ULL),
		(unsigned long long)(ev->ktime_ns % 1000000000ULL),
		(unsigned long long)ev->cgroup_id, sbuf, dbuf,
		ev->record_len, ev->captured_len,
		trunc_name(ev->trunc_reason));
}
