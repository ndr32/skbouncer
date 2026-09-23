// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>

#include "event.h"

/* inet_ntop() into a caller slot: two calls per line need two buffers. */
static const char *ip4(char buf[INET_ADDRSTRLEN], uint32_t be_addr)
{
	struct in_addr a = { .s_addr = be_addr };

	return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) ? buf : "?";
}

const char *skb_direction_name(uint8_t dir)
{
	return dir == SKB_DIR_INGRESS ? "ingress" : "egress";
}

/* Short enough to stay in one column. Also the JSON `trunc` values. */
static const char *trunc_name(uint8_t reason)
{
	switch (reason) {
	case SKB_TRUNC_NONE:     return "none";
	case SKB_TRUNC_SEGMENT:  return "segment";
	case SKB_TRUNC_EXT_LIMIT: return "ext_limit";
	case SKB_TRUNC_PARSE:    return "parse";
	default:                 return "?";
	}
}

/* The cgroup id, not the veth, identifies the container: containers sharing
 * a network namespace share one veth. It is 0 for anything forwarded,
 * which is every bridged container at a physical interface. */
void skb_event_header(FILE *out, bool verdict)
{
	if (verdict)
		fprintf(out, "%-9s ", "VERDICT");
	fprintf(out, "%-18s %-15s %-7s %-10s %-20s %-21s %-21s %6s %8s %-8s %-6s %7s %s\n",
		"TIME(mono)", "IFACE", "DIR", "CGROUP", "CONTAINER", "SOURCE", "DEST",
		"RECORD", "CAPTURED", "TRUNC", "LEGACY", "CIPHERS", "VERSIONS");
}

void skb_event_print(FILE *out, const struct skb_event *ev, const char *container,
		     const char *verdict)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	char sbuf[INET_ADDRSTRLEN + 8], dbuf[INET_ADDRSTRLEN + 8];
	char ifname[IF_NAMESIZE + 12];
	char dev[IF_NAMESIZE];

	/* The device may be gone by the time we print - a container that has
	 * already exited takes its veth with it. Fall back to the index. */
	if (if_indextoname(ev->ifindex, dev))
		snprintf(ifname, sizeof(ifname), "%s", dev);
	else
		snprintf(ifname, sizeof(ifname), "if%u", ev->ifindex);

	snprintf(sbuf, sizeof(sbuf), "%s:%u", ip4(src, ev->tuple.saddr),
		 ntohs(ev->tuple.sport));
	snprintf(dbuf, sizeof(dbuf), "%s:%u", ip4(dst, ev->tuple.daddr),
		 ntohs(ev->tuple.dport));

	if (verdict)
		fprintf(out, "%-9s ", verdict);
	/* __u64 is unsigned long long here, so PRIu64 ("lu") would not match. */
	fprintf(out, "%6llu.%09llu %-15s %-7s %-10llu %-20s %-21s %-21s %6u %8u %-8s %04x %6u%s ",
		(unsigned long long)(ev->ktime_ns / 1000000000ULL),
		(unsigned long long)(ev->ktime_ns % 1000000000ULL),
		ifname, skb_direction_name(ev->direction),
		(unsigned long long)ev->cgroup_id, container ? container : "-",
		sbuf, dbuf, ev->record_len, ev->captured_len,
		trunc_name(ev->trunc_reason), ev->legacy_version,
		ev->n_ciphers, ev->ciphers_capped ? "+" : " ");
	for (unsigned i = 0; i < ev->n_versions && i < SKB_MAX_VERSIONS; i++)
		fprintf(out, "%s%04x", i ? "," : "", ntohs(ev->versions[i]));
	fprintf(out, "%s\n", ev->n_versions ? "" : "-");
}

static void u16_array(FILE *out, const __u16 *v, unsigned n, unsigned max)
{
	fputc('[', out);
	for (unsigned i = 0; i < n && i < max; i++)
		fprintf(out, "%s%u", i ? "," : "", ntohs(v[i]));
	fputc(']', out);
}

/* Docker names are [a-zA-Z0-9][a-zA-Z0-9_.-]+, but escape anyway. */
static void json_str(FILE *out, const char *s)
{
	if (!s) {
		fputs("null", out);
		return;
	}
	fputc('"', out);
	for (; *s; s++) {
		unsigned char c = *s;

		if (c == '"' || c == '\\')
			fprintf(out, "\\%c", c);
		else if (c < 0x20)
			fprintf(out, "\\u%04x", c);
		else
			fputc(c, out);
	}
	fputc('"', out);
}

void skb_event_print_json(FILE *out, const struct skb_event *ev,
			  const char *container, const char *verdict)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

	fprintf(out, "{\"ktime_ns\":%llu,\"ifindex\":%u,\"direction\":\"%s\","
		"\"cgroup_id\":%llu,\"container\":",
		(unsigned long long)ev->ktime_ns, ev->ifindex,
		skb_direction_name(ev->direction),
		(unsigned long long)ev->cgroup_id);
	json_str(out, container);
	fprintf(out, ",\"saddr\":\"%s\",\"sport\":%u,"
		"\"daddr\":\"%s\",\"dport\":%u,\"record_len\":%u,"
		"\"captured_len\":%u,\"trunc\":\"%s\",\"handshake_len\":%u,"
		"\"legacy_version\":%u,\"versions\":",
		ip4(src, ev->tuple.saddr), ntohs(ev->tuple.sport),
		ip4(dst, ev->tuple.daddr), ntohs(ev->tuple.dport),
		ev->record_len, ev->captured_len, trunc_name(ev->trunc_reason),
		ev->handshake_len, ev->legacy_version);
	u16_array(out, ev->versions, ev->n_versions, SKB_MAX_VERSIONS);
	fputs(",\"ciphers\":", out);
	u16_array(out, ev->ciphers, ev->n_ciphers, SKB_MAX_CIPHERS);
	fprintf(out, ",\"ciphers_capped\":%s,\"ciphers_seen\":%s,\"versions_seen\":%s",
		ev->ciphers_capped ? "true" : "false",
		ev->seen & SKB_SEEN_CIPHERS ? "true" : "false",
		ev->seen & SKB_SEEN_VERSIONS ? "true" : "false");
	if (verdict)
		fprintf(out, ",\"verdict\":\"%s\"", verdict);
	fputs("}\n", out);
}
