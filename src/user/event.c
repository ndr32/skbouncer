// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "event.h"
#include "policy.h"

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

static const char *action_name(uint8_t a)
{
	return a == SKB_ACTION_BLOCK ? "block" : "pass";
}

/* ktime_ns is CLOCK_MONOTONIC; shift it by the clocks' current offset. */
static struct timespec wall_time(uint64_t ktime_ns)
{
	struct timespec mono, real;
	int64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	ns = (int64_t)real.tv_sec * 1000000000LL + real.tv_nsec -
	     ((int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec) + (int64_t)ktime_ns;
	return (struct timespec){ ns / 1000000000LL, ns % 1000000000LL };
}

void skb_event_header(FILE *out, bool verdict, bool action)
{
	fprintf(out, "%-8s ", "TIME");
	if (action)
		fprintf(out, "%-6s ", "ACTION");
	if (verdict)
		fprintf(out, "%-9s ", "VERDICT");
	fprintf(out, "%-20s %-21s %-21s %-8s %-9s %-44s%s\n",
		"CONTAINER", "SOURCE", "DEST", "TLS", "BYTES", "CIPHERS",
		verdict ? " REASON" : "");
}

/* "1.3,1.2", GREASE skipped; the legacy version if the walk proved there
 * was no supported_versions, "?" if it could not tell. */
static void format_versions(const struct skb_event *ev, char *buf, size_t len)
{
	char vb[8];
	size_t n = 0;

	buf[0] = '\0';
	for (unsigned i = 0; i < ev->n_versions && i < SKB_MAX_VERSIONS; i++) {
		uint16_t v = ntohs(ev->versions[i]);

		if (!skb_is_grease(v) && n < len)
			n += snprintf(buf + n, len - n, "%s%s", n ? "," : "",
				      skb_version_name(v, vb));
	}
	if (!n)
		snprintf(buf, len, "%s", ev->seen & SKB_SEEN_VERSIONS ?
			 skb_version_name(ev->legacy_version, vb) : "?");
}

/* The first real offer by name, then a count: a full list would not fit on
 * a line. A trailing + means the list was capped. */
static void format_ciphers(const struct skb_event *ev, char *buf, size_t len)
{
	unsigned shown = 0;
	size_t n;

	buf[0] = '\0';
	for (unsigned i = 0; i < ev->n_ciphers && i < SKB_MAX_CIPHERS; i++) {
		uint16_t c = ntohs(ev->ciphers[i]);
		const char *name;

		if (skb_cipher_ignored(c) || shown++)
			continue;
		if ((name = skb_cipher_name(c)))
			snprintf(buf, len, "%s", name);
		else
			snprintf(buf, len, "0x%04x", c);
	}
	if (!shown)
		snprintf(buf, len, "-");
	n = strlen(buf);
	if (shown > 1 || ev->ciphers_capped)
		snprintf(buf + n, len - n, " +%u%s", shown ? shown - 1 : 0,
			 ev->ciphers_capped ? "+" : "");
}

/* The cgroup id, not the veth, identifies the container: containers sharing
 * a network namespace share one veth. It is 0 for anything forwarded,
 * which is every bridged container at a physical interface. */
void skb_event_print(FILE *out, const struct skb_event *ev, const char *container,
		     const char *verdict, const char *reason)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	char sbuf[INET_ADDRSTRLEN + 8], dbuf[INET_ADDRSTRLEN + 8];
	char who[32], tls[32], bytes[24], ciphers[80];
	struct timespec ts = wall_time(ev->ktime_ns);
	struct tm tm;

	localtime_r(&ts.tv_sec, &tm);
	if (container)
		snprintf(who, sizeof(who), "%s", container);
	else
		snprintf(who, sizeof(who), "cgroup %llu", (unsigned long long)ev->cgroup_id);
	snprintf(sbuf, sizeof(sbuf), "%s:%u", ip4(src, ev->tuple.saddr),
		 ntohs(ev->tuple.sport));
	snprintf(dbuf, sizeof(dbuf), "%s:%u", ip4(dst, ev->tuple.daddr),
		 ntohs(ev->tuple.dport));
	format_versions(ev, tls, sizeof(tls));
	format_ciphers(ev, ciphers, sizeof(ciphers));
	if (ev->captured_len < ev->record_len)
		snprintf(bytes, sizeof(bytes), "%u/%u", ev->captured_len, ev->record_len);
	else
		snprintf(bytes, sizeof(bytes), "%u", ev->record_len);

	fprintf(out, "%02d:%02d:%02d ", tm.tm_hour, tm.tm_min, tm.tm_sec);
	if (ev->action)
		fprintf(out, "%-6s ", action_name(ev->action));
	if (verdict)
		fprintf(out, "%-9s ", verdict);
	fprintf(out, "%-20s %-21s %-21s %-8s %-9s %-44s%s%s\n", who, sbuf, dbuf,
		tls, bytes, ciphers, reason ? " " : "", reason ? reason : "");
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
			  const char *container, const char *verdict, const char *reason)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	struct timespec ts = wall_time(ev->ktime_ns);
	char stamp[64], zone[8];
	struct tm tm;

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
	if (reason) {
		fputs(",\"reason\":", out);
		json_str(out, reason);
	}
	/* The kernel only judges in enforce mode, where action is set, and
	 * only in scope; elsewhere kernel_verdict is null. */
	if (ev->action) {
		fprintf(out, ",\"action\":\"%s\",\"kernel_verdict\":", action_name(ev->action));
		if (ev->verdict == SKB_VERDICT_NONE)
			fputs("null", out);
		else
			fprintf(out, "\"%s\"", skb_verdict_str(ev->verdict));
	}
	/* ISO 8601 local time with a +hh:mm offset, which %z does not give. */
	localtime_r(&ts.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);
	strftime(zone, sizeof(zone), "%z", &tm);
	fprintf(out, ",\"time\":\"%s.%06ld%.3s:%.2s\"}\n", stamp,
		ts.tv_nsec / 1000, zone, zone + 3);
}
