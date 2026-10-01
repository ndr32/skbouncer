// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "event.h"
#include "policy.h"

/* inet_ntop() into a buffer from the caller. One line holds two addresses
 * and needs two buffers. */
static const char *ip4(char buf[INET_ADDRSTRLEN], uint32_t be_addr)
{
	struct in_addr a = { .s_addr = be_addr };

	return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) ? buf : "?";
}

const char *skb_direction_name(uint8_t dir)
{
	return dir == SKB_DIR_INGRESS ? "ingress" : "egress";
}

/* Names short enough for one column. They are also the JSON `trunc` values. */
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

/* ktime_ns is CLOCK_MONOTONIC. The wall clock time adds the current offset
 * between the two clocks. */
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

/* Writes the versions as "1.3,1.2", skipping GREASE. Without
 * supported_versions it writes the legacy version if the walk proved the
 * extension absent, and "?" otherwise. */
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

/* Writes the first real offer by name and then a count of the rest. A full
 * list would not fit on a line. A trailing + means the list was capped. */
static void format_ciphers(const struct skb_event *ev, char *buf, size_t len)
{
	unsigned shown = 0;
	size_t n;

	buf[0] = '\0';
	for (unsigned i = 0; i < ev->n_ciphers && i < SKB_MAX_CIPHERS; i++) {
		uint16_t c = ntohs(ev->ciphers[i]);
		const char *name;

		if (skb_cipher_ignored(c))
			continue;
		if (shown == 0) {
			name = skb_cipher_name(c);
			if (name)
				snprintf(buf, len, "%s", name);
			else
				snprintf(buf, len, "0x%04x", c);
		}
		shown++;
	}
	if (!shown)
		snprintf(buf, len, "-");
	n = strlen(buf);
	if (shown > 1 || ev->ciphers_capped)
		snprintf(buf + n, len - n, " +%u%s", shown ? shown - 1 : 0,
			 ev->ciphers_capped ? "+" : "");
}

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

/* A list in wire order, as host-order numbers. */
static json_t *u16_list(const __u16 *v, unsigned n, unsigned max)
{
	json_t *a = json_array();

	for (unsigned i = 0; i < n && i < max; i++)
		json_array_append_new(a, json_integer(ntohs(v[i])));
	return a;
}

/* ISO 8601 local time with a +hh:mm offset, which %z does not give. */
static const char *iso_time(uint64_t ktime_ns, char *buf, size_t len)
{
	struct timespec ts = wall_time(ktime_ns);
	char stamp[32], zone[8];
	struct tm tm;

	localtime_r(&ts.tv_sec, &tm);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);
	strftime(zone, sizeof(zone), "%z", &tm);
	snprintf(buf, len, "%s.%06ld%.3s:%.2s", stamp, ts.tv_nsec / 1000, zone, zone + 3);
	return buf;
}

void skb_event_print_json(FILE *out, const struct skb_event *ev,
			  const char *container, const char *verdict, const char *reason)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], when[48];
	json_t *o;

	o = json_pack("{s:I, s:I, s:s, s:I, s:s?, s:s, s:i, s:s, s:i, s:i, s:i, s:s,"
		      " s:i, s:i, s:o, s:o, s:b, s:b, s:b}",
		"ktime_ns", (json_int_t)ev->ktime_ns,
		"ifindex", (json_int_t)ev->ifindex,
		"direction", skb_direction_name(ev->direction),
		"cgroup_id", (json_int_t)ev->cgroup_id,
		"container", container,
		"saddr", ip4(src, ev->tuple.saddr),
		"sport", ntohs(ev->tuple.sport),
		"daddr", ip4(dst, ev->tuple.daddr),
		"dport", ntohs(ev->tuple.dport),
		"record_len", ev->record_len,
		"captured_len", ev->captured_len,
		"trunc", trunc_name(ev->trunc_reason),
		"handshake_len", ev->handshake_len,
		"legacy_version", ev->legacy_version,
		"versions", u16_list(ev->versions, ev->n_versions, SKB_MAX_VERSIONS),
		"ciphers", u16_list(ev->ciphers, ev->n_ciphers, SKB_MAX_CIPHERS),
		"ciphers_capped", ev->ciphers_capped,
		"ciphers_seen", !!(ev->seen & SKB_SEEN_CIPHERS),
		"versions_seen", !!(ev->seen & SKB_SEEN_VERSIONS));
	if (!o) {
		fprintf(stderr, "skbouncer: cannot encode an event as JSON\n");
		return;
	}
	if (verdict)
		json_object_set_new(o, "verdict", json_string(verdict));
	if (reason)
		json_object_set_new(o, "reason", json_string(reason));
	/* The kernel judges in enforce mode only, where action is set, and
	 * only in scope. Elsewhere kernel_verdict is null. */
	if (ev->action) {
		json_object_set_new(o, "action", json_string(action_name(ev->action)));
		json_object_set_new(o, "kernel_verdict", ev->verdict == SKB_VERDICT_NONE ?
				    json_null() : json_string(skb_verdict_str(ev->verdict)));
	}
	json_object_set_new(o, "time", json_string(iso_time(ev->ktime_ns, when, sizeof(when))));
	json_dumpf(o, out, JSON_COMPACT);
	fputc('\n', out);
	json_decref(o);
}
