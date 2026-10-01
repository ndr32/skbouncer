// SPDX-License-Identifier: GPL-2.0
/* Loads the JSON policy and gives verdicts. policy/README.md defines the
 * format and the verdict rules. */
#include <arpa/inet.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "policy.h"

#include <jansson.h>

struct skb_rule {
	char *container;	/* fnmatch() pattern */
	uint16_t min_version;	/* 0 = any */
	bool any_cipher;
	uint16_t *ciphers;
	size_t n_ciphers;
};

struct skb_policy {
	bool default_allow;
	bool unknown_block;
	struct skb_rule *rules;
	size_t n_rules;
};

/* Names from the IANA TLS Cipher Suites registry that are in current use.
 * Other cipher suites can be given in hex. */
static const struct { const char *name; uint16_t id; } cipher_names[] = {
	{ "TLS_AES_128_GCM_SHA256",                        0x1301 },
	{ "TLS_AES_256_GCM_SHA384",                        0x1302 },
	{ "TLS_CHACHA20_POLY1305_SHA256",                  0x1303 },
	{ "TLS_AES_128_CCM_SHA256",                        0x1304 },
	{ "TLS_AES_128_CCM_8_SHA256",                      0x1305 },
	{ "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",       0xc02b },
	{ "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",       0xc02c },
	{ "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",         0xc02f },
	{ "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",         0xc030 },
	{ "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",   0xcca8 },
	{ "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9 },
	{ "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",     0xccaa },
	{ "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",       0xc023 },
	{ "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",       0xc024 },
	{ "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",         0xc027 },
	{ "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",         0xc028 },
	{ "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",          0xc009 },
	{ "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",          0xc00a },
	{ "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",            0xc013 },
	{ "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",            0xc014 },
	{ "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",              0xc0ac },
	{ "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",              0xc0ad },
	{ "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",            0xc0ae },
	{ "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",            0xc0af },
	{ "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",           0xc012 },
	{ "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",         0xc008 },
	{ "TLS_ECDHE_RSA_WITH_RC4_128_SHA",                0xc011 },
	{ "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",              0xc007 },
	{ "TLS_ECDHE_RSA_WITH_NULL_SHA",                   0xc010 },
	{ "TLS_ECDHE_ECDSA_WITH_NULL_SHA",                 0xc006 },
	{ "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",           0x009e },
	{ "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",           0x009f },
	{ "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",           0x0067 },
	{ "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",           0x006b },
	{ "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",              0x0033 },
	{ "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",              0x0039 },
	{ "TLS_DHE_RSA_WITH_AES_128_CCM",                  0xc09e },
	{ "TLS_DHE_RSA_WITH_AES_256_CCM",                  0xc09f },
	{ "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",             0x0016 },
	{ "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",           0x00a2 },
	{ "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",           0x00a3 },
	{ "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",           0x0040 },
	{ "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",           0x006a },
	{ "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",              0x0032 },
	{ "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",              0x0038 },
	{ "TLS_RSA_WITH_AES_128_GCM_SHA256",               0x009c },
	{ "TLS_RSA_WITH_AES_256_GCM_SHA384",               0x009d },
	{ "TLS_RSA_WITH_AES_128_CBC_SHA256",               0x003c },
	{ "TLS_RSA_WITH_AES_256_CBC_SHA256",               0x003d },
	{ "TLS_RSA_WITH_AES_128_CBC_SHA",                  0x002f },
	{ "TLS_RSA_WITH_AES_256_CBC_SHA",                  0x0035 },
	{ "TLS_RSA_WITH_AES_128_CCM",                      0xc09c },
	{ "TLS_RSA_WITH_AES_256_CCM",                      0xc09d },
	{ "TLS_RSA_WITH_AES_128_CCM_8",                    0xc0a0 },
	{ "TLS_RSA_WITH_AES_256_CCM_8",                    0xc0a1 },
	{ "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",             0x0041 },
	{ "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",             0x0084 },
	{ "TLS_RSA_WITH_SEED_CBC_SHA",                     0x0096 },
	{ "TLS_RSA_WITH_IDEA_CBC_SHA",                     0x0007 },
	{ "TLS_RSA_WITH_3DES_EDE_CBC_SHA",                 0x000a },
	{ "TLS_RSA_WITH_DES_CBC_SHA",                      0x0009 },
	{ "TLS_RSA_WITH_RC4_128_SHA",                      0x0005 },
	{ "TLS_RSA_WITH_RC4_128_MD5",                      0x0004 },
	{ "TLS_RSA_WITH_NULL_SHA256",                      0x003b },
	{ "TLS_RSA_WITH_NULL_SHA",                         0x0002 },
	{ "TLS_RSA_WITH_NULL_MD5",                         0x0001 },
	{ "TLS_NULL_WITH_NULL_NULL",                       0x0000 },
	{ "TLS_PSK_WITH_AES_128_GCM_SHA256",               0x00a8 },
	{ "TLS_PSK_WITH_AES_256_GCM_SHA384",               0x00a9 },
	{ "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",         0xccab },
	{ "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",   0xccac },
	{ "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",     0xccad },
	{ "TLS_DH_anon_WITH_AES_128_CBC_SHA",              0x0034 },
	{ "TLS_DH_anon_WITH_AES_256_CBC_SHA",              0x003a },
	{ "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",            0xc018 },
	{ "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",            0xc019 },
	{ "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",             SKB_SCSV_RENEGOTIATION },
	{ "TLS_FALLBACK_SCSV",                             SKB_SCSV_FALLBACK },
};

static bool parse_cipher(const char *s, uint16_t *out)
{
	if (strncasecmp(s, "0x", 2) == 0) {
		char *end;
		unsigned long v;

		if (!s[2] || strlen(s) > 6)
			return false;
		v = strtoul(s + 2, &end, 16);
		if (*end)
			return false;
		*out = v;
		return true;
	}
	for (size_t i = 0; i < sizeof(cipher_names) / sizeof(cipher_names[0]); i++) {
		if (strcmp(s, cipher_names[i].name) == 0) {
			*out = cipher_names[i].id;
			return true;
		}
	}
	return false;
}

static bool parse_version(const char *s, uint16_t *out)
{
	static const char *const names[] = { "1.0", "1.1", "1.2", "1.3" };

	for (int i = 0; i < 4; i++) {
		if (strcmp(s, names[i]) == 0) {
			*out = 0x0301 + i;
			return true;
		}
	}
	return false;
}

/* Reports an unknown key as an error. A misspelt "min_versoin" would
 * otherwise loosen the rule without warning. */
static bool only_keys(json_t *obj, const char *const *keys, const char **bad)
{
	const char *k;
	json_t *v;

	json_object_foreach(obj, k, v) {
		bool known = false;

		for (int i = 0; keys[i]; i++)
			if (strcmp(k, keys[i]) == 0)
				known = true;
		if (!known) {
			*bad = k;
			return false;
		}
	}
	return true;
}

/* Reads an optional key whose value must be `no` or `yes`. Sets *on for
 * `yes` and leaves *on unchanged when the key is absent. */
static bool read_choice(json_t *obj, const char *key, const char *no,
			const char *yes, bool *on)
{
	json_t *v = json_object_get(obj, key);
	const char *s;

	if (!v)
		return true;
	s = json_is_string(v) ? json_string_value(v) : "";
	if (strcmp(s, yes) == 0)
		*on = true;
	return strcmp(s, yes) == 0 || strcmp(s, no) == 0;
}

#define FAIL(...) do { snprintf(errbuf, errlen, __VA_ARGS__); goto err; } while (0)

static int load_rule(struct skb_rule *r, json_t *j, const char *path, size_t idx,
		     char *errbuf, size_t errlen)
{
	static const char *const keys[] = { "container", "min_version", "ciphers", NULL };
	json_t *v;
	const char *bad;
	size_t i;

	if (!json_is_object(j))
		FAIL("%s: rules[%zu]: not an object", path, idx);
	if (!only_keys(j, keys, &bad))
		FAIL("%s: rules[%zu]: unknown key \"%s\"", path, idx, bad);

	v = json_object_get(j, "container");
	if (!json_is_string(v))
		FAIL("%s: rules[%zu]: \"container\" must be a string", path, idx);
	r->container = strdup(json_string_value(v));
	if (!r->container)
		FAIL("%s: out of memory", path);

	v = json_object_get(j, "min_version");
	if (v && (!json_is_string(v) ||
		  !parse_version(json_string_value(v), &r->min_version)))
		FAIL("%s: rules[%zu]: \"min_version\" must be \"1.0\" to \"1.3\"",
		     path, idx);

	v = json_object_get(j, "ciphers");
	if (!v) {
		r->any_cipher = true;
		return 0;
	}
	if (!json_is_array(v))
		FAIL("%s: rules[%zu]: \"ciphers\" must be an array", path, idx);
	r->ciphers = calloc(json_array_size(v) + 1, sizeof(*r->ciphers));
	if (!r->ciphers)
		FAIL("%s: out of memory", path);
	for (i = 0; i < json_array_size(v); i++) {
		json_t *c = json_array_get(v, i);

		if (!json_is_string(c))
			FAIL("%s: rules[%zu].ciphers[%zu]: not a string", path, idx, i);
		if (!parse_cipher(json_string_value(c), &r->ciphers[i]))
			FAIL("%s: rules[%zu].ciphers[%zu]: unknown cipher \"%s\"",
			     path, idx, i, json_string_value(c));
	}
	r->n_ciphers = i;
	return 0;
err:
	return -1;
}

struct skb_policy *skb_policy_load(const char *path, char *errbuf, size_t errlen)
{
	static const char *const keys[] = { "version", "default", "on_unknown", "rules", NULL };
	struct skb_policy *pol;
	json_error_t jerr;
	json_t *root, *v;
	const char *bad;

	root = json_load_file(path, JSON_REJECT_DUPLICATES, &jerr);
	if (!root) {
		snprintf(errbuf, errlen, "%s: line %d, column %d: %s",
			 path, jerr.line, jerr.column, jerr.text);
		return NULL;
	}
	pol = calloc(1, sizeof(*pol));
	if (!pol)
		FAIL("%s: out of memory", path);

	if (!json_is_object(root))
		FAIL("%s: top level must be an object", path);
	if (!only_keys(root, keys, &bad))
		FAIL("%s: unknown key \"%s\"", path, bad);

	v = json_object_get(root, "version");
	if (!json_is_integer(v) || json_integer_value(v) != 1)
		FAIL("%s: \"version\" must be 1", path);

	/* Without "default" the policy denies. Without "on_unknown" it allows,
	 * so skbouncer never blocks on bytes it did not see. */
	if (!read_choice(root, "default", "deny", "allow", &pol->default_allow))
		FAIL("%s: \"default\" must be \"allow\" or \"deny\"", path);
	if (!read_choice(root, "on_unknown", "allow", "block", &pol->unknown_block))
		FAIL("%s: \"on_unknown\" must be \"allow\" or \"block\"", path);

	v = json_object_get(root, "rules");
	if (v) {
		if (!json_is_array(v))
			FAIL("%s: \"rules\" must be an array", path);
		if (json_array_size(v) > SKB_MAX_RULES)
			FAIL("%s: more than %d rules", path, SKB_MAX_RULES);
		pol->rules = calloc(json_array_size(v) + 1, sizeof(*pol->rules));
		if (!pol->rules)
			FAIL("%s: out of memory", path);
		for (size_t i = 0; i < json_array_size(v); i++) {
			pol->n_rules = i + 1;
			if (load_rule(&pol->rules[i], json_array_get(v, i), path, i,
				      errbuf, errlen))
				goto err;
		}
	}
	json_decref(root);
	return pol;
err:
	json_decref(root);
	skb_policy_free(pol);
	return NULL;
}

static const struct skb_rule *match(const struct skb_policy *pol,
				    const char *container)
{
	if (!container)
		return NULL;
	for (size_t i = 0; i < pol->n_rules; i++)
		if (fnmatch(pol->rules[i].container, container, 0) == 0)
			return &pol->rules[i];
	return NULL;
}

static bool cipher_permitted(const struct skb_rule *r, uint16_t c)
{
	for (size_t i = 0; i < r->n_ciphers; i++)
		if (r->ciphers[i] == c)
			return true;
	return false;
}

const char *skb_cipher_name(uint16_t id)
{
	for (size_t i = 0; i < sizeof(cipher_names) / sizeof(cipher_names[0]); i++)
		if (cipher_names[i].id == id)
			return cipher_names[i].name;
	return NULL;
}

const char *skb_version_name(uint16_t v, char buf[8])
{
	if (v >= 0x0301 && v <= 0x0304)
		snprintf(buf, 8, "1.%u", v - 0x0301);
	else
		snprintf(buf, 8, "0x%04x", v);
	return buf;
}

#define WHY(...) do { if (why) snprintf(why, len, __VA_ARGS__); } while (0)

/* One offer that breaks the rule is a violation, however much of the
 * ClientHello went unseen. With no such offer and a constrained list seen
 * only in part, the verdict is unknown. */
enum skb_verdict skb_policy_explain(const struct skb_policy *pol,
				    const struct skb_event *ev,
				    const char *container, char *why, size_t len)
{
	const struct skb_rule *r = match(pol, container);
	bool part_c = false, part_v = false;
	uint16_t low = 0, bad = 0;
	unsigned n_bad = 0;
	char vb[2][8], cb[8];
	size_t n = 0;

	if (!r) {
		if (container)
			WHY("no rule for %s; default %s", container,
			    pol->default_allow ? "allow" : "deny");
		else
			WHY("not a known container; default %s",
			    pol->default_allow ? "allow" : "deny");
		return pol->default_allow ? SKB_VERDICT_ALLOW : SKB_VERDICT_VIOLATION;
	}

	if (!r->any_cipher) {
		for (unsigned i = 0; i < ev->n_ciphers && i < SKB_MAX_CIPHERS; i++) {
			uint16_t c = ntohs(ev->ciphers[i]);

			if (skb_cipher_ignored(c) || cipher_permitted(r, c))
				continue;
			if (n_bad == 0)
				bad = c;
			n_bad++;
		}
		part_c = !(ev->seen & SKB_SEEN_CIPHERS);
	}

	if (r->min_version) {
		/* With no supported_versions seen, legacy_version is the offer
		 * only if the walk proved the extension absent. */
		if (ev->n_versions) {
			for (unsigned i = 0; i < ev->n_versions && i < SKB_MAX_VERSIONS; i++) {
				uint16_t v = ntohs(ev->versions[i]);

				if (!skb_is_grease(v) && v < r->min_version && (!low || v < low))
					low = v;
			}
		} else if ((ev->seen & SKB_SEEN_VERSIONS) &&
			   ev->legacy_version < r->min_version) {
			low = ev->legacy_version;
		}
		part_v = !(ev->seen & SKB_SEEN_VERSIONS);
	}

	/* The reason names every limit the ClientHello breaks, so fixing one
	 * does not reveal another. */
	if (low || n_bad) {
		if (why && low)
			n += snprintf(why, len, "offers TLS %s, minimum is %s",
				      skb_version_name(low, vb[0]),
				      skb_version_name(r->min_version, vb[1]));
		if (why && n_bad && n < len) {
			const char *name = skb_cipher_name(bad);

			if (!name)
				snprintf(cb, sizeof(cb), "0x%04x", bad);
			n += snprintf(why + n, len - n, "%soffers %s%s, not permitted",
				      n ? "; " : "", name ? name : cb,
				      n_bad > 1 ? " and others" : "");
		}
		return SKB_VERDICT_VIOLATION;
	}

	if (part_c || part_v) {
		WHY("%s not seen in full%s",
		    part_c && part_v ? "ciphers and versions" : part_c ? "ciphers" : "versions",
		    ev->trunc_reason == SKB_TRUNC_SEGMENT ? " (ClientHello split across segments)" :
		    ev->ciphers_capped ? " (more than 64 ciphers)" : "");
		return SKB_VERDICT_UNKNOWN;
	}
	WHY("complies with rule %s", r->container);
	return SKB_VERDICT_ALLOW;
}

unsigned skb_policy_rule_slot(const struct skb_policy *pol, const char *container)
{
	const struct skb_rule *r = match(pol, container);

	return r ? r - pol->rules + 1 : 0;
}

size_t skb_policy_n_rules(const struct skb_policy *pol)
{
	return pol->n_rules;
}

bool skb_policy_blocks_unknown(const struct skb_policy *pol)
{
	return pol->unknown_block;
}

/* Must decide exactly as skb_policy_explain() does. The kernel copy,
 * check_policy(), must agree as well. */
void skb_policy_compile(const struct skb_policy *pol, unsigned slot,
			struct skb_krule *out)
{
	const struct skb_rule *r;

	memset(out, 0, sizeof(*out));
	out->flags = SKB_KRULE_VALID;
	if (slot == 0 || slot > pol->n_rules) {
		out->flags |= SKB_KRULE_FIXED;
		out->fixed = pol->default_allow ? SKB_VERDICT_ALLOW : SKB_VERDICT_VIOLATION;
		return;
	}
	r = &pol->rules[slot - 1];
	out->min_version = r->min_version;
	if (r->any_cipher)
		out->flags |= SKB_KRULE_ANY_CIPHER;
	for (size_t i = 0; i < r->n_ciphers; i++)
		out->ciphers[r->ciphers[i] / 64] |= 1ULL << (r->ciphers[i] % 64);
}

const char *skb_verdict_str(enum skb_verdict v)
{
	switch (v) {
	case SKB_VERDICT_ALLOW:     return "allow";
	case SKB_VERDICT_VIOLATION: return "violation";
	case SKB_VERDICT_UNKNOWN:   return "unknown";
	case SKB_VERDICT_NONE:      return "none";
	}
	return "invalid";
}

void skb_policy_free(struct skb_policy *pol)
{
	if (!pol)
		return;
	for (size_t i = 0; i < pol->n_rules; i++) {
		free(pol->rules[i].container);
		free(pol->rules[i].ciphers);
	}
	free(pol->rules);
	free(pol);
}
