/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_LOADER_H
#define SKB_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "skbouncer.h"

struct skb_loader;

struct skb_loader_opts {
	const char *ifname;	/* NULL loads without attaching */
	bool verbose;

	/* Enforce mode. Blocks within the cgroup scope_id, at depth
	 * scope_level, and the cgroups below it. */
	bool enforce;
	bool unknown_block;
	uint64_t scope_id;
	uint32_t scope_level;

	/* Called from skb_loader_poll() for each ringbuf record. */
	void (*on_event)(void *ctx, const struct skb_event *ev);
	void *ctx;
};

/* Loads the program. Attaching is a separate step, so enforce mode can fill
 * the policy maps first. */
struct skb_loader *skb_loader_open(const struct skb_loader_opts *opts,
				   char *errbuf, size_t errlen);
int skb_loader_attach(struct skb_loader *ldr, const char *ifname,
		      char *errbuf, size_t errlen);

/* The compiled policy. Each returns 0 or a negative errno. */
int skb_loader_set_rule(struct skb_loader *ldr, uint32_t slot,
			const struct skb_krule *rule);
int skb_loader_set_cgroup(struct skb_loader *ldr, uint64_t cgroup_id,
			  uint32_t slot);
int skb_loader_del_cgroup(struct skb_loader *ldr, uint64_t cgroup_id);
/* Walks the keys of cgroup_rule. prev is NULL for the first key, and -ENOENT
 * means the walk is past the last. */
int skb_loader_next_cgroup(struct skb_loader *ldr, const uint64_t *prev,
			   uint64_t *next);
/* Reads the kernel-side counters into out[0..SKB_STAT__MAX). `n` is the
 * length of out[]. Returns 0 or a negative errno. */
int skb_loader_stats(const struct skb_loader *ldr, uint64_t *out, size_t n);

/* Drains the ringbuf. Returns the number of records handled, or a negative
 * errno. -EINTR means a signal arrived. */
int skb_loader_poll(struct skb_loader *ldr, int timeout_ms);

void skb_loader_close(struct skb_loader *ldr);

#endif /* SKB_LOADER_H */
