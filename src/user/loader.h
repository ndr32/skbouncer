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
	enum skb_direction direction;	/* which clsact hook on that device */
	bool verbose;

	/* Enforce mode: block within the cgroup scope_id, at scope_level in
	 * the hierarchy, and its descendants. */
	bool enforce;
	bool unknown_block;
	uint64_t scope_id;
	uint32_t scope_level;

	/* Called from skb_loader_poll() for each ringbuf record. */
	void (*on_event)(void *ctx, const struct skb_event *ev);
	void *ctx;
};

/* Loads; attaching is a separate step so that enforce mode can fill the
 * policy maps first. */
struct skb_loader *skb_loader_open(const struct skb_loader_opts *opts);
int skb_loader_attach(struct skb_loader *ldr, const char *ifname,
		      enum skb_direction dir);

/* The compiled policy. Return 0 or a negative errno. */
int skb_loader_set_rule(struct skb_loader *ldr, uint32_t slot,
			const struct skb_krule *rule);
int skb_loader_set_cgroup(struct skb_loader *ldr, uint64_t cgroup_id,
			  uint32_t slot);
uint32_t skb_loader_prog_id(const struct skb_loader *ldr);

/* May be shorter than the C symbol: BPF_OBJ_NAME_LEN is 16 incl. NUL. */
const char *skb_loader_prog_name(const struct skb_loader *ldr);

/* Reads the kernel-side counters into out[0..SKB_STAT__MAX). `n` is the
 * length of out[]. Returns 0 or a negative errno. */
int skb_loader_stats(const struct skb_loader *ldr, uint64_t *out, size_t n);

/* Drains the ringbuf. Returns the number of records handled, or a negative
 * errno; -EINTR just means a signal arrived. */
int skb_loader_poll(struct skb_loader *ldr, int timeout_ms);

void skb_loader_close(struct skb_loader *ldr);

#endif /* SKB_LOADER_H */
