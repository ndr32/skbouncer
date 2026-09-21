/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_LOADER_H
#define SKB_LOADER_H

#include <stdbool.h>
#include <stdint.h>

struct skb_loader;

struct skb_loader_opts {
	const char *ifname;	/* NULL loads without attaching */
	bool verbose;
};

struct skb_loader *skb_loader_open(const struct skb_loader_opts *opts);
uint32_t skb_loader_prog_id(const struct skb_loader *ldr);

/* May be shorter than the C symbol: BPF_OBJ_NAME_LEN is 16 incl. NUL. */
const char *skb_loader_prog_name(const struct skb_loader *ldr);

void skb_loader_close(struct skb_loader *ldr);

#endif /* SKB_LOADER_H */
