/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_ENFORCE_H
#define SKB_ENFORCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "container.h"
#include "loader.h"
#include "policy.h"

/* The cgroup v2 id and depth of `path`, as bpf_skb_ancestor_cgroup_id()
 * wants them. Refuses the root however it is spelt. */
int skb_enforce_scope(const char *path, uint64_t *id, uint32_t *level,
		      char *errbuf, size_t errlen);

/* True if `ifname` is driven by veth, the only place enforce mode attaches. */
bool skb_enforce_is_veth(const char *ifname);

/* Writes every rule, then points each known container's cgroups at the rule
 * its name matches. Cheap to repeat; only does work when `containers` has
 * changed since the last call. Returns 0 or a negative errno. */
int skb_enforce_sync(struct skb_loader *ldr, const struct skb_policy *pol,
		     struct skb_container_map *containers);

#endif /* SKB_ENFORCE_H */
