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
 * wants them. Refuses the root cgroup however the path spells it. */
int skb_enforce_scope(const char *path, uint64_t *id, uint32_t *level,
		      char *errbuf, size_t errlen);

/* True if the veth driver runs `ifname`. Enforce mode attaches to veths
 * only. */
bool skb_enforce_is_veth(const char *ifname);

/* Writes every compiled rule into the kernel's rule map. Called once, before
 * the first sync. Returns 0 or a negative errno. */
int skb_enforce_load_rules(struct skb_loader *ldr, const struct skb_policy *pol);

/* Points every cgroup in `scope` (the --cgroup directory and the cgroups
 * below it) at the rule its container matches, and removes all other cgroups
 * from the kernel map. Nothing out of scope is blocked, and a removed cgroup
 * never returns. Returns 0 or a negative errno, and -EINVAL before
 * skb_enforce_load_rules() has succeeded. */
int skb_enforce_sync(struct skb_loader *ldr, const struct skb_policy *pol,
		     struct skb_container_map *containers, const char *scope);

/* Whether the last sync found this cgroup in scope. */
bool skb_enforce_in_scope(uint64_t cgroup_id);

#endif /* SKB_ENFORCE_H */
