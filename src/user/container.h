/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_CONTAINER_H
#define SKB_CONTAINER_H

#include <limits.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

#define SKB_CGROUP_ROOT "/sys/fs/cgroup"

/* Calls fn with the id of the cgroup at `path` and of every cgroup below it,
 * down to max_depth levels. A cgroup's id is the inode of its directory. */
void skb_cgroup_walk(const char *path, int max_depth,
		     void (*fn)(uint64_t id, void *ctx), void *ctx);

struct skb_container_map;

struct skb_container_map *skb_container_map_new(void);

/* NULL if the cgroup belongs to no known container. The map owns the string. */
const char *skb_container_lookup(struct skb_container_map *m, uint64_t cgroup_id);

/* Re-reads the container list from dockerd. skb_container_lookup() calls it
 * once on a miss. */
int skb_container_refresh(struct skb_container_map *m);


struct skb_container_info {
	char ifname[IF_NAMESIZE];	/* host end of its veth */
	char cgroup[PATH_MAX];		/* its cgroup v2 directory */
};

/* Asks dockerd for a running container by name or id. On failure errbuf
 * names the container and says why. Returns 0 or a negative errno. */
int skb_container_resolve(const char *name, struct skb_container_info *out,
			  char *errbuf, size_t errlen);

/* Calls fn for each running container: its name, the host end of its veth
 * and its cgroup id, or NULL and 0 where those cannot be found (a host
 * network container, say). Needs root to read the veth. Returns 0 or a
 * negative errno. */
int skb_container_list(void (*fn)(const char *name, const char *veth,
				  uint64_t cgroup_id, void *ctx), void *ctx);

void skb_container_map_free(struct skb_container_map *m);

#endif /* SKB_CONTAINER_H */
