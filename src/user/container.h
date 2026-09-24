/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_CONTAINER_H
#define SKB_CONTAINER_H

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

struct skb_container_map;

struct skb_container_map *skb_container_map_new(void);

/* NULL if the cgroup belongs to no known container. Map owns the string. */
const char *skb_container_lookup(struct skb_container_map *m, uint64_t cgroup_id);

/* Containers come and go; a miss should trigger one refresh before giving up. */
int skb_container_refresh(struct skb_container_map *m);


struct skb_container_info {
	char ifname[IF_NAMESIZE];	/* host end of its veth */
	char cgroup[512];		/* its cgroup v2 directory */
};

/* Asks dockerd for a running container by name or id. On failure errbuf
 * names the container and says why. Returns 0 or a negative errno. */
int skb_container_resolve(const char *name, struct skb_container_info *out,
			  char *errbuf, size_t errlen);

void skb_container_map_free(struct skb_container_map *m);

#endif /* SKB_CONTAINER_H */
