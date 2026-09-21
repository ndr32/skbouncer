/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SKB_CONTAINER_H
#define SKB_CONTAINER_H

#include <stdint.h>

struct skb_container_map;

struct skb_container_map *skb_container_map_new(void);

/* NULL if the cgroup belongs to no known container. Map owns the string. */
const char *skb_container_lookup(struct skb_container_map *m, uint64_t cgroup_id);

/* Containers come and go; a miss should trigger one refresh before giving up. */
int skb_container_refresh(struct skb_container_map *m);

void skb_container_map_free(struct skb_container_map *m);

#endif /* SKB_CONTAINER_H */
