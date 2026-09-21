// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>

#include "container.h"

struct skb_container_map {
	int placeholder;
};

struct skb_container_map *skb_container_map_new(void)
{
	return calloc(1, sizeof(struct skb_container_map));
}

const char *skb_container_lookup(struct skb_container_map *m, uint64_t cgroup_id)
{
	(void)m;
	(void)cgroup_id;
	return NULL;
}

int skb_container_refresh(struct skb_container_map *m)
{
	(void)m;
	return 0;
}

void skb_container_map_free(struct skb_container_map *m)
{
	free(m);
}
