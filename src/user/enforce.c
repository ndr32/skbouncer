// SPDX-License-Identifier: GPL-2.0
/* Enforce mode: the policy compiled into the kernel's maps. The verdict has
 * to be reached in the kernel, since one reached here arrives after the
 * ClientHello has left. */
#include <errno.h>
#include <limits.h>
#include <linux/ethtool.h>
#include <linux/magic.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "enforce.h"

#define SCOPE_DEPTH 8	/* nested cgroups followed below the scope */

int skb_enforce_scope(const char *path, uint64_t *id, uint32_t *level,
		      char *errbuf, size_t errlen)
{
	char real[PATH_MAX];
	struct statfs fs;
	struct stat st;
	const char *p;

	if (!realpath(path, real) || stat(real, &st) != 0) {
		snprintf(errbuf, errlen, "--cgroup %s: %s", path, strerror(errno));
		return -1;
	}
	if (statfs(real, &fs) != 0 || fs.f_type != CGROUP2_SUPER_MAGIC ||
	    !S_ISDIR(st.st_mode)) {
		snprintf(errbuf, errlen, "--cgroup %s: not a cgroup v2 directory", path);
		return -1;
	}
	if (strncmp(real, SKB_CGROUP_ROOT "/", sizeof(SKB_CGROUP_ROOT)) != 0) {
		snprintf(errbuf, errlen, "--cgroup %s: refusing the root cgroup, "
			 "or one outside " SKB_CGROUP_ROOT, path);
		return -1;
	}
	/* The root is level 0; each component below it adds one. */
	*level = 0;
	for (p = real + sizeof(SKB_CGROUP_ROOT) - 1; *p; p++)
		if (*p == '/' && p[1])
			(*level)++;
	*id = st.st_ino;
	return 0;
}

bool skb_enforce_is_veth(const char *ifname)
{
	struct ethtool_drvinfo info = { .cmd = ETHTOOL_GDRVINFO };
	struct ifreq ifr = { .ifr_data = (void *)&info };
	int fd, err;

	if (strlen(ifname) >= IFNAMSIZ)
		return false;
	strcpy(ifr.ifr_name, ifname);
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return false;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return err == 0 && strcmp(info.driver, "veth") == 0;
}

/* The cgroups the kernel can block: the scope and everything below it, as
 * of the last sync. Sorted, for skb_enforce_in_scope(). */
static uint64_t scope_ids[SKB_MAX_CGROUPS];
static size_t n_scope;

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static void add_to_scope(uint64_t id, void *ctx)
{
	if (n_scope < SKB_MAX_CGROUPS)
		scope_ids[n_scope++] = id;
}

bool skb_enforce_in_scope(uint64_t cgroup_id)
{
	return bsearch(&cgroup_id, scope_ids, n_scope, sizeof(*scope_ids), cmp_u64);
}

static int load_rules(struct skb_loader *ldr, const struct skb_policy *pol)
{
	struct skb_krule *r = malloc(sizeof(*r));
	int err = 0;

	if (!r)
		return -ENOMEM;
	for (unsigned slot = 0; slot <= skb_policy_n_rules(pol) && !err; slot++) {
		skb_policy_compile(pol, slot, r);
		err = skb_loader_set_rule(ldr, slot, r);
	}
	free(r);
	return err;
}

int skb_enforce_sync(struct skb_loader *ldr, const struct skb_policy *pol,
		     struct skb_container_map *containers, const char *scope)
{
	static bool rules_done;
	uint64_t key, *prev = NULL, *stale;
	size_t n_stale = 0;
	int err;

	if (!rules_done) {
		if ((err = load_rules(ldr, pol)))
			return err;
		rules_done = true;
	}

	n_scope = 0;
	skb_cgroup_walk(scope, SCOPE_DEPTH, add_to_scope, NULL);
	qsort(scope_ids, n_scope, sizeof(*scope_ids), cmp_u64);
	for (size_t i = 0; i < n_scope; i++) {
		const char *name = skb_container_lookup(containers, scope_ids[i]);

		err = skb_loader_set_cgroup(ldr, scope_ids[i],
					    skb_policy_rule_slot(pol, name));
		if (err)
			return err;
	}

	/* Collected first: deleting the key get_next_key started from would
	 * restart the walk. */
	if (!(stale = malloc(SKB_MAX_CGROUPS * sizeof(*stale))))
		return -ENOMEM;
	while (n_stale < SKB_MAX_CGROUPS &&
	       skb_loader_next_cgroup(ldr, prev, &key) == 0) {
		if (!skb_enforce_in_scope(key))
			stale[n_stale++] = key;
		prev = &key;
	}
	for (size_t i = 0; i < n_stale && !err; i++)
		err = skb_loader_del_cgroup(ldr, stale[i]);
	free(stale);
	return err;
}
