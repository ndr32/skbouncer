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

#define CGROUP_ROOT "/sys/fs/cgroup"

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
	if (strncmp(real, CGROUP_ROOT "/", sizeof(CGROUP_ROOT)) != 0) {
		snprintf(errbuf, errlen, "--cgroup %s: refusing the root cgroup, "
			 "or one outside " CGROUP_ROOT, path);
		return -1;
	}
	/* The root is level 0; each component below it adds one. */
	*level = 0;
	for (p = real + sizeof(CGROUP_ROOT) - 1; *p; p++)
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

struct sync_ctx {
	struct skb_loader *ldr;
	const struct skb_policy *pol;
	int err;
};

static void sync_one(void *arg, uint64_t cgroup_id, const char *name)
{
	struct sync_ctx *c = arg;
	int err = skb_loader_set_cgroup(c->ldr, cgroup_id,
					skb_policy_rule_slot(c->pol, name));

	if (err && !c->err)
		c->err = err;
}

int skb_enforce_sync(struct skb_loader *ldr, const struct skb_policy *pol,
		     struct skb_container_map *containers)
{
	static bool rules_done;
	static unsigned synced_gen;
	struct sync_ctx c = { ldr, pol, 0 };
	unsigned gen = skb_container_generation(containers);

	if (!rules_done) {
		struct skb_krule *r = malloc(sizeof(*r));

		if (!r)
			return -ENOMEM;
		for (unsigned slot = 0; slot <= skb_policy_n_rules(pol); slot++) {
			int err;

			skb_policy_compile(pol, slot, r);
			err = skb_loader_set_rule(ldr, slot, r);
			if (err) {
				free(r);
				return err;
			}
		}
		free(r);
		rules_done = true;
	} else if (gen == synced_gen) {
		return 0;
	}
	skb_container_foreach(containers, sync_one, &c);
	if (!c.err)
		synced_gen = gen;
	return c.err;
}
