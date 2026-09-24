// SPDX-License-Identifier: GPL-2.0
/*
 * cgroup id -> Docker container name.
 *
 * A container's cgroup v2 id is the inode of its cgroup directory, so the
 * map is built by asking dockerd for every container id (Engine API on the
 * unix socket, no CLI) and stat()ing the cgroup directory each id implies.
 * Nested cgroups a container creates under its own are mapped too.
 *
 * cgroup ids are not reused within a boot, so an entry never goes stale:
 * entries are kept after their container exits, which lets a late event
 * from a just-removed container still resolve. For the same reason a
 * cgroup found to be no container stays that way, and is cached as a miss
 * so host traffic does not make every event cost a round trip to dockerd.
 */
#include <dirent.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "container.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#endif

#define DOCKER_SOCK	"/var/run/docker.sock"
#define CGROUP_ROOT	"/sys/fs/cgroup"
#define RESP_MAX	(8 << 20)
#define NESTED_DEPTH	4
#define MISS_SLOTS	256

struct entry {
	uint64_t cgroup_id;
	char *name;
};

struct skb_container_map {
	struct entry *v;
	size_t n, cap;
	uint64_t miss[MISS_SLOTS];	/* ring; 0 = empty slot */
	unsigned miss_next;
};

struct skb_container_map *skb_container_map_new(void)
{
	return calloc(1, sizeof(struct skb_container_map));
}

static struct entry *find(struct skb_container_map *m, uint64_t id)
{
	for (size_t i = 0; i < m->n; i++)
		if (m->v[i].cgroup_id == id)
			return &m->v[i];
	return NULL;
}

static bool known_miss(const struct skb_container_map *m, uint64_t id)
{
	for (unsigned i = 0; i < MISS_SLOTS; i++)
		if (m->miss[i] == id)
			return true;
	return false;
}

static int put(struct skb_container_map *m, uint64_t id, const char *name)
{
	struct entry *e = find(m, id);
	char *dup = strdup(name);

	if (!dup)
		return -ENOMEM;
	if (e && strcmp(e->name, name) == 0) {
		free(dup);
		return 0;
	}
	if (e) {		/* renamed */
		free(e->name);
		e->name = dup;
		return 0;
	}
	if (m->n == m->cap) {
		size_t cap = m->cap ? m->cap * 2 : 32;
		struct entry *v = realloc(m->v, cap * sizeof(*v));

		if (!v) {
			free(dup);
			return -ENOMEM;
		}
		m->v = v;
		m->cap = cap;
	}
	m->v[m->n++] = (struct entry){ id, dup };
	return 0;
}

/* The cgroup at `path` and those nested under it, bounded in depth. */
static void put_tree(struct skb_container_map *m, const char *path,
		     const char *name, int depth)
{
	struct stat st;
	struct dirent *d;
	DIR *dir;

	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
		return;
	put(m, st.st_ino, name);
	if (depth >= NESTED_DEPTH || !(dir = opendir(path)))
		return;
	while ((d = readdir(dir))) {
		char sub[4096];

		if (d->d_type != DT_DIR || d->d_name[0] == '.')
			continue;
		if (snprintf(sub, sizeof(sub), "%s/%s", path, d->d_name) <
		    (int)sizeof(sub))
			put_tree(m, sub, name, depth + 1);
	}
	closedir(dir);
}

/* HTTP/1.0 so dockerd neither chunks the body nor keeps the connection:
 * the body simply runs to EOF. The timeouts bound how long a wedged dockerd
 * can stall the event loop. */
static char *docker_get(const char *req_path, size_t *len)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX, .sun_path = DOCKER_SOCK };
	struct timeval tv = { .tv_sec = 1 };
	char req[256];
	char *buf = NULL;
	size_t n = 0, cap = 0;
	int fd, rlen;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return NULL;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	rlen = snprintf(req, sizeof(req),
			"GET %s HTTP/1.0\r\nHost: docker\r\n\r\n", req_path);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    write(fd, req, rlen) != rlen)
		goto fail;

	for (;;) {
		ssize_t r;

		if (n + 1 >= cap) {
			char *nb;

			if (cap >= RESP_MAX)
				goto fail;
			cap = cap ? cap * 2 : 16384;
			if (!(nb = realloc(buf, cap)))
				goto fail;
			buf = nb;
		}
		r = read(fd, buf + n, cap - n - 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			goto fail;
		if (r == 0)
			break;
		n += r;
	}
	close(fd);
	buf[n] = '\0';
	*len = n;
	return buf;
fail:
	close(fd);
	free(buf);
	return NULL;
}

#ifdef HAVE_JANSSON
/* GET `path` from dockerd. Returns the parsed body on a 200, else NULL, with
 * *status the HTTP status, or 0 when dockerd gave no parsable answer. */
static json_t *docker_json(const char *path, int *status)
{
	size_t len;
	char *resp = docker_get(path, &len);
	char *body;
	json_t *root = NULL;

	*status = 0;
	if (!resp)
		return NULL;
	if (len > 12 && strncmp(resp, "HTTP/1.", 7) == 0 && resp[8] == ' ')
		*status = atoi(resp + 9);
	body = strstr(resp, "\r\n\r\n");
	if (*status == 200 && body)
		root = json_loads(body + 4, 0, NULL);
	free(resp);
	return root;
}

/* The container's cgroup directory: the systemd driver (this host), then
 * cgroupfs. An id with a / would escape CGROUP_ROOT. */
static int cgroup_of(const char *id, char *path, size_t len)
{
	struct stat st;

	if (strchr(id, '/'))
		return -1;
	snprintf(path, len, CGROUP_ROOT "/system.slice/docker-%s.scope", id);
	if (stat(path, &st) == 0)
		return 0;
	snprintf(path, len, CGROUP_ROOT "/docker/%s", id);
	return stat(path, &st) == 0 ? 0 : -1;
}
#endif

int skb_container_refresh(struct skb_container_map *m)
{
#ifdef HAVE_JANSSON
	json_t *root, *c;
	int status;
	size_t i;

	root = docker_json("/containers/json?all=1", &status);
	if (!json_is_array(root)) {
		json_decref(root);
		return status ? -EPROTO : -EIO;
	}
	json_array_foreach(root, i, c) {
		const char *id = json_string_value(json_object_get(c, "Id"));
		const char *name = json_string_value(
			json_array_get(json_object_get(c, "Names"), 0));
		char path[512];

		if (!id || !name || cgroup_of(id, path, sizeof(path)))
			continue;
		put_tree(m, path, name[0] == '/' ? name + 1 : name, 0);
	}
	json_decref(root);
	return 0;
#else
	(void)m;
	return -ENOTSUP;
#endif
}

#ifdef HAVE_JANSSON
/* The host end of the veth whose peer is one of `pid`'s interfaces. The
 * container's own sysfs, reached through its root, lists its interfaces;
 * each one's iflink is the host-side peer's ifindex. */
static int host_veth(int pid, char *ifname, char *errbuf, size_t errlen)
{
	char dir[64], path[512], buf[32];
	struct dirent *d;
	unsigned found = 0;
	DIR *dh;

	snprintf(dir, sizeof(dir), "/proc/%d/root/sys/class/net", pid);
	if (!(dh = opendir(dir))) {
		snprintf(errbuf, errlen, "cannot read %s: %s", dir, strerror(errno));
		return -errno;
	}
	while ((d = readdir(dh))) {
		char own[32] = "", host[IF_NAMESIZE];
		unsigned link;
		FILE *f;

		if (d->d_name[0] == '.' || strcmp(d->d_name, "lo") == 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s/ifindex", dir, d->d_name);
		if ((f = fopen(path, "r"))) {
			if (!fgets(own, sizeof(own), f))
				own[0] = '\0';
			fclose(f);
		}
		snprintf(path, sizeof(path), "%s/%s/iflink", dir, d->d_name);
		if (!(f = fopen(path, "r")))
			continue;
		link = fgets(buf, sizeof(buf), f) ? strtoul(buf, NULL, 10) : 0;
		fclose(f);
		/* iflink == ifindex: no peer, as with --network host. */
		if (!link || link == strtoul(own, NULL, 10) || !if_indextoname(link, host))
			continue;
		if (found++ == 0)
			snprintf(ifname, IF_NAMESIZE, "%s", host);
	}
	closedir(dh);
	if (found == 1)
		return 0;
	snprintf(errbuf, errlen, found ? "has %u network interfaces; pick one with -i" :
		 "has no veth (host network?)", found);
	return -ENODEV;
}

int skb_container_resolve(const char *name, struct skb_container_info *out,
			  char *errbuf, size_t errlen)
{
	char req[512], why[256];
	const char *id;
	json_t *root;
	int status, pid, err = 0;

	/* A name with / or ? would turn into a different API path. */
	if (!*name || strpbrk(name, "/?#% ")) {
		snprintf(errbuf, errlen, "no such container: %s", name);
		return -ENOENT;
	}
	snprintf(req, sizeof(req), "/containers/%s/json", name);
	if (!(root = docker_json(req, &status))) {
		if (status == 404)
			snprintf(errbuf, errlen, "no such container: %s", name);
		else if (status)
			snprintf(errbuf, errlen, "dockerd gave no usable answer for container %s",
				 name);
		else
			snprintf(errbuf, errlen, "cannot ask dockerd about container %s via "
				 DOCKER_SOCK, name);
		return status == 404 ? -ENOENT : status ? -EPROTO : -EIO;
	}

	id = json_string_value(json_object_get(root, "Id"));
	pid = json_integer_value(json_object_get(json_object_get(root, "State"), "Pid"));
	if (!id) {
		snprintf(errbuf, errlen, "dockerd gave no id for container %s", name);
		err = -EPROTO;
	} else if (pid <= 0) {
		snprintf(errbuf, errlen, "container %s is not running", name);
		err = -ENOENT;
	} else if ((err = host_veth(pid, out->ifname, why, sizeof(why)))) {
		snprintf(errbuf, errlen, "container %s %s", name, why);
	} else if (cgroup_of(id, out->cgroup, sizeof(out->cgroup))) {
		snprintf(errbuf, errlen, "cannot find the cgroup of container %s", name);
		err = -ENOENT;
	}
	json_decref(root);
	return err;
}
#else
int skb_container_resolve(const char *name, struct skb_container_info *out,
			  char *errbuf, size_t errlen)
{
	snprintf(errbuf, errlen, "cannot look up container %s: built without jansson", name);
	return -ENOTSUP;
}
#endif

const char *skb_container_lookup(struct skb_container_map *m, uint64_t cgroup_id)
{
	struct entry *e;

	/* 0 is a forwarded skb with no socket: no cgroup to name. */
	if (cgroup_id == 0 || known_miss(m, cgroup_id))
		return NULL;
	if ((e = find(m, cgroup_id)))
		return e->name;
	/* Only a successful refresh proves a miss; if dockerd was down, ask
	 * again next time. */
	if (skb_container_refresh(m) != 0)
		return NULL;
	if ((e = find(m, cgroup_id)))
		return e->name;
	m->miss[m->miss_next++ % MISS_SLOTS] = cgroup_id;
	return NULL;
}

void skb_container_map_free(struct skb_container_map *m)
{
	if (!m)
		return;
	for (size_t i = 0; i < m->n; i++)
		free(m->v[i].name);
	free(m->v);
	free(m);
}
