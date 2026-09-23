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

/* systemd driver first (what this host uses), then cgroupfs. */
static void put_container(struct skb_container_map *m, const char *id,
			  const char *name)
{
	char path[512];

	snprintf(path, sizeof(path), CGROUP_ROOT "/system.slice/docker-%s.scope", id);
	put_tree(m, path, name, 0);
	snprintf(path, sizeof(path), CGROUP_ROOT "/docker/%s", id);
	put_tree(m, path, name, 0);
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

int skb_container_refresh(struct skb_container_map *m)
{
#ifdef HAVE_JANSSON
	size_t len;
	char *resp = docker_get("/containers/json?all=1", &len);
	char *body;
	json_t *root, *c;
	size_t i;

	if (!resp)
		return -EIO;
	body = strstr(resp, "\r\n\r\n");
	if (strncmp(resp, "HTTP/1.", 7) != 0 || strncmp(resp + 8, " 200", 4) != 0 ||
	    !body) {
		free(resp);
		return -EPROTO;
	}
	root = json_loads(body + 4, 0, NULL);
	free(resp);
	if (!json_is_array(root)) {
		json_decref(root);
		return -EPROTO;
	}
	json_array_foreach(root, i, c) {
		const char *id = json_string_value(json_object_get(c, "Id"));
		const char *name = json_string_value(
			json_array_get(json_object_get(c, "Names"), 0));

		if (!id || !name || strchr(id, '/'))
			continue;
		put_container(m, id, name[0] == '/' ? name + 1 : name);
	}
	json_decref(root);
	return 0;
#else
	(void)m;
	return -ENOTSUP;
#endif
}

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
