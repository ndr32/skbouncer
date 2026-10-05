// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "loader.h"
#include "skbouncer.skel.h"

struct skb_loader {
	struct skbouncer_bpf *skel;
	struct ring_buffer *rb;

	struct bpf_link *link;	/* NULL when not attached */
	bool enforce;

	void (*on_event)(void *ctx, const struct skb_event *ev);
	void *ctx;
};

static bool want_verbose;

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !want_verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct skb_loader *ldr = ctx;
	const struct skb_event *ev = data;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "skbouncer: short event (%zu < %zu), dropping\n",
			len, sizeof(*ev));
		return 0;
	}
	if (ev->event_version != SKB_EVENT_VERSION) {
		fprintf(stderr, "skbouncer: event version %u, expected %u; "
			"stale skbouncer.bpf.o?\n",
			ev->event_version, SKB_EVENT_VERSION);
		return 0;
	}
	if (ldr->on_event)
		ldr->on_event(ldr->ctx, ev);
	return 0;
}

/* Attaches through a tcx link owned by this process. The kernel detaches the
 * link when its last file descriptor closes, however the process ends. Other
 * instances on the same hook keep their own links. An audit instance
 * attaches first and also reports what an enforce instance drops. An enforce
 * instance attaches last. */
int skb_loader_attach(struct skb_loader *ldr, const char *ifname)
{
	LIBBPF_OPTS(bpf_tcx_opts, opts, .flags = ldr->enforce ? 0 : BPF_F_BEFORE);
	int ifindex = if_nametoindex(ifname);

	if (!ifindex) {
		fprintf(stderr, "skbouncer: no such interface '%s'\n", ifname);
		return -1;
	}
	ldr->link = bpf_program__attach_tcx(ldr->skel->progs.skb_tc, ifindex, &opts);
	if (!ldr->link) {
		fprintf(stderr, "skbouncer: cannot attach to %s ingress: %s\n",
			ifname, strerror(errno));
		return -1;
	}
	return 0;
}

struct skb_loader *skb_loader_open(const struct skb_loader_opts *opts)
{
	struct skb_loader *ldr;

	want_verbose = opts && opts->verbose;
	libbpf_set_print(print_fn);

	ldr = calloc(1, sizeof(*ldr));
	if (!ldr) {
		fprintf(stderr, "skbouncer: out of memory\n");
		return NULL;
	}
	if (opts) {
		ldr->on_event = opts->on_event;
		ldr->ctx = opts->ctx;
	}

	ldr->skel = skbouncer_bpf__open();
	if (!ldr->skel) {
		fprintf(stderr, "skbouncer: failed to open BPF object: %s\n",
			strerror(errno));
		free(ldr);
		return NULL;
	}

	if (opts && opts->enforce) {
		ldr->enforce = true;
		ldr->skel->rodata->enforce = 1;
		ldr->skel->rodata->unknown_block = opts->unknown_block;
		ldr->skel->rodata->scope_id = opts->scope_id;
		ldr->skel->rodata->scope_level = opts->scope_level;
	}

	if (skbouncer_bpf__load(ldr->skel)) {
		fprintf(stderr, "skbouncer: failed to load BPF object: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "skbouncer: loading BPF needs root; try sudo\n");
		skbouncer_bpf__destroy(ldr->skel);
		free(ldr);
		return NULL;
	}

	ldr->rb = ring_buffer__new(bpf_map__fd(ldr->skel->maps.events),
				   handle_event, ldr, NULL);
	if (!ldr->rb) {
		fprintf(stderr, "skbouncer: cannot open ringbuf: %s\n",
			strerror(errno));
		skb_loader_close(ldr);
		return NULL;
	}

	return ldr;
}

int skb_loader_set_rule(struct skb_loader *ldr, uint32_t slot,
			const struct skb_krule *rule)
{
	return bpf_map__update_elem(ldr->skel->maps.rules, &slot, sizeof(slot),
				    rule, sizeof(*rule), BPF_ANY);
}

int skb_loader_set_cgroup(struct skb_loader *ldr, uint64_t cgroup_id,
			  uint32_t slot)
{
	return bpf_map__update_elem(ldr->skel->maps.cgroup_rule, &cgroup_id,
				    sizeof(cgroup_id), &slot, sizeof(slot), BPF_ANY);
}

int skb_loader_del_cgroup(struct skb_loader *ldr, uint64_t cgroup_id)
{
	return bpf_map__delete_elem(ldr->skel->maps.cgroup_rule, &cgroup_id,
				    sizeof(cgroup_id), 0);
}

int skb_loader_next_cgroup(struct skb_loader *ldr, const uint64_t *prev,
			   uint64_t *next)
{
	return bpf_map__get_next_key(ldr->skel->maps.cgroup_rule, prev, next,
				     sizeof(*next));
}

int skb_loader_stats(const struct skb_loader *ldr, uint64_t *out, size_t n)
{
	int fd;

	if (!ldr || !ldr->skel || n < SKB_STAT__MAX)
		return -EINVAL;

	fd = bpf_map__fd(ldr->skel->maps.stats);
	for (uint32_t k = 0; k < SKB_STAT__MAX; k++) {
		int err = bpf_map_lookup_elem(fd, &k, &out[k]);

		if (err)
			return err;
	}
	return 0;
}

int skb_loader_poll(struct skb_loader *ldr, int timeout_ms)
{
	if (!ldr || !ldr->rb)
		return -EINVAL;
	return ring_buffer__poll(ldr->rb, timeout_ms);
}

void skb_loader_close(struct skb_loader *ldr)
{
	if (!ldr)
		return;
	bpf_link__destroy(ldr->link);
	ring_buffer__free(ldr->rb);
	skbouncer_bpf__destroy(ldr->skel);
	free(ldr);
}
