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

/* Our filter on the shared clsact egress hook. Fixed so a stale filter from
 * a killed run is replaced rather than stacked on top of. */
#define SKB_TC_HANDLE   1
#define SKB_TC_PRIORITY 1

struct skb_loader {
	struct skbouncer_bpf *skel;
	struct ring_buffer *rb;
	uint32_t prog_id;
	char prog_name[16];	/* BPF_OBJ_NAME_LEN */

	int ifindex;		/* 0 when not attached */
	bool made_hook;		/* we created clsact, so we may remove it */
	bool attached;

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

/* clsact is shared with anything else on the interface, so an existing hook
 * is not an error and must not be torn down on exit. */
static int attach_tc(struct skb_loader *ldr, const char *ifname)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tcopts,
		    .handle = SKB_TC_HANDLE, .priority = SKB_TC_PRIORITY);
	int err;

	ldr->ifindex = if_nametoindex(ifname);
	if (!ldr->ifindex) {
		fprintf(stderr, "skbouncer: no such interface '%s'\n", ifname);
		return -1;
	}
	hook.ifindex = ldr->ifindex;

	err = bpf_tc_hook_create(&hook);
	if (err == 0) {
		ldr->made_hook = true;
	} else if (err != -EEXIST) {
		fprintf(stderr, "skbouncer: cannot create clsact on %s: %s\n",
			ifname, strerror(-err));
		return -1;
	}

	tcopts.prog_fd = bpf_program__fd(ldr->skel->progs.skb_egress);
	tcopts.flags = BPF_TC_F_REPLACE;
	err = bpf_tc_attach(&hook, &tcopts);
	if (err) {
		fprintf(stderr, "skbouncer: cannot attach to %s egress: %s\n",
			ifname, strerror(-err));
		if (ldr->made_hook) {
			hook.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS;
			bpf_tc_hook_destroy(&hook);
			ldr->made_hook = false;
		}
		return -1;
	}

	ldr->attached = true;
	return 0;
}

static void detach_tc(struct skb_loader *ldr)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tcopts,
		    .handle = SKB_TC_HANDLE, .priority = SKB_TC_PRIORITY);

	if (!ldr->ifindex)
		return;
	hook.ifindex = ldr->ifindex;

	if (ldr->attached)
		bpf_tc_detach(&hook, &tcopts);

	/* Destroying clsact takes every filter on the interface with it, so
	 * only do it if the interface had none before us. */
	if (ldr->made_hook) {
		hook.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS;
		bpf_tc_hook_destroy(&hook);
	}
}

struct skb_loader *skb_loader_open(const struct skb_loader_opts *opts)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct skb_loader *ldr;
	int prog_fd, err;

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

	ldr->skel = skbouncer_bpf__open_and_load();
	if (!ldr->skel) {
		fprintf(stderr, "skbouncer: failed to load BPF object: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "skbouncer: loading BPF needs root; try sudo\n");
		free(ldr);
		return NULL;
	}

	prog_fd = bpf_program__fd(ldr->skel->progs.skb_egress);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "skbouncer: cannot query program info: %s\n",
			strerror(-err));
		skbouncer_bpf__destroy(ldr->skel);
		free(ldr);
		return NULL;
	}

	ldr->prog_id = info.id;
	memcpy(ldr->prog_name, info.name, sizeof(ldr->prog_name) - 1);

	ldr->rb = ring_buffer__new(bpf_map__fd(ldr->skel->maps.events),
				   handle_event, ldr, NULL);
	if (!ldr->rb) {
		fprintf(stderr, "skbouncer: cannot open ringbuf: %s\n",
			strerror(errno));
		skb_loader_close(ldr);
		return NULL;
	}

	if (opts && opts->ifname && attach_tc(ldr, opts->ifname) != 0) {
		skb_loader_close(ldr);
		return NULL;
	}

	return ldr;
}

uint32_t skb_loader_prog_id(const struct skb_loader *ldr)
{
	return ldr ? ldr->prog_id : 0;
}

const char *skb_loader_prog_name(const struct skb_loader *ldr)
{
	return ldr ? ldr->prog_name : "";
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
	detach_tc(ldr);
	ring_buffer__free(ldr->rb);
	skbouncer_bpf__destroy(ldr->skel);
	free(ldr);
}
