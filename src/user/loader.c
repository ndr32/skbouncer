// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
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
	uint32_t prog_id;
	char prog_name[16];	/* BPF_OBJ_NAME_LEN */
};

static bool want_verbose;

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !want_verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
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

	if (opts && opts->ifname) {
		fprintf(stderr, "skbouncer: attach not implemented\n");
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

void skb_loader_close(struct skb_loader *ldr)
{
	if (!ldr)
		return;
	skbouncer_bpf__destroy(ldr->skel);
	free(ldr);
}
