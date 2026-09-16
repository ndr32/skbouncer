// SPDX-License-Identifier: GPL-2.0
/*
 * skbouncer - M1 loader
 *
 * Loads the tc egress program and holds it open so it stays visible in
 * `bpftool prog list`. Attaches to nothing: attachment arrives in M2, and
 * attaching anything to a cgroup is deliberately out of scope here.
 */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "skbouncer.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(void)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct skbouncer_bpf *skel;
	sigset_t mask, orig_mask;
	int prog_fd, err;

	/* Line-buffer: off a tty stdout is block-buffered, and the process
	 * then blocks in sigsuspend() without ever flushing the prog id. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_print(libbpf_print_fn);

	skel = skbouncer_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF skeleton: %s\n",
			strerror(errno));
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.skb_egress);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "failed to query program info: %s\n",
			strerror(-err));
		skbouncer_bpf__destroy(skel);
		return 1;
	}

	printf("skbouncer: loaded prog id=%u name=%s\n", info.id, info.name);
	printf("verify with: bpftool prog show id %u\n", info.id);
	printf("holding program open; Ctrl-C to unload\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Block both signals before testing the flag. pause() here would race:
	 * a signal arriving between the test and the call sets exiting with no
	 * one waiting, and pause() then sleeps until a second Ctrl-C. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, &orig_mask)) {
		perror("sigprocmask");
		skbouncer_bpf__destroy(skel);
		return 1;
	}

	while (!exiting)
		sigsuspend(&orig_mask);

	sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	printf("\nunloading\n");
	skbouncer_bpf__destroy(skel);
	return 0;
}
