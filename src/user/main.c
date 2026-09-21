// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "container.h"
#include "loader.h"
#include "policy.h"

enum run_mode {
	MODE_AUDIT = 0,
	MODE_ENFORCE,
};

struct options {
	const char *ifname;
	const char *cgroup_path;
	const char *policy_path;
	enum run_mode mode;
	bool verbose;
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static void usage(FILE *out, const char *argv0)
{
	fprintf(out,
"usage: %s [options]\n"
"\n"
"  -i, --iface <dev>     attach to clsact egress on <dev>\n"
"  -c, --cgroup <path>   restrict to this cgroup v2 path\n"
"  -p, --policy <file>   JSON policy file\n"
"  -m, --mode <mode>     audit (default) or enforce\n"
"  -v, --verbose         pass libbpf debug output through\n"
"  -h, --help            this text\n"
"\n"
"enforce mode requires --cgroup and refuses the root cgroup.\n",
		argv0);
}

/* Checked here, not at the attach site, so no future caller can skip it. */
static bool cgroup_path_is_safe(const char *path, const char **why)
{
	static const char *const root_paths[] = {
		"/sys/fs/cgroup", "/sys/fs/cgroup/", "/", NULL
	};

	if (!path || path[0] == '\0') {
		*why = "empty path";
		return false;
	}
	if (path[0] != '/') {
		*why = "must be an absolute path";
		return false;
	}
	for (int i = 0; root_paths[i]; i++) {
		if (strcmp(path, root_paths[i]) == 0) {
			*why = "refusing the root cgroup";
			return false;
		}
	}
	return true;
}

static int parse_args(int argc, char **argv, struct options *opt)
{
	static const struct option longopts[] = {
		{ "iface",   required_argument, NULL, 'i' },
		{ "cgroup",  required_argument, NULL, 'c' },
		{ "policy",  required_argument, NULL, 'p' },
		{ "mode",    required_argument, NULL, 'm' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c;

	while ((c = getopt_long(argc, argv, "i:c:p:m:vh", longopts, NULL)) != -1) {
		switch (c) {
		case 'i': opt->ifname = optarg; break;
		case 'c': opt->cgroup_path = optarg; break;
		case 'p': opt->policy_path = optarg; break;
		case 'v': opt->verbose = true; break;
		case 'h': usage(stdout, argv[0]); exit(EXIT_SUCCESS);
		case 'm':
			if (strcmp(optarg, "audit") == 0) {
				opt->mode = MODE_AUDIT;
			} else if (strcmp(optarg, "enforce") == 0) {
				opt->mode = MODE_ENFORCE;
			} else {
				fprintf(stderr, "skbouncer: unknown mode '%s'\n", optarg);
				return -1;
			}
			break;
		default:
			return -1;
		}
	}

	if (opt->mode == MODE_ENFORCE) {
		const char *why = NULL;

		if (!opt->cgroup_path) {
			fprintf(stderr, "skbouncer: enforce mode requires --cgroup\n");
			return -1;
		}
		if (!cgroup_path_is_safe(opt->cgroup_path, &why)) {
			fprintf(stderr, "skbouncer: unsafe --cgroup '%s': %s\n",
				opt->cgroup_path, why);
			return -1;
		}
	} else if (opt->cgroup_path) {
		const char *why = NULL;

		if (!cgroup_path_is_safe(opt->cgroup_path, &why)) {
			fprintf(stderr, "skbouncer: unsafe --cgroup '%s': %s\n",
				opt->cgroup_path, why);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct options opt = { .mode = MODE_AUDIT };
	struct skb_loader_opts lopts;
	struct skb_loader *ldr;
	sigset_t mask, orig_mask;

	/* Off a tty stdout is block buffered and we then block in sigsuspend(),
	 * so the prog id would never flush. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (parse_args(argc, argv, &opt) != 0) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	if (opt.mode == MODE_ENFORCE) {
		fprintf(stderr, "skbouncer: enforce mode not implemented\n");
		return EXIT_FAILURE;
	}
	if (opt.policy_path) {
		char errbuf[256];
		struct skb_policy *pol = skb_policy_load(opt.policy_path,
							 errbuf, sizeof(errbuf));
		if (!pol) {
			fprintf(stderr, "skbouncer: %s\n", errbuf);
			return EXIT_FAILURE;
		}
		skb_policy_free(pol);
	}

	lopts = (struct skb_loader_opts){
		.ifname  = opt.ifname,
		.verbose = opt.verbose,
	};

	ldr = skb_loader_open(&lopts);
	if (!ldr)
		return EXIT_FAILURE;

	printf("skbouncer: loaded prog id=%u name=%s\n",
	       skb_loader_prog_id(ldr), skb_loader_prog_name(ldr));
	printf("verify with: bpftool prog show id %u\n", skb_loader_prog_id(ldr));
	printf("holding program open; Ctrl-C to unload\n");

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Block before testing the flag: pause() would race and miss the
	 * first Ctrl-C. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) != 0) {
		perror("skbouncer: sigprocmask");
		skb_loader_close(ldr);
		return EXIT_FAILURE;
	}

	while (!exiting)
		sigsuspend(&orig_mask);

	sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	printf("\nskbouncer: unloading\n");
	skb_loader_close(ldr);
	return EXIT_SUCCESS;
}
