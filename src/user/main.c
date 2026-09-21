// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "container.h"
#include "event.h"
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

/* No SA_RESTART: the poll loop must see EINTR to notice `exiting`. */
static int catch_signal(int sig)
{
	struct sigaction sa = { .sa_handler = on_signal };

	sigemptyset(&sa.sa_mask);
	return sigaction(sig, &sa, NULL);
}

struct run_state {
	unsigned long events;
};

static void on_event(void *ctx, const struct skb_event *ev)
{
	struct run_state *st = ctx;

	if (st->events++ == 0)
		skb_event_header(stdout);
	skb_event_print(stdout, ev);
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
	struct run_state state = {};

	/* Off a tty stdout is block buffered and the poll loop then blocks, so
	 * events would sit unflushed until exit. */
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
		.ifname   = opt.ifname,
		.verbose  = opt.verbose,
		.on_event = on_event,
		.ctx      = &state,
	};

	ldr = skb_loader_open(&lopts);
	if (!ldr)
		return EXIT_FAILURE;

	printf("skbouncer: loaded prog id=%u name=%s\n",
	       skb_loader_prog_id(ldr), skb_loader_prog_name(ldr));
	printf("verify with: bpftool prog show id %u\n", skb_loader_prog_id(ldr));
	if (opt.ifname)
		printf("watching %s egress for TLS ClientHello; Ctrl-C to stop\n",
		       opt.ifname);
	else
		printf("loaded but not attached (pass -i <dev>); Ctrl-C to unload\n");

	if (catch_signal(SIGINT) != 0 || catch_signal(SIGTERM) != 0) {
		perror("skbouncer: sigaction");
		skb_loader_close(ldr);
		return EXIT_FAILURE;
	}

	while (!exiting) {
		int err = skb_loader_poll(ldr, 200 /* ms */);

		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "skbouncer: ringbuf poll failed: %s\n",
				strerror(-err));
			skb_loader_close(ldr);
			return EXIT_FAILURE;
		}
	}

	printf("\nskbouncer: %lu ClientHello event(s); unloading\n", state.events);
	skb_loader_close(ldr);
	return EXIT_SUCCESS;
}
