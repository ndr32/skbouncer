// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "container.h"
#include "enforce.h"
#include "event.h"
#include "loader.h"
#include "policy.h"
#include "version.h"

enum run_mode {
	MODE_AUDIT = 0,
	MODE_ENFORCE,
};


struct options {
	const char *container;
	const char *ifname;
	const char *cgroup_path;
	const char *policy_path;
	enum run_mode mode;
	enum skb_direction direction;
	bool direction_set;
	bool verbose;
	bool json;
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
	bool json;
	bool enforce;
	struct skb_loader *ldr;
	struct skb_container_map *containers;
	struct skb_policy *policy;	/* NULL: no verdicts */
};

static void sync_policy(struct run_state *st)
{
	int err = skb_enforce_sync(st->ldr, st->policy, st->containers);

	if (err)
		fprintf(stderr, "skbouncer: cannot update policy maps: %s\n",
			strerror(-err));
}

static void on_event(void *ctx, const struct skb_event *ev)
{
	struct run_state *st = ctx;
	const char *name = skb_container_lookup(st->containers, ev->cgroup_id);
	char why[160];
	enum skb_verdict v = st->policy ?
		skb_policy_explain(st->policy, ev, name, why, sizeof(why)) : 0;
	const char *verdict = st->policy ? skb_verdict_str(v) : NULL;
	const char *reason = st->policy ? why : NULL;

	if (st->enforce) {
		/* The lookup may have found a new container; the kernel decided
		 * this one without it, so they can disagree once. */
		if (v != ev->verdict)
			fprintf(stderr, "skbouncer: kernel verdict %s, userspace %s "
				"(cgroup %llu); container map was stale\n",
				skb_verdict_str(ev->verdict), verdict,
				(unsigned long long)ev->cgroup_id);
		sync_policy(st);
	}

	if (st->json) {
		st->events++;
		skb_event_print_json(stdout, ev, name, verdict, reason);
		return;
	}
	if (st->events++ == 0)
		skb_event_header(stdout, verdict, st->enforce);
	skb_event_print(stdout, ev, name, verdict, reason);
}

/* The detected/delivered/dropped split is the coverage denominator M7
 * needs: an event lost to a full ringbuf must not look like a connection
 * that never happened. */
static void report(const struct skb_loader *ldr, const struct run_state *st)
{
	uint64_t stat[SKB_STAT__MAX];
	int err = skb_loader_stats(ldr, stat, SKB_STAT__MAX);

	if (err) {
		fprintf(stderr, "\nskbouncer: cannot read counters: %s\n",
			strerror(-err));
		fprintf(stderr, "skbouncer: %lu ClientHello event(s); unloading\n",
			st->events);
		return;
	}

	fprintf(stderr, "\nskbouncer: %llu ClientHello detected, %lu delivered, "
		"%llu dropped (ringbuf full); unloading\n",
		(unsigned long long)stat[SKB_STAT_DETECTED], st->events,
		(unsigned long long)stat[SKB_STAT_DROPPED]);

	/* Detected but neither delivered nor counted as dropped means the
	 * loss is somewhere else, which would silently bias M7. */
	if (stat[SKB_STAT_DETECTED] != st->events + stat[SKB_STAT_DROPPED])
		fprintf(stderr, "skbouncer: counters do not balance; "
			"event loss is unaccounted for\n");
}

static void usage(FILE *out, const char *argv0)
{
	fprintf(out,
"usage: %s --container <name> [options]\n"
"       %s -i <dev> [options]\n"
"\n"
"Watches TLS ClientHellos and checks them against a policy.\n"
"\n"
"  -C, --container <name> watch this Docker container: its veth, ingress\n"
"  -i, --iface <dev>     attach to clsact on <dev> instead\n"
"  -d, --direction <d>   ingress (default on a veth) or egress (default\n"
"                        elsewhere)\n"
"  -c, --cgroup <path>   restrict enforcement to this cgroup v2 path\n"
"                        (default with --container: the container's)\n"
"  -p, --policy <file>   JSON policy file (see policy/README.md)\n"
"  -m, --mode <mode>     audit (default) or enforce\n"
"  -f, --format <fmt>    text (default) or json, one object per line\n"
"  -v, --verbose         pass libbpf debug output through\n"
"  -V, --version         print the version\n"
"  -h, --help            this text\n"
"\n"
"Output goes to stdout; status and errors go to stderr.\n"
"\n"
"enforce mode drops violating ClientHellos in the kernel. It requires -p\n"
"and a veth, and blocks only in the --cgroup scope, which --container\n"
"supplies. The root cgroup is refused.\n"
"\n"
"A bridged container's outbound traffic is INGRESS on the host side of its\n"
"veth, and is still pre-NAT there; --container attaches there for you.\n"
"The physical interface sees it forwarded and SNATed, with no cgroup id.\n",
		argv0, argv0);
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
		{ "container", required_argument, NULL, 'C' },
		{ "iface",     required_argument, NULL, 'i' },
		{ "direction", required_argument, NULL, 'd' },
		{ "cgroup",    required_argument, NULL, 'c' },
		{ "policy",    required_argument, NULL, 'p' },
		{ "mode",      required_argument, NULL, 'm' },
		{ "format",    required_argument, NULL, 'f' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "version",   no_argument,       NULL, 'V' },
		{ "help",      no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c;

	while ((c = getopt_long(argc, argv, "C:i:d:c:p:m:f:vVh", longopts, NULL)) != -1) {
		switch (c) {
		case 'C': opt->container = optarg; break;
		case 'i': opt->ifname = optarg; break;
		case 'c': opt->cgroup_path = optarg; break;
		case 'd':
			opt->direction_set = true;
			if (strcmp(optarg, "egress") == 0) {
				opt->direction = SKB_DIR_EGRESS;
			} else if (strcmp(optarg, "ingress") == 0) {
				opt->direction = SKB_DIR_INGRESS;
			} else {
				fprintf(stderr, "skbouncer: unknown direction '%s'\n",
					optarg);
				return -1;
			}
			break;
		case 'p': opt->policy_path = optarg; break;
		case 'f':
			if (strcmp(optarg, "text") == 0) {
				opt->json = false;
			} else if (strcmp(optarg, "json") == 0) {
				opt->json = true;
			} else {
				fprintf(stderr, "skbouncer: unknown format '%s'\n",
					optarg);
				return -1;
			}
			break;
		case 'v': opt->verbose = true; break;
		case 'h': usage(stdout, argv[0]); exit(EXIT_SUCCESS);
		case 'V': printf("skbouncer %s\n", SKB_VERSION); exit(EXIT_SUCCESS);
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
	if (optind < argc) {
		fprintf(stderr, "skbouncer: unexpected argument '%s'\n", argv[optind]);
		return -1;
	}
	if (opt->container && opt->ifname) {
		fprintf(stderr, "skbouncer: give --container or -i, not both\n");
		return -1;
	}
	return 0;
}

/* After --container has filled in -i and --cgroup. */
static int check_args(struct options *opt)
{
	/* Container traffic is ingress on the host end of its veth. */
	if (!opt->direction_set && opt->ifname && skb_enforce_is_veth(opt->ifname))
		opt->direction = SKB_DIR_INGRESS;

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
		if (!opt->policy_path) {
			fprintf(stderr, "skbouncer: enforce mode requires a policy (-p)\n");
			return -1;
		}
		/* The host's own traffic, SSH included, never crosses a veth. */
		if (!opt->ifname || !skb_enforce_is_veth(opt->ifname)) {
			fprintf(stderr, "skbouncer: enforce mode only attaches to a veth; "
				"%s is not one\n", opt->ifname ? opt->ifname : "no -i given");
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
	struct skb_container_info cinfo;
	unsigned ticks = 0;

	/* Off a tty stdout is block buffered and the poll loop then blocks, so
	 * events would sit unflushed until exit. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (parse_args(argc, argv, &opt) != 0) {
		fprintf(stderr, "run '%s --help' for usage\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (opt.container) {
		char errbuf[512];

		if (skb_container_resolve(opt.container, &cinfo, errbuf, sizeof(errbuf))) {
			fprintf(stderr, "skbouncer: %s\n", errbuf);
			return EXIT_FAILURE;
		}
		opt.ifname = cinfo.ifname;
		if (!opt.cgroup_path)
			opt.cgroup_path = cinfo.cgroup;
	}
	if (check_args(&opt) != 0)
		return EXIT_FAILURE;
	state.json = opt.json;
	state.enforce = opt.mode == MODE_ENFORCE;
	/* Before anything is loaded: a bad policy must cost nothing. */
	if (opt.policy_path) {
		char errbuf[512];

		state.policy = skb_policy_load(opt.policy_path, errbuf, sizeof(errbuf));
		if (!state.policy) {
			fprintf(stderr, "skbouncer: %s\n", errbuf);
			return EXIT_FAILURE;
		}
	}

	lopts = (struct skb_loader_opts){
		.ifname    = opt.ifname,
		.direction = opt.direction,
		.verbose   = opt.verbose,
		.enforce   = state.enforce,
		.on_event  = on_event,
		.ctx       = &state,
	};
	if (state.enforce) {
		char errbuf[512];

		if (skb_enforce_scope(opt.cgroup_path, &lopts.scope_id,
				      &lopts.scope_level, errbuf, sizeof(errbuf))) {
			fprintf(stderr, "skbouncer: %s\n", errbuf);
			skb_policy_free(state.policy);
			return EXIT_FAILURE;
		}
		lopts.unknown_block = skb_policy_blocks_unknown(state.policy);
	}

	/* Warm the cache so the first events cost no round trip to dockerd.
	 * Failure is not fatal: names are then null until dockerd answers. */
	state.containers = skb_container_map_new();
	if (!state.containers) {
		perror("skbouncer: container map");
		skb_policy_free(state.policy);
		return EXIT_FAILURE;
	}
	if (skb_container_refresh(state.containers) != 0)
		fprintf(stderr, "skbouncer: cannot list containers via "
			"/var/run/docker.sock; container names unavailable\n");

	ldr = skb_loader_open(&lopts);
	state.ldr = ldr;
	if (!ldr)
		goto fail;
	/* The policy goes in before the attach: an empty map fails open. */
	if (state.enforce && skb_enforce_sync(ldr, state.policy, state.containers)) {
		fprintf(stderr, "skbouncer: cannot load policy into the kernel\n");
		goto fail;
	}
	if (opt.ifname && skb_loader_attach(ldr, opt.ifname, opt.direction)) {
fail:
		skb_loader_close(ldr);
		skb_container_map_free(state.containers);
		skb_policy_free(state.policy);
		return EXIT_FAILURE;
	}

	if (opt.container)
		fprintf(stderr, "skbouncer: %s container %s (%s %s); Ctrl-C to stop\n",
			state.enforce ? "enforcing on" : "watching", opt.container,
			opt.ifname, skb_direction_name(opt.direction));
	else if (opt.ifname)
		fprintf(stderr, "skbouncer: %s %s %s; Ctrl-C to stop\n",
			state.enforce ? "enforcing on" : "watching",
			opt.ifname, skb_direction_name(opt.direction));
	else
		fprintf(stderr, "skbouncer: loaded but not attached (pass --container "
			"or -i); Ctrl-C to unload\n");

	if (catch_signal(SIGINT) != 0 || catch_signal(SIGTERM) != 0) {
		perror("skbouncer: sigaction");
		skb_loader_close(ldr);
		skb_container_map_free(state.containers);
		skb_policy_free(state.policy);
		return EXIT_FAILURE;
	}

	while (!exiting) {
		int err = skb_loader_poll(ldr, 200 /* ms */);

		/* A container started since the last look gets its rule
		 * before its first ClientHello, not after. */
		if (state.enforce && ++ticks % 5 == 0) {
			skb_container_refresh(state.containers);
			sync_policy(&state);
		}

		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "skbouncer: ringbuf poll failed: %s\n",
				strerror(-err));
			skb_loader_close(ldr);
			skb_container_map_free(state.containers);
			return EXIT_FAILURE;
		}
	}

	/* Anything the kernel submitted just before the signal is still in the
	 * ringbuf; drain it so the delivered count can be compared with the
	 * kernel's own tally. */
	skb_loader_poll(ldr, 0);
	report(ldr, &state);

	skb_loader_close(ldr);
	skb_container_map_free(state.containers);
	skb_policy_free(state.policy);
	return EXIT_SUCCESS;
}
