// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
	struct skb_container_info cinfo;	/* what --container resolved to */
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

/* Installed without SA_RESTART. The poll loop has to see EINTR to notice
 * `exiting`. */
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
	struct skb_policy *policy;	/* NULL when no policy is loaded */
	const char *scope;		/* enforce mode's --cgroup */
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sync_policy(struct run_state *st)
{
	int err = skb_enforce_sync(st->ldr, st->policy, st->containers, st->scope);

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

	/* A cgroup created since the last sync reached the kernel without
	 * its rule. Out of scope the kernel does not judge. */
	if (st->enforce && v != ev->verdict && skb_enforce_in_scope(ev->cgroup_id))
		fprintf(stderr, "skbouncer: kernel verdict %s, userspace %s "
			"(cgroup %llu); policy map was stale\n",
			skb_verdict_str(ev->verdict), verdict,
			(unsigned long long)ev->cgroup_id);

	if (st->json) {
		st->events++;
		skb_event_print_json(stdout, ev, name, verdict, reason);
		return;
	}
	if (st->events++ == 0)
		skb_event_header(stdout, verdict, st->enforce);
	skb_event_print(stdout, ev, name, verdict, reason);
}

/* Prints the counters. Detected, delivered and dropped together give the
 * coverage denominator, and a ClientHello lost to a full ringbuf still
 * counts as detected. */
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
		"%llu dropped (ringbuf full), %llu too short to classify; "
		"unloading\n",
		(unsigned long long)stat[SKB_STAT_DETECTED], st->events,
		(unsigned long long)stat[SKB_STAT_DROPPED],
		(unsigned long long)stat[SKB_STAT_SHORT]);

	/* A ClientHello detected but neither delivered nor dropped was lost
	 * elsewhere, and the coverage figures would be biased without
	 * notice. */
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
"  -i, --iface <dev>     attach to <dev> instead\n"
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

/* Runs after --container has filled in -i and --cgroup. */
static int check_args(struct options *opt)
{
	if (!opt->direction_set && opt->ifname && skb_enforce_is_veth(opt->ifname))
		opt->direction = SKB_DIR_INGRESS;

	if (opt->mode != MODE_ENFORCE)
		return 0;
	if (!opt->cgroup_path) {
		fprintf(stderr, "skbouncer: enforce mode requires --cgroup\n");
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
	return 0;
}

static int resolve_container(struct options *opt)
{
	char errbuf[512];

	if (skb_container_resolve(opt->container, &opt->cinfo, errbuf, sizeof(errbuf))) {
		fprintf(stderr, "skbouncer: %s\n", errbuf);
		return -1;
	}
	opt->ifname = opt->cinfo.ifname;
	if (!opt->cgroup_path)
		opt->cgroup_path = opt->cinfo.cgroup;
	return 0;
}

/* Loads the policy and the program, fills the policy maps and attaches.
 * Whatever setup() managed to create stays in `st` for teardown(). */
static int setup(const struct options *opt, struct run_state *st)
{
	struct skb_loader_opts lopts = {
		.ifname    = opt->ifname,
		.direction = opt->direction,
		.verbose   = opt->verbose,
		.enforce   = st->enforce,
		.on_event  = on_event,
		.ctx       = st,
	};
	char errbuf[512];

	/* The policy loads first, so a bad policy file fails before anything
	 * enters the kernel. */
	if (opt->policy_path &&
	    !(st->policy = skb_policy_load(opt->policy_path, errbuf, sizeof(errbuf)))) {
		fprintf(stderr, "skbouncer: %s\n", errbuf);
		return -1;
	}
	if (st->enforce) {
		if (skb_enforce_scope(opt->cgroup_path, &lopts.scope_id,
				      &lopts.scope_level, errbuf, sizeof(errbuf))) {
			fprintf(stderr, "skbouncer: %s\n", errbuf);
			return -1;
		}
		lopts.unknown_block = skb_policy_blocks_unknown(st->policy);
		st->scope = opt->cgroup_path;
	}

	/* Fills the name cache before the first event. If dockerd does not
	 * answer, names stay null until it does. */
	if (!(st->containers = skb_container_map_new())) {
		perror("skbouncer: container map");
		return -1;
	}
	if (skb_container_refresh(st->containers) != 0)
		fprintf(stderr, "skbouncer: cannot list containers via "
			"/var/run/docker.sock; container names unavailable\n");

	if (!(st->ldr = skb_loader_open(&lopts)))
		return -1;
	/* The policy maps are filled before the attach. An empty map would
	 * let every ClientHello through. */
	if (st->enforce && skb_enforce_sync(st->ldr, st->policy, st->containers,
					    st->scope)) {
		fprintf(stderr, "skbouncer: cannot load policy into the kernel\n");
		return -1;
	}
	if (opt->ifname && skb_loader_attach(st->ldr, opt->ifname, opt->direction))
		return -1;
	return 0;
}

static void announce(const struct options *opt, const struct run_state *st)
{
	const char *doing = st->enforce ? "enforcing on" : "watching";

	if (opt->container)
		fprintf(stderr, "skbouncer: %s container %s (%s %s); Ctrl-C to stop\n",
			doing, opt->container, opt->ifname,
			skb_direction_name(opt->direction));
	else if (opt->ifname)
		fprintf(stderr, "skbouncer: %s %s %s; Ctrl-C to stop\n", doing,
			opt->ifname, skb_direction_name(opt->direction));
	else
		fprintf(stderr, "skbouncer: loaded but not attached (pass --container "
			"or -i); Ctrl-C to unload\n");
}

/* SIGPIPE and SIGHUP also stop skbouncer cleanly. A closed pipe or terminal
 * ends the run, and the counters are still printed. */
static int catch_signals(void)
{
	if (catch_signal(SIGINT) || catch_signal(SIGTERM) ||
	    catch_signal(SIGHUP) || catch_signal(SIGPIPE)) {
		perror("skbouncer: sigaction");
		return -1;
	}
	return 0;
}

static int run(struct run_state *st)
{
	uint64_t next_sync = 0;

	while (!exiting) {
		int err = skb_loader_poll(st->ldr, 200 /* ms */);

		/* A container started since the last sync gets its rule
		 * before its first ClientHello. The sync runs on its own
		 * clock. A busy ringbuf returns from poll() far more often
		 * than every 200 ms. */
		if (st->enforce && now_ms() >= next_sync) {
			skb_container_refresh(st->containers);
			sync_policy(st);
			next_sync = now_ms() + 1000;
		}
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "skbouncer: ringbuf poll failed: %s\n",
				strerror(-err));
			return EXIT_FAILURE;
		}
	}

	/* Events the kernel submitted before the signal may still be in the
	 * ringbuf. Draining them keeps the delivered count comparable with
	 * the kernel counters. */
	skb_loader_poll(st->ldr, 0);
	report(st->ldr, st);
	return EXIT_SUCCESS;
}

static void teardown(struct run_state *st)
{
	skb_loader_close(st->ldr);
	skb_container_map_free(st->containers);
	skb_policy_free(st->policy);
}

int main(int argc, char **argv)
{
	struct options opt = { .mode = MODE_AUDIT };
	struct run_state st = {};
	int rc = EXIT_FAILURE;

	/* When stdout is not a terminal it is block buffered. Events would
	 * then wait unflushed while the poll loop blocks. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (parse_args(argc, argv, &opt) != 0) {
		fprintf(stderr, "run '%s --help' for usage\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (opt.container && resolve_container(&opt) != 0)
		return EXIT_FAILURE;
	if (check_args(&opt) != 0)
		return EXIT_FAILURE;

	st.json = opt.json;
	st.enforce = opt.mode == MODE_ENFORCE;
	if (setup(&opt, &st) == 0 && catch_signals() == 0) {
		announce(&opt, &st);
		rc = run(&st);
	}
	teardown(&st);
	return rc;
}
