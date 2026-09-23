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
	enum skb_direction direction;
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
	struct skb_container_map *containers;
};

static void on_event(void *ctx, const struct skb_event *ev)
{
	struct run_state *st = ctx;
	const char *name = skb_container_lookup(st->containers, ev->cgroup_id);

	if (st->json) {
		st->events++;
		skb_event_print_json(stdout, ev, name);
		return;
	}
	if (st->events++ == 0)
		skb_event_header(stdout);
	skb_event_print(stdout, ev, name);
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
		printf("skbouncer: %lu ClientHello event(s); unloading\n",
		       st->events);
		return;
	}

	printf("\nskbouncer: %llu ClientHello detected, %lu delivered, "
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
"usage: %s [options]\n"
"\n"
"  -i, --iface <dev>     attach to clsact on <dev>\n"
"  -d, --direction <d>   egress (default) or ingress\n"
"  -c, --cgroup <path>   restrict to this cgroup v2 path\n"
"  -p, --policy <file>   JSON policy file\n"
"  -m, --mode <mode>     audit (default) or enforce\n"
"  -f, --format <fmt>    text (default) or json, one object per line\n"
"  -v, --verbose         pass libbpf debug output through\n"
"  -h, --help            this text\n"
"\n"
"enforce mode requires --cgroup and refuses the root cgroup.\n"
"\n"
"A bridged container's outbound traffic is INGRESS on the host side of its\n"
"veth, and is still pre-NAT there. Watching one container therefore means\n"
"  -i <its veth> --direction ingress\n"
"rather than the physical interface, where the packet has been forwarded\n"
"and SNATed and carries no cgroup id.\n",
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
		{ "iface",     required_argument, NULL, 'i' },
		{ "direction", required_argument, NULL, 'd' },
		{ "cgroup",    required_argument, NULL, 'c' },
		{ "policy",    required_argument, NULL, 'p' },
		{ "mode",      required_argument, NULL, 'm' },
		{ "format",    required_argument, NULL, 'f' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c;

	while ((c = getopt_long(argc, argv, "i:d:c:p:m:f:vh", longopts, NULL)) != -1) {
		switch (c) {
		case 'i': opt->ifname = optarg; break;
		case 'c': opt->cgroup_path = optarg; break;
		case 'd':
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
	state.json = opt.json;

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
		.ifname    = opt.ifname,
		.direction = opt.direction,
		.verbose   = opt.verbose,
		.on_event  = on_event,
		.ctx       = &state,
	};

	/* Warm the cache so the first events cost no round trip to dockerd.
	 * Failure is not fatal: names are then null until dockerd answers. */
	state.containers = skb_container_map_new();
	if (!state.containers) {
		perror("skbouncer: container map");
		return EXIT_FAILURE;
	}
	if (skb_container_refresh(state.containers) != 0)
		fprintf(stderr, "skbouncer: cannot list containers via "
			"/var/run/docker.sock; container names unavailable\n");

	ldr = skb_loader_open(&lopts);
	if (!ldr) {
		skb_container_map_free(state.containers);
		return EXIT_FAILURE;
	}

	printf("skbouncer: loaded prog id=%u name=%s\n",
	       skb_loader_prog_id(ldr), skb_loader_prog_name(ldr));
	printf("verify with: bpftool prog show id %u\n", skb_loader_prog_id(ldr));
	if (opt.ifname)
		printf("watching %s %s for TLS ClientHello; Ctrl-C to stop\n",
		       opt.ifname, skb_direction_name(opt.direction));
	else
		printf("loaded but not attached (pass -i <dev>); Ctrl-C to unload\n");

	if (catch_signal(SIGINT) != 0 || catch_signal(SIGTERM) != 0) {
		perror("skbouncer: sigaction");
		skb_loader_close(ldr);
		skb_container_map_free(state.containers);
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
	return EXIT_SUCCESS;
}
