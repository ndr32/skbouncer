// SPDX-License-Identifier: GPL-2.0
/* The main menu. Each choice runs skbouncer itself with the options a
 * person would type, so the menu and the command line take one path. */
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "container.h"
#include "menu.h"
#include "policy.h"
#include "version.h"

#define MAX_LISTED 64

struct listing {
	struct {
		char name[128];
		char veth[IF_NAMESIZE];
		uint64_t cgroup_id;
	} c[MAX_LISTED];
	size_t n;
};

static void add(const char *name, const char *veth, uint64_t cgroup_id, void *ctx)
{
	struct listing *l = ctx;

	if (l->n == MAX_LISTED)
		return;
	snprintf(l->c[l->n].name, sizeof(l->c[l->n].name), "%s", name);
	snprintf(l->c[l->n].veth, sizeof(l->c[l->n].veth), "%s", veth ? veth : "-");
	l->c[l->n++].cgroup_id = cgroup_id;
}

/* One line from the terminal, without its newline. False at end of input. */
static bool ask(const char *prompt, char *buf, size_t len)
{
	fputs(prompt, stdout);
	fflush(stdout);
	if (!fgets(buf, len, stdin))
		return false;
	buf[strcspn(buf, "\n")] = '\0';
	return true;
}

/* Prints the running containers, numbered. False if there are none. */
static bool list(struct listing *l)
{
	l->n = 0;
	if (skb_container_list(add, l) != 0) {
		puts("cannot ask dockerd for containers");
		return false;
	}
	if (l->n == 0) {
		puts("no running containers");
		return false;
	}
	puts("Running containers:");
	for (size_t i = 0; i < l->n; i++)
		printf("  %zu  %s  (%s, cgroup %llu)\n", i + 1, l->c[i].name, l->c[i].veth,
		       (unsigned long long)l->c[i].cgroup_id);
	return true;
}

/* The chosen container's name, by number or by name, or NULL. */
static const char *pick(struct listing *l)
{
	char buf[128], *end;
	unsigned long k;

	if (!list(l) || !ask("Container: ", buf, sizeof(buf)))
		return NULL;
	k = strtoul(buf, &end, 10);
	if (buf[0] && !*end && k >= 1 && k <= l->n)
		return l->c[k - 1].name;
	for (size_t i = 0; i < l->n; i++)
		if (strcmp(buf, l->c[i].name) == 0)
			return l->c[i].name;
	puts("no such container");
	return NULL;
}

/* Asks for a policy file and describes it. The path, or NULL if the file
 * does not load. */
static const char *ask_policy(char *path, size_t len)
{
	char err[PATH_MAX + 256];
	struct skb_policy *pol;

	if (!ask("Policy file: ", path, len))
		return NULL;
	pol = skb_policy_load(path, err, sizeof(err));
	if (!pol) {
		puts(err);
		return NULL;
	}
	skb_policy_describe(pol, stdout);
	skb_policy_free(pol);
	return path;
}

static bool confirm(const char *container)
{
	char buf[8];

	printf("This drops violating ClientHellos from %s.\n", container);
	return ask("Continue? [y/N] ", buf, sizeof(buf)) && (buf[0] == 'y' || buf[0] == 'Y');
}

/* Runs skbouncer with `args` and waits. Ctrl-C reaches the child, which
 * stops and prints its summary; the menu ignores it and carries on. */
static void run(char *const args[])
{
	struct sigaction ignore = { .sa_handler = SIG_IGN }, old;
	pid_t pid;

	fputs("Running: skbouncer", stdout);
	for (size_t i = 1; args[i]; i++)
		printf(" %s", args[i]);
	puts("\n(Ctrl-C ends the run and returns to the menu)");
	fflush(stdout);

	sigaction(SIGINT, &ignore, &old);
	pid = fork();
	if (pid == 0) {
		/* exec keeps an ignored signal ignored: restore it first. */
		sigaction(SIGINT, &old, NULL);
		execv("/proc/self/exe", args);
		perror("skbouncer: exec");
		_exit(127);
	}
	if (pid < 0)
		perror("skbouncer: fork");
	else
		waitpid(pid, NULL, 0);
	sigaction(SIGINT, &old, NULL);
}

int skb_menu_run(void)
{
	static struct listing l;
	char choice[16], path[PATH_MAX];
	const char *c, *p;

	for (;;) {
		printf("\nskbouncer %s: TLS policy for Docker containers\n\n"
		       "  1  Watch a container\n"
		       "  2  Audit a container against a policy\n"
		       "  3  Enforce a policy on a container\n"
		       "  4  Check a policy file\n"
		       "  5  List running containers\n"
		       "  q  Quit\n\n", SKB_VERSION);
		if (!ask("Choose: ", choice, sizeof(choice)) || choice[0] == 'q')
			return EXIT_SUCCESS;
		if (strchr("1235", choice[0]) && choice[0] && geteuid() != 0) {
			puts("This needs root: run sudo ./skbouncer");
			continue;
		}
		switch (choice[0]) {
		case '1':
			if ((c = pick(&l)))
				run((char *[]){ "skbouncer", "--container", (char *)c, NULL });
			break;
		case '2':
			if ((c = pick(&l)) && (p = ask_policy(path, sizeof(path))))
				run((char *[]){ "skbouncer", "--container", (char *)c,
						"-p", (char *)p, NULL });
			break;
		case '3':
			if ((c = pick(&l)) && (p = ask_policy(path, sizeof(path))) && confirm(c))
				run((char *[]){ "skbouncer", "--container", (char *)c,
						"-p", (char *)p, "--mode", "enforce", NULL });
			break;
		case '4':
			ask_policy(path, sizeof(path));
			break;
		case '5':
			list(&l);
			break;
		default:
			puts("Choose 1 to 5, or q.");
		}
	}
}
