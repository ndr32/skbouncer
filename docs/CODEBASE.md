# How the code fits together

skbouncer is one eBPF program in the kernel and one C program in userspace.
The kernel program reads the cipher suites and versions of each TLS
ClientHello a container sends. In enforce mode it also drops the ClientHellos
the policy forbids. The userspace program loads the kernel program, names the
container behind each ClientHello and prints one line per ClientHello with
its verdict and the reason.

The tool is about 3,100 lines of C: 660 on the kernel side with its shared
header, 2,400 in userspace. The rest of the repo is test and evaluation
tooling ([Around the tool](#around-the-tool)).

## Architecture

A container's outgoing traffic arrives on the host end of its veth, so the
program attaches there, on the ingress hook. At that point the source
address is still the container's own (before NAT), and the packet still
belongs to the sending socket, so `bpf_skb_cgroup_id()` returns the
container's cgroup. skbouncer names the container from that cgroup id.

In the diagram below the data path runs down the left. A ClientHello passes
through the kernel program and the ringbuf to `on_event()`, which prints it
as a text line or a JSON object. The control path runs up the right.
`policy.c` compiles the rules and `container.c` maps cgroups to containers;
`enforce.c` writes both into the kernel's maps once a second. In enforce mode
the kernel reaches a verdict to decide the packet. Userspace reaches its own
verdict in every mode for the report, and `on_event()` warns if the two
differ.

```
   the operator
        │ sudo ./skbouncer --container web -p policy.json [--mode enforce]
        │ (no arguments in a terminal: menu.c asks, then reruns skbouncer
        │  with the options a person would type)
   ┌────▼─────────┐
   │ main.c       │  options; safety checks: enforce needs a policy, a veth
   │              │  and a container's cgroup, and refuses the root cgroup
   └────┬─────────┘
   ┌────▼─────────┐
   │ loader.c     │  libbpf skeleton: load skb_tc, attach it through tcx
   └────┬─────────┘  to the host end of the container's veth, ingress
        │
        │ attaches skb_tc          a client in the container
        │                                │ ClientHello, ingress
 ═══════╪═══════════════════ kernel side ╪══════════════════════════════════
   ┌────▼─────────────────┐              │
   │ read_headers()       │◄─────────────┘  one skb at a time; Ethernet,
   │                      │  IPv4, TCP; clamp to gso_size, one segment
   └────┬─────────────────┘
   ┌────▼─────────────────┐
   │ is_client_hello()    │  record 0x16, handshake 0x01, structural
   │ not_a_hello()        │  checks; anything else passes untouched
   └────┬─────────────────┘
   ┌────▼─────────────────┐
   │ fill_event()         │  cgroup id, addresses, length; up to 64
   │ walk_hello()         │  cipher suites, supported_versions (0x002b),
   │                      │  flags for what the first segment lacked
   └────┬─────────────────┘
        │ enforce mode only                  ┌──────────────────┐
   ┌────▼─────────────────┐       reads      │ maps             │
   │ judge()              │◄─────────────────┤ cgroup_rule      │
   │ check_policy()       │                  │ rules            │
   └────┬────────────┬────┘                  └────────▲─────────┘
        │            └──► drop, or pass to the bridge │
        │ one skb_event per ClientHello               │
  ringbuf "events"                                    │
 ═══════╪════════════════════ userspace side ═════════╪══════════════════════
        │                                             │ once a second
   ┌────▼─────────────────┐                  ┌────────┴─────────┐
   │ loader.c             │                  │ enforce.c        │  every in-scope
   │ skb_loader_poll()    │                  │ skb_enforce_     │  cgroup gets its
   └────┬─────────────────┘                  │ sync()           │  rule
        │                                    └───▲──────────▲───┘
   ┌────▼─────────────────┐                      │          │
   │ main.c               │◄──── name ───── ┌────┴───────┐  │
   │ on_event()           │                 │container.c │◄─┼── dockerd
   │                      │                 │ cgroup id →│  │   (docker.sock,
   │                      │                 │ name       │  │    libcurl)
   │                      │                 └────────────┘  │
   │                      │◄─ verdict ───── ┌────────────┐  │
   │                      │   + reason      │ policy.c   ├──┘
   │                      │                 │ explain(), │◄──── policy.json
   └────┬────────────┬────┘                 │ compile()  │      (jansson)
        │            │                      └────────────┘
   ┌────▼───────┐    └──► on exit: counters, then one
   │ event.c    │         summary line per container
   └──┬──────┬──┘
      │      │
    text    JSON
    lines   objects
```

## Reading order

| File | Lines | What it does |
|---|---:|---|
| `include/skbouncer.h` | 138 | The event and rule formats the kernel and userspace share. Start here. |
| `src/bpf/skbouncer.bpf.c` | 525 | The kernel program: detect, measure, parse, judge, drop. |
| `src/user/main.c` | 559 | The CLI: options, safety checks, setup, the event loop, exit report and summary. |
| `src/user/menu.c` | 191 | The menu shown with no arguments. Each choice reruns skbouncer with options. |
| `src/user/loader.c` | 183 | Loads the program, attaches it, reads the ringbuf and the maps. |
| `src/user/container.c` | 381 | Docker: cgroup id → container name, `--container` → veth and cgroup, `--list`. |
| `src/user/policy.c` | 510 | The JSON policy: loading, the verdict and its reason, compiling rules for the kernel, `--check`. |
| `src/user/enforce.c` | 150 | Enforce mode: the cgroup scope, the veth check, keeping the kernel's maps current. |
| `src/user/event.c` | 221 | Output: the text line and the JSON object. |

Each `.c` in `src/user/` has a short `.h` beside it listing what it exports.

## One ClientHello, start to finish

1. A client in the container connects and sends its ClientHello. On the
   host end of the veth the packet is ingress, and `skb_tc()` runs.
2. **Headers.** `read_headers()` checks Ethernet → IPv4 → TCP, and finds
   where the TCP payload starts. Anything else passes untouched.
3. **How much of the record is here.** tc runs before the kernel cuts large
   sends into segments, so one packet here can be several segments on the
   wire. `read_headers()` clamps `avail` to `skb->gso_size`, the size of one
   segment. Without the clamp no ClientHello would ever look split, and the
   fragmentation measurement would read zero.
4. **Is it a ClientHello?** In `is_client_hello()`, the first 6 bytes must
   hold record type `0x16` (handshake), version major `0x03` and handshake
   type `0x01`. `not_a_hello()` then rejects
   byte patterns that only look like one, such as a handshake length too
   small to hold a ClientHello. It uses no per-connection state, so a real
   ClientHello after plaintext (STARTTLS) is still caught.
5. **Count and report.** It bumps the `detected` counter and reserves an
   event in the ringbuf. If the ringbuf is full, it bumps `dropped`; in
   enforce mode it builds the event in `scratch` instead, so enforcement
   never depends on room to report.
6. **Parse.** `fill_event()` fills the event and calls `walk_hello()`. That
   reads the cipher list (up to 64 entries) through `copy_list()`, then
   `walk_extensions()` looks for `supported_versions` (up to 32 extensions)
   and `read_versions()` reads it. Nothing past the bytes this segment holds
   is read. The walk records `trunc_reason` (did the record continue in a
   later segment?) and the `seen` flags (was each list read in full?).
7. **Judge, enforce mode only.** In `judge()`, if the packet's cgroup is
   inside the `--cgroup` scope, `check_policy()` gives a verdict from the
   rule in the `rules` map. A `violation`, or an `unknown` with
   `on_unknown: block`, returns `TCX_DROP`, and the ClientHello never
   reaches the server.
8. **Submit.** The event goes to userspace. The program returns `TCX_NEXT`,
   which lets other programs on the same hook run too.
9. **Userspace.** `skb_loader_poll()` hands each event to `on_event()` in
   `main.c`, which:
   - names the container from its cgroup id (`skb_container_lookup()`);
   - gets the verdict and a one-line reason (`skb_policy_explain()`);
   - prints a text line or a JSON object (`event.c`).
10. **Exit.** On Ctrl-C it drains the ringbuf and prints the counters
    (detected, delivered, dropped, too short), with a warning if detected
    is not delivered plus dropped. One summary line per container follows.

## The kernel side

`src/bpf/skbouncer.bpf.c`, one program (`skb_tc`) and its helpers.

| Function | Job |
|---|---|
| `skb_tc()` | Entry point. Calls the steps in order, and reserves and submits the event (steps 5 and 8). |
| `read_headers()` | Ethernet, IPv4 and TCP headers, the tuple, and the clamp to one segment (steps 2 and 3). |
| `is_client_hello()` | The 6-byte check, `not_a_hello()`, and how many record bytes the segment holds (step 4). |
| `not_a_hello()` | Structural checks that reject what cannot be a ClientHello. |
| `count_short()` | Counts a segment of 1 to 5 bytes that starts a record, too short to classify. |
| `fill_event()` | The event's fields, the walk, and the truncation reason (step 6). |
| `walk_hello()` | The ClientHello's header, session id, cipher list and compression, in order. |
| `copy_list()` | Copies a list of two-byte entries, at most N, from inside the segment only. Used for ciphers and versions. |
| `walk_extensions()` | Bounded walk over the extensions, looking for `supported_versions`. |
| `read_versions()` | Reads the `supported_versions` list. |
| `judge()` | Enforce mode: the verdict in scope, and drop or pass (step 7). |
| `check_policy()` | The kernel's verdict. Must agree with `skb_policy_explain()`. |

| Map | Type | Holds |
|---|---|---|
| `events` | ringbuf, 256 KiB | Events to userspace. |
| `stats` | array | `detected`, `dropped`, `short` counters. |
| `rules` | array | The compiled policy. Slot 0 is the default; each rule's ciphers are a 65,536-bit bitmap, so a check is one lookup. |
| `cgroup_rule` | hash | cgroup id → rule slot, for in-scope cgroups only. |
| `scratch` | per-CPU array | Room to build an event when the ringbuf is full. |

Settings fixed at load time (`const volatile`): `enforce`, `unknown_block`,
`scope_id`, `scope_level`.

### Constraints on the kernel code

- **Bounded everything.** The kernel's verifier rejects any loop it cannot
  prove ends and any read it cannot prove is in bounds. Hence the caps (64
  ciphers, 8 versions, 32 extensions) and `bpf_skb_load_bytes()` for the
  payload.
- **Judged in the kernel.** In enforce mode the verdict has to be reached
  before the packet leaves, so it cannot wait for userspace.
- **tcx links.** The attachment belongs to the process. If skbouncer exits
  or crashes, the kernel removes the program and nothing is left blocking.

## The userspace side

- **`main.c`.** `main()` is the whole flow in order: `parse_args()` →
  `resolve_container()` → `check_args()` → `setup()` → `run()` →
  `teardown()`. `check_args()` holds the safety rules: enforce mode needs a
  policy, a cgroup scope and a veth, and the root cgroup is refused.
  `run()` polls the ringbuf, and in enforce mode refreshes containers and
  the kernel's maps once a second. `on_event()` keeps a tally per cgroup
  id, which `summarise()` prints on exit after the counter line. With no
  arguments `main()` hands over to the menu if stdin and stdout are a
  terminal, and prints usage otherwise. `--list` and `--check` return
  before `setup()`, so neither loads the program.
- **`menu.c`.** `skb_menu_run()` prints the choices, picks a container from
  a numbered list, and describes the policy file. Each run is skbouncer
  itself, started with `execv("/proc/self/exe")` and the same options a
  person would type, so the menu adds no second code path. The menu
  ignores SIGINT while the child runs, so Ctrl-C ends the child, which
  prints its summary, and the menu carries on.
- **`loader.c`.** Wraps libbpf and the generated skeleton
  (`build/skbouncer.skel.h`). It writes the load-time settings, loads,
  attaches through tcx, and exposes one function per map operation. An
  audit instance attaches first on the hook and an enforce instance last,
  so an auditor also reports what an enforcer drops.
- **`container.c`.** Talks to dockerd over `/var/run/docker.sock` with
  libcurl (no Docker CLI). A container's cgroup id is the inode number of its
  cgroup directory, so the name map is built by listing containers and
  `stat()`ing each one's directory. Unknown ids trigger one refresh, then
  are cached as misses. `skb_container_resolve()` turns `--container NAME`
  into the host end of its veth and its cgroup path.
  `skb_container_list()` calls back once per running container with its
  veth and cgroup id, for `--list` and the menu.
- **`policy.c`.** Loads the JSON policy with jansson. `skb_policy_explain()`
  gives the verdict and the reason printed with it. `skb_policy_compile()`
  turns a rule into the kernel's `skb_krule`. `skb_policy_describe()`
  prints a policy rule by rule for `--check` and the menu. It also holds
  the cipher-name table for output.
- **`enforce.c`.** Works out the scope (the `--cgroup` directory's id and
  depth), checks the interface is a veth, and on each sync points every
  in-scope cgroup at its rule and removes the rest.
- **`event.c`.** The text columns, and the JSON object written by jansson.
  The JSON is the raw event plus container, verdict and reason; the
  evaluation reads it.

## Audit and enforce

| | Audit | Enforce |
|---|---|---|
| Verdict shown to the operator | userspace | userspace |
| Verdict that decides the packet | none | kernel (`check_policy()`) |
| On a violation | reported | ClientHello dropped, and reported |
| Scope | every ClientHello on the veth | judged only inside `--cgroup`; others pass |

The verdict rule is written twice, in `skb_policy_explain()` and in
`check_policy()`. In scope, `on_event()` compares the two verdicts and warns
if they differ.
Semantics and limits are in `policy/README.md`.

## Around the tool

| Where | What |
|---|---|
| `docs/c-deslop.md` | Review rules for keeping the C and eBPF code plain: what counts as slop here, and what only looks like it. |
| `policy/README.md` | The policy format, verdict rules, enforcement scope, limits. |
| `scripts/verify-M*.sh`, `tests/check_*.py` | One verifier per milestone. Each sets up containers, runs skbouncer, and checks the result against an independent source (the TLS server's own log, `bpftool`). `verify-M6.6.sh` reruns the chain from M3; `verify-M9.sh` adds the command line and drives the menu through a terminal (`tests/m9_menu.py`). |
| `tests/tls/Dockerfile` | The pinned OpenSSL 3.5.8 test image. |
| `eval/census/` | ClientHello sizes and split points across 24 real clients, measured from the server's side. |
| `eval/functional.sh` | Experiment 1: the verifier chain as the 14-row functional table, plus the control run and non-TLS traffic. |
| `eval/collect.sh` | Runs clients with skbouncer watching; saves events and ground truth. For parse accuracy and fragmentation coverage. |
| `eval/cost.sh` | Handshake throughput with skbouncer off, in audit and in enforce mode. |
| `eval/env.sh` | Records the environment every result depends on. |
| `eval/PLAN.md`, `eval/CONFORMANCE.md` | The evaluation plan; the proposal checked against the build. |
| `PROMPT.md`, `PROGRESS.md`, `scripts/loop.sh`, `scripts/guard.sh` | The development loop: the current task, the log of every iteration, the runner, and the guard that stops an iteration from editing its own tests. |
| `src/bpf/vmlinux.h` | Kernel type definitions, generated once and pinned. Not read by hand. |
