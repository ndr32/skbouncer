# How the code fits together

skbouncer is one eBPF program in the kernel and one C program in userspace.
The kernel program sees every packet a container sends, finds TLS
ClientHellos, reads their cipher suites and versions, and in enforce mode
drops the ones the policy forbids. The userspace program loads it, names the
container behind each ClientHello, gives the verdict and its reason, and
prints one line per ClientHello.

About 2,700 lines of C: 620 in the kernel side and its shared header, 2,100
in userspace. Everything else in the repo is tests, evaluation or
development tooling (see [Around the tool](#around-the-tool)).

## At a glance

```
 container                     host
 ─────────                     ────────────────────────────────────────────────────────
 client ──► eth0 ═══ veth ═══► [tcx ingress: skb_tc]  ──► bridge ──► server / internet
                                 │  parse the ClientHello
                                 │  judge it (enforce mode) ──► drop if it breaks policy
                                 ▼
                           ringbuf "events"
                                 │
                                 ▼
                          skbouncer (userspace)
                           name the container (dockerd), verdict + reason, print
```

A container's outgoing traffic arrives on the host end of its veth, so the
program attaches there, on the ingress hook. At that point the source
address is still the container's own (before NAT), and the packet still
belongs to the sending socket, so `bpf_skb_cgroup_id()` returns the
container's cgroup. That cgroup id is what names the container.

## Reading order

| File | Lines | What it does |
|---|---:|---|
| `include/skbouncer.h` | 141 | The event and rule formats the kernel and userspace share. Start here. |
| `src/bpf/skbouncer.bpf.c` | 479 | The kernel program: detect, measure, parse, judge, drop. |
| `src/user/main.c` | 464 | The CLI: options, safety checks, setup, the event loop, exit report. |
| `src/user/loader.c` | 202 | Loads the program, attaches it, reads the ringbuf and the maps. |
| `src/user/container.c` | 380 | Docker: cgroup id → container name, and `--container` → veth and cgroup. |
| `src/user/policy.c` | 486 | The JSON policy: loading, the verdict and its reason, compiling rules for the kernel. |
| `src/user/enforce.c` | 170 | Enforce mode: the cgroup scope, the veth check, keeping the kernel's maps current. |
| `src/user/event.c` | 229 | Output: the text line and the JSON object. |

Each `.c` in `src/user/` has a short `.h` beside it listing what it exports.

## One ClientHello, start to finish

1. A client in the container connects and sends its ClientHello. On the
   host end of the veth the packet is ingress, and `skb_tc()` runs.
2. **Headers.** It checks Ethernet → IPv4 → TCP, and finds where the TCP
   payload starts. Anything else passes untouched.
3. **How much of the record is here.** tc runs before the kernel cuts large
   sends into segments, so one packet here can be several segments on the
   wire. `avail` is clamped to `skb->gso_size`, the size of one segment.
   This is the fragmentation measurement: without the clamp no ClientHello
   would ever look split.
4. **Is it a ClientHello?** The first 6 bytes must be `0x16` (handshake),
   `0x03` (TLS), and handshake type `0x01`. `not_a_hello()` then rejects
   byte patterns that only look like one, such as a handshake length too
   small to hold a ClientHello. It uses no per-connection state, so a real
   ClientHello after plaintext (STARTTLS) is still caught.
5. **Count and report.** It bumps the `detected` counter and reserves an
   event in the ringbuf. If the ringbuf is full, it bumps `dropped`; in
   enforce mode it builds the event in `scratch` instead, so enforcement
   never depends on room to report.
6. **Parse.** `walk_hello()` reads the cipher list (up to 64 entries) and
   the `supported_versions` extension (up to 32 extensions walked), never
   past the bytes this segment holds. It records `trunc_reason` (did the
   record continue in a later segment?) and the `seen` flags (was each list
   read in full?).
7. **Judge, enforce mode only.** If the packet's cgroup is inside the
   `--cgroup` scope, `check_policy()` gives a verdict from the rule in the
   `rules` map. A `violation`, or an `unknown` with `on_unknown: block`,
   returns `TCX_DROP`: the ClientHello never reaches the server.
8. **Submit.** The event goes to userspace. The program returns `TCX_NEXT`,
   which lets other programs on the same hook run too.
9. **Userspace.** `skb_loader_poll()` hands each event to `on_event()` in
   `main.c`, which:
   - names the container from its cgroup id (`skb_container_lookup()`);
   - gets the verdict and a one-line reason (`skb_policy_explain()`);
   - prints a text line or a JSON object (`event.c`).
10. **Exit.** On Ctrl-C it drains the ringbuf and prints the counters:
    detected, delivered, dropped, too short. If they don't add up, it says so.

## The kernel side

`src/bpf/skbouncer.bpf.c`, one program (`skb_tc`) and its helpers.

| Function | Job |
|---|---|
| `skb_tc()` | Entry point: steps 2–8 above. |
| `not_a_hello()` | Structural checks that reject what cannot be a ClientHello. |
| `walk_hello()` | Bounded walk over the ClientHello: ciphers, then extensions. |
| `check_policy()` | The kernel's verdict. Must agree with `skb_policy_explain()`. |
| `count_short()` | Counts a 1–5 byte segment that starts a record: too short to classify. |

| Map | Type | Holds |
|---|---|---|
| `events` | ringbuf, 256 KiB | Events to userspace. |
| `stats` | array | `detected`, `dropped`, `short` counters. |
| `rules` | array | The compiled policy. Slot 0 is the default; each rule's ciphers are a 65,536-bit bitmap, so a check is one lookup. |
| `cgroup_rule` | hash | cgroup id → rule slot, for in-scope cgroups only. |
| `scratch` | per-CPU array | Room to build an event when the ringbuf is full. |

Settings fixed at load time (`const volatile`): `attach_dir`, `enforce`,
`unknown_block`, `scope_id`, `scope_level`.

Why it is written the way it is:

- **Bounded everything.** The kernel's verifier rejects any loop it cannot
  prove ends and any read it cannot prove is in bounds. Hence the caps (64
  ciphers, 8 versions, 32 extensions) and `bpf_skb_load_bytes()` for the
  payload.
- **Judged in the kernel.** In enforce mode the verdict has to be reached
  before the packet leaves, so it cannot wait for userspace.
- **tcx links.** The attachment belongs to the process: if skbouncer exits
  or crashes, the kernel removes the program, and nothing is left blocking.

## The userspace side

- **`main.c`.** `main()` is the whole flow in order: `parse_args()` →
  `resolve_container()` → `check_args()` → `setup()` → `run()` →
  `teardown()`. `check_args()` holds the safety rules: enforce mode needs a
  policy, a cgroup scope and a veth, and the root cgroup is refused.
  `run()` polls the ringbuf, and in enforce mode refreshes containers and
  the kernel's maps once a second.
- **`loader.c`.** Wraps libbpf and the generated skeleton
  (`build/skbouncer.skel.h`). It writes the load-time settings, loads,
  attaches through tcx, and gives the rest of the code small functions for
  the maps. An audit instance attaches first on the hook and an enforce
  instance last, so an auditor also reports what an enforcer drops.
- **`container.c`.** Talks to dockerd over `/var/run/docker.sock` with
  libcurl (no Docker CLI). A container's cgroup id is the inode number of its
  cgroup directory, so the name map is built by listing containers and
  `stat()`ing each one's directory. Unknown ids trigger one refresh, then
  are cached as misses. `skb_container_resolve()` turns `--container NAME`
  into the host end of its veth and its cgroup path.
- **`policy.c`.** Loads the JSON policy with jansson. `skb_policy_explain()`
  gives the verdict and the reason printed with it. `skb_policy_compile()`
  turns a rule into the kernel's `skb_krule`. It also holds the cipher-name
  table for output.
- **`enforce.c`.** Works out the scope (the `--cgroup` directory's id and
  depth), checks the interface is a veth, and on each sync points every
  in-scope cgroup at its rule and removes the rest.
- **`event.c`.** The text columns, and the JSON object, written by jansson.
  The JSON is the raw event plus container, verdict and reason; the
  evaluation reads it.

## Audit and enforce

| | Audit | Enforce |
|---|---|---|
| Verdict shown to the user | userspace | userspace |
| Verdict that decides the packet | none | kernel (`check_policy()`) |
| On a violation | reported | ClientHello dropped, and reported |
| Scope | every ClientHello on the veth | judged only inside `--cgroup`; others pass |

Both sides implement the same rule, once for userspace and once for
the kernel. In scope, `on_event()` compares the two and warns if they differ.
Semantics and limits are in `policy/README.md`.

## Around the tool

| Where | What |
|---|---|
| `policy/README.md` | The policy format, verdict rules, enforcement scope, limits. |
| `scripts/verify-M*.sh`, `tests/check_*.py` | One verifier per milestone. Each sets up containers, runs skbouncer, and checks the result against an independent source (the TLS server's own log, `bpftool`). `verify-M6.6.sh` reruns the chain from M3. |
| `tests/tls/Dockerfile` | The pinned OpenSSL 3.5.8 test image. |
| `eval/census/` | ClientHello sizes and split points across 24 real clients, measured from the server's side. |
| `eval/functional.sh` | Experiment 1: the verifier chain as the 14-row functional table, plus the control run and non-TLS traffic. |
| `eval/collect.sh` | Runs clients with skbouncer watching; saves events and ground truth. For parse accuracy and fragmentation coverage. |
| `eval/cost.sh` | Handshake throughput with skbouncer off, in audit and in enforce mode. |
| `eval/env.sh` | Records the environment every result depends on. |
| `eval/PLAN.md`, `eval/CONFORMANCE.md` | The evaluation plan; the proposal checked against the build. |
| `PROMPT.md`, `PROGRESS.md`, `scripts/loop.sh`, `scripts/guard.sh` | The development loop: the current task, the log of every iteration, the runner, and the guard that stops an iteration from editing its own tests. |
| `src/bpf/vmlinux.h` | Kernel type definitions, generated once and pinned. Not read by hand. |
