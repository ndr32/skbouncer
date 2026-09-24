# Loop task: M6.6 — hardening from the codebase review

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Fix what the whole-codebase review found. Each item is checked by
`scripts/verify-M6.6.sh` or a strengthened earlier verifier.

1. **No orphaned filters.** Today a killed skbouncer (SIGPIPE, SIGHUP, a
   crash) leaves `skb_tc` attached and still blocking. Attach through tcx
   (`bpf_program__attach_tcx`, kernel 7.0 has it): the link goes away with
   the process. Also exit cleanly on SIGPIPE and SIGHUP.
2. **Instances coexist.** An audit and an enforce instance on one veth must
   both work, and either exiting must leave the other attached. Under tcx a
   "pass" must not end the chain for the other programs on the hook.
3. **Structural checks, not flow state.** A mid-connection segment that only
   looks like a ClientHello header must not be judged. But a real ClientHello
   later in a connection (STARTTLS) must still be enforced, so do not limit
   detection to a connection's first payload. Reject what a real ClientHello
   cannot be (inner lengths that disagree), and keep a ClientHello split
   across records working.
4. **The kernel cgroup_rule map holds only in-scope cgroups**, and drops ones
   that no longer exist. Keep the map named `cgroup_rule`; the verifier reads
   it.
5. **The dockerd refresh runs on a clock**, about once a second, not every
   few `poll()` returns. Not checked by a verifier; say in `PROGRESS.md` how
   you confirmed it.
6. **The kernel's verdict is visible.** In enforce mode, JSON events carry
   `"kernel_verdict"`, which must equal `"verdict"`. `verify-M6.sh` now checks
   this, and exercises a rule with no cipher list and both fixed defaults.
7. **Count what is missed.** Add a counter for a first segment that starts a
   TLS record but is too short to classify, and print it with the others at
   exit. `policy/README.md` documents the limit.

`verify-M3.sh` also got stricter: it checks `ciphers_seen` and
`versions_seen` against where those fields end in the real ClientHello.

## Done means `scripts/verify-M6.6.sh` passes

It runs `verify-M6.5.sh` first (M6.5 down to M3, including the stronger M6
and M3). Run it as often as you like; the loop ends when it passes.

## Rules

- Never edit `scripts/verify-*.sh`, `tests/`, `policy/README.md`,
  `scripts/loop.sh` or `scripts/guard.sh`. If you believe a verifier is
  wrong, say so in `PROGRESS.md` and stop.
- Enforce only on test-container veths. Never run enforce mode on `ens33`,
  `tailscale0` or `docker0`.
- Never regenerate `src/bpf/vmlinux.h`. Never run `apt`, `apt-get`,
  `apt-mark`. Never attach to the root cgroup.
- Bump `SKB_EVENT_VERSION` on any layout change.
- Leave nothing running or attached when you finish; the loop checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
