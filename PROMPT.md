# Loop task: M6 — enforce mode

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Implement the Enforcement section of `policy/README.md`: with
`--mode enforce`, drop violating ClientHellos in the kernel, so they never
reach the server.

- Decide in the kernel. A verdict computed in userspace arrives after the
  ClientHello has left, and the verifier checks from the server's side
  that a blocked ClientHello never arrived. So userspace compiles the policy,
  with container names resolved to cgroup ids, into maps the tc program
  reads, and keeps them current.
- Honour `on_unknown` (default `"allow"`): `unknown` is blocked only when it
  is `"block"`.
- Only enforce within `--cgroup PATH` and its descendants
  (`bpf_skb_ancestor_cgroup_id()` works from tc). Other cgroups on the same
  veth get a verdict but always pass.
- Refuse to start in enforce mode without `--cgroup`, with the root cgroup,
  without `-p`, or on an interface that is not a veth.
- JSON events gain `"action"`: `"block"` or `"pass"`, which is what the
  kernel actually did. It must agree with the userspace `"verdict"`.

## Done means `scripts/verify-M6.sh` passes

It runs `verify-M5.sh` first (which runs M4 and M3), checks the four
refusals, then drives nine handshakes over one veth shared by three
containers, with enforcement scoped to one of them. The cases are:
- violations that must be blocked;
- a split post-quantum ClientHello that must pass;
- an `unknown` that passes by default, then is blocked with
  `on_unknown: block`;
- out-of-scope violations that must pass.

Run it as often as you like; the loop ends when it passes.

## Rules

- Enforce only on test-container veths. Never run enforce mode on `ens33`,
  `tailscale0` or `docker0`; the non-veth refusal is tested on `lo`.
- Never edit `scripts/verify-*.sh`, `tests/`, `policy/README.md`,
  `scripts/loop.sh` or `scripts/guard.sh`. If you believe the verifier or
  the spec is wrong, say so in `PROGRESS.md` and stop.
- Never regenerate `src/bpf/vmlinux.h`. Never run `apt`, `apt-get`,
  `apt-mark`. Never attach to the root cgroup.
- Bump `SKB_EVENT_VERSION` on any layout change.
- Leave nothing running or attached when you finish; the loop checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
