# Loop task: M6.5 — make the CLI usable

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

An operator should be able to watch a container by name and read the output
without knowing skbouncer's internals. The contract is in the header of
`scripts/verify-M6.5.sh`; in short:

- `--container NAME`: find the container's veth, watch ingress, and in
  enforce mode supply the `--cgroup` scope from the container. Refuse an
  unknown name, naming it.
- `-i <veth>` with no `--direction` watches ingress; other interfaces keep
  egress.
- JSON events gain `"reason"` (why this verdict) and `"time"` (ISO 8601
  wall clock). In JSON mode stdout carries only JSON lines; anything else goes
  to stderr.
- Text output: wall-clock `HH:MM:SS`, versions as `1.3`/`1.2` (never
  `0304`), cipher names, the same reason as JSON, no `bpftool` hint. Keep
  lines readable.
- `--version`, unprivileged. `--help` documents `--container`.

JSON fields from earlier milestones must not change: the earlier verifiers
parse them. Measurement fields stay as they are.

Out of scope: `--all-containers`, and the four M6 limits listed in
`PROGRESS.md` — those go to the codebase review.

## Done means `scripts/verify-M6.5.sh` passes

It runs `verify-M6.sh` first, then drives skbouncer by container name in
text, JSON, and enforce mode, and checks the output an operator sees. Run it
as often as you like; the loop ends when it passes.

## Rules

- Never edit `scripts/verify-*.sh`, `tests/`, `policy/README.md`,
  `scripts/loop.sh` or `scripts/guard.sh`. If you believe the verifier is
  wrong, say so in `PROGRESS.md` and stop.
- Enforce only on test-container veths. Never run enforce mode on `ens33`,
  `tailscale0` or `docker0`.
- Never regenerate `src/bpf/vmlinux.h`. Never run `apt`, `apt-get`,
  `apt-mark`. Never attach to the root cgroup.
- Leave nothing running or attached when you finish; the loop checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
