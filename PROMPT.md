# Loop task: M4 — name the container behind each event

Read `CLAUDE.md` for scope and safety rules; they override this file. Note
the MEASURED 2026-09-23 entry: the cgroup id is the container identity, not
the veth.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

In userspace, resolve each event's `cgroup_id` to the Docker container it
belongs to, using `src/user/container.{c,h}` (the interface already exists).

- Add `"container"` to the JSON output: the container name, or `null` when
  the cgroup belongs to no container. Show it in the text output too.
- Containers start after skbouncer does. A lookup miss must refresh before
  answering `null`.
- Resolve from the cgroup id, never from the interface: containers sharing a
  network namespace share one veth and one source address.

## Done means `scripts/verify-M4.sh` passes

It runs `verify-M3.sh` first, then watches container A's veth while A, and
B (started later, inside A's network namespace), make handshakes; C sits on
an unwatched veth. Each event must carry the right cgroup id and name. Run
it yourself as often as you like; the loop ends when it passes.

## Rules

- Never edit `scripts/verify-*.sh`, `tests/`, `scripts/loop.sh` or
  `scripts/guard.sh`. They are fingerprinted; editing one stops the loop.
  If you believe a verifier is wrong, say so in `PROGRESS.md` and stop.
- skbouncer runs as root and may block the event loop only briefly: cache
  lookups, and do not shell out to the `docker` CLI. Libraries stay libbpf,
  libelf, zlib and jansson.
- Never regenerate `src/bpf/vmlinux.h`. Never run `apt`, `apt-get`,
  `apt-mark`. Never attach to the root cgroup.
- Leave nothing running or attached when you finish; the loop checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
