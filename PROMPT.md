# Loop task: M5 — policy and audit mode

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Implement `policy/README.md`: load a JSON policy with `-p FILE` and give
every event a verdict in audit mode. Nothing is blocked yet; that is M6.

- JSON output gains `"verdict"`: `"allow"`, `"violation"` or `"unknown"`,
  present whenever a policy is loaded. Show it in text output too.
- A malformed policy or an unknown cipher name makes skbouncer exit non-zero
  before loading BPF, with an error naming the file position or the bad name.
- `src/user/policy.{c,h}` exist as stubs with jansson already wired in. Change
  the interface if it needs the container name; nothing outside `src/` is
  bound to it.

The hard part is `unknown`. A truncated record is not automatically
`unknown`: if the cipher list and versions were read in full before the cut,
the verdict is certain. Userspace cannot currently tell a fully read list
from one cut by the segment boundary, so the kernel will need to say so.

## Done means `scripts/verify-M5.sh` passes

It runs `verify-M4.sh` first (which runs M3). Then it checks two bad policy
files are rejected, and nine handshakes from five containers sharing one
veth get the verdicts `policy/README.md` prescribes — including a 1833-byte
post-quantum ClientHello that splits but must still be `allow`, and a
64-of-83-ciphers case that must be `unknown`. Run it as often as you like;
the loop ends when it passes.

## Rules

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
