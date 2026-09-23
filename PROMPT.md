# Loop task: M3 — walk the ClientHello in the kernel

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Extend the tc program so each ClientHello event also carries:

- `legacy_version`
- the cipher suite list, in wire order, capped at 64 with a flag when capped
- the `supported_versions` extension (0x002b), if present

Keep `captured_len` and `trunc_reason` correct as the walk goes deeper: when
the walk needs bytes beyond what this segment carries, report what was seen
and mark it truncated. Those events are the fragmentation dataset — never
drop them.

Add `--format json`: one JSON object per event on stdout. The verifier
needs these keys, with these names:

    dport record_len captured_len trunc legacy_version
    versions ciphers ciphers_capped

`trunc` is a string: "none", "segment", "ext_limit" or "parse". `versions`
and `ciphers` are arrays of integers. Keep the existing text output as the
default.

## Done means `scripts/verify-M3.sh` passes

It attaches to a client container's veth ingress, sends six handshakes to
TLS servers in a second container, and compares your events with the
ClientHellos the servers logged. Cases include TLS 1.2 and 1.3, 83 offered
ciphers (the cap), a 1519-byte post-quantum ClientHello that spans two
segments, and plaintext that must produce nothing.

Run it yourself as often as you like; its output says exactly what is
wrong. The loop ends when it passes. Do not write a DONE line.

## Rules

- Never edit `scripts/verify-M3.sh`, `tests/`, `scripts/loop.sh` or
  `scripts/guard.sh`. They are fingerprinted; editing one stops the loop.
  If you believe the verifier is wrong, say so in `PROGRESS.md` and stop.
- Never regenerate `src/bpf/vmlinux.h`. Never run `apt`, `apt-get`,
  `apt-mark`. Never attach to the root cgroup.
- Bounds-check every read; bound every loop (`bpf_loop()` is available).
- Keep the ringbuf record small; do not bring back the 512-byte snapshot
  just to carry ciphers. Bump `SKB_EVENT_VERSION` on any layout change.
- Leave nothing running or attached when you finish; the loop checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
