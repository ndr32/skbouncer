# Loop task: M2 — detect TLS ClientHello on tc egress

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations.

## Goal

Detect a TLS ClientHello on tc egress and emit one ringbuf event per
detection. Detection: TCP payload starts with a TLS record header, content
type `0x16`, first handshake body byte `0x01`.

Do not parse the ClientHello body — no ciphers, no extensions. That is M3.
Emit only `cgroup_id`, the 4-tuple, `record_len`, `ktime_ns`.

## Exit criterion

Verify each, do not assume:

1. `make` succeeds, no new warnings.
2. `sudo ./skbouncer -i lo` attaches without verifier rejection.
3. One event per ClientHello from a real handshake:
   `docker run --rm curlimages/curl -sI https://example.com`
4. Non-TLS traffic emits nothing.
5. `PROGRESS.md` contains `- [x] DONE` as a top-level line.

The loop stops on the DONE line. Writing it before 1–4 pass ends the run
with the work unfinished.

## Rules

- Never regenerate `src/bpf/vmlinux.h`.
- Never run `apt`, `apt-get`, `apt-mark`.
- Never attach to the root cgroup.
- Bounds-check against `data_end` before every read; bound every loop.
- Extend `struct skb_event` rather than adding a parallel struct; bump
  `SKB_EVENT_VERSION` on layout change.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier output
verbatim when it rejects. Then `git commit`.
