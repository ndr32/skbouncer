# Loop task: M2.5 — make the fragmentation signal measurable

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations.

M2 works: ClientHello detection and one ringbuf event per handshake. This
task fixes three things that would corrupt the M7 dataset if left.

## 1. Count dropped events

`bpf_ringbuf_reserve()` returning NULL currently drops the event silently.
M7 reports fragmentation *coverage*, which needs a denominator — a lost
event must not be indistinguishable from a connection that never happened.

Add a counter map for detections and reserve failures. Print both at exit.

## 2. Record how much of the record was actually present

`captured_len` and `trunc_reason` are declared and never set. The program
already knows `record_len` from the TLS header and `skb->len - pay_off`.
The difference between them is the measurement this project exists to make.

Set, in M2 terms:

- `captured_len` = bytes of the TLS record body present in this segment,
  i.e. `min(skb->len - pay_off - TLS_RECORD_HLEN, record_len)`
- `trunc_reason` = `SKB_TRUNC_SEGMENT` when `captured_len < record_len`,
  otherwise `SKB_TRUNC_NONE`

Leave `handshake_len` and `legacy_version` at 0; those need the body walk,
which is M3.

Print `captured_len` and a truncation flag in the event line.

## 3. Stop sending 512 unused bytes per event

`struct skb_event` is 560 bytes, 512 of which is a `snapshot` nothing
writes until M3. That caps the ringbuf at 468 events instead of ~5400 and
makes the drops in item 1 far more likely.

Emit only the header portion. Add `SKB_EVENT_HDR_LEN` as
`offsetof(struct skb_event, snapshot)` and emit
`SKB_EVENT_HDR_LEN + captured_len` bytes — `captured_len` is 0 here, so
header only, and M3 can grow the record without another format change.

Bump `SKB_EVENT_VERSION` to 2. Userspace must accept any record of at least
`SKB_EVENT_HDR_LEN` rather than requiring `sizeof(struct skb_event)`.

## Exit criterion

Verify each, do not assume:

1. `make` clean, no new warnings.
2. `sudo ./skbouncer -i ens33` attaches without verifier rejection.
3. A real handshake over the docker bridge produces an event whose
   `captured_len` and `trunc_reason` are consistent with `record_len`:
   `docker run --rm curlimages/curl -sI https://example.com`
   Docker bridge networking works now; do not use `--network host`.
4. A ClientHello larger than the MSS reports `SKB_TRUNC_SEGMENT`, and one
   that fits reports `SKB_TRUNC_NONE`. Show both.
5. Exit output reports detections and drops.
6. `PROGRESS.md` contains `- [x] DONE M2.5` as a top-level line.

The loop stops on that exact line. Writing it before 1–5 pass ends the run
with the work unfinished.

## Rules

- Never regenerate `src/bpf/vmlinux.h`.
- Never run `apt`, `apt-get`, `apt-mark`.
- Never attach to the root cgroup.
- Bounds-check against `data_end` before every read; bound every loop.
- Do not parse the ClientHello body. That is M3.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier output
verbatim when it rejects. Then `git commit`.
