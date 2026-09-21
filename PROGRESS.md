# Progress log

Append only. Each iteration starts with no memory of the last one; record
failures in as much detail as successes.

## M2 — ClientHello detection on tc egress

Status: not started.

### Baseline

- `make` builds clean; `./skbouncer` runs, loads only as root.
- M1 complete (2026-09-21). Verified on kernel 7.0.0-31-generic: the program
  loaded and the kernel assigned `id=264 name=skb_egress`. Name is not
  truncated, so it is addressable as `bpftool prog show name skb_egress`.
- `skbouncer.bpf.c` is a stub returning TC_ACT_OK. No maps, nothing attached.
- `struct skb_event` already has the M2 fields, plus `trunc_reason` for M3.

### Iterations

<!-- append below -->
