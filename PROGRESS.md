# Progress log

Append only. Each iteration starts with no memory of the last one; record
failures in as much detail as successes.

## M2 — ClientHello detection on tc egress

Status: not started.

### Baseline

- `make` builds clean; `./skbouncer` runs, loads only as root.
- M1 complete (2026-09-21), kernel 7.0.0-31-generic:

      264: sched_cls  name skb_egress  tag 691ef55febf78432  gpl
           loaded_at 2026-09-21T08:57:04+0000  uid 0
           xlated 16B  jited 20B  memlock 4096B  btf_id 179

  sched_cls confirms SEC("tc") resolves to the type clsact egress needs.
  Name is not truncated, so `bpftool prog show name skb_egress` works.
- `skbouncer.bpf.c` is a stub returning TC_ACT_OK. No maps, nothing attached.
- `struct skb_event` already has the M2 fields, plus `trunc_reason` for M3.

### Iterations

<!-- append below -->
