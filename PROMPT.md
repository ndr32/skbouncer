# Loop task: M2.6 — observe container egress at the veth

Read `CLAUDE.md` for scope and safety rules; they override this file. Note
the MEASURED note about cgroup attribution — it is the reason for this task.
Read `PROGRESS.md` — you have no memory of earlier iterations.

## Why

Measured on 2026-09-21: at `ens33` egress a bridged container's packet is
already forwarded and SNATed, so `bpf_skb_cgroup_id()` returns 0 and the
tuple shows the host address. The veth and docker0 see nothing at egress,
because container-outbound traffic is INGRESS on the host side of the veth.

The loader only ever attaches `BPF_TC_EGRESS`, so today the tool can observe
a container handshake or attribute it, never both.

## Goal

Support attaching to `BPF_TC_INGRESS` as well, so the program can watch a
container's veth and see its outbound handshakes pre-NAT.

1. Add a direction to `skb_loader_opts` and a CLI flag, e.g.
   `--direction egress|ingress` defaulting to `egress`.
2. `attach_tc()` and `detach_tc()` must use the chosen attach point. Keep
   the existing `made_hook` behaviour: clsact is shared, so do not destroy a
   hook this process did not create.
3. Record which direction produced an event. Container identity comes from
   the attachment point, not from `cgroup_id`, so the output must make the
   interface visible.

Do not parse the ClientHello body. That is still M3.

## Exit criterion

Verify each, do not assume. Use a real bridged container — not
`--network host`, which hides the whole problem.

1. `make` clean, no new warnings.
2. `sudo ./skbouncer -i <veth> --direction ingress` attaches without
   verifier rejection, and `bpftool net show dev <veth>` shows it on the
   ingress hook.
3. A handshake from inside that container produces exactly one event, whose
   source address is the container's `172.17.x.x` — proving it is pre-NAT.
4. `record_len`, `captured_len` and `trunc_reason` are still correct on this
   path. State whether truncation appears here and why.
5. Egress on `ens33` still behaves as before; this must not regress.
6. Report what `cgroup_id` actually is on the veth ingress path. Do not
   assume it is useful — measure it and write down the value.
7. `PROGRESS.md` contains `- [x] DONE M2.6` as a top-level line.

Finding the veth for a container:

    IDX=$(docker exec <cid> cat /sys/class/net/eth0/iflink)
    ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}'

## Rules

- Never regenerate `src/bpf/vmlinux.h`.
- Never run `apt`, `apt-get`, `apt-mark`.
- Never attach to the root cgroup.
- Bounds-check against `data_end` before every read; bound every loop.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier output
verbatim when it rejects. Then `git commit`.
