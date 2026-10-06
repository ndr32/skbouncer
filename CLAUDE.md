# skBouncer

Final Year Project (BSc Hons Computing Science, Coventry Univ. / PSB Academy).
Author: Lee Junyeong. Supervisor: Dr. Matthew Yok Wool Teow.
Proposal (final, F2) lives on the author's Mac at ~/Desktop/PSB_CU/ICSP/.

## What it is

A CLI tool in C/eBPF that:
1. Reads TLS ClientHellos (cleartext only) from inside the Linux kernel. The proposal (S2.2.2)
   also says ServerHello: not built, future work (eval/CONFORMANCE.md)
2. Attributes each connection to its originating **container** via cgroup v2 id
3. Enforces an operator-defined JSON policy of permitted cipher suites and protocol versions

Two modes: **audit** (log violations) and **enforce** (block).

## The three problems it addresses

1. Kernel-level TLS observers (CryptoMon) report per-host, not per-container
2. Observers detect but cannot block; blocking needs a second tool
3. **Nobody has measured how much of a ClientHello is lost to TCP fragmentation** - this is
   the actual research contribution. Grows worse as post-quantum key exchange inflates
   ClientHello size.

## Environment (verified, do not assume otherwise)

- Ubuntu 26.04 LTS, kernel 7.0.0-31-generic, x86_64 (native, not emulated)
- Kernel is `apt-mark hold`-ed. DO NOT let it upgrade: fragmentation results are
  kernel-sensitive and must stay comparable across the whole measurement campaign.
- clang 21.1.8 | libbpf-dev 1.6.3 | bpftool 7.7.0 | Docker | BTF present at /sys/kernel/btf/vmlinux
- `src/vmlinux.h` already generated (167k lines)
- This VM is for development. M7 measures on EC2 (decided 2026-09-30): `ubuntu@skb-ec2`
  over Tailscale, c7i.2xlarge, ap-southeast-1, Ubuntu 26.04.1, kernel 7.0.0-1013-aws (held,
  same toolchain versions as here). Full record: eval/env/ec2.txt, from `eval/env.sh`.
  Code goes over by rsync; images by digest (skb-tls-test by docker save/load). An EBS
  snapshot replaces the VMware one before enforce runs. Stop the instance when idle.
  Proposal S1.5.1 ("Ubuntu 24.04, kernel 6.8") gets updated to this at write-up.
- VM suspend breaks container networking: open-vm-tools' suspend hook flushes every NIC's
  addresses, and on resume only ens33 is reconfigured, so docker0 loses 172.17.0.1.
  Fix after the fact: `sudo systemctl restart docker`. Prevent it:
  `sudo vmware-toolbox-cmd script suspend disable` (and `resume`). Also costs chrony sync.

## Critical design decisions

**The enforcement hook problem.** `cgroup/connect4` fires at connect() time, BEFORE any TLS
handshake exists - there you only know (cgroup, dst IP, dst port). The ClientHello appears
later on data egress. So "observe and block at the same hook" does not work. Approach:
- Built: detect the violating ClientHello at tcx (veth ingress) and drop it
- Not built: cache violating (cgroup, dst) so connect4 denies future attempts. Planned
  2026-09-30 to explain in the write-up instead (eval/CONFORMANCE.md)

**cgroup helpers.** `bpf_get_current_cgroup_id()` needs process context, which tc programs do
NOT have. From tc use `bpf_skb_cgroup_id()`; from socket hooks use `bpf_sk_cgroup_id()`.

**MEASURED 2026-09-21 - cgroup attribution does not work on the physical interface for
bridged containers.** At `ens33` egress a container's packet has already been forwarded and
SNATed, so it has no local socket: `bpf_skb_cgroup_id()` returns 0 and the tuple shows the
host address, not `172.17.0.2`. Host-local sockets are fine (measured cgroup_id 18387,
matching the shell's cgroup inode). The veth and docker0 see nothing at egress, because
container-outbound traffic is INGRESS on the host side of the veth.

So container identity comes from the attachment point: attach BPF_TC_INGRESS to a
specific container's veth, where one veth is one container and the tuple is still pre-NAT.
`--network host` hides this, because there the socket is local.

**CORRECTION, MEASURED 2026-09-21 (M2.6).** At *veth ingress* `bpf_skb_cgroup_id()` does
work: the skb has only just left the container's socket via `veth_xmit` and has not been
orphaned, so `skb->sk` still resolves. Two concurrent containers reported 32773 and 33295,
each an exact match for `stat -c %i` of its own `docker-<id>.scope`. The helper returning 0
is specific to the *forwarded* skb at `ens33`, not to containers in general.

**MEASURED 2026-09-23 - the cgroup id is the container identity, not the veth.** One veth is
one network namespace. With `--network container:A`, B's traffic leaves through A's veth
with A's source IP but carries B's cgroup id. So attach at the veth to get the pre-NAT
tuple, and name the container from the cgroup id. A veth/cgroup disagreement is expected
for sidecars, not a bug.

**Verifier discipline.** Bounds-check against data_end before EVERY read. Bound all loops
(`bpf_loop()` available). Cap cipher-suite list at 64 entries.

**SAFETY: never attach enforcement to the root cgroup.** It will block this VM's own SSH and
lock the author out. Scope to a specific container cgroup path
(/sys/fs/cgroup/system.slice/docker-<id>.scope) and make that a REQUIRED CLI arg with no
default. `--container NAME` counts as naming it: it resolves to that container's own
scope, the narrowest possible (decided 2026-09-24, M6.5 review). Take a VMware snapshot before every enforce-mode experiment.
Enforce mode also refuses any interface that is not a veth (policy/README.md), so the
host's own traffic is never in the path.

## Scope (from the proposal - do not silently expand)

IN: single host, IPv4, TLS 1.2 + 1.3, cleartext handshake parsing only, JSON policy,
audit + enforce, evaluation of parse accuracy / fragmentation coverage / runtime cost.

OUT: decryption, IPv6 (connect4 is v4-only), Kubernetes / multi-host, Encrypted ClientHello, GUI.

## Milestones

- M1 - trivial eBPF program builds, loads, appears in `bpftool prog list`
- M2 - tc egress program detects TLS ClientHello (content type 0x16, handshake type 0x01),
       emits {cgroup_id, tuple, len} to a ringbuf. NO PARSING YET.
- M3 - in-kernel ClientHello walk: cipher suites + supported_versions (ext 0x002b),
       PLUS a truncation flag from day one (this is the fragmentation dataset)
- M4 - cgroup id -> Docker container name in userspace
- M5 - JSON policy format + userspace policy check + audit mode
       (format and verdict semantics: policy/README.md)
- M6 - enforce mode
- M6.5 - CLI usability. Before the questionnaire shows its output: `--container NAME`
       resolves the veth (and the enforce cgroup); ingress by default for containers;
       a reason with each verdict; versions as 1.3/1.2 and cipher names; wall-clock time
       in text output; drop dev-only startup lines; `--version`. Not `--all-containers`.
- M6.6 - hardening from the whole-codebase review: tcx links (no orphaned filters,
       instances coexist), structural ClientHello checks, scoped cgroup_rule, kernel
       verdict only in scope. Tagged beta2.
- M7 - evaluation harness (parse accuracy, fragmentation coverage, runtime cost)
       Was FROZEN at tag `eval-1` (2026-10-01) for the campaign: no changes to
       src/, include/, Makefile, policy/, eval/functional.sh, eval/collect.*,
       eval/cost.*, eval/clients*.txt or eval/cost-policy.json. The campaign ran tag
       `eval-1.1` (same tool source as eval-1, plus fuzz/attrib/load/enforce
       harnesses) on 2026-10-03; results in eval/results/.
- M8 - refactor round toward `eval-2` (started 2026-10-05), from the review against
       docs/c-deslop.md. Egress support removed (`--direction`, `attach_dir`, the event's
       `direction` field; SKB_EVENT_VERSION 8). When the round ends: tag eval-2, rerun the
       whole campaign, regenerate eval/results with eval/score.py and eval/workbook.py.
       The M7 verifiers check the tool against the latest eval-* tag; before
       tagging, run them with FREEZE_REF=HEAD.  <- CURRENT

Build each milestone so it loads and runs before starting the next.

## Evaluation notes

For the PQC arm: Ubuntu's stock OpenSSL will not produce large enough ClientHellos.
Use OpenSSL 3.5+ (ML-KEM, hybrid X25519MLKEM768) in a container to generate genuinely
oversized handshakes rather than synthesising them with padding.

Record exact kernel + OpenSSL versions with every result set, plus `ethtool -k` offload
state (TSO/GSO/GRO) of the veth under test: veth forwards GSO super-packets intact, so
segment boundaries depend on it. Do not suspend the VM during a capture campaign.

Measured baseline (OpenSSL 3.5.8, stock client): default X25519MLKEM768 ClientHello is
1519 bytes and spans two segments; the same client with X25519 only is 285 bytes.

## Development loop

`MILESTONE=M3 scripts/loop.sh` runs PROMPT.md with fresh context per iteration on branch
`loop/<M>`. It ends when `scripts/verify-<M>.sh` passes. The verifier, `tests/`, and the
loop scripts are fingerprinted by `scripts/guard.sh`; an iteration that edits them aborts
the run. After a deliberate change to them: `scripts/guard.sh init`.

## Access

Developed over SSH/mosh from a MacBook via Tailscale (host `skbouncer`, user `admin1`).
Work inside tmux session `fyp` so sessions survive disconnects.
