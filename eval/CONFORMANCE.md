# Proposal against build

What the proposal (F2, 31 Aug 2026) commits to, and where the build stands,
as of beta2 + refactor (2026-09-30). For the write-up's implementation and
limitations sections.

Status: **met**, **differs** (done another way; explain in the report),
**not built**, **pending** (M7).

| Proposal says | Where | Status | Evidence, or what to write |
|---|---|---|---|
| Read cipher suites and versions from the ClientHello | Obj 2, §1.5.2 | met | `walk_hello()`; verify-M3 |
| Ignore GREASE; read the real version from supported_versions | §2.2.2 | met | `skb_is_grease()`; policy/README.md, Verdicts |
| Read the ServerHello too | §2.2.2 | not built | Future work. `census/serverhello.py`: the negotiated cipher and version end by byte 87 in every ServerHello measured (OpenSSL server) |
| Name the container from its cgroup id, matched against running containers | §1.2.2(1), §2.2.3 | met | `bpf_skb_cgroup_id()` at veth ingress; Docker API in container.c; verify-M4 |
| Tell apart two containers whose traffic looks the same | §2.2.3 | met | verify-M4, shared network namespace case |
| JSON policy of permitted ciphers and versions | Obj 3, §1.5.1 | met | policy/README.md |
| Userspace checks each handshake against it | Obj 3 | met | policy.c; the kernel mirrors it in enforce mode |
| Audit and enforce modes | §1.2.2(2) | met | verify-M5, verify-M6 |
| The hook that observes can also refuse | §1.2.2(2) | met | One tcx program parses and returns `TCX_DROP` |
| Refuse violating IPv4 connections; stopped as attempted | §1.5.2, §1.2.2(2) | differs | Drops the ClientHello, so no session forms; the client retransmits until TCP gives up (about 15 min). policy/README.md, Limits |
| Enforcement hook such as cgroup/connect4 | §1.5.2 | differs | connect4 runs before any ClientHello exists, so it has nothing to judge. tcx at the veth instead |
| Control-group hooks as a core feature | §2.1.1 | differs | Scoped by `bpf_skb_ancestor_cgroup_id()` inside the tc program, not a cgroup attach type |
| Build with CO-RE | §1.5.1, §2.1.1 | differs | The program reads only `__sk_buff` and packet bytes, both stable ABI, so it needs no CO-RE relocations to run on another kernel |
| Tested on Ubuntu Server 24.04, kernel 6.8 | §1.5.1 | pending | Developed on 26.04 / 7.0; measured on EC2. Report the EC2 release and kernel |
| Single Docker host, IPv4, TLS 1.2/1.3, no decryption, no ECH, no GUI | §1.5.2 | met | |
| No per-container software | §1.4 | met | Nothing runs in the container. One skbouncer process per watched container; instances coexist on tcx |
| Evaluate parse accuracy, coverage under fragmentation, runtime cost | Obj 5 | pending | eval/PLAN.md |
| Measure across ClientHello sizes, post-quantum included | §1.2.2(3) | pending | Modelled in eval/census; M7 measures it with skbouncer |
| CryptoMon "is a benchmark to skBouncer" | §2.3.3 | not built | Decide: compare against it in M7, or reword as the closest prior work |

## Measurement readiness

What each experiment in PLAN.md needs, and whether skbouncer emits it.

- **Coverage.** `record_len`, `captured_len` (record bytes in the first
  segment), `trunc`, `ciphers_seen`, `versions_seen` and `verdict` are in
  every JSON event. Joined to ground truth by port, one port per case, as in
  the census. Ready.
- **Accuracy.** Full cipher list (up to 64, with `ciphers_capped`) and
  versions, in wire order. Ready.
- **Cost.**
  - `bpf_stats` gives one run time and count per program, not per packet
    type. Kernel cost on ClientHellos versus ordinary packets needs two
    runs (handshakes only, bulk non-TLS only), not one split. PLAN.md to
    change.
  - Detected/dropped counters are printed on exit, as text on stderr. The
    harness parses that line; no change needed.
  - Every instance's program is named `skb_tc`, so cost runs use one
    instance, found by `bpftool prog show name skb_tc`.
- **EC2.** The VPC default MTU is 9001; Docker networks set their own, so
  coverage is unaffected, but record it. Use a non-burstable instance for
  the cost runs. The build needs clang, libbpf-dev, libjansson-dev and
  bpftool, whose package name differs between Ubuntu releases.
