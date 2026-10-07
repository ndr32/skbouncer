# Proposal against build

What the proposal (F2, 31 Aug 2026) commits to, and where the build stands,
as measured at tag `eval-2` (2026-10-06). For the write-up's implementation and
limitations sections.

Status: **met**, **differs** (done another way; explain in the report),
**not built**.

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
| Tested on Ubuntu Server 24.04, kernel 6.8 | §1.5.1 | differs | Measured on EC2 c7i.2xlarge, Ubuntu 26.04.1, kernel 7.0.0-1013-aws; developed on Ubuntu 26.04, kernel 7.0.0-31-generic. Update the platform line in the report |
| Single Docker host, IPv4, TLS 1.2/1.3, no decryption, no ECH, no GUI | §1.5.2 | met | |
| No per-container software | §1.4 | met | Nothing runs in the container. One skbouncer process per watched container; instances coexist on tcx |
| Evaluate parse accuracy, coverage under fragmentation, runtime cost | Obj 5 | met | eval/PLAN.md; results in eval/results/eval-2/criteria.md, all 21 scored criteria met |
| Measure across ClientHello sizes, post-quantum included | §1.2.2(3) | met | Experiment 4: 24 clients, 210 to 1934 bytes, six MTU and timestamp arms (C8, C9) |
| CryptoMon "is a benchmark to skBouncer" | §2.3.3 | differs | Not run side by side. Experiment 4's discussion states what first-segment fragmentation means for any per-packet observer, CryptoMon included. Reword as the closest prior work |
