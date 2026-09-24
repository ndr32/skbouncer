# M7 evaluation plan

Draft for review. Nothing is measured until the method below is agreed, so
the method cannot be shaped by the numbers.

The proposal asks for three things: parse accuracy, fragmentation coverage,
and runtime cost. The census (`eval/census/`) already predicts the second;
M7 measures it with skbouncer itself.

## Before any run

- **Freeze the tool.** Tag the commit measured (`eval-1`); every result set
  records `skbouncer --version`. No code changes during a campaign.
- **Freeze the host.** Kernel 7.0.0-31-generic (held), no VM suspend during a
  run, no standing VMware snapshot, chrony synchronised.
- **Record with every result set** (`env.json`, written by the harness):
  skbouncer version, kernel, client and server OpenSSL versions, Docker
  version, network MTU, TCP timestamps on/off, `ethtool -k` offload state of
  the veth under test, `uptime`, chrony status, CPU and memory.

## Experiment 1 — fragmentation coverage (the research contribution)

**Question.** Across clients and real path MTUs, how much of the ClientHello
does a first-segment observer see, and do the fields a policy needs
survive?

**Setup.** One Docker network per MTU: 1500, 1492, 1460, 1420, 1400, 1280.
Client and server containers on the same network, skbouncer on the client's
veth. Each MTU run twice: TCP timestamps on (Linux, macOS) and off
(Windows), set per container with `--sysctl`.

**Clients.** The census set: OpenSSL 3.5.8 across key exchange groups
(classical, hybrid, pure ML-KEM), curl, Python, Node, Go, and browsers via
curl-impersonate. 30 handshakes per client per condition; Chrome permutes
extension order, so Chrome gets 100.

**Measured per handshake.** Record length, bytes in the first segment,
truncation reason, whether ciphers and versions were seen in full, and the
verdict under a reference policy with both `min_version` and `ciphers`.

**Reported.**
- Visible fraction of the ClientHello, per client × MTU (median, IQR).
- Share of connections whose versions were seen in full (the field a
  version policy needs), with 95% Wilson intervals.
- **Enforceability**: share of connections a version policy can decide
  (`allow` or `violation`, not `unknown`).
- The census model (first segment = MTU − 52 with timestamps, − 40
  without) against the measurement, per MTU.

**Hypotheses, stated in advance.**
- H1. Every post-quantum ClientHello exceeds one segment at every MTU
  tested; no classical one does.
- H2. Whether `supported_versions` survives depends on the implementation's
  extension order, not on MTU: OpenSSL-based clients and Go keep it,
  Firefox and Safari lose it, Chrome loses it in most connections.
- H3. Cipher lists survive in every case measured.

**Check first.** At one MTU, confirm the veth's `gso_size` follows the
network MTU. If it does not, the MTU arm measures nothing and is redesigned.

## Experiment 2 — parse accuracy

**Question.** When skbouncer reports a field, is it right?

**Ground truth.** The server's own decode of the bytes it received
(`openssl s_server -msg`), parsed independently, as in the verifiers.

**Clients.** Experiment 1's set at MTU 1500, plus the edge cases the
verifiers use (TLS 1.2 only, 83 ciphers, a long ALPN list). For
external validity, a subset from **real headless Chromium and Firefox** in
containers, to test curl-impersonate's fidelity rather than assume it.

**Reported.**
- Detection: ClientHellos seen ÷ ClientHellos sent; duplicates.
- Per field (record length, legacy version, ciphers in order, cap flag,
  versions): exact-match rate among fields flagged seen in full.
- **False-certainty rate**: fields flagged seen in full that are wrong.
  The claim is that this is zero; one counterexample matters more than the
  rate.
- Verdict agreement with a reference verdict computed from ground truth
  and the same policy.
- False positives: events on non-TLS traffic (HTTP, SSH, random binary,
  the verifier's mid-connection junk), per 10,000 connections.

## Experiment 3 — runtime cost

**Question.** What does skbouncer cost the traffic it watches?

**Conditions.** Not attached (baseline), audit, enforce; interleaved
(A-B-C-A-B-C...) across runs so VM drift does not favour one condition.

**Measured.**
- **Handshake latency**: TLS handshake time, client side, 1,000 handshakes
  per condition. Median, p95, p99, and the difference from baseline with a
  bootstrap 95% interval.
- **Per-packet kernel cost**: the BPF program's run time per invocation
  (`bpf_stats`), on ClientHello packets and on ordinary packets separately.
- **Throughput**: bulk non-TLS transfer between containers (iperf3), since
  the program runs on every packet, not only handshakes.
- **Userspace**: CPU and resident memory over a run, including the
  once-a-second container refresh in enforce mode.
- **Saturation**: the handshake rate at which events are first dropped
  (ringbuf full), using the detected/delivered/dropped counters.

Absolute numbers on a 2-CPU VM over a virtual network are small and
host-specific; the result is the overhead relative to baseline.

## Threats to validity (for the write-up)

- A VM on a virtual path: segmentation is modelled by `gso_size`, not done
  by a NIC. Experiment 1's check guards the MTU arm; the rest is stated.
- curl-impersonate reproduces browser fingerprints; the real-browser subset
  measures how closely.
- Single host, IPv4, Docker's default bridge, one kernel.
- The observer is first-segment by design; the result describes that class
  of tool (including per-packet observers like CryptoMon), not TLS monitoring
  with stream reassembly.
- Enforcement is drop-based: a blocked connection keeps retransmitting
  (`policy/README.md`). Experiment 3 counts connections, not events.

## Layout and order

```
eval/
  PLAN.md            this file
  census/            done
  coverage/          experiment 1: run.sh, analyze.py, results/<run>/
  accuracy/          experiment 2
  cost/              experiment 3
```

Order: 1, then 2, then 3. Experiment 1 carries the contribution and reuses
the census clients; 2 reuses 1's data at MTU 1500; 3 is independent.

Harnesses are written and checked like the verifiers, but campaigns are run
by hand, not by the development loop: a loop that retries until numbers
look right is how results get fabricated.

## Needs from the author

- Approve or change: the MTU list, sample sizes, hypotheses, and whether
  the real-browser subset is worth the setup.
- Once per session, for experiment 3: `sudo sysctl -w kernel.bpf_stats_enabled=1`
  (or add it to the sudoers rule).
- Delete the `pre-M6` VMware snapshot before experiment 3.
