# Chapter 4 evaluation plan

Replaces the 24 Sep draft. Follows the supervisor's software testing guidance
of 15 Sep 2026 in shape, adapted to a kernel tool with a command-line interface.

Eight experiments test 25 criteria. Experiments 1 and 3 to 8 are measured
on EC2. Experiment 2 is desk work on the code. The user survey is reported
separately and is not an evaluation point.
Every experiment is written up in the same six parts. The percentages are the
share of each write-up and come from the supervisor's guidance.

| Part | Share | Answers |
|---|---:|---|
| Objective | 5% | What the experiment tests |
| Method | 10% | How it was done |
| Results | 10% | The table, chart or output |
| Analysis | 30% | What the results show |
| Discussion | 40% | Why, in terms of the design and the code |
| Conclusion | 5% | Three to five points |

Discussion carries the most weight. Each experiment therefore collects a small
data set and spends the effort on explaining it.

---

## Evaluation criteria

Targets are fixed before any run. A criterion without a target is reported as
a measurement and discussed without a pass mark.

| ID | Criterion | Measure | Target | Exp |
|---|---|---|---|---|
| C1 | Functional correctness | Rows of the functional table that pass | 14 of 14 | 1 |
| C2 | Detection rate | ClientHellos reported ÷ ClientHellos sent | 100% | 3 |
| C3 | False positives | Events on HTTP, SSH and random-byte traffic | 0 | 1 |
| C4 | Cipher list accuracy | Exact matches among cipher lists flagged complete | 100% | 3 |
| C5 | Version accuracy | Exact matches among version lists flagged complete | 100% | 3 |
| C6 | False certainty | Fields flagged complete that differ from the server's decode | 0 | 3 |
| C7 | Container attribution | Events carrying the correct container name | 100% | 3 |
| C8 | Truncation reporting | ClientHellos flagged split, against the server's record length + 5 > MSS | 100% of split flagged, none that fit | 4 |
| C9 | Fragmentation coverage | Share of connections with a decidable version verdict, per client and MTU | None, tested against H1 to H3 | 4 |
| C10 | Verdict agreement | Among `allow` and `violation` verdicts, those equal to a reference verdict from the server's decode | 100% | 3 |
| C11 | Enforcement accuracy | Violating ClientHellos blocked, compliant ClientHellos passed | 100% blocked, 0 compliant blocked | 1 |
| C12 | Safe failure | Fail open on `unknown`, refuse the root cgroup, detach on exit | All hold | 1 |
| C13 | Handshake overhead | Change in connections per second against skbouncer off | Under 5% | 5 |
| C14 | Kernel cost per packet | Mean run time per program call | None, reported | 5 |
| C15 | Event loss | Events dropped with the ring buffer full during experiment 5 | 0 | 5 |
| C16 | Robustness to malformed input | Crashes, and fields flagged complete that differ from an independent decode of the mutated bytes | 0 and 0 | 3 |
| C17 | Data-path overhead | Change in bulk TCP throughput against skbouncer off | Under 5% | 5 |
| C18 | Tail latency | Change in p99 handshake latency against skbouncer off | Under 10% | 5 |
| C19 | Policy scalability | Change in handshake rate from 1 rule to 64 rules, and from 1 permitted cipher to every cipher offered | Under 5% | 5 |
| C20 | Saturation | Handshake rate at which the first event is dropped | None, reported | 5 |
| C21 | Resource footprint | Program size, verified instructions, map memory, userspace memory and CPU | None, reported | 5 |
| C22 | Enforcement at scale | Census ClientHellos under three policies blocked exactly when the reference verdict requires it | 100% | 6 |
| C23 | Scenario validation | Scripted scenarios flagged in audit mode and blocked in enforce mode | All | 6 |
| C24 | Attribution under concurrency | Events naming the correct container with 10 and with 50 containers at once | 100%, none unnamed | 7 |
| C25 | Grade agreement | Security grade from skbouncer's output equal to the grade from the server's decode, among ClientHellos read in full | 100% | 8 |

The targets in C13, C17, C18 and C19 are the author's choice and are set
now so the results cannot move them.

---

## Before any run

- The measured code is tagged: `eval-1.1` ran on 3 Oct, and `eval-2`, the final
  code, on 6 Oct. No code changes after a tag. A fix means a new tag and a
  rerun of every experiment it could affect.
- Every experiment runs on the EC2 instance: c7i.2xlarge, ap-southeast-1,
  Ubuntu 26.04.1, kernel 7.0.0-1013-aws (held). Harnesses are built and
  checked on the development VM, which has the same toolchain and identical
  container images, then run on EC2 from the tag.
- Every result set carries `env.txt` from `eval/env.sh`: the skbouncer
  version and commit, kernel, toolchain and library versions, image ids,
  OpenSSL version, MTUs, the `ethtool -k` offloads of the veth under test,
  and clock sync.

---

## Experiment 1. Functional test (black box)

**Objective.** Check that each function in the proposal works as specified.

**Criteria.** C1, C3, C11, C12.

**Method.** Run `scripts/verify-M6.6.sh`, which reruns the M3 to M6.5
verifiers. Map each verifier case to one row of the table below. Row 14,
the control with skbouncer stopped, is not in the verifiers; experiment 1's
harness adds it.

| No | Function | Input | Expected |
|---|---|---|---|
| 1 | Detect a ClientHello | TLS 1.3 handshake from a container | One event |
| 2 | Ignore other traffic | HTTP, SSH, random bytes mid-connection | No event |
| 3 | Read the cipher suites | Forced cipher list | Same list, GREASE removed |
| 4 | Read the versions | TLS 1.2 only, TLS 1.3 | Versions from `supported_versions` |
| 5 | Flag a split ClientHello | Post-quantum ClientHello | Bytes seen below record length |
| 6 | Name the container | Two containers at once; two sharing one network namespace | Correct name on each event, told apart by cgroup id |
| 7 | Audit a violation | TLS 1.2 client, policy minimum 1.3 | `violation`, handshake completes |
| 8 | Enforce a violation | Same, `--mode enforce` | Server never receives the ClientHello |
| 9 | Fail open | Versions cut off, `on_unknown` allow | `unknown`, handshake completes |
| 10 | Block unknown on request | Same, `on_unknown` block | Server never receives the ClientHello |
| 11 | Refuse the root cgroup | `--cgroup /sys/fs/cgroup` | Refused with a message |
| 12 | Refuse a non-veth in enforce mode | `-i lo --mode enforce` | Refused with a message |
| 13 | Detach on exit | Exit on SIGINT; die on SIGPIPE, SIGHUP, and an unhandled SIGUSR2 standing in for a crash | No program left attached |
| 14 | Control | Row 8 with skbouncer stopped | Handshake completes |

**Results.** The table with a Result column and PASS or FAIL.

**Discussion.** Link each row to the part of the design that makes it pass.
Row 8 against row 7 shows the kernel dropping the ClientHello. Row 14 shows
the block in row 8 came from skbouncer. Row 13 covers the process owning the
tcx link, and the SIGUSR2 case shows it holds when skbouncer cannot clean
up.

---

## Experiment 2. Code tracing (white box)

**Objective.** Show how the kernel side reaches a verdict.

**Criteria.** None scored. Experiment 2 explains the code behind C4, C8 and C11.

**Method.** One system level flowchart and three code segments. Each code
segment gets an algorithm level flowchart, a line by line explanation and a
screenshot of its output.

- System level flowchart. Packet reaches the veth and `skb_tc()` runs.
  `read_headers()` reads the headers and clamps to one segment,
  `is_client_hello()` and `not_a_hello()` filter, `fill_event()` and
  `walk_hello()` read, `judge()` and `check_policy()` decide, the packet is
  dropped or passed, the event goes to the ring buffer, and userspace names
  the container and prints the line.
- Segment A. `not_a_hello()`. A decision chain of three structural checks
  that rejects bytes resembling a TLS record.
- Segment B. `walk_hello()` with `copy_list()`, `walk_extensions()` and
  `read_versions()`. The bounded walk over the cipher list (capped at 64)
  and the extensions (capped at 32), the cut at the segment's end, and the
  truncation reason. GREASE values are skipped later, in `check_policy()`.
- Segment C. The `gso_size` clamp in `read_headers()`. Without it every split
  ClientHello reports as complete.

Code is quoted from `v1.0.0`; the kernel side is unchanged since the `eval-2`
campaign.

**Results.** The flowcharts, the code, and the output of each segment. For
segment C, the before and after lines from the development log (a 1557-byte record
reported 1557 bytes seen and `none`, then 1455 bytes seen and `segment`).

**Discussion.** The verifier limits that shaped segment B (bounded loops,
`data_end` checks). The measured reason for segment C. Why the cipher list is
capped at 64.

---

## Experiment 3. Parse accuracy

**Objective.** Measure whether the fields skbouncer reports match the bytes
the client sent.

**Criteria.** C2, C4, C5, C6, C7, C10, C16.

**Method.** `eval/collect.sh` with the census clients at MTU 1500, 10
connections each, plus two edge cases (TLS 1.2 only, an 83-cipher list).
Ground truth is the server's own decode of the bytes it received
(`openssl s_server -msg`, decoded by `eval/collect.py`). Compare record length, legacy version, cipher list
in order and versions. Compare the container name on each event with the
name of the container that ran the client. Compute a reference verdict from
the server's decode under the example policy and compare it with
skbouncer's verdict.

Robustness (C16) uses `eval/fuzz.sh`. Real ClientHellos from the census are
mutated 5,000 times with byte changes, cuts and wrong length fields. Each
mutant is sent as the first segment of its own connection while skbouncer
runs in audit mode. An independent Python decoder parses each mutant as it
was sent. Every field skbouncer flags complete must match that decode, the
skbouncer process must still run at the end, and the program must still be
attached.

**Results.** One table with one row per criterion (C2, C4, C5, C6, C7,
C10, C16), the count, the total and the target.

`unknown` verdicts are not scored here: they are counted for C9. A decided
verdict that disagrees with the reference can only come from a field flagged
complete that is wrong, so it also counts against C6.

**Discussion.** A field flagged complete but wrong would let enforce mode
block or pass a connection on false data. The expected count is zero. Any case above zero is
explained from the code. An `unknown` where the reference says `violation`
is the fail-open design, not an error.

**Limitation.** `eval/collect.py` is a second parser. Disagreements are checked by
hand against the hex bytes.

---

## Experiment 4. Fragmentation coverage (the research contribution)

**Objective.** Measure how much of each ClientHello the first TCP segment
carries, and whether a version policy can still be judged.

**Criteria.** C8, C9.

**Method.** `eval/collect.sh` with the census clients, skbouncer on the
client's veth. MTU 1500 and MTU 1280 with TCP timestamps on, 20 connections
per client. Four further arms with 5 connections per client: MTU 1460 and
1400 with timestamps on, and MTU 1500 and 1280 with timestamps off. Ground truth for
"split" does not come from skbouncer: the record length from the server's
decode, plus the 5-byte record header, against the MSS the collector
measures with `getsockopt(TCP_MAXSEG)` in the client's namespace. Checked
while building the harness: at MTU 1500, 1280 and with TCP timestamps off, a
split ClientHello showed exactly MSS − 5 record bytes, so the network MTU
sets the segment skbouncer sees.

**Hypotheses, stated before the run.**
- H1. Every post-quantum ClientHello is split at every MTU tested. No
  classical one is split.
- H2. Whether `supported_versions` is in the first segment depends on the
  client's extension order and not on the MTU.
- H3. The cipher list is always in the first segment.

**Results.** One table per arm (record length, bytes seen, versions
complete). One bar chart of the share of connections with a decidable
verdict, per client.

**Discussion.** Compare the measurement with the census model. Explain H2
from the extension order of each client. State what this means for any
per-packet observer, CryptoMon included. Add the ServerHello result from
the census (`eval/census/serverhello.py`): the negotiated cipher and version
end within the first 87 bytes of every ServerHello measured, so a ServerHello
reader would recover the version where the offer is cut. One server
implementation (OpenSSL); future work.

---

## Experiment 5. Runtime cost

**Objective.** Measure what running skbouncer costs handshakes and ordinary
traffic, and how much of the host it uses.

**Criteria.** C13 to C15, C17 to C21.

**Method.** `eval/cost.sh`: `openssl s_time -new -time 30` against the
server container. Three conditions (off, audit, enforce), 10 rounds, the
order rotated each round. Server, client and skbouncer each on their own
physical core. The policy lists every cipher `s_time` offers, so enforce
mode runs the full check and blocks nothing. The throughput rounds run with
`bpf_stats` off, since timing every call slows the program; C14 comes from a
separate short pass with `kernel.bpf_stats_enabled=1`. Read the
dropped-event counter that skbouncer prints on exit after each audit and
enforce run.

`eval/load.sh` adds the rest, under the same pinning and rotation.
- C17. iperf3 bulk TCP throughput between two containers, off, audit and
  enforce, 5 runs of 20 seconds each.
- C18. 2,000 sequential handshakes per condition, each timed by the client.
  p50 and p99 per condition.
- C19. Handshake rate in enforce mode with 1, 16 and 64 rules, the client's
  container matched by the last rule, and with 1 permitted cipher against
  every cipher the client offers. 5 runs of 20 seconds each.
- C20. Parallel `s_time` clients, doubled each step until an event is
  dropped or the client CPUs are saturated.
- C21. `bpftool prog show` (translated and JIT size, verified
  instructions), `bpftool map show` (memory per map), and the skbouncer
  process's resident memory and CPU time over a 30-second audit run.

**Results.** Median connections per second per condition and the change
from off. Mean nanoseconds per program call. Dropped events per run.
Throughput, p50 and p99 latency per condition. A line chart of handshake
rate against rule count. The saturation step. The footprint table.

**Limitation.** One EC2 instance, client and server on the same host. The
percentage change is the claim, and the absolute figures apply to this
machine only. Each handshake costs over a millisecond of CPU and the program
well under a microsecond per packet, so C13 is expected to pass by a wide
margin; the discussion says so rather than presenting it as close. C14 is a
mean over every packet the client sends (about six per connection), not
over ClientHellos alone.

---

## Experiment 6. Enforcement at scale and scenarios

**Objective.** Check that enforce mode blocks exactly what the policy
forbids across real clients, and show it stopping concrete cases.

**Criteria.** C22, C23.

**Method.** `eval/enforce.sh`. The census clients run against three
policies: a TLS 1.3 minimum, a list of permitted cipher suites, and the
TLS 1.3 minimum with `on_unknown` set to block. A reference verdict comes
from the server's decode of each ClientHello. Blocked means the server
never received the ClientHello. Three scripted scenarios follow, each
in audit mode and then in enforce mode.
- A legacy client that offers only TLS 1.0 and 1.1.
- A client that offers a CBC cipher suite with SHA-1, outside the permitted
  list.
- A post-quantum browser ClientHello cut before `supported_versions`, under
  `on_unknown` block.

For each blocked client, the time until the client reports failure, capped
at 300 seconds.

**Results.** A table of clients by policy with blocked or passed against
the reference. One screenshot per scenario in each mode. The time each
blocked client waits.

**Discussion.** Blocking drops the ClientHello and leaves the connection
retransmitting (policy/README.md, Limits). The wait times show what an
administrator sees on the client side.

---

## Experiment 7. Attribution under concurrency

**Objective.** Check that every event names the right container when many
containers make handshakes at the same time.

**Criteria.** C24.

**Method.** `eval/attrib.sh`. 10 and then 50 containers, each making 5
handshakes at once. Half of the containers share network namespaces in
groups of five, so several containers leave through one veth. Each event's
container name is compared with the container that made the connection.

**Results.** Correct, wrong and unnamed events at each size.

**Discussion.** The cgroup id names the container. The veth only names the
network namespace, which the shared groups make visible.

---

## Experiment 8. Security grading

**Objective.** Show what an administrator learns about each container's TLS
security from skbouncer alone, using the grading scale of Durumeric et al.
(NDSS 2017).

**Criteria.** C25.

**Method.** Analysis of the data from experiment 3, with no new run. Each
ClientHello gets a grade from its offered cipher suites and versions. F
when it offers an export or DES cipher suite. C when it offers RC4 or its
best version is SSL 3.0. B when it offers none of Chrome's strong cipher
suites or its best version is TLS 1.1. A otherwise. The grade is computed
twice, from skbouncer's events and from the server's decode, and the two
are compared where skbouncer read both lists in full.

**Results.** Grades per client from both sources. The agreement count.
The capped 83-cipher client, graded from a partial list.

**Discussion.** A partial cipher list can hide a weak cipher suite, so the
grade is reported as certain only when the list was read in full. This
matches the `unknown` verdict.

---

## Chapter conclusion

One section after experiment 8. The criteria table from this plan with a
Result column and met or not met in each row, followed by the overall
conclusion drawn from the eight individual conclusions.

---

## Schedule (final, Tue 6 Oct)

| Date | Work |
|---|---|
| Wed 30 Sep to Thu 1 Oct | Harnesses for experiments 1, 3, 4 and 5. Tag `eval-1`. |
| Sat 3 Oct | Plan revised to eight experiments. Harnesses `fuzz.sh`, `load.sh`, `enforce.sh`, `attrib.sh`. First campaign on EC2, tag `eval-1.1`. |
| Mon 5 to Tue 6 Oct | De-slop review, egress removed, refactor, code review. Second campaign, tag `eval-2`. |
| Wed 7 to Sun 11 Oct | Write chapter 4. Experiment 2 is desk work. |
| Mon 12 to Sun 18 Oct | Revision of the whole report. |
| Mon 19 Oct | Submit. |

---

## Rules for the harnesses

The development loop writes and checks the harnesses. A campaign runs by
hand. A loop that retries until the numbers pass would fabricate results.
