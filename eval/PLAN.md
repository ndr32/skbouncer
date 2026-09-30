# Chapter 4 evaluation plan

Replaces the 24 Sep draft. Follows the supervisor's software testing guidance
of 15 Sep 2026 in shape, adapted to a kernel tool with a command-line interface.

Six experiments test 16 criteria. Experiments 1 to 5 are objective testing
and experiment 6 is subjective testing.
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
| C8 | Truncation reporting | Split ClientHellos flagged as split | 100% | 4 |
| C9 | Fragmentation coverage | Share of connections with a decidable version verdict, per client and MTU | None, tested against H1 to H3 | 4 |
| C10 | Verdict agreement | skbouncer's verdict equal to a reference verdict from the server's decode | 100% | 3 |
| C11 | Enforcement accuracy | Violating ClientHellos blocked, compliant ClientHellos passed | 100% blocked, 0 compliant blocked | 1 |
| C12 | Safe failure | Fail open on `unknown`, refuse the root cgroup, detach on exit | All hold | 1 |
| C13 | Handshake overhead | Change in connections per second against skbouncer off | Under 5% | 5 |
| C14 | Kernel cost per packet | Mean run time per program call | None, reported | 5 |
| C15 | Event loss | Events dropped with the ring buffer full during experiment 5 | 0 | 5 |
| C16 | Operator opinion | Median survey score on the measurable questions | 4 of 5 or above | 6 |

The 5% target in C13 and the median of 4 in C16 are the author's choice
and are set now so the results cannot move them.

---

## Before any run

- Tag the measured commit `eval-1`. No code changes after the tag.
- Kernel 7.0.0-31-generic (held). No VM suspend during a run.
- Save `env.json` with every result set. It records the skbouncer version,
  the kernel, the client and server OpenSSL versions, the Docker version, the
  network MTU and the `ethtool -k` offload state of the veth under test.

---

## Experiment 1. Functional test (black box)

**Objective.** Check that each function in the proposal works as specified.

**Criteria.** C1, C3, C11, C12.

**Method.** Run `scripts/verify-M6.6.sh`, which reruns the M3 to M6.5
verifiers. Map each verifier case to one row of the table below. Add one
control row with skbouncer stopped.

| No | Function | Input | Expected |
|---|---|---|---|
| 1 | Detect a ClientHello | TLS 1.3 handshake from a container | One event |
| 2 | Ignore other traffic | HTTP, SSH, random bytes mid-connection | No event |
| 3 | Read the cipher suites | Forced cipher list | Same list, GREASE removed |
| 4 | Read the versions | TLS 1.2 only, TLS 1.3 | Versions from `supported_versions` |
| 5 | Flag a split ClientHello | Post-quantum ClientHello | Bytes seen below record length |
| 6 | Name the container | Two containers at once | Correct name on each event |
| 7 | Audit a violation | TLS 1.2 client, policy minimum 1.3 | `violation`, handshake completes |
| 8 | Enforce a violation | Same, `--mode enforce` | Server never receives the ClientHello |
| 9 | Fail open | Versions cut off, `on_unknown` allow | `unknown`, handshake completes |
| 10 | Block unknown on request | Same, `on_unknown` block | Server never receives the ClientHello |
| 11 | Refuse the root cgroup | `--cgroup /sys/fs/cgroup` | Refused with a message |
| 12 | Refuse a non-veth in enforce mode | `-i ens33 --mode enforce` | Refused with a message |
| 13 | Detach on exit | Kill with SIGINT and SIGPIPE | No program left attached |
| 14 | Control | Row 8 with skbouncer stopped | Handshake completes |

**Results.** The table with a Result column and PASS or FAIL.

**Discussion.** Link each row to the part of the design that makes it pass.
Row 8 against row 7 shows the kernel dropping the ClientHello. Row 14 shows
the block in row 8 came from skbouncer. Row 13 covers the process owning the
tcx link.

---

## Experiment 2. Code tracing (white box)

**Objective.** Show how the kernel side reaches a verdict.

**Criteria.** None scored. Experiment 2 explains the code behind C4, C8 and C11.

**Method.** One system level flowchart and three code segments. Each code
segment gets an algorithm level flowchart, a line by line explanation and a
screenshot of its output.

- System level flowchart. Packet reaches the veth, `skb_tc()` runs,
  `not_a_hello()` filters, `walk_hello()` reads, `check_policy()` judges,
  the packet is dropped or passed, the event goes to the ring buffer, and
  userspace names the container and prints the line.
- Segment A. `not_a_hello()`. A decision chain of three structural checks
  that rejects bytes resembling a TLS record.
- Segment B. `walk_hello()`. The bounded walk over the cipher list (capped at
  64) and the extensions, the GREASE skip, and the truncation reason.
- Segment C. The `gso_size` clamp in `skb_tc()`. Without it every split
  ClientHello reports as complete.

**Results.** The flowcharts, the code, and the output of each segment. For
segment C, the before and after lines from PROGRESS.md (a 1557-byte record
reported 1557 bytes seen and `none`, then 1455 bytes seen and `segment`).

**Discussion.** The verifier limits that shaped segment B (bounded loops,
`data_end` checks). The measured reason for segment C. Why the cipher list is
capped at 64.

---

## Experiment 3. Parse accuracy

**Objective.** Measure whether the fields skbouncer reports match the bytes
the client sent.

**Criteria.** C2, C4, C5, C6, C7, C10.

**Method.** The census clients at MTU 1500, 10 connections each, plus two
edge cases (TLS 1.2 only, an 83-cipher list). Ground truth is the server's
own decode of the bytes it received (`openssl s_server -msg`, parsed by
`eval/census/parse.py`). Compare record length, legacy version, cipher list
in order and versions. Compare the container name on each event with the
name of the container that ran the client. Compute a reference verdict from
the server's decode under the example policy and compare it with
skbouncer's verdict.

**Results.** One table with one row per criterion (C2, C4, C5, C6, C7,
C10), the count, the total and the target.

**Discussion.** A field flagged complete but wrong would let enforce mode
block or pass a connection on false data. The expected count is zero. Any case above zero is
explained from the code.

**Limitation.** `parse.py` is a second parser. Disagreements are checked by
hand against the hex bytes.

---

## Experiment 4. Fragmentation coverage (the research contribution)

**Objective.** Measure how much of each ClientHello the first TCP segment
carries, and whether a version policy can still be judged.

**Criteria.** C8, C9.

**Method.** The census clients at MTU 1500 and MTU 1280, 20 connections
each, skbouncer on the client's veth. First check that the veth's
`gso_size` follows the network MTU. If it does not, drop the 1280 arm and
state why.

**Hypotheses, stated before the run.**
- H1. Every post-quantum ClientHello is split at both MTUs. No classical one
  is split.
- H2. Whether `supported_versions` is in the first segment depends on the
  client's extension order and not on the MTU.
- H3. The cipher list is always in the first segment.

**Results.** One table per MTU (record length, bytes seen, versions
complete). One bar chart of the share of connections with a decidable
verdict, per client.

**Discussion.** Compare the measurement with the census model. Explain H2
from the extension order of each client. State what this means for any
per-packet observer, CryptoMon included.

---

## Experiment 5. Runtime cost

**Objective.** Measure the handshake cost of running skbouncer.

**Criteria.** C13, C14, C15.

**Method.** `openssl s_time -new -time 30` against the server container.
Three conditions (off, audit, enforce), alternating, 10 runs each. With
`kernel.bpf_stats_enabled=1`, also read the program's run time per call from
`bpftool prog show`. Read the dropped-event counter that skbouncer prints on
exit after each audit and enforce run.

**Results.** Median connections per second per condition and the change
from off. Mean nanoseconds per program call. Dropped events per run.

**Limitation.** One 2-CPU VM. The percentage change is the claim, and the
absolute figures apply to this machine only.

---

## Experiment 6. User survey (subjective)

**Objective.** Measure how possible operators rate the purpose and the
functions of skbouncer.

**Criteria.** C16.

**Method.** 20 to 30 respondents with an IT background. Respondents cannot
run a kernel tool, so the survey opens with a two minute screen recording of
skbouncer in audit and enforce mode. Ten questions from the survey pool,
covering the functions and the purpose, with one open feedback question. No
questions on the interface. Likert scale for the measurable questions.

**Results.** One chart per measurable question. The open answers grouped by
theme.

**Conclusion.** Three to five points drawn from the survey.

---

## Chapter conclusion

One section after experiment 6. The criteria table from this plan with a
Result column and met or not met in each row, followed by the overall
conclusion drawn from the six individual conclusions.

---

## Schedule (today is Wed 30 Sep)

| Date | Work |
|---|---|
| Wed 30 Sep to Thu 1 Oct | Harnesses for experiments 3, 4 and 5. Tag `eval-1`. Record the screen recording. Build the survey. |
| Fri 2 Oct | Survey goes out. |
| Fri 2 to Sun 4 Oct | Run experiments 1, 3, 4 and 5. |
| Mon 5 to Sun 11 Oct | Write chapter 4. Experiment 2 is desk work. Survey closes Sun 11 Oct. |
| Mon 12 to Sun 18 Oct | Survey charts, revision of the whole report. |
| Mon 19 Oct | Submit. |

If time runs short, drop the 1280 arm of experiment 4 and the `bpf_stats`
reading in experiment 5.

---

## Rules for the harnesses

The development loop writes and checks the harnesses. A campaign runs by
hand. A loop that retries until the numbers pass would fabricate results.
