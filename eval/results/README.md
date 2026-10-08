# Campaign results

Two campaigns, each run on EC2 (c7i.2xlarge, ap-southeast-1, kernel
7.0.0-1013-aws) with the same harnesses and settings.

| Tag | Run | Archive | SHA-256 | Scored |
|---|---|---|---|---|
| `eval-1.1` | 2026-10-03 | `results-eval-1.1.tar.xz` (18 MB) | `02a946ed...7a27` | `eval-1.1/` |
| `eval-2` | 2026-10-06 | `results-eval-2.tar.xz` (17 MB) | `9edec910...8f52` | `eval-2/` |
| `eval-2.1` | 2026-10-08 | `results-eval-2.1.tar.xz` (8 KB), experiment 1 only | `5d45f60b...103a` | `eval-2.1/` |

`eval-2` is `eval-1.1` with egress removed, the de-slop review applied and the
code review's fixes. Each of their scored folders holds `criteria.md` and
`scores.json` from `eval/score.py`, and `skbouncer-<tag>.xlsx` from
`eval/workbook.py`.

`eval-2.1` is `eval-2` with the menu, `--list`, `--check` and the exit
summary. The change is userspace only, so only experiment 1 was rerun. Its
archive holds `results-eval-2.1/` with `exp1/` and a failed first run, and
`eval-2.1/criteria.md` scores C1 and C3 by hand from `exp1/results.json`.

The EC2 instance ran 18% slower in the `eval-2` campaign: 610 handshakes per
second with skbouncer off, against 747 in `eval-1.1`. Compare overheads within
a campaign, never absolute figures across the two.

Unpack an archive with `tar -xJf results-<tag>.tar.xz` (outside the repo). The
environment is in `results/env-<tag>.txt` inside it, and in each run's
`env.txt`. Both archives share this layout.

| Directory | Experiment | Harness and settings |
|---|---|---|
| `exp1/` | 1, functional table | `functional.sh`, 100 random-byte connections |
| `exp3/census/` | 3, parse accuracy | `collect.sh`, MTU 1500, 10 per client, `policy/example.json` |
| `exp3/census-mixed/` | 3, parse accuracy | the same under `exp3/policy-mixed.json` (TLS 1.2 minimum, OpenSSL's 30 default ciphers) |
| `exp3/edge/` | 3, parse accuracy | `collect.sh`, `clients-edge.txt`, 10 each |
| `exp3/fuzz/` | 3, robustness (C16) | `fuzz.sh`, 5000 mutants, seed 1 |
| `exp4/<mtu>-<on/off>/` | 4, fragmentation coverage | `collect.sh`, MTU 1500 and 1280 at 20 per client, 1460, 1400 and timestamps off at 5, `exp4/policy.json` (TLS 1.2 minimum) |
| `exp5/cost/` | 5, handshake cost | `cost.sh`, 10 rounds of 30 s, `bpf_stats` off |
| `exp5/cost-stats/` | 5, cost per call (C14) | `cost.sh`, 2 rounds of 30 s, `bpf_stats` on |
| `exp5/load/` | 5, C17 to C21 | `load.sh` at its defaults |
| `exp6/` | 6, enforcement and scenarios | `enforce.sh` at its defaults, wait cap 300 s |
| `exp7/n10/`, `exp7/n50/` | 7, attribution | `attrib.sh`, 10 and 50 containers, 5 handshakes each |

Experiment 2 is desk work. Experiment 8 is computed from `exp3/`.
