# Campaign results, eval-1.1

`results-eval-1.1.tar.xz` holds every raw result of the chapter 4 campaign,
run on 2026-10-03 on EC2 (c7i.2xlarge, ap-southeast-1, kernel
7.0.0-1013-aws) from tag `eval-1.1`. The environment is recorded in
`results/env-eval-1.1.txt` inside the archive, and again in each run's
`env.txt`.

SHA-256 `02a946ed7776b0d36f68eb1db446b32afc1f3eb87f10c8652a3a832ffacd7a27`,
18 MB compressed, 660 MB unpacked. Unpack with
`tar -xJf results-eval-1.1.tar.xz` (outside the repo).

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
