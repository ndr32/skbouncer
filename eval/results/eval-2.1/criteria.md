# Criteria results, eval-2.1

From `eval/results/results-eval-2.1.tar.xz`, experiment 1 only, run on EC2
on 2026-10-08 (kernel 7.0.0-1013-aws, OpenSSL 3.5.8, skbouncer eval-2.1 at
ebc9add). eval-2.1 changes only userspace since eval-2 (the menu, `--list`,
`--check` and the exit summary), so experiments 2 to 8 stand as measured at
eval-2.

| ID | Criterion | Result | Target | Status |
|---|---|---|---|---|
| C1 | Functional correctness | 14 of 14 rows pass | 14 of 14 | met |
| C3 | False positives | 0 events on 101 non-TLS connections (409621 bytes) | 0 | met |

`exp1/m9.txt` is `scripts/verify-M9.sh` on the same host: the command line
and the menu driven through a terminal, after the M3 to M6.6 chain. It
passes with 0 failures.

The first run (`exp1-run1/`) failed row 2 with 0 connections received at
the sink and 0 events. The instance had been up for one minute, and
`functional.sh` starts the Python sink with `docker run -d` and sends at
once, with no wait for the sink to listen. The rerun, with the same code
and image, received all 101 connections. Both runs are in the archive.
