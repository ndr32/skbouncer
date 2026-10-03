# Loop task: M7.4 — load and enforcement harnesses

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

Two new harnesses for `eval/PLAN.md`: `eval/load.sh` (experiment 5, C17 to
C21) and `eval/enforce.sh` (experiment 6, C22 and C23). They save raw data
and score nothing. skbouncer is frozen at `eval-1`. `eval/cost.sh` shows
the house style for runs with pinning, rotation and `bpf_stats`;
`eval/collect.sh` for server logs and clients.

The VM has 3.3 GiB of memory and 2 CPUs. Keep runs small while iterating.

## eval/load.sh

```
eval/load.sh --out DIR [--runs R] [--seconds S] [--handshakes H] [--max-parallel P]
```

Defaults R = 5, S = 20, H = 2000, P = 8. One server and one client
container (`skb-tls-test` or `python:3-alpine`), MTU 1500. Pinning and
`bpf_stats` exactly as in `eval/cost.sh`, which you may import from or
copy but not edit. Conditions `off`, `audit` and `enforce` rotate each
round as in `cost.sh`; enforce uses `eval/cost-policy.json` unless a part
says otherwise. Every audit or enforce run records
`"skbouncer": {"counters", "events", "blocks", "passes"}` (`passes`: events
with `"action": "pass"`) and `"attached"`, sampled during the run.

1. Throughput (C17), R runs per condition. A bulk TCP transfer from client
   to server for S seconds, timed by the receiver. `throughput.jsonl`:
   `{"round", "condition", "bytes", "wall_seconds", "gbps", "attached", "skbouncer"}`.
2. Latency (C18), R runs per condition. H sequential TLS handshakes from
   one client process, each timed on its own. `latency.jsonl`:
   `{"round", "condition", "ok", "ms": [H timings], "skbouncer"}`.
3. Policy scalability (C19), enforce mode, R runs of S seconds of
   `s_time` for each of four policies: 1, 16 and 64 rules with the client
   offering and permitted its 30 ciphers, and 1 rule with the client
   offering and permitted one cipher. The client's container matches the
   last rule. `policy.jsonl`:
   `{"round", "rules", "ciphers", "connections", "wall_seconds", "cps", "skbouncer"}`.
4. Saturation (C20), audit mode, S seconds per level: 1, 2, 4 ... up to P
   parallel `s_time` clients. `saturation.jsonl`:
   `{"parallel", "connections", "wall_seconds", "cps", "counters"}`.
5. Footprint (C21), one audit run of S seconds under `s_time` load.
   `footprint.json`: `{"prog": {"bytes_xlated", "bytes_jited",
   "verified_insns"}, "maps": [{"name", "type", "bytes_memlock"}],
   "rss_kib", "cpu_seconds", "seconds"}`, from `bpftool -j` and the
   skbouncer process's `/proc` entries.
6. `run.json`: `{"runs", "seconds", "handshakes", "max_parallel", "nproc",
   "bpf_stats_enabled", "pinning"}`, and `env.txt` from `eval/env.sh`.

## eval/enforce.sh

```
eval/enforce.sh --out DIR [--clients FILE] [--wait-cap S]
```

Defaults: `eval/clients.txt`, S = 300. Server: `skb-tls-test` with every
key exchange group enabled (as in `eval/census/run.sh`), one
`openssl s_server -msg -naccept 1` per connection, logging to
`DIR/server/<port>.log`.

Enforce mode blocks only inside the `--cgroup` scope, so every client runs
in its own container on its own network, never in another container's
namespace. Start it with `sleep`, attach skbouncer with `--container` on
it, then `docker exec` the client command.

1. Policies, written to `DIR/policies/<name>.json`, each with one rule for
   the client containers: `min13` (minimum TLS 1.3), `ciphers` (the three
   TLS 1.3 suites and the ECDHE GCM suites only), `min13_block` (minimum
   TLS 1.3 with `"on_unknown": "block"`).
2. Matrix, every client in the file under every policy. First a reference
   pass with no skbouncer, then an enforce pass with
   `--mode enforce --format json -p <policy>`. Each client command runs
   under `timeout 15`: a blocked client otherwise waits for TCP to give up.
   `matrix.jsonl`: `{"label", "policy", "ref_port", "enf_port",
   "reference", "enforce_received", "events"}`. `reference` is the server's
   decode of the reference pass (`record_len`, `legacy_version`,
   `ciphers`, `versions`, as in `eval/collect.py`); `enforce_received`
   whether the enforce pass's server log shows a ClientHello; `events` the
   enforce pass's events.
3. Scenarios, each run in audit mode and then in enforce mode, with text
   output (no `--format`) saved for screenshots as
   `DIR/scenarios/<name>-audit.txt` and `<name>-enforce.txt`, and JSON as
   well. The server for these accepts TLS 1.0 and every cipher
   (`-cipher ALL@SECLEVEL=0 -min_protocol TLSv1`).
   - `legacy`: OpenSSL offering only TLS 1.0 and 1.1, policy `min13`.
   - `cbc_sha1`: OpenSSL with `-tls1_2 -cipher ECDHE-RSA-AES128-SHA`,
     policy `ciphers`.
   - `pq_unknown`: `curl_firefox147`, policy `min13_block`.
   `scenarios.jsonl`: `{"name", "audit": {"port", "events"},
   "enforce": {"port", "received", "events"}}`.
4. Wait times: each client once more under `min13` in enforce mode,
   without `timeout 15`, timed until the client exits, capped at S.
   `waits.jsonl`: `{"label", "seconds", "capped", "exit"}`.
5. `run.json`: `{"clients", "policies", "wait_cap"}`, and `env.txt`.

## Done means `scripts/verify-M7.4.sh` passes

It runs `load.sh` with 1 run of 3 seconds, 200 handshakes and up to 2
parallel clients, and `enforce.sh` with 3 clients and a 20-second cap. It
reports, without failing, whether blocks match what the servers received:
that is the measurement, about a frozen tool.

## Rules

- skbouncer is frozen: never edit `src/`, `include/`, `Makefile` or
  `policy/`. The verifier fails if they differ from `eval-1`.
- Never edit `scripts/verify-*.sh`, `tests/`, `scripts/loop.sh`,
  `scripts/guard.sh`, `eval/census/`, `eval/env.sh`, `eval/collect.*`,
  `eval/cost.*`, `eval/functional.sh`, `eval/fuzz*`, `eval/attrib*` or the
  client lists. If you believe a verifier is wrong, say so in
  `PROGRESS.md` and stop.
- Enforce mode only through `--container` on a test container made by the
  harness. Never on `ens33`, `tailscale0` or `docker0`, never the root
  cgroup.
- Name everything `skb-load-*` or `skb-enforce-*` and remove it on exit,
  on failure and Ctrl-C too.
- `sudo -n` works for `./skbouncer` and `bpftool` only.
- Never run `apt`, `apt-get`, `apt-mark`. Never regenerate `src/bpf/vmlinux.h`.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
