# Loop task: M7.2 — runtime cost runner

Read `CLAUDE.md` for scope and safety rules; they override this file.
Read `PROGRESS.md` — you have no memory of earlier iterations. The loop
appends the verifier's verdict there after every iteration.

## Goal

`eval/cost.sh` measures TLS handshake throughput with skbouncer off, in
audit mode and in enforce mode, and saves raw data. It scores nothing.
skbouncer itself is frozen. `eval/collect.sh` (M7.1) shows the house style.

```
eval/cost.sh --out DIR [--rounds R] [--seconds S] [--policy FILE]
```

Defaults: R = 10, S = 30, policy `eval/cost-policy.json`, which you write:
it must permit the `s_time` client, so nothing is ever blocked.

## What it does

1. Everything it creates is named `skb-cost-*` and is removed when it exits,
   on failure and Ctrl-C too.
2. A Docker network, MTU 1500. A server container (`skb-tls-test`) running
   one long-lived `openssl s_server`. A client container (`skb-tls-test`)
   that runs `openssl s_time -connect <server> -new -time S` once per run.
3. Runs, in rounds. Round r runs the three conditions starting r - 1 places
   along: `off, audit, enforce`, then `audit, enforce, off`, then
   `enforce, off, audit`, and so on.
   - `off`: nothing loaded.
   - `audit`: `skbouncer --container <client> --format json -p POLICY`.
   - `enforce`: the same with `--mode enforce`.
   skbouncer is attached before `s_time` starts, and stopped with SIGINT
   after it ends.
4. Wall time: `s_time` reports whole seconds only, which is too coarse.
   Time each run yourself to 10 ms or better, around `s_time` itself (the
   container's `/proc/uptime` has 10 ms resolution; busybox `date` has no
   `%N`). `cps` is connections ÷ wall seconds.
5. `bpf_stats`: if `kernel.bpf_stats_enabled` is 1, read the program's
   `run_cnt` and `run_time_ns` from `bpftool -j prog show` just before
   stopping skbouncer. Only one skbouncer runs during a run, so exactly one
   program is named `skb_tc`. If it is 0, record null. Never try to switch
   it on: `sudo` here covers `./skbouncer` and `bpftool` only.
6. CPU pinning, when the host has 6 or more CPUs: server, client and
   skbouncer each on their own CPUs (`--cpuset-cpus`; `taskset` before
   `sudo -n ./skbouncer`, which the child inherits). With fewer, no pinning.
7. `DIR/env.txt`, the output of `eval/env.sh`.
8. `DIR/run.json`:
   `{"rounds", "seconds", "policy", "nproc", "bpf_stats_enabled", "pinning"}`.
   `policy` is the policy file's path; `pinning` is null or
   `{"server", "client", "skbouncer"}`, each a cpuset string such as `"2-3"`.
9. `DIR/runs.jsonl`, one object per run in the order run:
   `{"round", "condition", "connections", "wall_seconds", "cps", "attached", "skbouncer"}`.
   - `connections`: from `s_time`'s `N connections in ...s;` line.
   - `attached`: how many `skb_tc` programs are on the client's veth,
     sampled while `s_time` runs.
   - `skbouncer`: null for `off`, else
     `{"counters": {"detected", "delivered", "dropped", "short"}, "events", "blocks", "bpf"}`.
     `counters` from skbouncer's exit line, `events` the number of JSON
     events, `blocks` how many have `"action": "block"`, `bpf` null or
     `{"run_cnt", "run_time_ns"}`.
10. Raw files: `DIR/runs/<round>-<condition>.s_time.txt` (s_time's output),
    and for audit and enforce `.jsonl` and `.err` (skbouncer's stdout and
    stderr).

## Done means `scripts/verify-M7.2.sh` passes

It runs 2 rounds of 5-second runs and checks the saved runs against
`s_time`'s output and skbouncer's raw events. About a minute. On this VM
`bpf_stats` is off and there are 2 CPUs, so the verifier expects `bpf` null
and no pinning here; the same code must fill both on EC2.

## Rules

- skbouncer is frozen: never edit `src/`, `include/`, `Makefile` or `policy/`.
  The verifier fails if they differ from `main`.
- Never edit `scripts/verify-*.sh`, `tests/`, `scripts/loop.sh`,
  `scripts/guard.sh`, `eval/census/`, `eval/env.sh`, `eval/collect.*` or
  `eval/clients.txt`. If you believe a verifier is wrong, say so in
  `PROGRESS.md` and stop.
- Enforce mode only through `--container` on the cost client container.
  Never on `ens33`, `tailscale0` or `docker0`, never the root cgroup.
- `sudo -n` works for `./skbouncer` and `bpftool` only.
- Never run `apt`, `apt-get`, `apt-mark`. Never regenerate `src/bpf/vmlinux.h`.
- Leave nothing running, attached or created; the verifier checks.

## Each iteration

Append to `PROGRESS.md` what you tried and what happened — verifier
rejections verbatim. Then `git commit`.
