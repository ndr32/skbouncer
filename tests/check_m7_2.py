#!/usr/bin/env python3
"""M7.2 oracle: the runtime cost runner. Connection counts are checked
against s_time's own output, and event counts against skbouncer's raw
events, never against the runner's summary alone.

usage: check_m7_2.py OUTDIR
"""
import json
import re
import statistics
import sys
from pathlib import Path

ROUNDS, SECONDS = 2, 5
CONDITIONS = ["off", "audit", "enforce"]


def order(rnd):
    """Round r starts r - 1 places along: off,audit,enforce / audit,enforce,off / ..."""
    k = (rnd - 1) % len(CONDITIONS)
    return CONDITIONS[k:] + CONDITIONS[:k]


def cpus(spec):
    s = set()
    for part in str(spec).split(","):
        lo, _, hi = part.partition("-")
        s |= set(range(int(lo), int(hi or lo) + 1))
    return s


def check_run(d, r, F):
    name = f"round {r['round']} {r['condition']}"
    raw = d / "runs" / f"{r['round']}-{r['condition']}.s_time.txt"
    m = re.search(r"^(\d+) connections in [\d.]+s;", raw.read_text() if raw.exists() else "", re.M)
    if not m:
        F(f"{name}: no s_time result line in {raw}")
        return
    conns = int(m[1])
    if r.get("connections") != conns or conns == 0:
        F(f"{name}: connections {r.get('connections')}, s_time says {conns}")
    w = r.get("wall_seconds") or 0
    if not SECONDS <= w <= SECONDS + 3:
        F(f"{name}: wall_seconds {w} for a {SECONDS} s run")
    elif abs(r.get("cps", 0) - conns / w) > 0.005 * conns / w:
        F(f"{name}: cps {r.get('cps')}, connections / wall_seconds is {conns / w:.2f}")

    s = r.get("skbouncer")
    if r["condition"] == "off":
        if s is not None or r.get("attached") != 0:
            F(f"{name}: skbouncer {s!r}, attached {r.get('attached')}; off means nothing loaded")
        return
    if r.get("attached") != 1:
        F(f"{name}: attached {r.get('attached')}; expected exactly one skb_tc on the client's veth")
    if not s:
        F(f"{name}: no skbouncer record")
        return
    evf = d / "runs" / f"{r['round']}-{r['condition']}.jsonl"
    events = [json.loads(l) for l in evf.read_text().splitlines() if l.startswith("{")] if evf.exists() else []
    k = s.get("counters") or {}
    if k.get("detected") != k.get("delivered", -1) + k.get("dropped", 0):
        F(f"{name}: counters {k} do not balance")
    if k.get("delivered") != len(events) or s.get("events") != len(events):
        F(f"{name}: {len(events)} events in {evf.name}, record says {s.get('events')}, "
          f"counters say {k.get('delivered')}")
    if abs(k.get("detected", 0) - conns) > 3:
        F(f"{name}: {k.get('detected')} ClientHellos detected for {conns} connections")
    blocks = sum(e.get("action") == "block" for e in events)
    if s.get("blocks") != blocks or blocks:
        F(f"{name}: {blocks} blocked (record says {s.get('blocks')}); the cost policy must permit s_time")
    acting = [e.get("action") for e in events if "action" in e]
    if r["condition"] == "enforce" and (len(acting) != len(events) or set(acting) - {"pass"}):
        F(f"{name}: not every event carries action \"pass\"; was it enforce mode?")
    if r["condition"] == "audit" and acting:
        F(f"{name}: audit events carry an action; was it enforce mode?")
    return s


def check(out):
    fails = []
    F = fails.append
    d = out / "run"
    host = json.loads((out / "host.json").read_text())
    try:
        run = json.loads((d / "run.json").read_text())
        runs = [json.loads(l) for l in (d / "runs.jsonl").read_text().splitlines() if l.strip()]
    except (OSError, ValueError) as e:
        return [f"cannot read run.json / runs.jsonl: {e}"]

    if run.get("rounds") != ROUNDS or run.get("seconds") != SECONDS:
        F(f"run.json: rounds {run.get('rounds')}, seconds {run.get('seconds')}")
    if not Path(str(run.get("policy"))).is_file():
        F(f"run.json: policy {run.get('policy')!r} is not a file")
    env = (d / "env.txt").read_text() if (d / "env.txt").exists() else ""
    if "kernel: " not in env or "skbouncer: " not in env:
        F("env.txt missing or lacks the kernel and skbouncer lines (eval/env.sh)")

    got = [(r.get("round"), r.get("condition")) for r in runs]
    want = [(n, c) for n in range(1, ROUNDS + 1) for c in order(n)]
    if got != want:
        F(f"runs out of order or missing: {got}, expected {want}")
        return fails

    if run.get("bpf_stats_enabled") != host["bpf_stats_enabled"]:
        F(f"run.json bpf_stats_enabled {run.get('bpf_stats_enabled')}, the host says {host['bpf_stats_enabled']}")
    p = run.get("pinning")
    if host["nproc"] >= 6:
        sets = [cpus(p[k]) for k in ("server", "client", "skbouncer")] if p else []
        if not sets or any(a & b for i, a in enumerate(sets) for b in sets[i + 1:]):
            F(f"pinning {p!r}; with {host['nproc']} CPUs server, client and skbouncer get disjoint CPUs")

    for r in runs:
        s = check_run(d, r, F)
        if not s:
            continue
        b = s.get("bpf")
        if host["bpf_stats_enabled"]:
            if not b or b.get("run_cnt", 0) < s["counters"].get("detected", 1) or not b.get("run_time_ns"):
                F(f"round {r['round']} {r['condition']}: bpf {b!r}; with bpf_stats on, run_cnt covers "
                  f"every packet and run_time_ns is positive")
        elif b is not None:
            F(f"round {r['round']} {r['condition']}: bpf {b!r} with bpf_stats off; expected null")

    for c in CONDITIONS:
        cps = [r["cps"] for r in runs if r["condition"] == c and r.get("cps")]
        if cps:
            print(f"info: {c:7} median {statistics.median(cps):.1f} connections/s over {len(cps)} runs")

    if host["containers"] or host["networks"]:
        F(f"left behind: containers [{host['containers']}], networks [{host['networks']}]")
    if host["skbouncer_pids"] or host["attached"]:
        F(f"left running or attached: skbouncer pids [{host['skbouncer_pids']}], "
          f"{host['attached']} skb_tc attachment(s)")
    return fails


if __name__ == "__main__":
    fails = check(Path(sys.argv[1]))
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(fails)} failures")
    sys.exit(1 if fails else 0)
