#!/usr/bin/env python3
"""M7.4 oracle: the load and enforcement harnesses. Server logs are read
here, independently of the harness. Whether skbouncer blocked the right
ClientHellos is the C22 and C23 measurement, so it is reported, not failed.

usage: check_m7_4.py OUTDIR
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_m7_1 import decode  # noqa: E402  the server log's ClientHello

RUNS, HANDSHAKES, MAX_PARALLEL = 1, 200, 2
CONDITIONS = ("off", "audit", "enforce")
POLICY_COMBOS = {(1, 30), (16, 30), (64, 30), (1, 1)}
POLICIES = ("min13", "ciphers", "min13_block")
SCENARIOS = ("legacy", "cbc_sha1", "pq_unknown")
CLIENTS, WAIT_CAP = 3, 20
MAPS = {"events", "rules", "cgroup_rule", "stats", "scratch"}


def jsonl(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def cpus(spec):
    s = set()
    for part in str(spec).split(","):
        lo, _, hi = part.partition("-")
        s |= set(range(int(lo), int(hi or lo) + 1))
    return s


def skb_ok(name, s, F, conns=None, enforce=False):
    """The skbouncer record of one run: balanced counters, nothing blocked."""
    if not s:
        F(f"{name}: no skbouncer record")
        return
    k = s.get("counters") or {}
    if k.get("detected") is None or k.get("detected") != k.get("delivered", -1) + k.get("dropped", 0):
        F(f"{name}: counters {k} missing or unbalanced")
    if s.get("blocks"):
        F(f"{name}: {s.get('blocks')} blocked; the load policy must permit every client")
    if conns is not None and abs(k.get("detected", 0) - conns) > 3 * MAX_PARALLEL:
        F(f"{name}: {k.get('detected')} ClientHellos detected for {conns} connections")


def check_load(out, host, F):
    d = out / "load"
    try:
        run = json.loads((d / "run.json").read_text())
        tput, lat = jsonl(d / "throughput.jsonl"), jsonl(d / "latency.jsonl")
        pol, sat = jsonl(d / "policy.jsonl"), jsonl(d / "saturation.jsonl")
        fp = json.loads((d / "footprint.json").read_text())
    except (OSError, ValueError) as e:
        F(f"load: cannot read its output files: {e}")
        return
    if run.get("bpf_stats_enabled") != host["bpf_stats_enabled"]:
        F(f"load: bpf_stats_enabled {run.get('bpf_stats_enabled')}, the host says {host['bpf_stats_enabled']}")
    p = run.get("pinning")
    if host["nproc"] >= 6:
        sets = [cpus(p[k]) for k in ("server", "client", "skbouncer")] if p else []
        if not sets or any(a & b for i, a in enumerate(sets) for b in sets[i + 1:]):
            F(f"load: pinning {p!r}; with {host['nproc']} CPUs each side gets its own CPUs")

    for c in CONDITIONS:
        rows = [r for r in tput if r.get("condition") == c]
        if len(rows) != RUNS:
            F(f"load: throughput has {len(rows)} {c} runs, expected {RUNS}")
        for r in rows:
            n = f"load: throughput {c}"
            if not (r.get("gbps") or 0) > 0 or not (r.get("bytes") or 0) > 0:
                F(f"{n}: gbps {r.get('gbps')}, bytes {r.get('bytes')}")
            if c == "off":
                if r.get("skbouncer") is not None or r.get("attached") != 0:
                    F(f"{n}: skbouncer loaded during an off run")
            else:
                if r.get("attached") != 1:
                    F(f"{n}: attached {r.get('attached')}, expected 1")
                skb_ok(n, r.get("skbouncer"), F)
        rows = [r for r in lat if r.get("condition") == c]
        if len(rows) != RUNS:
            F(f"load: latency has {len(rows)} {c} runs, expected {RUNS}")
        for r in rows:
            ms = r.get("ms") or []
            if len(ms) != HANDSHAKES or r.get("ok") != HANDSHAKES or not all(x > 0 for x in ms):
                F(f"load: latency {c}: {len(ms)} timings, ok {r.get('ok')}, expected {HANDSHAKES} positive")
            if c != "off":
                skb_ok(f"load: latency {c}", r.get("skbouncer"), F, conns=HANDSHAKES)

    got = {(r.get("rules"), r.get("ciphers")) for r in pol}
    if got != POLICY_COMBOS or len(pol) != RUNS * len(POLICY_COMBOS):
        F(f"load: policy runs {sorted(got)} ({len(pol)} rows), expected {sorted(POLICY_COMBOS)} x {RUNS}")
    for r in pol:
        n = f"load: policy rules={r.get('rules')} ciphers={r.get('ciphers')}"
        if not (r.get("cps") or 0) > 0:
            F(f"{n}: cps {r.get('cps')}")
        skb_ok(n, r.get("skbouncer"), F, conns=r.get("connections"))
        if (r.get("skbouncer") or {}).get("passes") != (r.get("skbouncer") or {}).get("events"):
            F(f"{n}: not every event is an enforce-mode pass")

    levels = [r.get("parallel") for r in sat]
    want = [1 << i for i in range(MAX_PARALLEL.bit_length()) if 1 << i <= MAX_PARALLEL]
    if levels[:len(want)] != want:
        F(f"load: saturation levels {levels}, expected {want}")
    for r in sat:
        k = r.get("counters") or {}
        if k.get("detected") is None or k.get("detected") != k.get("delivered", -1) + k.get("dropped", 0):
            F(f"load: saturation x{r.get('parallel')}: counters {k} missing or unbalanced")
    print(f"info: load: saturation {[(r.get('parallel'), round(r.get('cps') or 0), (r.get('counters') or {}).get('dropped')) for r in sat]}")

    prog = fp.get("prog") or {}
    for k in ("bytes_xlated", "bytes_jited", "verified_insns"):
        if not (prog.get(k) or 0) > 0:
            F(f"load: footprint prog.{k} is {prog.get(k)}")
    names = {m.get("name") for m in fp.get("maps") or [] if (m.get("bytes_memlock") or 0) > 0}
    if not MAPS <= names:
        F(f"load: footprint maps with memory {sorted(names)}, expected {sorted(MAPS)}")
    if not (fp.get("rss_kib") or 0) > 0 or fp.get("cpu_seconds") is None:
        F(f"load: footprint rss_kib {fp.get('rss_kib')}, cpu_seconds {fp.get('cpu_seconds')}")
    if not (d / "env.txt").exists():
        F("load: env.txt missing")


def got_hello(d, port):
    p = d / "server" / f"{port}.log"
    if not p.exists():
        return None
    return bool(re.search(r"<<< [^\n]*ClientHello", p.read_text(errors="replace")))


def check_enforce(out, F):
    d = out / "enforce"
    try:
        run = json.loads((d / "run.json").read_text())
        mx, sc, waits = jsonl(d / "matrix.jsonl"), jsonl(d / "scenarios.jsonl"), jsonl(d / "waits.jsonl")
    except (OSError, ValueError) as e:
        F(f"enforce: cannot read its output files: {e}")
        return
    for pname in POLICIES:
        try:
            json.loads((d / "policies" / f"{pname}.json").read_text())
        except (OSError, ValueError):
            F(f"enforce: policies/{pname}.json missing or not JSON")
    if len(mx) != CLIENTS * len(POLICIES):
        F(f"enforce: {len(mx)} matrix rows, expected {CLIENTS} clients x {len(POLICIES)} policies")
    agree = 0
    for r in mx:
        n = f"enforce: {r.get('label')} / {r.get('policy')}"
        log = d / "server" / f"{r.get('ref_port')}.log"
        truth = decode(log.read_text()) if log.exists() else (None, 0)
        truth = truth[0] if isinstance(truth, tuple) else truth
        if truth is None:
            F(f"{n}: the reference pass's server log holds no ClientHello")
        elif {k: (r.get("reference") or {}).get(k) for k in truth} != truth:
            F(f"{n}: reference {r.get('reference')} differs from the server log")
        rx = got_hello(d, r.get("enf_port"))
        if rx is None or r.get("enforce_received") != rx:
            F(f"{n}: enforce_received {r.get('enforce_received')}, the server log says {rx}")
        evs = r.get("events") or []
        if not evs or any("action" not in e for e in evs):
            F(f"{n}: enforce pass has {len(evs)} events, each needs an action")
        blocked = any(e.get("action") == "block" for e in evs)
        agree += blocked == (rx is False)
    print(f"info: enforce: {agree} of {len(mx)} rows where a block event matches the server not "
          f"receiving the ClientHello")

    if sorted(s.get("name") for s in sc) != sorted(SCENARIOS):
        F(f"enforce: scenarios {[s.get('name') for s in sc]}, expected {list(SCENARIOS)}")
    for s in sc:
        n = f"enforce: scenario {s.get('name')}"
        a, e = s.get("audit") or {}, s.get("enforce") or {}
        if not a.get("events") or "verdict" not in a["events"][0]:
            F(f"{n}: audit pass has no event with a verdict")
        rx = got_hello(d, e.get("port"))
        if rx is None or e.get("received") != rx:
            F(f"{n}: enforce received {e.get('received')}, the server log says {rx}")
        for mode in ("audit", "enforce"):
            if not (d / "scenarios" / f"{s.get('name')}-{mode}.txt").exists():
                F(f"{n}: no text output for the {mode} screenshot")
        print(f"info: {n}: audit {[x.get('verdict') for x in a.get('events', [])][:1]}, "
              f"enforce received {e.get('received')}")

    if len(waits) != CLIENTS:
        F(f"enforce: {len(waits)} wait times, expected one per client ({CLIENTS})")
    for w in waits:
        s = w.get("seconds")
        if s is None or s < 0 or s > WAIT_CAP + 5 or w.get("capped") != (s >= WAIT_CAP):
            F(f"enforce: wait for {w.get('label')}: {s} s, capped {w.get('capped')}, cap {WAIT_CAP}")
    if run.get("wait_cap") != WAIT_CAP:
        F(f"enforce: wait_cap {run.get('wait_cap')}, expected {WAIT_CAP}")
    if not (d / "env.txt").exists():
        F("enforce: env.txt missing")


def check(out):
    fails = []
    F = fails.append
    host = json.loads((out / "host.json").read_text())
    check_load(out, host, F)
    check_enforce(out, F)
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
