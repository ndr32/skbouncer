#!/usr/bin/env python3
"""The last step of one eval/cost.sh run: one runs.jsonl record from the raw files.

usage: cost.py OUT ROUND CONDITION ATTACHED BPF_JSON
BPF_JSON is bpftool -j prog show output, or "" when bpf_stats is off.
"""
import json
import re
import sys

out, rnd, cond, attached, bpf = sys.argv[1:]
base = f"{out}/runs/{rnd}-{cond}"

m = re.search(r"^(\d+) connections in [\d.]+s;", open(f"{base}.s_time.txt").read(), re.M)
if not m:
    sys.exit(f"cost.py: no s_time result line in {base}.s_time.txt")
conns = int(m[1])
a, b = open(f"{base}.wall").read().split()
wall = round(float(b) - float(a), 2)

skb = None
if cond != "off":
    err = open(f"{base}.err").read()
    k = re.search(r"(\d+) ClientHello detected, (\d+) delivered, (\d+) dropped \(ringbuf full\), "
                  r"(\d+) too short", err)
    if not k:
        sys.exit(f"cost.py: no exit line in {base}.err")
    events = [json.loads(l) for l in open(f"{base}.jsonl") if l.startswith("{")]
    b = None
    if bpf:
        p = json.loads(bpf)
        p = p[0] if isinstance(p, list) else p
        b = {"run_cnt": p["run_cnt"], "run_time_ns": p["run_time_ns"]}
    skb = {"counters": dict(zip(("detected", "delivered", "dropped", "short"), map(int, k.groups()))),
           "events": len(events),
           "blocks": sum(e.get("action") == "block" for e in events),
           "bpf": b}

rec = {"round": int(rnd), "condition": cond, "connections": conns, "wall_seconds": wall,
       "cps": round(conns / wall, 3) if wall else None, "attached": int(attached), "skbouncer": skb}
with open(f"{out}/runs.jsonl", "a") as f:
    f.write(json.dumps(rec) + "\n")
print(f"{rnd} {cond}: {conns} connections in {wall} s, {rec['cps']}/s")
