#!/usr/bin/env python3
"""eval/enforce.sh's helpers: the policies, and one jsonl row per matrix
cell, scenario or wait time from the raw files.

usage: enforce.py policies DIR
       enforce.py matrix OUT LABEL POLICY REF_PORT ENF_PORT
       enforce.py scenario OUT NAME AUDIT_PORT ENFORCE_PORT
       enforce.py wait OUT LABEL CAP MARKER
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect import server_view  # noqa: E402

RULE = "skb-enforce-*"
TLS13 = ["0x1301", "0x1302", "0x1303"]
ECDHE_GCM = ["0xc02b", "0xc02c", "0xc02f", "0xc030"]
POLICIES = {
    "min13": {"min_version": "1.3"},
    "ciphers": {"ciphers": TLS13 + ECDHE_GCM},
    "min13_block": {"min_version": "1.3"},
}


def policies(d):
    for name, rule in POLICIES.items():
        p = {"version": 1, "default": "allow",
             "on_unknown": "block" if name.endswith("_block") else "allow",
             "rules": [dict(container=RULE, **rule)]}
        (Path(d) / f"{name}.json").write_text(json.dumps(p, indent=1) + "\n")


def log(out, port):
    p = Path(out) / "server" / f"{port}.log"
    return p.read_text(errors="replace") if p.exists() else ""


def received(out, port):
    return bool(re.search(r"<<< [^\n]*ClientHello", log(out, port)))


def events(out, port):
    p = Path(out) / "skb" / f"{port}.jsonl"
    evs = []
    for l in p.read_text().splitlines() if p.exists() else []:
        try:
            e = json.loads(l)
        except ValueError:
            continue
        if e.get("dport") == int(port):
            evs.append(e)
    return evs


def append(out, name, rec):
    with open(Path(out) / name, "a") as f:
        f.write(json.dumps(rec) + "\n")


def matrix(out, label, policy, ref, enf):
    rec = {"label": label, "policy": policy, "ref_port": int(ref), "enf_port": int(enf),
           "reference": server_view(log(out, ref)), "enforce_received": received(out, enf),
           "events": events(out, enf)}
    append(out, "matrix.jsonl", rec)
    acts = [e.get("action") for e in rec["events"]]
    print(f"{label} / {policy}: received {rec['enforce_received']}, actions {acts}")


def scenario(out, name, a, e):
    rec = {"name": name, "audit": {"port": int(a), "events": events(out, a)},
           "enforce": {"port": int(e), "received": received(out, e), "events": events(out, e)}}
    append(out, "scenarios.jsonl", rec)
    print(f"{name}: audit {[x.get('verdict') for x in rec['audit']['events']]}, "
          f"enforce received {rec['enforce']['received']}")


def wait(out, label, cap, marker):
    a, b, rc = marker.split()
    s = round(float(b) - float(a), 2)
    rec = {"label": label, "seconds": s, "capped": s >= int(cap), "exit": int(rc)}
    append(out, "waits.jsonl", rec)
    print(f"{label}: {s} s, exit {rc}")


if __name__ == "__main__":
    {"policies": policies, "matrix": matrix, "scenario": scenario,
     "wait": wait}[sys.argv[1]](*sys.argv[2:])
