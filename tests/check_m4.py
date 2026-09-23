#!/usr/bin/env python3
"""M4 oracle: every event must name the container that sent the handshake.

Ground truth per case is the sending container's name (docker inspect) and
its cgroup v2 inode (stat of its docker-<id>.scope), both collected by
verify-M4.sh independently of skbouncer.

usage: check_m4.py EVENTS.jsonl CASES.json
"""
import json
import sys
from pathlib import Path


def check(events, cases):
    fails = []
    by_port = {}
    for ev in events:
        by_port.setdefault(ev.get("dport"), []).append(ev)

    for case in cases:
        name, got = case["name"], by_port.get(case["port"], [])
        if not case["watched"]:
            if got:
                fails.append(f"{name}: {case['container']} is on an unwatched veth, "
                             f"expected no events, got {len(got)}")
            continue
        if len(got) != 1:
            fails.append(f"{name}: expected exactly 1 event on port {case['port']}, got {len(got)}")
            continue
        ev = got[0]
        if ev.get("cgroup_id") != case["cgroup_id"]:
            fails.append(f"{name}: cgroup_id = {ev.get('cgroup_id')!r}, expected "
                         f"{case['cgroup_id']} ({case['container']}'s scope)")
        if ev.get("container") != case["container"]:
            fails.append(f"{name}: container = {ev.get('container')!r}, expected "
                         f"{case['container']!r}")
    return fails


def main():
    events = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines()
              if l.startswith("{")]
    cases = json.loads(Path(sys.argv[2]).read_text())
    fails = check(events, cases)
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(cases)} cases, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
