#!/usr/bin/env python3
"""M5 oracle: audit-mode verdicts, and policy load errors.

Each handshake case carries the verdict policy/README.md prescribes for it,
fixed in verify-M5.sh from the known ClientHello contents rather than from
anything skbouncer reports. Load-error cases carry skbouncer's exit status
and stderr for a policy that must be rejected.

usage: check_m5.py EVENTS.jsonl CASES.json
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
        name = case["name"]

        if case["kind"] == "load_error":
            if case["rc"] == 0 or case["rc"] == 124:
                fails.append(f"{name}: policy was accepted (exit {case['rc']}); "
                             f"it must be rejected at load")
            elif case["must_mention"] not in case["stderr"]:
                fails.append(f"{name}: error does not mention {case['must_mention']!r}: "
                             f"{case['stderr'].strip()[:120]!r}")
            continue

        got = by_port.get(case["port"], [])
        if len(got) != 1:
            fails.append(f"{name}: expected exactly 1 event on port {case['port']}, got {len(got)}")
            continue
        ev = got[0]
        if ev.get("container") != case["container"]:
            fails.append(f"{name}: container = {ev.get('container')!r}, expected {case['container']!r}")
        if ev.get("verdict") != case["verdict"]:
            fails.append(f"{name}: verdict = {ev.get('verdict')!r}, expected {case['verdict']!r} "
                         f"({case['why']})")
        if "trunc" in case and ev.get("trunc") != case["trunc"]:
            fails.append(f"{name}: harness problem, trunc = {ev.get('trunc')!r}, "
                         f"this case needs {case['trunc']!r}")
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
