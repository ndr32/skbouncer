#!/usr/bin/env python3
"""M6 oracle: enforce mode blocks what policy/README.md says, and only that.

Whether a handshake was blocked is judged outside skbouncer: the client
either reported an established connection or did not, and the server either
logged a ClientHello or did not. A block must stop the ClientHello reaching
the server, which is only possible from the kernel.

usage: check_m6.py EVENTS.jsonl CASES.json
"""
import json
import sys
from pathlib import Path


def check(events, cases):
    fails = []
    # Keyed by run as well as port: a blocked ClientHello is retransmitted
    # into later runs, where a different policy may decide it.
    by_port = {}
    for ev in events:
        by_port.setdefault((ev.get("_run"), ev.get("dport")), []).append(ev)

    for case in cases:
        name = case["name"]

        if case["kind"] == "refusal":
            if case["rc"] in (0, 124):
                fails.append(f"{name}: skbouncer accepted it (exit {case['rc']}); must refuse")
            elif case["must_mention"].lower() not in case["stderr"].lower():
                fails.append(f"{name}: refusal does not mention {case['must_mention']!r}: "
                             f"{case['stderr'].strip()[:120]!r}")
            continue

        blocked = case["expect"] == "blocked"
        got = by_port.get((case.get("run"), case["port"]), [])
        why = f"({case['why']})"

        if blocked and case["established"]:
            fails.append(f"{name}: connection was established, expected blocked {why}")
        if not blocked and not case["established"]:
            fails.append(f"{name}: connection failed, expected it to pass {why}")
        if blocked and case["server_saw_hello"]:
            fails.append(f"{name}: server received the ClientHello; a block must drop it "
                         f"before it leaves the host {why}")
        if not blocked and not case["server_saw_hello"]:
            fails.append(f"{name}: server never received the ClientHello {why}")

        if not got:
            fails.append(f"{name}: no event on port {case['port']}")
            continue
        want_action = "block" if blocked else "pass"
        actions = {ev.get("action") for ev in got}
        if actions != {want_action}:
            fails.append(f"{name}: action = {sorted(map(str, actions))}, expected {want_action!r}")
        for ev in got:
            kv = ev.get("kernel_verdict")
            if case["in_scope"] and kv != ev.get("verdict"):
                fails.append(f"{name}: kernel_verdict = {kv!r} but userspace verdict = "
                             f"{ev.get('verdict')!r}; the kernel's copy of the policy has drifted")
                break
            if not case["in_scope"] and kv not in (None, "none"):
                fails.append(f"{name}: kernel_verdict = {kv!r} out of scope; the kernel holds no "
                             f"rule for this cgroup, so it must not report a verdict")
                break
        verdicts = {ev.get("verdict") for ev in got}
        if verdicts != {case["verdict"]}:
            fails.append(f"{name}: verdict = {sorted(map(str, verdicts))}, expected {case['verdict']!r}")
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
