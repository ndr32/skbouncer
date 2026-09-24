#!/usr/bin/env python3
"""M6.6 oracle: hardening. Every check is judged outside skbouncer: what is
still attached (bpftool), whether traffic got through (client and server),
and what the kernel map holds.

usage: check_m6_6.py OUTDIR     (reads OUTDIR/cases.json)
"""
import json
import sys
from pathlib import Path


def check(c):
    fails = []
    F = fails.append

    for d in c["deaths"]:
        n = f"dies of {d['signal']}"
        if d["alive"]:
            F(f"{n}: skbouncer did not exit")
        if d["attached"]:
            F(f"{n}: skb_tc still attached afterwards; an orphaned filter keeps enforcing")
        if not d["traffic_after"]:
            F(f"{n}: a violating handshake is still blocked with no skbouncer running")

    k = c["coexist"]
    if not k["enforcer_blocked"]:
        F("coexist: the enforce instance did not block with an audit instance on the same veth")
    if k["auditor_events"] < 1:
        F("coexist: the audit instance saw nothing once the enforce instance attached")
    if not k["auditor_attached_after_enforcer_exit"]:
        F("coexist: the enforce instance's exit removed the audit instance's program")
    if k["auditor_events_after"] < 1:
        F("coexist: the audit instance stopped reporting after the enforce instance exited")
    if k["attached_after_both"]:
        F("coexist: something is still attached after both instances exited")

    j = c["junk"]
    if j["events"]:
        F(f"mid-connection junk: {j['events']} event(s); bytes that only look like a "
          f"ClientHello header must not be treated as one")
    if j["received"] != j["sent"]:
        F(f"mid-connection junk: server received {j['received']} of {j['sent']} bytes")

    s = c["starttls"]
    if s["received"] != s["plaintext"]:
        F(f"STARTTLS ClientHello: server received {s['received']} bytes, expected only the "
          f"{s['plaintext']} plaintext bytes before it; the ClientHello was not blocked")
    if "block" not in s["actions"]:
        F(f"STARTTLS ClientHello: actions {s['actions']}, expected a block")

    m = c["map"]
    if m["entries"] is None:
        F("kernel map: no cgroup_rule map found on the enforce instance's program")
    elif m["entries"] > m["in_scope"]:
        F(f"kernel map: {m['entries']} cgroup entries with {m['in_scope']} cgroup(s) in scope "
          f"and {m['other_containers']} other containers running; only in-scope cgroups belong")
    return fails


if __name__ == "__main__":
    fails = check(json.loads((Path(sys.argv[1]) / "cases.json").read_text()))
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(fails)} failures")
    sys.exit(1 if fails else 0)
