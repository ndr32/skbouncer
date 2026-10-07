#!/usr/bin/env python3
"""M9 oracle: --list, --check, the exit summary and the menu. Container ids
come from Docker and the cgroup filesystem; summary counts come from the
run's own JSON events.

usage: check_m9.py OUTDIR
"""
import json
import re
import sys
from pathlib import Path

SUMMARY = re.compile(r"^\s+(\S+): (\d+) ClientHellos, (\d+) allow, (\d+) violation, "
                     r"(\d+) unknown, (\d+) blocked$", re.M)
COUNTERS = re.compile(r"\d+ ClientHello detected, \d+ delivered, \d+ dropped")


def text(d, name):
    p = d / name
    return p.read_text(errors="replace") if p.exists() else ""


def check(d):
    fails = []
    F = fails.append
    c = json.loads((d / "cases.json").read_text())
    rc, a = c["rc"], c["container"]

    # --list
    line = [l for l in text(d, "list.out").splitlines() if l.split()[:1] == [a]]
    if rc["list"] != 0:
        F(f"--list exited {rc['list']} unprivileged: {text(d, 'list.err').strip()[:120]}")
    elif not line or line[0].split()[1:3] != [c["veth"], str(c["cgroup_id"])]:
        F(f"--list: expected '{a} {c['veth']} {c['cgroup_id']}', got {line[:1]}")

    # --check
    ck = text(d, "check.out")
    if rc["check"] != 0:
        F(f"--check exited {rc['check']} unprivileged: {text(d, 'check.err').strip()[:120]}")
    for want in (f"rule 1: {a}: TLS 1.3 or later", "TLS_AES_128_GCM_SHA256",
                 "TLS_AES_256_GCM_SHA384", "no rule matches: deny", "unknown verdicts: allow"):
        if want not in ck:
            F(f"--check output lacks {want!r}")
    if rc["bad"] == 0 or "TLS_NO_SUCH_CIPHER" not in text(d, "bad.err"):
        F(f"--check on a bad policy: exit {rc['bad']}, stderr {text(d, 'bad.err').strip()[:120]!r}")

    # no arguments, no terminal
    if rc["noarg"] == 0 or "usage:" not in text(d, "noarg.err") or "Choose:" in text(d, "noarg.out"):
        F(f"no arguments without a terminal: exit {rc['noarg']}; expected usage and a non-zero exit, no menu")

    # summary against the run's events
    err = text(d, "run.err")
    events = [json.loads(l) for l in text(d, "run.jsonl").splitlines() if l.startswith("{")]
    if not COUNTERS.search(err):
        F("the counter line changed; the harnesses parse it")
    rows = {m[1]: [int(x) for x in m.groups()[1:]] for m in SUMMARY.finditer(err)}
    want = [len(events)] + [sum(e.get("verdict") == v for e in events)
                            for v in ("allow", "violation", "unknown")] + [0]
    if "skbouncer: summary" not in err or rows.get(a) != want:
        F(f"summary for {a}: {rows.get(a)}, the events say {want} (ClientHellos, allow, violation, unknown, blocked)")
    if len(events) != 3 or sorted(e.get("verdict") for e in events) != ["allow", "violation", "violation"]:
        F(f"expected 3 events (1 allow, 2 violation), got {[e.get('verdict') for e in events]}")

    # the menu
    m = json.loads((d / "menu.json").read_text())
    for key, msg in (("menu", "no 'Choose:' prompt"), ("list", "item 5 did not list the container and its veth"),
                     ("check_prompt", "item 4 did not ask for a policy file"),
                     ("picker", "no numbered container to pick"),
                     ("confirm_prompt", "enforce did not ask 'Continue? [y/N]'"),
                     ("declined_back", "declining enforce did not return to the menu"),
                     ("running_line", "no 'Running: skbouncer ... --container' line before the audit run"),
                     ("violating_ok", "audit blocked a handshake"), ("allowed_ok", "audit blocked a handshake")):
        if not m.get(key):
            F(f"menu: {msg}")
    if "rule 1:" not in m.get("check", ""):
        F("menu: item 4 did not describe the policy")
    if m.get("declined_attached") != 0:
        F(f"menu: {m.get('declined_attached')} program(s) attached after enforce was declined")
    if m.get("audit_attached") != 1:
        F(f"menu: {m.get('audit_attached')} program(s) attached during the audit run, expected 1")
    if "skbouncer: summary" not in m.get("after_ctrl_c", "") or "Choose:" not in m.get("after_ctrl_c", ""):
        F("menu: Ctrl-C did not print the summary and return to the menu")
    if m.get("after_attached") != 0:
        F("menu: still attached after Ctrl-C")
    if m.get("exit_status") != 0:
        F(f"menu: 'q' exited with {m.get('exit_status')}")
    return fails


if __name__ == "__main__":
    fails = check(Path(sys.argv[1]))
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(fails)} failures")
    sys.exit(1 if fails else 0)
