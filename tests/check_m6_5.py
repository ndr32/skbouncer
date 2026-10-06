#!/usr/bin/env python3
"""M6.5 oracle: the CLI is usable without knowing skbouncer's internals.

usage: check_m6_5.py OUTDIR    (reads OUTDIR/cases.json and the files it names)
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

RAW_VERSION = re.compile(r"\b030[1-4]\b")
CLOCK = re.compile(r"\b(\d{2}):(\d{2}):(\d{2})\b")


def lines_for(text, port):
    return [l for l in text.splitlines() if f":{port} " in l or l.rstrip().endswith(f":{port}")]


def clock_ok(line, issued):
    """HH:MM:SS within 5 s of when the handshake was issued, UTC or local."""
    for m in CLOCK.finditer(line):
        sod = int(m[1]) * 3600 + int(m[2]) * 60 + int(m[3])
        for ref in (datetime.fromtimestamp(issued, timezone.utc), datetime.fromtimestamp(issued)):
            want = ref.hour * 3600 + ref.minute * 60 + ref.second
            if min((sod - want) % 86400, (want - sod) % 86400) <= 5:
                return True
    return False


def check(out):
    c = json.loads((out / "cases.json").read_text())
    fails = []
    F = fails.append

    # --version and --help, unprivileged
    if c["version"]["rc"] != 0 or "skbouncer" not in c["version"]["out"].lower():
        F(f"--version: exit {c['version']['rc']}, output {c['version']['out'].strip()[:80]!r}")
    if "--container" not in c["help"]:
        F("--help does not mention --container")

    # unknown container
    r = c["no_such_container"]
    if r["rc"] in (0, 124):
        F(f"--container {r['name']}: accepted (exit {r['rc']}); must refuse")
    elif r["name"] not in r["stderr"]:
        F(f"--container {r['name']}: error does not name it: {r['stderr'].strip()[:100]!r}")

    # JSON run: stdout is only JSON, with reason and time
    raw = (out / "json.out").read_text()
    events, bad = [], []
    for l in raw.splitlines():
        if not l.strip():
            continue
        try:
            events.append(json.loads(l))
        except json.JSONDecodeError:
            bad.append(l)
    if bad:
        F(f"--format json: stdout has non-JSON lines, e.g. {bad[0][:80]!r}")
    by_port = {}
    for ev in events:
        by_port.setdefault(ev.get("dport"), []).append(ev)
    reasons = {}
    for k in c["json_cases"]:
        got = by_port.get(k["port"], [])
        if len(got) != 1:
            F(f"json {k['name']}: expected 1 event on port {k['port']}, got {len(got)}")
            continue
        ev = got[0]
        if ev.get("container") != c["container"]:
            F(f"json {k['name']}: container = {ev.get('container')!r}, expected {c['container']!r}")
        if ev.get("verdict") != k["verdict"]:
            F(f"json {k['name']}: verdict = {ev.get('verdict')!r}, expected {k['verdict']!r}")
        reason = ev.get("reason") or ""
        reasons[k["name"]] = reason
        if k.get("reason_has") and k["reason_has"].lower() not in reason.lower():
            F(f"json {k['name']}: reason {reason!r} should mention {k['reason_has']!r}")
        try:
            t = datetime.fromisoformat(ev["time"]).timestamp()
            if abs(t - k["issued"]) > 5:
                F(f"json {k['name']}: time {ev['time']} is {t - k['issued']:+.0f} s from real time")
        except (KeyError, TypeError, ValueError):
            F(f"json {k['name']}: \"time\" missing or not ISO 8601: {ev.get('time')!r}")

    # Text run: readable, same reasons, no dev noise
    text = (out / "text.out").read_text()
    if "bpftool" in text:
        F("text mode stdout still prints the bpftool hint")
    for k in c["text_cases"]:
        ls = lines_for(text, k["port"])
        if len(ls) != 1:
            F(f"text {k['name']}: expected 1 line for port {k['port']}, got {len(ls)}")
            continue
        line = ls[0]
        if RAW_VERSION.search(line):
            F(f"text {k['name']}: shows raw version codes: {line.strip()[:120]!r}")
        for want in k.get("line_has", []):
            if want not in line:
                F(f"text {k['name']}: line lacks {want!r}: {line.strip()[:120]!r}")
        same = reasons.get(k["same_reason_as"], "")
        if same and same not in line:
            F(f"text {k['name']}: line lacks the reason {same!r}")
        if not clock_ok(line, k["issued"]):
            F(f"text {k['name']}: no wall-clock HH:MM:SS near the real time: {line.strip()[:120]!r}")

    # -i <veth> sees container traffic
    if c["ingress_default"]["events"] < 1:
        F("-i <veth> saw no ClientHello; container traffic is ingress on its veth")

    # enforce with only --container
    for k in c["enforce_cases"]:
        blocked = k["expect"] == "blocked"
        if k["rc_start"] != 0:
            F(f"enforce {k['name']}: --mode enforce --container did not start: {k['err'][:100]!r}")
            break
        if blocked == k["established"] or blocked == k["server_saw_hello"]:
            F(f"enforce {k['name']}: expected {k['expect']}, established={k['established']}, "
              f"server_saw_hello={k['server_saw_hello']}")
    return fails


if __name__ == "__main__":
    fails = check(Path(sys.argv[1]))
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(fails)} failures")
    sys.exit(1 if fails else 0)
