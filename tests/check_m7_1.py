#!/usr/bin/env python3
"""M7.1 oracle: the evaluation collector. The ground truth it saves is
checked against this file's own decode of the server's logs, never against
skbouncer or the collector's parser.

usage: check_m7_1.py OUTDIR
"""
import json
import re
import sys
from pathlib import Path

RUNS = [(1500, "on"), (1280, "on"), (1500, "off")]
N, CLIENTS = 2, 3
IPV4_TCP = 40
TIMESTAMPS = 12


def hexblock(text):
    return bytes.fromhex(re.sub(r"\s", "", text))


def decode(log):
    """The ClientHello the server received: record length, legacy version,
    every cipher and every supported_versions entry, in wire order."""
    hellos = re.findall(r"<<< [^\n]*Handshake \[length [0-9a-f]+\], ClientHello\n((?:\s+[0-9a-f ]+\n)+)", log)
    rec = re.search(r"<<< [^\n]*RecordHeader \[length 0005\]\n((?:\s+[0-9a-f ]+\n)+)", log)
    if not hellos or not rec:
        return None, 0
    r, b = hexblock(rec[1]), hexblock(hellos[0])
    p = 4
    legacy = int.from_bytes(b[p:p + 2], "big")
    p += 2 + 32
    p += 1 + b[p]
    n = int.from_bytes(b[p:p + 2], "big")
    ciphers = [int.from_bytes(b[i:i + 2], "big") for i in range(p + 2, p + 2 + n, 2)]
    p += 2 + n
    p += 1 + b[p]
    versions = []
    if p + 2 <= len(b):
        end = p + 2 + int.from_bytes(b[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            t, l = int.from_bytes(b[p:p + 2], "big"), int.from_bytes(b[p + 2:p + 4], "big")
            if t == 0x002B:
                versions = [int.from_bytes(b[i:i + 2], "big") for i in range(p + 5, p + 5 + b[p + 4], 2)]
            p += 4 + l
    return {"record_len": int.from_bytes(r[3:5], "big"), "legacy_version": legacy,
            "ciphers": ciphers, "versions": versions}, len(hellos)


def check_run(d, mtu, ts, F):
    name = f"MTU {mtu}, timestamps {ts}"
    try:
        run = json.loads((d / "run.json").read_text())
        conns = [json.loads(l) for l in (d / "connections.jsonl").read_text().splitlines() if l.strip()]
    except (OSError, ValueError) as e:
        F(f"{name}: cannot read run.json / connections.jsonl: {e}")
        return None

    want_mss = mtu - IPV4_TCP - (TIMESTAMPS if ts == "on" else 0)
    if run.get("mtu_observed") != mtu:
        F(f"{name}: client interface MTU is {run.get('mtu_observed')}, not {mtu}")
    if run.get("mss") != want_mss:
        F(f"{name}: mss {run.get('mss')}, expected {want_mss} for this MTU and timestamp setting")
    env = (d / "env.txt").read_text() if (d / "env.txt").exists() else ""
    if "kernel: " not in env or "skbouncer: " not in env:
        F(f"{name}: env.txt missing or lacks the kernel and skbouncer lines (eval/env.sh)")

    if len(conns) != N * CLIENTS:
        F(f"{name}: {len(conns)} connection records, expected {N * CLIENTS}")
    ports = [c.get("port") for c in conns]
    if len(set(ports)) != len(ports):
        F(f"{name}: ports are not unique per connection: {ports}")
    k = run.get("counters", {})
    if k.get("detected") != len(conns) or k.get("delivered") != len(conns) or k.get("dropped") != 0:
        F(f"{name}: counters {k}; expected every connection detected and delivered once, none dropped")

    captured = set()
    for c in conns:
        cn = f"{name}, port {c.get('port')} ({c.get('label')})"
        if not c.get("client_ok"):
            F(f"{cn}: client_ok is false")
        if c.get("mtu") != mtu or c.get("timestamps") != ts or c.get("mss") != run.get("mss"):
            F(f"{cn}: mtu/timestamps/mss fields disagree with run.json")
        log = d / "server" / f"{c.get('port')}.log"
        truth, hellos = decode(log.read_text()) if log.exists() else (None, 0)
        if truth is None:
            F(f"{cn}: no ClientHello in {log}")
            continue
        if hellos != 1:
            F(f"{cn}: server saw {hellos} ClientHellos; a HelloRetryRequest means the server "
              f"lacks the client's key exchange group")
        srv = c.get("server") or {}
        for key, want in truth.items():
            if srv.get(key) != want:
                F(f"{cn}: server.{key} is {srv.get(key)!r}, the server log says {want!r}")

        cont = c.get("container")
        if not cont or cont == run.get("anchor"):
            F(f"{cn}: container {cont!r}; each client runs in its own named container")
        evs = c.get("events") or []
        if len(evs) != 1:
            F(f"{cn}: {len(evs)} skbouncer events, expected exactly 1")
            continue
        e = evs[0]
        if e.get("dport") != c.get("port"):
            F(f"{cn}: event dport {e.get('dport')} joined to port {c.get('port')}")
        if e.get("record_len") != truth["record_len"]:
            F(f"{cn}: event record_len {e.get('record_len')}, server {truth['record_len']}; wrong join?")
        if e.get("container") != cont:
            F(f"{cn}: event names container {e.get('container')!r}, the client ran in {cont!r}")
        if not e.get("cgroup_id"):
            F(f"{cn}: event has no cgroup id")
        if "verdict" not in e:
            F(f"{cn}: event has no verdict; was --policy passed to skbouncer?")
        if e.get("captured_len", 0) < truth["record_len"]:
            captured.add(e["captured_len"])
    return want_mss, sorted(captured)


def check_clients(out, F):
    census = {json.loads(l)["label"] for l in (out / "census.jsonl").read_text().splitlines()
              if l.strip() and not json.loads(l)["label"].startswith("sample")}
    p = Path("eval/clients.txt")
    if not p.exists():
        F("eval/clients.txt missing: the census client set, one label|image|command per line")
        return
    labels = set()
    for l in p.read_text().splitlines():
        if not l.strip() or l.startswith("#"):
            continue
        f = l.split("|", 2)
        if len(f) != 3 or "@PORT@" not in f[2] or not ("@SIP@" in f[2] or "@SNI@" in f[2]):
            F(f"eval/clients.txt: malformed line: {l[:80]}")
            continue
        labels.add(f[0])
    if labels != census:
        F(f"eval/clients.txt: labels differ from the census: missing {sorted(census - labels)}, "
          f"extra {sorted(labels - census)}")


def check(out):
    fails = []
    F = fails.append
    for mtu, ts in RUNS:
        r = check_run(out / f"{mtu}-{ts}", mtu, ts, F)
        if r:
            print(f"info: MTU {mtu} timestamps {ts}: mss {r[0]}, split ClientHellos captured "
                  f"{r[1]} bytes (mss - 5 = {r[0] - 5})")
    check_clients(out, F)
    left = json.loads((out / "leftovers.json").read_text())
    if left["containers"] or left["networks"]:
        F(f"left behind: containers [{left['containers']}], networks [{left['networks']}]")
    if left["skbouncer_pids"] or left["attached"]:
        F(f"left running or attached: skbouncer pids [{left['skbouncer_pids']}], "
          f"{left['attached']} skb_tc attachment(s)")
    return fails


if __name__ == "__main__":
    fails = check(Path(sys.argv[1]))
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(fails)} failures")
    sys.exit(1 if fails else 0)
