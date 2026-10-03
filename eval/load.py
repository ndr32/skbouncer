#!/usr/bin/env python3
"""eval/load.sh's helpers. In a python:3-alpine container: the bulk sink and
sender, and the handshake timer. On the host: one jsonl row per run.

usage: load.py sink PORT                 receive one connection, time it
       load.py send HOST PORT SECONDS    send zeros for SECONDS
       load.py hs HOST PORT N            N sequential TLS handshakes, each timed
       load.py row OUT.jsonl BASE ATTACHED BPF_JSON FIELDS_JSON
       load.py policy BASE_POLICY CONTAINER RULES CIPHER OUT.json
       load.py footprint OUT.json PROG_JSON MAPS_JSON PID SECONDS VERIFIED_INSNS
"""
import json
import os
import re
import socket
import sys
import time


def sink(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", int(port)))
    s.listen(1)
    print("listening", file=sys.stderr, flush=True)
    c, _ = s.accept()
    buf = bytearray(1 << 20)
    n = c.recv_into(buf)
    t0 = time.monotonic()  # from the first byte to EOF
    while k := c.recv_into(buf):
        n += k
    print(json.dumps({"bytes": n, "wall_seconds": round(time.monotonic() - t0, 4)}))


def send(host, port, secs):
    s = socket.create_connection((host, int(port)))
    b = bytes(1 << 20)
    end = time.monotonic() + float(secs)
    while time.monotonic() < end:
        s.sendall(b)
    s.close()


def hs(host, port, n):
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ms = []
    for _ in range(int(n)):
        t = time.perf_counter_ns()
        try:
            with ctx.wrap_socket(socket.create_connection((host, int(port)), timeout=10)):
                ms.append((time.perf_counter_ns() - t) / 1e6)
        except OSError as e:
            print(f"handshake failed: {e}", file=sys.stderr)
    print(json.dumps({"ok": len(ms), "ms": [round(x, 4) for x in ms]}))


def skb(base, bpf):
    err = open(f"{base}.err").read()
    k = re.search(r"(\d+) ClientHello detected, (\d+) delivered, (\d+) dropped \(ringbuf full\), "
                  r"(\d+) too short", err)
    if not k:
        sys.exit(f"load.py: no exit line in {base}.err")
    events = [json.loads(l) for l in open(f"{base}.jsonl") if l.startswith("{")]
    b = None
    if bpf:
        p = json.loads(bpf)
        p = p[0] if isinstance(p, list) else p
        b = {"run_cnt": p["run_cnt"], "run_time_ns": p["run_time_ns"]}
    return {"counters": dict(zip(("detected", "delivered", "dropped", "short"), map(int, k.groups()))),
            "events": len(events),
            "blocks": sum(e.get("action") == "block" for e in events),
            "passes": sum(e.get("action") == "pass" for e in events),
            "bpf": b}


def s_time(base):
    """Connections over every s_time in BASE.s_time.txt, and the wall time."""
    conns = [int(m) for m in re.findall(r"^(\d+) connections in [\d.]+s;", open(f"{base}.s_time.txt").read(), re.M)]
    if not conns:
        sys.exit(f"load.py: no s_time result line in {base}.s_time.txt")
    a, b = open(f"{base}.wall").read().split()
    wall = round(float(b) - float(a), 2)
    return {"connections": sum(conns), "wall_seconds": wall, "cps": round(sum(conns) / wall, 3) if wall else None}


def row(out, base, attached, bpf, fields):
    r = json.loads(fields)
    kind = r.pop("_kind")
    if kind == "s_time":
        r.update(s_time(base))
    else:  # the container helper's own JSON
        r.update(json.loads(open(f"{base}.out").read()))
        if kind == "bulk":
            r["gbps"] = round(r["bytes"] * 8 / r["wall_seconds"] / 1e9, 4) if r["wall_seconds"] else None
    s = skb(base, bpf) if r.get("condition", "on") != "off" else None
    if r.pop("_counters_only", False):
        r["counters"] = s["counters"]
    else:
        r["attached"] = int(attached)
        r["skbouncer"] = s
    with open(out, "a") as f:
        f.write(json.dumps(r) + "\n")
    print(json.dumps({k: v for k, v in r.items() if k not in ("ms", "skbouncer")}))


def policy(base, container, rules, cipher, out):
    """BASE's single rule, renamed to CONTAINER and preceded by RULES - 1
    rules that match nothing; CIPHER, if given, replaces its cipher list."""
    p = json.load(open(base))
    last = dict(p["rules"][0], container=container)
    if cipher:
        last["ciphers"] = [cipher]
    p["rules"] = [dict(last, container=f"skb-load-none-{i}") for i in range(1, int(rules))] + [last]
    json.dump(p, open(out, "w"), indent=1)


def footprint(out, prog, maps, pid, secs, insns):
    p = json.loads(prog)
    p = p[0] if isinstance(p, list) else p
    ids = set(p.get("map_ids", []))
    ms = [m for m in json.loads(maps) if m.get("id") in ids]
    st = dict(l.split(":", 1) for l in open(f"/proc/{pid}/status").read().splitlines() if ":" in l)
    stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    tck = os.sysconf("SC_CLK_TCK")
    prog = {k: p.get(k) for k in ("bytes_xlated", "bytes_jited")}
    prog["verified_insns"] = int(insns)
    json.dump({"prog": prog, "verified_insns_from": "bpftool -d prog load, rodata defaults (audit)",
               "maps": [{k: m.get(k) for k in ("name", "type", "bytes_memlock")} for m in ms],
               "rss_kib": int(st["VmRSS"].split()[0]),
               "cpu_seconds": round((int(stat[11]) + int(stat[12])) / tck, 2),
               "seconds": int(secs)},
              open(out, "w"))


if __name__ == "__main__":
    {"sink": sink, "send": send, "hs": hs, "row": row, "policy": policy,
     "footprint": footprint}[sys.argv[1]](*sys.argv[2:])
