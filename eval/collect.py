#!/usr/bin/env python3
"""collect.sh's last step: run.json and connections.jsonl from the raw files.

usage: collect.py DIR MTU TS N NETWORK ANCHOR MTU_OBSERVED MSS
"""
import json
import re
import sys
from pathlib import Path

HEX = r"\n((?:\s+[0-9a-f ]+\n)+)"


def hexblock(text):
    return bytes.fromhex(re.sub(r"\s", "", text))


def u16(b, p):
    return int.from_bytes(b[p:p + 2], "big")


def server_view(log):
    """The first ClientHello the server received, from s_server -msg."""
    rec = next((hexblock(m) for m in re.findall(r"<<< [^\n]*RecordHeader \[length 0005\]" + HEX, log)
                if hexblock(m)[0] == 0x16), None)
    hello = re.search(r"<<< [^\n]*Handshake \[length [0-9a-f]+\], ClientHello" + HEX, log)
    if rec is None or hello is None:
        return None
    b = hexblock(hello[1])
    p = 4
    legacy = u16(b, p)
    p += 2 + 32
    p += 1 + b[p]
    n = u16(b, p)
    ciphers = [u16(b, i) for i in range(p + 2, p + 2 + n, 2)]
    p += 2 + n
    p += 1 + b[p]
    versions = []
    if p + 2 <= len(b):
        end = p + 2 + u16(b, p)
        p += 2
        while p + 4 <= end:
            t, l = u16(b, p), u16(b, p + 2)
            if t == 0x002B:
                versions = [u16(b, i) for i in range(p + 5, p + 5 + b[p + 4], 2)]
            p += 4 + l
    return {"record_len": u16(rec, 3), "legacy_version": legacy,
            "ciphers": ciphers, "versions": versions}


def counters(err):
    m = re.search(r"(\d+) ClientHello detected, (\d+) delivered, (\d+) dropped [^,]*, (\d+) too short", err)
    return dict(zip(("detected", "delivered", "dropped", "short"), map(int, m.groups()))) if m else {}


def main(d, mtu, ts, n, network, anchor, mtu_obs, mss):
    d = Path(d)
    mtu, n, mss = int(mtu), int(n), int(mss)
    events = []
    for l in (d / "skbouncer.jsonl").read_text().splitlines():
        try:
            events.append(json.loads(l))
        except ValueError:
            pass
    run = {"mtu": mtu, "timestamps": ts, "n": n, "network": network, "anchor": anchor,
           "mtu_observed": int(mtu_obs), "mss": mss,
           "counters": counters((d / "skbouncer.err").read_text())}
    (d / "run.json").write_text(json.dumps(run) + "\n")
    with open(d / "connections.jsonl", "w") as f:
        for l in (d / "manifest.tsv").read_text().splitlines():
            label, image, container, rep, port = l.split("\t")
            port = int(port)
            log = (d / "server" / f"{port}.log").read_text(errors="replace")
            f.write(json.dumps({
                "label": label, "image": image, "container": container, "rep": int(rep),
                "port": port, "mtu": mtu, "timestamps": ts, "mss": mss,
                "client_ok": bool(re.search(r"<<< [^\n]*Handshake \[length [0-9a-f]+\], Finished", log)),
                "server": server_view(log),
                "events": [e for e in events if e.get("dport") == port],
            }) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
