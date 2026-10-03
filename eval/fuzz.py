#!/usr/bin/env python3
"""fuzz.sh's three Python steps.

usage: fuzz.py gen N SEED > sends.jsonl          originals, then N mutants
       fuzz.py client SENDS HOST PORT BASE       in the anchor: one connection each
       fuzz.py join DIR N SEED ALIVE ATTACHED    mutants.jsonl and run.json
"""
import json
import random
import re
import socket
import sys
from pathlib import Path

R = Path(__file__).resolve().parent.parent
KINDS = ("flip", "truncate", "length", "insert")
# One of each kind of client the census saw, by its results.jsonl label.
ORIGINALS = ("openssl X25519 only (classical)", "openssl 3.5.8 default",
             "openssl TLS 1.2 only", "browser chrome150", "browser firefox147")
HEX = r"\n((?:\s+[0-9a-f ]+\n)+)"


def hexblock(text):
    return bytes.fromhex(re.sub(r"\s", "", text))


def u16(b, p):
    return int.from_bytes(b[p:p + 2], "big")


def original(log):
    """The first ClientHello record in an s_server -msg log: header and body."""
    hdr = next(h for h in map(hexblock, re.findall(r"<<< [^\n]*RecordHeader \[length 0005\]" + HEX, log))
               if h[0] == 0x16)
    hello = hexblock(re.search(r"<<< [^\n]*Handshake \[length [0-9a-f]+\], ClientHello" + HEX, log)[1])
    assert u16(hdr, 3) == len(hello), "record split across records"
    return hdr + hello


def length_fields(rec):
    """(name, offset, size) of every length field in a well-formed record."""
    f = [("record", 3, 2), ("handshake", 6, 3), ("session_id", 43, 1)]
    p = 44 + rec[43]
    f.append(("ciphers", p, 2))
    p += 2 + u16(rec, p)
    p += 1 + rec[p]
    if p + 2 > len(rec):
        return f
    f.append(("extensions", p, 2))
    p += 2
    exts = []
    while p + 4 <= len(rec):
        exts.append(("extension", p + 2, 2))
        p += 4 + u16(rec, p + 2)
    return f + exts


def mutate(rng, kind, rec):
    b = bytearray(rec)
    if kind == "flip":
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] ^= rng.randint(1, 255)
    elif kind == "truncate":
        del b[rng.randrange(1, len(b)):]
    elif kind == "insert":
        p = rng.randint(0, len(b))
        b[p:p] = rng.randbytes(rng.randint(1, 16))
    else:
        fields = length_fields(rec)
        # One extension in the draw, not one per extension.
        name, off, size = rng.choice([x for x in fields if x[0] != "extension"] +
                                     [rng.choice([x for x in fields if x[0] == "extension"])])
        v, top = int.from_bytes(b[off:off + size], "big"), (1 << 8 * size) - 1
        wrong = sorted({0, v - 1, v + 1, v // 2, v * 2, top, rng.randint(0, top)} - {v})
        b[off:off + size] = rng.choice([w for w in wrong if 0 <= w <= top]).to_bytes(size, "big")
    return bytes(b)


def gen(n, seed):
    rng = random.Random(seed)
    census = {}
    for l in (R / "eval/census/results.jsonl").read_text().splitlines():
        r = json.loads(l)
        census.setdefault(r["label"], r["log"])
    origs = [(label, original((R / census[label]).read_text())) for label in ORIGINALS]
    i = 0
    for label, rec in origs:
        print(json.dumps({"i": i, "kind": "original", "from": label, "hex": rec.hex()}))
        i += 1
    for k in range(n):
        label, rec = origs[rng.randrange(len(origs))]
        kind = KINDS[k % len(KINDS)]
        print(json.dumps({"i": i, "kind": kind, "from": label, "hex": mutate(rng, kind, rec).hex()}))
        i += 1


def client(sends, host, port, base):
    """Runs in the anchor. Source ports are bound, base + i, so no two
    connections share one and the sink's log joins by port."""
    for l in open(sends):
        r = json.loads(l)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(10)
        s.bind(("", int(base) + r["i"]))
        s.connect((host, int(port)))
        sport = s.getsockname()[1]
        s.sendall(bytes.fromhex(r["hex"]))
        s.shutdown(socket.SHUT_WR)
        while s.recv(65536):
            pass
        s.close()
        print(r["i"], sport, flush=True)


def join(d, n, seed, alive, attached):
    sys.path.insert(0, str(R / "eval"))
    from collect import counters
    d = Path(d)
    events = []
    for l in (d / "skbouncer.jsonl").read_text().splitlines():
        try:
            events.append(json.loads(l))
        except ValueError:
            pass
    sport = dict(map(int, l.split()) for l in (d / "client.txt").read_text().splitlines() if l.strip())
    received = {}
    for l in (d / "sink" / "sink.log").read_text().splitlines():
        p, c = l.split()
        received[int(p)] = int(c)
    sent = 0
    with open(d / "mutants.jsonl", "w") as f:
        for l in (d / "sends.jsonl").read_text().splitlines():
            r = json.loads(l)
            p = sport.get(r["i"])
            if p is None:
                break
            f.write(json.dumps({"i": r["i"], "kind": r["kind"], "from": r["from"], "sport": p,
                                "hex": r["hex"], "received": received.get(p),
                                "events": [e for e in events if e.get("sport") == p]}) + "\n")
            sent += 1
    run = {"n": int(n), "seed": int(seed), "sent": sent, "alive_at_end": alive == "1",
           "attached_at_end": int(attached), "counters": counters((d / "skbouncer.err").read_text())}
    (d / "run.json").write_text(json.dumps(run) + "\n")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "gen":
        gen(int(args[0]), int(args[1]))
    elif cmd == "client":
        client(*args)
    elif cmd == "join":
        join(*args)
    else:
        sys.exit(__doc__)
