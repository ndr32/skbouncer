#!/usr/bin/env python3
"""M7.3 oracle: the fuzz and attribution harnesses. Mutants are decoded here,
independently of the harness and of skbouncer. Whether skbouncer's fields
match a mutant's decode is the C16 measurement itself, so it is reported,
not failed: a mismatch is a finding about the frozen tool.

usage: check_m7_3.py OUTDIR
"""
import json
import sys
from pathlib import Path

N, ORIGINALS_MIN = 300, 4
KINDS = ("flip", "truncate", "length", "insert")
CONTAINERS, HANDSHAKES = 10, 3


def u16(b, p):
    return int.from_bytes(b[p:p + 2], "big") if p + 2 <= len(b) else None


def decode(rec):
    """Ciphers and supported_versions of a TLS record as sent, or None for a
    field the bytes cannot yield. Bounds-checked: mutants are malformed."""
    out = {"ciphers": None, "versions": None, "record_len": u16(rec, 3)}
    if len(rec) < 5 + 4 + 2 + 32 + 1 or rec[0] != 0x16 or rec[5] != 0x01:
        return out
    b = rec[5:]
    p = 4 + 2 + 32
    p += 1 + b[p]
    n = u16(b, p)
    if n is None or p + 2 + n > len(b):
        return out
    out["ciphers"] = [u16(b, i) for i in range(p + 2, p + 2 + n - n % 2, 2)]
    p += 2 + n
    if p >= len(b):
        return out
    p += 1 + b[p]
    ext = u16(b, p)
    if ext is None:
        out["versions"] = []
        return out
    end = min(p + 2 + ext, len(b))
    p += 2
    versions = []
    while p + 4 <= end:
        t, l = u16(b, p), u16(b, p + 2)
        if t == 0x002B and p + 5 <= end:
            k = b[p + 4]
            if p + 5 + k > end:
                return out
            versions = [u16(b, i) for i in range(p + 5, p + 5 + k - k % 2, 2)]
        p += 4 + l
    out["versions"] = versions
    return out


def rows_of(d):
    return [json.loads(l) for l in (d / "mutants.jsonl").read_text().splitlines() if l.strip()]


def check_fuzz(out, F):
    d = out / "fuzz-a"
    try:
        run = json.loads((d / "run.json").read_text())
        rows = rows_of(d)
        rows_b = rows_of(out / "fuzz-b")
    except (OSError, ValueError) as e:
        F(f"fuzz: cannot read run.json / mutants.jsonl: {e}")
        return
    if [r.get("hex") for r in rows] != [r.get("hex") for r in rows_b]:
        F("fuzz: two runs with seed 7 sent different bytes; mutants must follow from the seed")
    orig = [r for r in rows if r.get("kind") == "original"]
    muts = [r for r in rows if r.get("kind") != "original"]
    if len(orig) < ORIGINALS_MIN:
        F(f"fuzz: {len(orig)} unmutated originals, expected at least {ORIGINALS_MIN}")
    if len(muts) != N:
        F(f"fuzz: {len(muts)} mutants, expected {N}")
    for k in KINDS:
        share = sum(r.get("kind") == k for r in muts) / max(len(muts), 1)
        if share < 0.10:
            F(f"fuzz: mutation kind {k!r} is {share:.0%} of mutants, expected at least 10%")
    if set(r.get("kind") for r in muts) - set(KINDS):
        F(f"fuzz: unknown mutation kinds {sorted(set(r.get('kind') for r in muts) - set(KINDS))}")
    sports = [r.get("sport") for r in rows]
    if len(set(sports)) != len(sports) or not all(isinstance(p, int) and p > 0 for p in sports):
        F("fuzz: every connection needs its own recorded source port")
    for r in rows:
        if r.get("received") != len(bytes.fromhex(r.get("hex", ""))):
            F(f"fuzz: connection {r.get('i')}: sink received {r.get('received')} bytes, "
              f"{len(r.get('hex', '')) // 2} were sent")
            break
    if run.get("sent") != len(rows):
        F(f"fuzz: run.json says {run.get('sent')} sent, mutants.jsonl has {len(rows)}")
    if not run.get("alive_at_end") or run.get("attached_at_end") != 1:
        F(f"fuzz: alive_at_end {run.get('alive_at_end')}, attached_at_end "
          f"{run.get('attached_at_end')}; expected skbouncer running and attached at the end")
    k = run.get("counters") or {}
    if k.get("detected") is None or k.get("detected") != k.get("delivered", -1) + k.get("dropped", 0):
        F(f"fuzz: counters {k} missing or unbalanced")
    if not (d / "env.txt").exists():
        F("fuzz: env.txt missing")

    # The join: originals must come back exactly as the checker decodes them.
    joined = sum(len(r.get("events") or []) for r in rows)
    if joined != k.get("delivered"):
        F(f"fuzz: {joined} events joined to connections, skbouncer delivered {k.get('delivered')}")
    for r in orig:
        evs = r.get("events") or []
        truth = decode(bytes.fromhex(r["hex"]))
        if len(evs) != 1:
            F(f"fuzz: original {r.get('i')}: {len(evs)} events, expected 1")
            continue
        e = evs[0]
        if e.get("sport") != r.get("sport") or e.get("record_len") != truth["record_len"]:
            F(f"fuzz: original {r.get('i')}: event sport {e.get('sport')} record_len "
              f"{e.get('record_len')}, sent sport {r.get('sport')} record_len {truth['record_len']}")
        if e.get("ciphers_seen") and e.get("ciphers") != truth["ciphers"]:
            F(f"fuzz: original {r.get('i')}: ciphers flagged complete but differ from what was sent")

    # The measurement: reported, not failed.
    with_ev = disagree = 0
    for r in muts:
        evs = r.get("events") or []
        with_ev += bool(evs)
        truth = decode(bytes.fromhex(r["hex"]))
        for e in evs:
            for f, seen in (("ciphers", "ciphers_seen"), ("versions", "versions_seen")):
                if e.get(seen) and truth[f] is not None and e.get(f) and e.get(f) != truth[f]:
                    disagree += 1
    print(f"info: fuzz: {len(muts)} mutants, {with_ev} produced events, {disagree} fields "
          f"flagged complete that differ from the checker's decode")


def check_attrib(out, F):
    d = out / "attrib"
    try:
        run = json.loads((d / "run.json").read_text())
        cons = [json.loads(l) for l in (d / "containers.jsonl").read_text().splitlines() if l.strip()]
    except (OSError, ValueError) as e:
        F(f"attrib: cannot read run.json / containers.jsonl: {e}")
        return
    if len(cons) != CONTAINERS:
        F(f"attrib: {len(cons)} containers, expected {CONTAINERS}")
        return
    shared = [c for c in cons if c.get("shared")]
    if len(shared) != CONTAINERS // 2:
        F(f"attrib: {len(shared)} containers share a network namespace, expected {CONTAINERS // 2}")
    groups = {}
    for c in shared:
        groups.setdefault(c.get("veth"), []).append(c)
    for veth, g in groups.items():
        if len(g) != 5 or len({c.get("ip") for c in g}) != 1:
            F(f"attrib: shared group on {veth}: {len(g)} containers, IPs {sorted({c.get('ip') for c in g})}; "
              f"expected 5 containers with one IP")
    alone = [c for c in cons if not c.get("shared")]
    if len({c.get("veth") for c in alone}) != len(alone):
        F("attrib: standalone containers must each have their own veth")
    veths = {c.get("veth") for c in cons}
    if run.get("instances") != len(veths):
        F(f"attrib: {run.get('instances')} skbouncer instances for {len(veths)} veths")
    if len({c.get("dport") for c in cons}) != CONTAINERS:
        F("attrib: each container needs its own server port")
    wrong = unnamed = 0
    for c in cons:
        n = f"attrib: {c.get('name')}"
        if c.get("handshakes_ok") != HANDSHAKES:
            F(f"{n}: {c.get('handshakes_ok')} handshakes completed, expected {HANDSHAKES}")
        evs = c.get("events") or []
        if len(evs) != HANDSHAKES:
            F(f"{n}: {len(evs)} events, expected {HANDSHAKES}")
        for e in evs:
            if e.get("dport") != c.get("dport"):
                F(f"{n}: event with dport {e.get('dport')} joined to port {c.get('dport')}")
            if e.get("container") is None:
                unnamed += 1
            elif e.get("container") != c.get("name"):
                wrong += 1
    if wrong or unnamed:
        F(f"attrib: {wrong} events name the wrong container and {unnamed} name none, with "
          f"{CONTAINERS} containers; verify-M4 shows this works, so check the harness first")
    if not (d / "env.txt").exists():
        F("attrib: env.txt missing")


def check(out):
    fails = []
    F = fails.append
    check_fuzz(out, F)
    check_attrib(out, F)
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
