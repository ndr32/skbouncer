#!/usr/bin/env python3
"""M3 oracle: compare skbouncer's JSON events against the ClientHellos the
TLS servers actually received (openssl s_server -msg dumps).

Ground truth comes from the server's view of the wire bytes, parsed here
independently of skbouncer. Nothing is derived from client configuration.

usage: check_m3.py EVENTS.jsonl CASES.json SERVER_LOG_DIR
"""
import json
import re
import sys
from pathlib import Path

MAX_CIPHERS = 64  # SKB_MAX_CIPHERS

# Plausible TCP payload of the first segment on a 1500-MTU path: 1460 without
# TCP timestamps, 1448 with, less other options. Records clearly inside or
# outside this band have a known answer; the band itself is only checked for
# internal consistency, so the oracle never needs skbouncer's own numbers.
SEG_MIN, SEG_MAX = 1400, 1460
TLS_RECORD_HLEN = 5


def parse_server_log(text):
    """Return (record_len, clienthello_bytes) for the first ClientHello."""
    rec = re.search(r"RecordHeader \[length 0005\]\n((?:\s+[0-9a-f ]+\n)+)", text)
    hs = re.search(r"Handshake \[length [0-9a-f]+\], ClientHello\n((?:\s+[0-9a-f ]+\n)+)", text)
    if not rec or not hs:
        return None, None
    hdr = bytes.fromhex(rec.group(1).replace(" ", "").replace("\n", ""))
    body = bytes.fromhex(hs.group(1).replace(" ", "").replace("\n", ""))
    return int.from_bytes(hdr[3:5], "big"), body


def parse_clienthello(b):
    """Reference parser. b starts at the handshake header (type 0x01)."""
    assert b[0] == 0x01, "not a ClientHello"
    p = 4
    legacy_version = int.from_bytes(b[p:p + 2], "big"); p += 2
    p += 32                                   # random
    p += 1 + b[p]                             # session_id
    n = int.from_bytes(b[p:p + 2], "big"); p += 2
    ciphers = [int.from_bytes(b[p + i:p + i + 2], "big") for i in range(0, n, 2)]
    p += n
    ciphers_end = p
    p += 1 + b[p]                             # compression_methods
    versions, versions_end = [], None
    if p < len(b):
        end = p + 2 + int.from_bytes(b[p:p + 2], "big"); p += 2
        while p + 4 <= end:
            etype = int.from_bytes(b[p:p + 2], "big")
            elen = int.from_bytes(b[p + 2:p + 4], "big")
            if etype == 0x002B:
                vl = b[p + 4]
                versions = [int.from_bytes(b[p + 5 + i:p + 7 + i], "big")
                            for i in range(0, vl, 2)]
                versions_end = p + 4 + elen
            p += 4 + elen
    return {"legacy_version": legacy_version, "ciphers": ciphers,
            "versions": versions, "versions_end": versions_end,
            "ciphers_end": ciphers_end}


def check(events, cases, logdir):
    fails = []
    by_port = {}
    for ev in events:
        by_port.setdefault(ev.get("dport"), []).append(ev)

    for case in cases:
        name, port = case["name"], case["port"]
        got = by_port.get(port, [])

        if not case["tls"]:
            if got:
                fails.append(f"{name}: expected no events on non-TLS port {port}, got {len(got)}")
            continue

        if len(got) != 1:
            fails.append(f"{name}: expected exactly 1 event on port {port}, got {len(got)}")
            continue
        ev = got[0]

        record_len, ch = parse_server_log((logdir / f"{port}.log").read_text())
        if ch is None:
            fails.append(f"{name}: server on {port} logged no ClientHello; test harness problem")
            continue
        want = parse_clienthello(ch)

        def expect(field, value):
            if ev.get(field) != value:
                fails.append(f"{name}: {field} = {ev.get(field)!r}, expected {value!r}")

        expect("record_len", record_len)
        expect("legacy_version", want["legacy_version"])
        if want["versions_end"] is None or TLS_RECORD_HLEN + want["versions_end"] <= SEG_MIN:
            expect("versions", want["versions"])

        capped = len(want["ciphers"]) > MAX_CIPHERS
        expect("ciphers", want["ciphers"][:MAX_CIPHERS])
        expect("ciphers_capped", capped)

        # The "seen in full" flags decide unknown versus allow, so judge them
        # from where each field ends in the real ClientHello. Fields ending in
        # the band between SEG_MIN and SEG_MAX are not judged.
        def seen(field, end_offset):
            end = TLS_RECORD_HLEN + end_offset
            if end <= SEG_MIN:
                expect(field, True)
            elif end > SEG_MAX:
                expect(field, False)
        if capped:
            expect("ciphers_seen", False)
        else:
            seen("ciphers_seen", want["ciphers_end"])
        if want["versions_end"] is not None:
            seen("versions_seen", want["versions_end"])
        elif TLS_RECORD_HLEN + record_len <= SEG_MIN:
            expect("versions_seen", True)   # whole record seen: absence proven

        # Truncation, judged from record size alone.
        on_wire = TLS_RECORD_HLEN + record_len
        captured = ev.get("captured_len")
        if on_wire <= SEG_MIN:
            expect("captured_len", record_len)
            expect("trunc", "none")
        elif on_wire > SEG_MAX:
            expect("trunc", "segment")
            if not isinstance(captured, int) or not (
                    SEG_MIN - TLS_RECORD_HLEN <= captured < record_len):
                fails.append(f"{name}: captured_len={captured!r} outside the first-segment "
                             f"range for a {record_len}-byte record")
        if isinstance(captured, int) and (captured < record_len) != (ev.get("trunc") == "segment"):
            fails.append(f"{name}: captured_len={captured} and trunc={ev.get('trunc')!r} disagree")
        if case.get("expect_split") and on_wire <= SEG_MAX:
            fails.append(f"{name}: harness problem, {record_len}-byte ClientHello was meant "
                         f"to span two segments")

    return fails


def main():
    events_path, cases_path, logdir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    events = []
    for n, line in enumerate(Path(events_path).read_text().splitlines(), 1):
        if not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"FAIL: line {n} of events is not valid JSON: {e}")
            return 1
    cases = json.loads(Path(cases_path).read_text())
    fails = check(events, cases, logdir)
    for f in fails:
        print("FAIL:", f)
    print(f"{'PASS' if not fails else 'FAIL'}: {len(cases)} cases, {len(fails)} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
