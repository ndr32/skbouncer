#!/usr/bin/env python3
"""Where the negotiated cipher and version sit in each census ServerHello.

The ServerHello is the server's reply, so its layout is the server's
(OpenSSL 3.5.8 here), whatever the client. Offsets are from the start of
the TLS record, as in parse.py; segment model as in analyze.py."""
import json, re, sys

MTUS = [(1500, "Ethernet"), (1492, "PPPoE"), (1460, "GCP"), (1450, "VXLAN"),
        (1420, "WireGuard"), (1400, "IPsec"), (1280, "Tailscale")]
HDR = 20 + 20 + 12          # IPv4 + TCP + timestamps option, as analyze.py

def seg(mtu): return mtu - HDR

def server_hello(text):
    m = re.search(r">>> [^\n]*RecordHeader \[length 0005\]\n((?:\s+[0-9a-f ]+\n)+)"
                  r">>> [^\n]*Handshake \[length [0-9a-f]+\], ServerHello\n((?:\s+[0-9a-f ]+\n)+)", text)
    if not m:
        return None
    rec = bytes.fromhex(re.sub(r"\s", "", m.group(1)))
    b = bytes.fromhex(re.sub(r"\s", "", m.group(2)))
    p = 4 + 2 + 32
    p += 1 + b[p]
    cipher, cipher_end = int.from_bytes(b[p:p+2], "big"), p + 2
    p += 2 + 1
    end = p + 2 + int.from_bytes(b[p:p+2], "big"); p += 2
    version, versions_end, order = None, None, []
    while p + 4 <= end:
        t = int.from_bytes(b[p:p+2], "big"); l = int.from_bytes(b[p+2:p+4], "big")
        order.append(t)
        if t == 0x002B:
            version, versions_end = int.from_bytes(b[p+4:p+6], "big"), p + 4 + l
        p += 4 + l
    return {"record_len": int.from_bytes(rec[3:5], "big"), "cipher": cipher,
            "cipher_end": 5 + cipher_end, "version": version,
            "versions_end": None if versions_end is None else 5 + versions_end,
            "ext_order": order}

rows = [json.loads(l) for l in open(sys.argv[1])]
print("| Client | ClientHello | ServerHello | Cipher ends | Version ends | ServerHello splits at |")
print("|---|---:|---:|---:|---:|---|")
worst, samples = 0, {}
for r in rows:
    sh = server_hello(open(r["log"]).read())
    if not sh:
        print(f"| {r['label']} | {r['record_len']} | none | | | |")
        continue
    worst = max(worst, sh["cipher_end"], sh["versions_end"] or 0)
    if r["label"].startswith("sample"):
        n = r["label"].split()[1]
        samples.setdefault(n, []).append(sh)
        continue
    splits = [str(m) for m, _ in MTUS if 5 + sh["record_len"] > seg(m)]
    print(f"| {r['label']} | {r['record_len']} | {sh['record_len']} | {sh['cipher_end']} | "
          f"{sh['versions_end'] or 'legacy_version'} | {', '.join(splits) or '-'} |")
def span(shs, k):
    lo, hi = min(sh[k] for sh in shs), max(sh[k] for sh in shs)
    return str(lo) if lo == hi else f"{lo}–{hi}"
for n, shs in samples.items():
    splits = [str(m) for m, _ in MTUS if any(5 + sh["record_len"] > seg(m) for sh in shs)]
    print(f"| sample {n} ({len(shs)}) | | {span(shs, 'record_len')} | {span(shs, 'cipher_end')} | "
          f"{span(shs, 'versions_end')} | {', '.join(splits) or '-'} |")
print(f"\nNegotiated cipher and version end by byte {worst} of the record in every "
      f"ServerHello; the smallest first segment modelled holds {seg(MTUS[-1][0])}.")
