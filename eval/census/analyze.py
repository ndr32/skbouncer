#!/usr/bin/env python3
"""Split analysis for the ClientHello census."""
import json, sys
from collections import defaultdict

MTUS = [(1500, "Ethernet"), (1492, "PPPoE"), (1460, "GCP"), (1450, "VXLAN"),
        (1420, "WireGuard"), (1400, "IPsec"), (1280, "Tailscale")]
HDR = 20 + 20 + 12          # IPv4 + TCP + timestamps option

rows = [json.loads(l) for l in open(sys.argv[1])]
singles = [r for r in rows if not r["label"].startswith("sample")]
samples = defaultdict(list)
for r in rows:
    if r["label"].startswith("sample"):
        samples[r["label"].split()[1]].append(r)

def seg(mtu): return mtu - HDR
def mark(r, mtu):
    wire = 5 + r["record_len"]
    if wire <= seg(mtu): return "·"
    if r["versions_end"] is not None and r["versions_end"] > seg(mtu): return "V"
    if r["cipher_end"] > seg(mtu): return "C"
    return "S"

print("## Split per client and path MTU (IPv4, TCP timestamps on)\n")
print("`·` fits · `S` split, ciphers and versions still in segment 1 · "
      "`V` split before supported_versions ends · `C` split inside the cipher list\n")
print("| Client | Record | Key shares | " + " | ".join(f"{m} {n}" for m, n in MTUS) + " |")
print("|---|---:|---|" + "---|" * len(MTUS))
for r in singles:
    ks = " + ".join(k for k, _ in r["keyshares"] if not k.startswith("0x")) or "—"
    print(f"| {r['label']} | {r['record_len']} | {ks} | " + " | ".join(mark(r, m) for m, _ in MTUS) + " |")

print("\n## Repeated samples (20 connections each)\n")
print("| Client | Record min–max | supported_versions ends at (min–max) | "
      + " | ".join(f"verdict certain @{m}" for m, _ in MTUS) + " |")
print("|---|---|---|" + "---|" * len(MTUS))
for name, rs in samples.items():
    lens = [r["record_len"] for r in rs]; ve = [r["versions_end"] for r in rs]
    cells = []
    for m, _ in MTUS:
        ok = sum(1 for r in rs if (5 + r["record_len"] <= seg(m)) or
                 (r["versions_end"] <= seg(m) and r["cipher_end"] <= seg(m)))
        cells.append(f"{ok}/{len(rs)}")
    print(f"| {name} | {min(lens)}–{max(lens)} | {min(ve)}–{max(ve)} | " + " | ".join(cells) + " |")
