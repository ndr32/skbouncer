#!/usr/bin/env python3
"""Decode every ClientHello in an `openssl s_server -msg` log."""
import re, sys, json

GROUPS = {0x001d: "X25519", 0x001e: "X448", 0x0017: "secp256r1", 0x0018: "secp384r1",
          0x0019: "secp521r1", 0x11ec: "X25519MLKEM768", 0x11eb: "SecP256r1MLKEM768",
          0x11ed: "SecP384r1MLKEM1024", 0x0200: "MLKEM512", 0x0201: "MLKEM768",
          0x0202: "MLKEM1024", 0x6399: "X25519Kyber768Draft00"}

def blocks(text):
    out = []
    for m in re.finditer(r"(RecordHeader \[length 0005\]|Handshake \[length [0-9a-f]+\], ClientHello)\n((?:\s+[0-9a-f ]+\n)+)", text):
        out.append((m.group(1).startswith("Record"), bytes.fromhex(re.sub(r"\s", "", m.group(2)))))
    return out

def hello(b):
    p = 4 + 2 + 32
    p += 1 + b[p]
    n = int.from_bytes(b[p:p+2], "big"); ciphers = n // 2; p += 2 + n
    cipher_end = p
    p += 1 + b[p]
    exts, keyshares, versions_end = [], [], None
    end = p + 2 + int.from_bytes(b[p:p+2], "big"); p += 2
    while p + 4 <= end:
        t = int.from_bytes(b[p:p+2], "big"); l = int.from_bytes(b[p+2:p+4], "big")
        exts.append((t, l))
        if t == 0x002B:
            versions_end = p + 4 + l
        if t == 0x0033:
            q = p + 6
            while q + 4 <= p + 4 + l:
                g = int.from_bytes(b[q:q+2], "big"); kl = int.from_bytes(b[q+2:q+4], "big")
                keyshares.append((GROUPS.get(g, hex(g)), kl)); q += 4 + kl
        p += 4 + l
    # Offsets are from the start of the TLS record, i.e. on the wire after
    # the TCP header: 5-byte record header + handshake bytes.
    return {"ciphers": ciphers, "n_ext": len(exts),
            "cipher_end": 5 + cipher_end,
            "versions_end": None if versions_end is None else 5 + versions_end,
            "ext_order": [t for t, _ in exts],
            "keyshares": keyshares, "keyshare_bytes": sum(k for _, k in keyshares),
            "exts": exts}

def parse(text):
    recs, hellos = [], []
    for is_rec, data in blocks(text):
        if is_rec and data[0] == 0x16:
            recs.append(int.from_bytes(data[3:5], "big"))
        elif not is_rec:
            hellos.append(hello(data))
    return recs, hellos

if __name__ == "__main__":
    recs, hellos = parse(open(sys.argv[1]).read())
    print(json.dumps({"records": recs, "hellos": hellos}))
