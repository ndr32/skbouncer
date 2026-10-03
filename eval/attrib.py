#!/usr/bin/env python3
"""attrib.sh's last step: containers.jsonl and run.json from the raw files.

usage: attrib.py DIR HANDSHAKES
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect import counters  # noqa: E402


def main(d, k):
    d = Path(d)
    instances, events = [], []
    for err in sorted((d / "skb").glob("*.err")):
        veth = err.stem
        instances.append({"veth": veth, **counters(err.read_text())})
        for l in err.with_suffix(".jsonl").read_text().splitlines():
            try:
                events.append(json.loads(l))
            except ValueError:
                pass
    cons = []
    for l in (d / "manifest.tsv").read_text().splitlines():
        name, shared, veth, ip, dport = l.split("\t")
        dport = int(dport)
        out = (d / "clients" / f"{name}.log").read_text(errors="replace")
        cons.append({"name": name, "shared": shared == "1", "veth": veth, "ip": ip, "dport": dport,
                     "handshakes_ok": out.count("CONNECTION ESTABLISHED"),
                     "events": [e for e in events if e.get("dport") == dport]})
    with open(d / "containers.jsonl", "w") as f:
        for c in cons:
            f.write(json.dumps(c) + "\n")
    run = {"containers": len(cons), "handshakes": int(k), "instances": len(instances),
           "counters": instances}
    (d / "run.json").write_text(json.dumps(run) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
