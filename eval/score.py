#!/usr/bin/env python3
"""Scores the campaign: the 25 criteria of eval/PLAN.md from the raw results.

usage: eval/score.py RESULTS [OUT]

RESULTS is the unpacked `results/` directory of a campaign archive,
eval/results/results-<tag>.tar.xz. The tag comes from RESULTS/env-<tag>.txt.
Writes OUT/criteria.md and OUT/scores.json (OUT defaults to
eval/results/<tag>).

Reference verdicts (C10, C22) apply policy/README.md to the server's own
decode of each ClientHello, so they share no code with skbouncer. Cipher
names come from IANA's registry (eval/score/iana-tls-cipher-suites.csv).

Security grades (C25) follow Durumeric et al., NDSS 2017, section V-A.
F: an export, single DES, NULL-encryption or anonymous cipher suite, or
SSL 2.0 as the best version. C: an RC4 suite, or SSL 3.0 as the best
version. B: no strong suite (a TLS 1.3 suite, or ECDHE or DHE with GCM or
ChaCha20-Poly1305), or TLS 1.0 or 1.1 as the best version. A otherwise.
3DES is not graded down; the paper does not name it.
"""
import csv
import fnmatch
import json
import statistics as st
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))
from check_m7_3 import decode as decode_mutant  # noqa: E402

VERSION = {"1.0": 0x0301, "1.1": 0x0302, "1.2": 0x0303, "1.3": 0x0304}


def jsonl(p):
    return [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]


def grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def ignored(c):
    return grease(c) or c in (0x00FF, 0x5600)


def pct(x, base):
    return 100.0 * (x - base) / base


def iana():
    names = {}
    for row in csv.DictReader(open(REPO / "eval/score/iana-tls-cipher-suites.csv")):
        v = row["Value"].replace('"', "")
        if "-" in v or "*" in v or not row["Description"].startswith("TLS_"):
            continue
        hi, lo = v.split(",")
        names[int(hi, 16) << 8 | int(lo, 16)] = row["Description"]
    return names


NAMES = iana()
BY_NAME = {n: c for c, n in NAMES.items()}


# -- reference verdicts --------------------------------------------------------

def load_policy(path):
    p = json.loads(Path(path).read_text())
    rules = []
    for r in p.get("rules", []):
        ciphers = None
        if "ciphers" in r:
            ciphers = {int(c, 16) if c.lower().startswith("0x") else BY_NAME[c] for c in r["ciphers"]}
        rules.append((r["container"], VERSION.get(r.get("min_version")), ciphers))
    return {"rules": rules, "default_allow": p.get("default") == "allow",
            "unknown_block": p.get("on_unknown") == "block"}


def offered_versions(versions, legacy):
    v = [x for x in versions if not grease(x)]
    return v or [legacy]


def reference_verdict(pol, container, server):
    """allow or violation from the server's decode, as policy/README.md
    defines them. The server saw the whole ClientHello: never unknown."""
    for pattern, vmin, ciphers in pol["rules"]:
        if container and fnmatch.fnmatchcase(container, pattern):
            if vmin and any(v < vmin for v in offered_versions(server["versions"], server["legacy_version"])):
                return "violation"
            if ciphers is not None and any(c not in ciphers for c in server["ciphers"] if not ignored(c)):
                return "violation"
            return "allow"
    return "allow" if pol["default_allow"] else "violation"


# -- grades -------------------------------------------------------------------

def suite_grade(code):
    n = NAMES.get(code, "")
    if not n:
        return None
    if "_WITH_" not in n:
        return "A" if n.startswith("TLS_AES_") or n.startswith("TLS_CHACHA20") else None
    kx, enc = n[4:].split("_WITH_", 1)
    if "EXPORT" in n or enc.startswith("DES_") or enc.startswith("DES40") or enc.startswith("NULL") or "anon" in kx:
        return "F"
    if enc.startswith("RC4"):
        return "C"
    strong = kx.startswith(("ECDHE_", "DHE_")) and ("_GCM_" in enc or "CHACHA20_POLY1305" in enc)
    return "A" if strong else "B"


def grade(ciphers, versions, legacy):
    best = max(offered_versions(versions, legacy))
    grades = [g for g in (suite_grade(c) for c in ciphers if not ignored(c)) if g]
    if "F" in grades or best <= 0x0002:
        return "F"
    if "C" in grades or best == 0x0300:
        return "C"
    if "A" not in grades or best < 0x0303:
        return "B"
    return "A"


# -- per experiment -------------------------------------------------------------

def exp1(R):
    r = json.loads((R / "exp1/results.json").read_text())
    rows = {x["no"]: x["pass"] for x in r["rows"]}
    return {"rows": rows, "c3": r["c3"], "chain": r["chain_passed"]}


def exp3_connections(R):
    out = []
    for part, pol in (("census", "policy/example.json"), ("census-mixed", "exp3/policy-mixed.json"),
                      ("edge", "policy/example.json")):
        policy = load_policy(REPO / pol if pol.startswith("policy/") else R / pol)
        for c in jsonl(R / f"exp3/{part}/connections.jsonl"):
            out.append((part, policy, c))
    return out


def score_exp3(R):
    conns = exp3_connections(R)
    s = {"connections": len(conns), "reported": 0, "cipher_lists": [0, 0], "version_lists": [0, 0],
         "false_certain": 0, "named": [0, 0], "verdicts": [0, 0], "unknown": 0}
    for part, pol, c in conns:
        srv, evs = c["server"], c["events"]
        s["reported"] += bool(evs)
        for e in evs:
            s["named"][1] += 1
            s["named"][0] += e.get("container") == c["container"]
            if e.get("record_len") != srv["record_len"] or e.get("legacy_version") != srv["legacy_version"]:
                s["false_certain"] += 1
            if e.get("ciphers_seen"):
                s["cipher_lists"][1] += 1
                ok = e.get("ciphers") == srv["ciphers"]
                s["cipher_lists"][0] += ok
                s["false_certain"] += not ok
            if e.get("versions_seen"):
                s["version_lists"][1] += 1
                ok = e.get("versions") == srv["versions"]
                s["version_lists"][0] += ok
                s["false_certain"] += not ok
            v = e.get("verdict")
            if v == "unknown":
                s["unknown"] += 1
            elif v in ("allow", "violation"):
                s["verdicts"][1] += 1
                s["verdicts"][0] += v == reference_verdict(pol, c["container"], srv)
    return s


def score_fuzz(R):
    run = json.loads((R / "exp3/fuzz/run.json").read_text())
    rows = jsonl(R / "exp3/fuzz/mutants.jsonl")
    muts = [r for r in rows if r["kind"] != "original"]
    wrong = 0
    for r in muts:
        truth = decode_mutant(bytes.fromhex(r["hex"]))
        for e in r["events"]:
            for f, seen in (("ciphers", "ciphers_seen"), ("versions", "versions_seen")):
                if e.get(seen) and truth[f] is not None and e.get(f) and e.get(f) != truth[f]:
                    wrong += 1
    return {"mutants": len(muts), "with_events": sum(bool(r["events"]) for r in muts),
            "false_complete": wrong, "alive": run["alive_at_end"], "attached": run["attached_at_end"],
            "short": run["counters"]["short"]}


def post_quantum():
    pq = {}
    for l in (REPO / "eval/census/results.jsonl").read_text().splitlines():
        r = json.loads(l)
        pq.setdefault(r["label"], any("MLKEM" in k or "Kyber" in k for k, _ in r["keyshares"]))
    return pq


def score_exp4(R):
    pq = post_quantum()
    arms = sorted(p.name for p in (R / "exp4").iterdir() if p.is_dir())
    split_truth = split_flagged = fits = fits_flagged = 0
    h1_exceptions, table = [], {}
    ciphers_cut = 0
    for arm in arms:
        run = json.loads((R / f"exp4/{arm}/run.json").read_text())
        for c in jsonl(R / f"exp4/{arm}/connections.jsonl"):
            e = c["events"][0]
            is_split = c["server"]["record_len"] + 5 > run["mss"]
            flagged = e["captured_len"] < e["record_len"]
            if is_split:
                split_truth += 1
                split_flagged += flagged
            else:
                fits += 1
                fits_flagged += flagged
            if is_split != pq.get(c["label"], False):
                h1_exceptions.append(f"{c['label']} at {arm}: {'split' if is_split else 'fits'}")
            ciphers_cut += not e["ciphers_seen"]
            t = table.setdefault(c["label"], {}).setdefault(arm, [0, 0])
            t[1] += 1
            t[0] += e["verdict"] != "unknown"
    h2_varies = [label for label, by_arm in table.items() if not label.startswith("browser chrome")
                 and len({round(d / n, 2) for d, n in by_arm.values()}) > 1]
    return {"arms": arms, "split": [split_flagged, split_truth], "fits_flagged": [fits_flagged, fits],
            "h1_exceptions": sorted(set(h1_exceptions)), "h2_varies": h2_varies,
            "h3_ciphers_cut": ciphers_cut, "decidable": table}


def median_by(rows, key, val, conds=("off", "audit", "enforce")):
    return {c: st.median(r[val] for r in rows if r[key] == c) for c in conds}


def score_exp5(R):
    cost = jsonl(R / "exp5/cost/runs.jsonl")
    cps = median_by(cost, "condition", "cps")
    stats = jsonl(R / "exp5/cost-stats/runs.jsonl")
    ns = {}
    for r in stats:
        b = (r["skbouncer"] or {}).get("bpf")
        if b:
            ns.setdefault(r["condition"], []).append(b["run_time_ns"] / b["run_cnt"])
    tput = median_by(jsonl(R / "exp5/load/throughput.jsonl"), "condition", "gbps")
    lat = {}
    for r in jsonl(R / "exp5/load/latency.jsonl"):
        lat.setdefault(r["condition"], []).extend(r["ms"])
    p = {c: (sorted(v)[len(v) // 2], sorted(v)[int(len(v) * 0.99)]) for c, v in lat.items()}
    pol = jsonl(R / "exp5/load/policy.jsonl")
    pol_med = {f"{k[0]} rules, {k[1]} ciphers": st.median(r["cps"] for r in pol if (r["rules"], r["ciphers"]) == k)
               for k in sorted({(r["rules"], r["ciphers"]) for r in pol})}
    dropped = sum((r.get("skbouncer") or {}).get("counters", {}).get("dropped", 0)
                  for f in ("cost/runs.jsonl", "cost-stats/runs.jsonl", "load/throughput.jsonl",
                            "load/latency.jsonl", "load/policy.jsonl")
                  for r in jsonl(R / "exp5" / f))
    sat = [(r["parallel"], round(r["cps"]), r["counters"]["dropped"]) for r in jsonl(R / "exp5/load/saturation.jsonl")]
    fp = json.loads((R / "exp5/load/footprint.json").read_text())
    return {"cps": cps, "ns_per_call": {c: st.mean(v) for c, v in ns.items()}, "gbps": tput,
            "latency_ms": p, "policy_cps": pol_med, "dropped": dropped, "saturation": sat, "footprint": fp}


def score_exp6(R):
    pols = {n: load_policy(R / f"exp6/policies/{n}.json") for n in ("min13", "ciphers", "min13_block")}
    rows = jsonl(R / "exp6/matrix.jsonl")
    agree = fail_open = 0
    for r in rows:
        pol = pols[r["policy"]]
        e = r["events"][0]
        blocked = not r["enforce_received"]
        ref = reference_verdict(pol, e.get("container"), r["reference"])
        expect = ref == "violation" if e["verdict"] != "unknown" else pol["unknown_block"]
        agree += blocked == expect
        fail_open += e["verdict"] == "unknown" and not pol["unknown_block"] and ref == "violation" and not blocked
    sc = {s["name"]: (s["audit"]["events"][0]["verdict"], not s["enforce"]["received"])
          for s in jsonl(R / "exp6/scenarios.jsonl")}
    waits = {w["label"]: (w["seconds"], w["capped"]) for w in jsonl(R / "exp6/waits.jsonl")}
    return {"rows": len(rows), "agree": agree, "fail_open": fail_open, "scenarios": sc, "waits": waits}


def score_exp7(R):
    out = {}
    for n in ("n10", "n50"):
        cons = jsonl(R / f"exp7/{n}/containers.jsonl")
        ev = [(c, e) for c in cons for e in c["events"]]
        out[n] = {"events": len(ev), "correct": sum(e.get("container") == c["name"] for c, e in ev),
                  "unnamed": sum(e.get("container") is None for c, e in ev)}
    return out


def score_exp8(R):
    agree = total = 0
    per_client, partial = {}, {}
    for part, _, c in exp3_connections(R):
        if part == "census-mixed":
            continue
        srv = c["server"]
        truth = grade(srv["ciphers"], srv["versions"], srv["legacy_version"])
        for e in c["events"]:
            mine = grade(e["ciphers"], e["versions"], e["legacy_version"])
            per_client.setdefault(c["label"], set()).add(truth)
            if e["ciphers_seen"] and e["versions_seen"]:
                total += 1
                agree += mine == truth
            else:
                partial.setdefault(c["label"], set()).add((mine, truth))
    return {"agree": agree, "total": total,
            "grades": {k: sorted(v) for k, v in per_client.items()},
            "partial": {k: sorted(v) for k, v in partial.items()}}


# -- the table ----------------------------------------------------------------

def label(R):
    return next(Path(R).glob("env-*.txt")).stem[len("env-"):]


def main(R, out=None):
    R = Path(R)
    out = Path(out) if out else REPO / "eval/results" / label(R)
    out.mkdir(parents=True, exist_ok=True)
    e1, e3, fz, e4 = exp1(R), score_exp3(R), score_fuzz(R), score_exp4(R)
    e5, e6, e7, e8 = score_exp5(R), score_exp6(R), score_exp7(R), score_exp8(R)
    rows = e1["rows"]
    cps, gb, lat, pc = e5["cps"], e5["gbps"], e5["latency_ms"], e5["policy_cps"]
    base = pc["1 rules, 30 ciphers"]
    worst_c13 = max(abs(pct(cps[c], cps["off"])) for c in ("audit", "enforce"))
    worst_c17 = max(abs(pct(gb[c], gb["off"])) for c in ("audit", "enforce"))
    worst_c18 = max(pct(lat[c][1], lat["off"][1]) for c in ("audit", "enforce"))
    rules_change = max(abs(pct(pc[k], base)) for k in pc if "30 ciphers" in k)
    cipher_change = pct(pc["1 rules, 1 ciphers"], base)
    fp = e5["footprint"]
    sat_ok = [x for x in e5["saturation"] if x[2] == 0]

    def met(ok):
        return "met" if ok else "not met"

    C = [
        ("C1", "Functional correctness", f"{sum(rows.values())} of {len(rows)} rows pass", "14 of 14",
         met(sum(rows.values()) == 14)),
        ("C2", "Detection rate", f"{e3['reported']} of {e3['connections']} ClientHellos reported", "100%",
         met(e3["reported"] == e3["connections"])),
        ("C3", "False positives", f"{e1['c3']['events']} events on {e1['c3']['connections_received']} "
         f"non-TLS connections ({e1['c3']['bytes_received']} bytes)", "0", met(e1["c3"]["events"] == 0)),
        ("C4", "Cipher list accuracy", f"{e3['cipher_lists'][0]} of {e3['cipher_lists'][1]} complete lists exact",
         "100%", met(e3["cipher_lists"][0] == e3["cipher_lists"][1])),
        ("C5", "Version accuracy", f"{e3['version_lists'][0]} of {e3['version_lists'][1]} complete lists exact",
         "100%", met(e3["version_lists"][0] == e3["version_lists"][1])),
        ("C6", "False certainty", f"{e3['false_certain']} fields flagged complete that differ", "0",
         met(e3["false_certain"] == 0)),
        ("C7", "Container attribution", f"{e3['named'][0]} of {e3['named'][1]} events", "100%",
         met(e3["named"][0] == e3["named"][1])),
        ("C8", "Truncation reporting", f"{e4['split'][0]} of {e4['split'][1]} split flagged; "
         f"{e4['fits_flagged'][0]} of {e4['fits_flagged'][1]} that fit flagged", "100%, none that fit",
         met(e4["split"][0] == e4["split"][1] and e4["fits_flagged"][0] == 0)),
        ("C9", "Fragmentation coverage", f"H1 {'holds' if not e4['h1_exceptions'] else 'holds except ' + '; '.join(e4['h1_exceptions'])}; "
         f"H2 {'holds' if not e4['h2_varies'] else 'fails for ' + ', '.join(e4['h2_varies'])}; "
         f"H3 {'holds' if not e4['h3_ciphers_cut'] else str(e4['h3_ciphers_cut']) + ' cipher lists cut'}",
         "tested against H1 to H3", "reported"),
        ("C10", "Verdict agreement", f"{e3['verdicts'][0]} of {e3['verdicts'][1]} decided verdicts "
         f"({e3['unknown']} unknown, scored in C9)", "100%", met(e3["verdicts"][0] == e3["verdicts"][1])),
        ("C11", "Enforcement accuracy", f"rows 8, 9, 10 {'pass' if all(rows[i] for i in (8, 9, 10)) else 'fail'}",
         "100% blocked, 0 compliant blocked", met(all(rows[i] for i in (8, 9, 10)))),
        ("C12", "Safe failure", f"rows 9, 11, 12, 13 {'pass' if all(rows[i] for i in (9, 11, 12, 13)) else 'fail'}",
         "all hold", met(all(rows[i] for i in (9, 11, 12, 13)))),
        ("C13", "Handshake overhead", f"{cps['off']:.1f} / {cps['audit']:.1f} / {cps['enforce']:.1f} per s "
         f"(off / audit / enforce), worst change {worst_c13:.2f}%", "under 5%", met(worst_c13 < 5)),
        ("C14", "Kernel cost per packet", " / ".join(f"{c} {v:.0f} ns" for c, v in sorted(e5["ns_per_call"].items())),
         "reported", "reported"),
        ("C15", "Event loss", f"{e5['dropped']} dropped across experiment 5", "0", met(e5["dropped"] == 0)),
        ("C16", "Robustness to malformed input",
         f"{0 if fz['alive'] and fz['attached'] == 1 else 1} crashes; {fz['false_complete']} false complete fields "
         f"over {fz['mutants']} mutants", "0 and 0",
         met(fz["alive"] and fz["attached"] == 1 and fz["false_complete"] == 0)),
        ("C17", "Data-path overhead", f"{gb['off']:.2f} / {gb['audit']:.2f} / {gb['enforce']:.2f} Gbps, "
         f"worst change {worst_c17:.2f}%", "under 5%", met(worst_c17 < 5)),
        ("C18", "Tail latency", f"p99 {lat['off'][1]:.3f} / {lat['audit'][1]:.3f} / {lat['enforce'][1]:.3f} ms, "
         f"worst change {worst_c18:+.1f}%", "under 10%", met(worst_c18 < 10)),
        ("C19", "Policy scalability", f"1 to 64 rules {rules_change:.2f}%; 1 against 30 ciphers {cipher_change:+.1f}% "
         f"(the client's handshake changes too)", "under 5%", met(rules_change < 5 and abs(cipher_change) < 5)),
        ("C20", "Saturation", f"no event dropped up to {max(x[0] for x in sat_ok)} parallel clients "
         f"({max(x[1] for x in sat_ok)} handshakes per s)", "reported", "reported"),
        ("C21", "Resource footprint", f"{fp['prog']['bytes_jited']} B JIT, {fp['prog']['verified_insns']} verified "
         f"instructions, {sum(m['bytes_memlock'] for m in fp['maps']) // 1024} KiB maps, {fp['rss_kib']} KiB RSS, "
         f"{fp['cpu_seconds']:.2f} s CPU in {fp['seconds']} s", "reported", "reported"),
        ("C22", "Enforcement at scale", f"{e6['agree']} of {e6['rows']} rows as the reference requires "
         f"({e6['fail_open']} fail-open passes on unknown)", "100%", met(e6["agree"] == e6["rows"])),
        ("C23", "Scenario validation", "; ".join(f"{n} {v} / {'blocked' if b else 'passed'}" for n, (v, b) in e6["scenarios"].items()),
         "all", met(all(v in ("violation", "unknown") and b for v, b in e6["scenarios"].values()))),
        ("C24", "Attribution under concurrency", "; ".join(f"{n[1:]} containers {v['correct']} of {v['events']}, "
         f"{v['unnamed']} unnamed" for n, v in e7.items()), "100%, none unnamed",
         met(all(v["correct"] == v["events"] and v["unnamed"] == 0 for v in e7.values()))),
        ("C25", "Grade agreement", f"{e8['agree']} of {e8['total']} ClientHellos read in full", "100%",
         met(e8["agree"] == e8["total"])),
    ]
    with open(out / "criteria.md", "w") as f:
        f.write(f"# Criteria results, {label(R)}\n\nGenerated by `eval/score.py` from "
                f"`eval/results/results-{label(R)}.tar.xz`.\n\n")
        f.write("| ID | Criterion | Result | Target | Status |\n|---|---|---|---|---|\n")
        for row in C:
            f.write("| " + " | ".join(row) + " |\n")
    detail = {"exp1": e1, "exp3": e3, "fuzz": fz, "exp4": e4, "exp5": e5, "exp6": e6, "exp7": e7, "exp8": e8}
    (out / "scores.json").write_text(json.dumps(detail, indent=1, default=list) + "\n")
    print((out / "criteria.md").read_text())


if __name__ == "__main__":
    main(*sys.argv[1:3])
