#!/usr/bin/env bash
# M7.2 oracle: the runtime cost runner, eval/cost.sh.
#
# Runs it for two rounds of 5-second runs (off, audit, enforce, rotated) and
# checks the saved runs against s_time's own output and skbouncer's raw
# events, read independently by tests/check_m7_2.py. bpf_stats is required
# only where the kernel has it switched on: on this VM sudo cannot switch it
# on, on EC2 it can. Also: skbouncer itself is frozen, and nothing is left
# running, attached or created.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=.loop/verify-M7.2
PFX=skb-cost

die() { echo "verify: $*" >&2; exit 1; }
cleanup() {
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
	docker network ls -q --filter "name=$PFX" | xargs -r docker network rm >/dev/null 2>&1
}
trap cleanup EXIT

REF=${FREEZE_REF:-main}
git diff --quiet "$REF" -- src include Makefile policy ||
	die "skbouncer differs from $REF (src, include, Makefile or policy); harness work must not change the tool"
make -s >/dev/null || die "build failed"
[[ -x eval/cost.sh ]] || die "eval/cost.sh missing or not executable"

rm -rf "$OUT"
mkdir -p "$OUT"
cleanup

echo "verify: cost runner, 2 rounds x 3 conditions x 5 s"
timeout 900 eval/cost.sh --out "$OUT/run" --rounds 2 --seconds 5 >"$OUT/run.log" 2>&1 ||
	die "cost runner failed; see $OUT/run.log"

# What it left behind, and what this host allows. Captured, not piped.
net=$(sudo -n bpftool net show 2>/dev/null) || die "cannot run bpftool via sudo -n"
python3 - "$OUT" \
	"$(docker ps -a --format '{{.Names}}' --filter "name=$PFX" | paste -sd, -)" \
	"$(docker network ls --format '{{.Name}}' --filter "name=$PFX" | paste -sd, -)" \
	"$(pgrep -x skbouncer | paste -sd, -)" \
	"$(grep -c skb_tc <<<"$net")" \
	"$(sysctl -n kernel.bpf_stats_enabled)" "$(nproc)" <<'PY'
import json, sys
out, c, n, p, a, stats, nproc = sys.argv[1:]
json.dump({"containers": c, "networks": n, "skbouncer_pids": p, "attached": int(a),
           "bpf_stats_enabled": stats == "1", "nproc": int(nproc)},
          open(f"{out}/host.json", "w"))
PY

python3 tests/check_m7_2.py "$OUT"
