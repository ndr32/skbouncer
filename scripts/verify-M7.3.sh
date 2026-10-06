#!/usr/bin/env bash
# M7.3 oracle: two harnesses, eval/fuzz.sh (experiment 3, C16) and
# eval/attrib.sh (experiment 7, C24).
#
# fuzz.sh is run twice with one seed (the mutants must be identical) and
# checked against tests/check_m7_3.py's own decode of what was sent and what
# the sink received. attrib.sh is run with 10 containers. skbouncer itself
# must be unchanged from the latest eval-* tag, and nothing may be left behind.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=.loop/verify-M7.3
PFXS="skb-fuzz skb-attrib"

die() { echo "verify: $*" >&2; exit 1; }
cleanup() {
	for p in $PFXS; do
		docker ps -aq --filter "name=$p" | xargs -r docker rm -f >/dev/null 2>&1
		docker network ls -q --filter "name=$p" | xargs -r docker network rm >/dev/null 2>&1
	done
}
trap cleanup EXIT

# The tool must be the measured one: the latest eval-* tag, or FREEZE_REF.
REF=${FREEZE_REF:-$(git describe --tags --abbrev=0 --match 'eval-*' 2>/dev/null)}
[[ $REF ]] || die "no eval-* tag to compare the tool with; set FREEZE_REF"
git diff --quiet "$REF" -- src include Makefile policy ||
	die "skbouncer differs from $REF (src, include, Makefile or policy); tag the new version first"
make -s >/dev/null || die "build failed"
for h in eval/fuzz.sh eval/attrib.sh; do
	[[ -x $h ]] || die "$h missing or not executable"
done

rm -rf "$OUT"
mkdir -p "$OUT"
cleanup

echo "verify: fuzz.sh, 300 mutants, seed 7, twice"
for run in a b; do
	timeout 900 eval/fuzz.sh --out "$OUT/fuzz-$run" --n 300 --seed 7 >"$OUT/fuzz-$run.log" 2>&1 ||
		die "fuzz.sh failed (run $run); see $OUT/fuzz-$run.log"
done

echo "verify: attrib.sh, 10 containers, 3 handshakes each"
timeout 900 eval/attrib.sh --out "$OUT/attrib" --containers 10 --handshakes 3 >"$OUT/attrib.log" 2>&1 ||
	die "attrib.sh failed; see $OUT/attrib.log"

# What was left behind. Captured, not piped: pipefail + grep -q.
net=$(sudo -n bpftool net show 2>/dev/null) || die "cannot run bpftool via sudo -n"
python3 - "$OUT" \
	"$(for p in $PFXS; do docker ps -a --format '{{.Names}}' --filter "name=$p"; done | paste -sd, -)" \
	"$(for p in $PFXS; do docker network ls --format '{{.Name}}' --filter "name=$p"; done | paste -sd, -)" \
	"$(pgrep -x skbouncer | paste -sd, -)" \
	"$(grep -c skb_tc <<<"$net")" <<'PY'
import json, sys
out, c, n, p, a = sys.argv[1:]
json.dump({"containers": c, "networks": n, "skbouncer_pids": p, "attached": int(a)},
          open(f"{out}/leftovers.json", "w"))
PY

python3 tests/check_m7_3.py "$OUT"
