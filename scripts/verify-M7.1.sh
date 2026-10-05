#!/usr/bin/env bash
# M7.1 oracle: the evaluation collector, eval/collect.sh.
#
# Runs the collector three times (MTU 1500 and 1280 with TCP timestamps on,
# 1500 with them off), three clients twice each, and checks what it saved
# against the server's own logs, decoded independently by
# tests/check_m7_1.py. Also: skbouncer itself is frozen (unchanged from
# main), eval/clients.txt carries the census client set, and nothing is left
# running, attached or created.
#
# Does not rerun the M3-M6.6 chain: the frozen check stands in for it.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=.loop/verify-M7.1
PFX=skb-eval

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
[[ -x eval/collect.sh ]] || die "eval/collect.sh missing or not executable"

rm -rf "$OUT"
mkdir -p "$OUT"
cleanup

# One classical client, one post-quantum client whose versions fit segment 1,
# and one browser whose versions do not.
cat >"$OUT/clients.txt" <<'EOF'
# label|image|command
openssl X25519 only (classical)|skb-tls-test|openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ -groups X25519 </dev/null
openssl 3.5.8 default|skb-tls-test|openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ </dev/null
browser firefox147|lexiforest/curl-impersonate:latest|curl_firefox147 -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/
EOF
cat >"$OUT/policy.json" <<'EOF'
{ "version": 1, "default": "allow", "rules": [ { "container": "*", "min_version": "1.3" } ] }
EOF

for run in "1500 on" "1280 on" "1500 off"; do
	set -- $run
	d="$OUT/$1-$2"
	echo "verify: collecting MTU $1, timestamps $2"
	timeout 900 eval/collect.sh --out "$d" --mtu "$1" --timestamps "$2" --n 2 \
		--policy "$OUT/policy.json" "$OUT/clients.txt" >"$d.log" 2>&1 ||
		die "collector failed for MTU $1, timestamps $2; see $d.log"
done

# What the collector left behind. Captured, not piped: pipefail + grep -q.
net=$(sudo -n bpftool net show 2>/dev/null) || die "cannot run bpftool via sudo -n"
python3 - "$OUT" \
	"$(docker ps -a --format '{{.Names}}' --filter "name=$PFX" | paste -sd, -)" \
	"$(docker network ls --format '{{.Name}}' --filter "name=$PFX" | paste -sd, -)" \
	"$(pgrep -x skbouncer | paste -sd, -)" \
	"$(grep -c skb_tc <<<"$net")" <<'PY'
import json, sys
out, c, n, p, a = sys.argv[1:]
json.dump({"containers": c, "networks": n, "skbouncer_pids": p, "attached": int(a)},
          open(f"{out}/leftovers.json", "w"))
PY

# The census client labels, as committed on main.
git show main:eval/census/results.jsonl >"$OUT/census.jsonl" || die "cannot read the census from main"

python3 tests/check_m7_1.py "$OUT"
