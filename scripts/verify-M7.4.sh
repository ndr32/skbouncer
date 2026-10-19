#!/usr/bin/env bash
# M7.4 oracle: two harnesses, eval/load.sh (experiment 5, C17 to C21) and
# eval/enforce.sh (experiment 6, C22 and C23), at sizes the 2-CPU VM can
# carry. tests/check_m7_4.py reads the server logs and raw outputs itself.
# Enforcement outcomes are reported, not failed: they measure a frozen tool.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=.loop/verify-M7.4
PFXS="skb-load skb-enforce"

die() { echo "verify: $*" >&2; exit 1; }
cleanup() {
	for p in $PFXS; do
		docker ps -aq --filter "name=$p" | xargs -r docker rm -f >/dev/null 2>&1
		docker network ls -q --filter "name=$p" | xargs -r docker network rm >/dev/null 2>&1
	done
}
trap cleanup EXIT

# The tool must be the measured one: the latest release tag (v*), or FREEZE_REF.
REF=${FREEZE_REF:-$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null)}
[[ $REF ]] || die "no release tag to compare the tool with; set FREEZE_REF"
git diff --quiet "$REF" -- src include Makefile policy ||
	die "skbouncer differs from $REF (src, include, Makefile or policy); tag the new version first"
make -s >/dev/null || die "build failed"
for h in eval/load.sh eval/enforce.sh; do
	[[ -x $h ]] || die "$h missing or not executable"
done

rm -rf "$OUT"
mkdir -p "$OUT"
cleanup

echo "verify: load.sh, 1 run of 3 s per condition, 200 handshakes, up to 2 parallel clients"
timeout 1200 eval/load.sh --out "$OUT/load" --runs 1 --seconds 3 --handshakes 200 --max-parallel 2 \
	>"$OUT/load.log" 2>&1 || die "load.sh failed; see $OUT/load.log"

cat >"$OUT/clients.txt" <<'EOF'
# label|image|command
openssl X25519 only (classical)|skb-tls-test|openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ </dev/null -groups X25519
openssl 3.5.8 default|skb-tls-test|openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ </dev/null
browser firefox147|lexiforest/curl-impersonate:latest|curl_firefox147 -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/
EOF
echo "verify: enforce.sh, 3 clients, 3 policies, 3 scenarios, wait cap 20 s"
timeout 1800 eval/enforce.sh --out "$OUT/enforce" --clients "$OUT/clients.txt" --wait-cap 20 \
	>"$OUT/enforce.log" 2>&1 || die "enforce.sh failed; see $OUT/enforce.log"

net=$(sudo -n bpftool net show 2>/dev/null) || die "cannot run bpftool via sudo -n"
python3 - "$OUT" \
	"$(for p in $PFXS; do docker ps -a --format '{{.Names}}' --filter "name=$p"; done | paste -sd, -)" \
	"$(for p in $PFXS; do docker network ls --format '{{.Name}}' --filter "name=$p"; done | paste -sd, -)" \
	"$(pgrep -x skbouncer | paste -sd, -)" \
	"$(grep -c skb_tc <<<"$net")" \
	"$(sysctl -n kernel.bpf_stats_enabled)" "$(nproc)" <<'PY'
import json, sys
out, c, n, p, a, stats, nproc = sys.argv[1:]
json.dump({"containers": c, "networks": n, "skbouncer_pids": p, "attached": int(a),
           "bpf_stats_enabled": stats == "1", "nproc": int(nproc)},
          open(f"{out}/host.json", "w"))
PY

python3 tests/check_m7_4.py "$OUT"
