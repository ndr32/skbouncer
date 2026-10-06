#!/usr/bin/env bash
# M6.5 oracle: CLI usability. skbouncer is driven the way an operator would
# drive it: by container name, without looking up veths or directions.
#
# Contract (JSON fields from earlier milestones are unchanged):
#   --version works unprivileged; --help mentions --container.
#   --container NAME finds the container's veth, watches ingress, and in
#     enforce mode also supplies the --cgroup scope. Unknown names are refused.
#   -i <veth> watches ingress.
#   JSON events gain "reason" (why the verdict) and "time" (ISO 8601 wall
#     clock); in JSON mode stdout carries nothing but JSON lines.
#   Text lines show HH:MM:SS, versions as 1.3/1.2 not 0304, cipher names, and
#     the same reason; no bpftool hint.
#
# Runs verify-M6.sh first (which runs M5, M4, M3).
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
PFX=skb-verify-m65
SRV=$PFX-srv A=$PFX-a
OUT=.loop/verify-M6.5
LOADER=

die() { echo "verify: $*" >&2; exit 1; }
stop_loader() {
	if [[ -n "$LOADER" ]]; then
		kill -INT "$LOADER" 2>/dev/null
		wait "$LOADER" 2>/dev/null
		LOADER=
	fi
}
cleanup() {
	stop_loader
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
}
trap cleanup EXIT

AES=TLS_AES_128_GCM_SHA256
ALPN=$(python3 -c "print(','.join(f'proto-{i:04d}' for i in range(160)))")
OK="-tls1_3 -ciphersuites $AES -groups X25519"
DOWN="-groups X25519"
CHACHA="-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519"

echo "verify: M6 regression (includes M5, M4, M3)"
scripts/verify-M6.sh | tail -4
[[ ${PIPESTATUS[0]} == 0 ]] || die "M6 verifier fails; M6.5 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT/srv"
docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
make -s >/dev/null || die "build failed"

docker run -d --name "$SRV" -v "$PWD/$OUT/srv:/logs" "$IMAGE" sh -c '
	for p in $(seq 4481 4490); do
		openssl s_server -quiet -msg -naccept 1 -accept $p \
			-cert /cert.pem -key /key.pem >/logs/$p.log 2>&1 &
	done
	wait' >/dev/null || die "cannot start server container"
docker run -d --name "$A" "$IMAGE" sleep infinity >/dev/null || die "cannot start $A"
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
IDX=$(docker exec "$A" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
[[ -n $SIP && -n $VETH ]] || die "test containers have no network"

cat >"$OUT/policy.json" <<POLICY
{ "version": 1, "default": "deny",
  "rules": [ { "container": "$A", "min_version": "1.3",
               "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] } ] }
POLICY

# Captured, not piped: `bpftool | grep -q` under pipefail can SIGPIPE.
attached() { local o; o=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); [[ $o == *skb_tc* ]]; }
start() {	# name args...  -> returns 0 once attached, 1 if skbouncer exited
	local name=$1; shift
	sudo -n ./skbouncer "$@" >"$OUT/$name.out" 2>"$OUT/$name.err" &
	LOADER=$!
	for _ in $(seq 1 20); do
		attached && return 0
		kill -0 "$LOADER" 2>/dev/null || { LOADER=; return 1; }
		sleep 0.5
	done
	return 1
}
hs() {	# port args -> prints the issue time; client output in client-PORT.log
	date +%s
	docker exec "$A" sh -c "timeout 4 openssl s_client -brief -connect $SIP:$1 $2 </dev/null 2>&1" \
		>"$OUT/client-$1.log"
	sleep 0.5
}
seen() { grep -q ClientHello "$OUT/srv/$1.log" && echo True || echo False; }
est() { grep -q 'CONNECTION ESTABLISHED' "$OUT/client-$1.log" && echo True || echo False; }

./skbouncer --version >"$OUT/version.out" 2>&1; VERSION_RC=$?
./skbouncer --help >"$OUT/help.out" 2>&1
timeout -s INT 5 sudo -n ./skbouncer --container "$PFX-nope" >/dev/null 2>"$OUT/nope.err"
NOPE_RC=$?

start json --container "$A" -p "$OUT/policy.json" --format json ||
	die "skbouncer --container $A --format json did not attach: $(head -1 "$OUT/json.err")"
T84=$(hs 4484 "$OK"); T85=$(hs 4485 "$DOWN"); T86=$(hs 4486 "$CHACHA"); T87=$(hs 4487 "$OK -alpn $ALPN")
sleep 1; stop_loader

start text --container "$A" -p "$OUT/policy.json" ||
	die "skbouncer --container $A did not attach: $(head -1 "$OUT/text.err")"
T81=$(hs 4481 "$OK"); T82=$(hs 4482 "$DOWN"); T83=$(hs 4483 "$CHACHA")
sleep 1; stop_loader

INGRESS=0
if start ingress -i "$VETH" --format json; then
	hs 4488 "$OK" >/dev/null
	sleep 1; stop_loader
	INGRESS=$(grep -c '"dport": *4488' "$OUT/ingress.out")
fi

ENF_RC=0
EST89=False SEEN89=False EST90=False SEEN90=False
if start enforce --container "$A" --mode enforce -p "$OUT/policy.json" --format json; then
	# Sampled now, not at the end: a blocked ClientHello keeps being
	# retransmitted, and one arriving after skbouncer stops gets through.
	hs 4489 "$DOWN" >/dev/null; EST89=$(est 4489); SEEN89=$(seen 4489)
	hs 4490 "$OK" >/dev/null;   EST90=$(est 4490); SEEN90=$(seen 4490)
	sleep 1; stop_loader
else
	ENF_RC=1
fi

python3 - "$OUT" <<PY
import json, sys
out = sys.argv[1]
def err(n):
    try: return open(f"{out}/{n}").read()
    except OSError: return ""
json.dump({
  "container": "$A",
  "version": {"rc": $VERSION_RC, "out": err("version.out")},
  "help": err("help.out"),
  "no_such_container": {"name": "$PFX-nope", "rc": $NOPE_RC, "stderr": err("nope.err")},
  "json_cases": [
    {"name": "complies",  "port": 4484, "verdict": "allow",     "issued": $T84},
    {"name": "downgrade", "port": 4485, "verdict": "violation", "reason_has": "1.2",      "issued": $T85},
    {"name": "cipher",    "port": 4486, "verdict": "violation", "reason_has": "CHACHA20", "issued": $T86},
    {"name": "unseen",    "port": 4487, "verdict": "unknown",   "reason_has": "version",  "issued": $T87}],
  "text_cases": [
    {"name": "complies",  "port": 4481, "same_reason_as": "complies",
     "line_has": ["$AES", "1.3", "allow"], "issued": $T81},
    {"name": "downgrade", "port": 4482, "same_reason_as": "downgrade",
     "line_has": ["violation"], "issued": $T82},
    {"name": "cipher",    "port": 4483, "same_reason_as": "cipher",
     "line_has": ["violation"], "issued": $T83}],
  "ingress_default": {"events": $INGRESS},
  "enforce_cases": [
    {"name": "downgrade", "expect": "blocked", "rc_start": $ENF_RC, "err": err("enforce.err"),
     "established": $EST89, "server_saw_hello": $SEEN89},
    {"name": "complies",  "expect": "passed",  "rc_start": $ENF_RC, "err": err("enforce.err"),
     "established": $EST90, "server_saw_hello": $SEEN90}],
}, open(f"{out}/cases.json", "w"), indent=1)
PY
python3 tests/check_m6_5.py "$OUT"
