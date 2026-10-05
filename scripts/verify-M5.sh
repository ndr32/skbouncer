#!/usr/bin/env bash
# M5 oracle: policy loading and audit-mode verdicts (policy/README.md).
#
# Five containers share one network namespace, so one veth carries all of
# them and the policy must be applied per container by name. Expected
# verdicts are fixed below from the known ClientHello contents.
#
# Contract for skbouncer: `-p FILE` loads a policy; with one loaded, every
# JSON event also has "verdict": "allow" | "violation" | "unknown". A policy
# that is malformed or names an unknown cipher makes skbouncer exit non-zero
# before loading anything, with an error naming the problem.
#
# Runs verify-M4.sh first (which runs verify-M3.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
PFX=skb-verify-m5
SRV=$PFX-srv
OUT=.loop/verify-M5
LOADER=

die() { echo "verify: $*" >&2; exit 1; }

cleanup() {
	if [[ -n "$LOADER" ]]; then
		kill -INT "$LOADER" 2>/dev/null
		wait "$LOADER" 2>/dev/null
	fi
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
}
trap cleanup EXIT

# A long ALPN list: OpenSSL writes ALPN before supported_versions, so this
# pushes supported_versions past the first segment boundary.
ALPN=$(python3 -c "print(','.join(f'proto-{i:04d}' for i in range(160)))")

# port|container|s_client args|verdict|why|trunc
CASES="4451|strict|-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519|allow|TLS 1.3 only, permitted cipher|
4452|strict|-groups X25519|violation|also offers TLS 1.2, below min 1.3|
4453|strict|-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519|violation|offers 0x1303, not permitted|
4454|strict|-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups SecP384r1MLKEM1024|allow|record split across segments, but ciphers and versions fully seen|segment
4455|legacy|-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256|allow|0xc02f over TLS 1.2|
4456|legacy|-tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384|violation|offers 0xc030, not permitted|
4457|wide|-tls1_2 -cipher ALL:@SECLEVEL=0|unknown|83 offered, 64 seen and permitted, 19 unseen|
4458|other|-groups X25519|allow|matches glob rule with no cipher list|
4459|stranger|-groups X25519|violation|no rule matches, default deny|
4460|strict|-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 -alpn $ALPN|unknown|cut lands before supported_versions; cipher seen and permitted|segment
4461|strict|-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519 -alpn $ALPN|violation|cut before supported_versions, but a forbidden cipher was seen|segment"

echo "verify: M4 regression (includes M3)"
scripts/verify-M4.sh | tail -2
[[ ${PIPESTATUS[0]} == 0 ]] || die "M4 verifier fails; M5 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT"
docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1

# Policy load errors: must exit non-zero on its own, not load and hold.
load_error() {	# name file must_mention
	local rc
	timeout -s INT 10 sudo -n ./skbouncer -p "$2" >/dev/null 2>"$OUT/$1.err"
	rc=$?
	python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"kind":"load_error",
		"rc":int(sys.argv[2]),"must_mention":sys.argv[3],"stderr":open(sys.argv[4]).read()}))' \
		"$1" "$rc" "$3" "$OUT/$1.err"
}
echo '{"version": 1, "rules": [{"container": "x",}]}' >"$OUT/malformed.json"
echo '{"version": 1, "rules": [{"container": "x", "ciphers": ["TLS_AES_128_GCM_SHA999"]}]}' \
	>"$OUT/typo.json"
{
	load_error malformed_json "$OUT/malformed.json" line
	load_error unknown_cipher "$OUT/typo.json" TLS_AES_128_GCM_SHA999
} >"$OUT/load_errors.jsonl"

ports=$(echo "$CASES" | cut -d'|' -f1 | tr '\n' ' ')
docker run -d --name "$SRV" "$IMAGE" sh -c "
	for p in $ports; do
		openssl s_server -quiet -naccept 1 -accept \$p \
			-cert /cert.pem -key /key.pem >/dev/null 2>&1 &
	done
	wait" >/dev/null || die "cannot start server container"
docker run -d --name "$PFX-strict" "$IMAGE" sleep infinity >/dev/null || die "cannot start $PFX-strict"
for c in legacy wide other stranger; do
	docker run -d --name "$PFX-$c" --network "container:$PFX-strict" "$IMAGE" sleep infinity \
		>/dev/null || die "cannot start $PFX-$c"
done
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
[[ -n "$SIP" ]] || die "server container has no bridge address"

# Every cipher the "wide" client will offer, so all 64 it can see are allowed.
WIDE=$(docker exec "$PFX-wide" openssl ciphers -V -s -tls1_2 'ALL:@SECLEVEL=0' |
	awk '{split($1,b,","); printf "%s\"0x%s%s\"", (NR>1?",":""), tolower(substr(b[1],3)), tolower(substr(b[2],3))}')
cat >"$OUT/policy.json" <<POLICY
{
  "version": 1,
  "default": "deny",
  "rules": [
    { "container": "$PFX-strict", "min_version": "1.3",
      "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] },
    { "container": "$PFX-legacy", "min_version": "1.2", "ciphers": ["0xc02f"] },
    { "container": "$PFX-wide", "ciphers": [$WIDE] },
    { "container": "$PFX-o*", "min_version": "1.2" }
  ]
}
POLICY
python3 -m json.tool "$OUT/policy.json" >/dev/null || die "generated policy is not valid JSON"

IDX=$(docker exec "$PFX-strict" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
[[ -n "$VETH" ]] || die "cannot find the shared veth"

sudo -n ./skbouncer -i "$VETH" --format json -p "$OUT/policy.json" \
	>"$OUT/events.jsonl" 2>"$OUT/loader.err" &
LOADER=$!
# Captured, not piped: `bpftool | grep -q` under pipefail can SIGPIPE.
attached() { local out; out=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); [[ $out == *skb_tc* ]]; }
for _ in $(seq 1 20); do
	attached && break
	kill -0 "$LOADER" 2>/dev/null || { LOADER=; die "skbouncer exited early: $(head -1 "$OUT/loader.err")"; }
	sleep 0.5
done
attached || die "skbouncer never attached to $VETH ingress"

while IFS='|' read -r port who args verdict why trunc; do
	docker exec "$PFX-$who" sh -c "timeout 5 openssl s_client -connect $SIP:$port $args </dev/null >/dev/null 2>&1"
	sleep 0.3
	python3 -c 'import json,sys; c={"name":sys.argv[2]+"_"+sys.argv[1],"kind":"handshake",
		"port":int(sys.argv[1]),"container":sys.argv[3],"verdict":sys.argv[4],"why":sys.argv[5]}
if sys.argv[6]: c["trunc"]=sys.argv[6]
print(json.dumps(c))' "$port" "$who" "$PFX-$who" "$verdict" "$why" "$trunc"
done <<<"$CASES" >"$OUT/handshakes.jsonl"

sleep 1
kill -INT "$LOADER" 2>/dev/null
wait "$LOADER" 2>/dev/null
LOADER=

python3 -c 'import json,sys; print(json.dumps([json.loads(l) for f in sys.argv[1:] for l in open(f)]))' \
	"$OUT/load_errors.jsonl" "$OUT/handshakes.jsonl" >"$OUT/cases.json"
python3 tests/check_m5.py "$OUT/events.jsonl" "$OUT/cases.json"
