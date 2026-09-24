#!/usr/bin/env bash
# M6 oracle: enforce mode (policy/README.md, Enforcement).
#
# Blocked or not is judged outside skbouncer: the client reports whether the
# TLS connection was established, and the server logs whether a ClientHello
# arrived. A block must stop the ClientHello reaching the server.
#
# Three containers share one veth; enforcement is scoped to one of them by
# --cgroup, so the other two must get verdicts but never be blocked.
#
# Contract for skbouncer: in enforce mode every JSON event also has
# "action": "block" | "pass", and "kernel_verdict": the verdict the tc program
# reached, which must equal the userspace "verdict". Enforce mode refuses to start without
# --cgroup, with the root cgroup, without -p, or on a non-veth interface.
#
# Runs verify-M5.sh first (which runs M4 and M3). Blocking happens only on
# test-container veths; the non-veth refusal is tested on lo, never ens33.
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
PFX=skb-verify-m6
SRV=$PFX-srv
OUT=.loop/verify-M6
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

ALPN=$(python3 -c "print(','.join(f'proto-{i:04d}' for i in range(160)))")
AES=TLS_AES_128_GCM_SHA256

# run|port|container|s_client args|expect|verdict|why
CASES="1|4471|strict|-tls1_3 -ciphersuites $AES -groups X25519|passed|allow|complies
1|4472|strict|-groups X25519|blocked|violation|offers TLS 1.2, below min 1.3
1|4473|strict|-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519|blocked|violation|offers a forbidden cipher
1|4474|strict|-tls1_3 -ciphersuites $AES -groups SecP384r1MLKEM1024|passed|allow|split post-quantum ClientHello that complies
1|4475|strict|-tls1_3 -ciphersuites $AES -groups X25519 -alpn $ALPN|passed|unknown|unknown, and on_unknown defaults to allow
1|4476|legacy|-tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384|passed|violation|violation, but outside the --cgroup scope
1|4477|stranger|-groups X25519|passed|violation|default deny, but outside the --cgroup scope
2|4478|strict|-tls1_3 -ciphersuites $AES -groups X25519 -alpn $ALPN|blocked|unknown|unknown with on_unknown block
2|4479|strict|-tls1_3 -ciphersuites $AES -groups X25519|passed|allow|on_unknown block leaves compliant traffic alone
3|4491|strict|-groups X25519|passed|allow|rule without a cipher list permits any cipher
4|4492|strict|-groups X25519|passed|allow|no rule matches, default allow
5|4493|strict|-tls1_3 -ciphersuites $AES -groups X25519|blocked|violation|no rule matches, default deny"

echo "verify: M5 regression (includes M4, M3)"
scripts/verify-M5.sh | tail -3
[[ ${PIPESTATUS[0]} == 0 ]] || die "M5 verifier fails; M6 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT/srv"
docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1

# The servers enable SecP384r1MLKEM1024: it is not in OpenSSL's default
# server groups, and without it the split post-quantum case cannot complete.
ports=$(echo "$CASES" | cut -d'|' -f2 | tr '\n' ' ')
docker run -d --name "$SRV" -v "$PWD/$OUT/srv:/logs" "$IMAGE" sh -c "
	for p in $ports; do
		openssl s_server -quiet -msg -naccept 1 -accept \$p \
			-groups SecP384r1MLKEM1024:X25519MLKEM768:X25519 \
			-cert /cert.pem -key /key.pem >/logs/\$p.log 2>&1 &
	done
	wait" >/dev/null || die "cannot start server container"
docker run -d --name "$PFX-strict" "$IMAGE" sleep infinity >/dev/null || die "cannot start $PFX-strict"
for c in legacy stranger; do
	docker run -d --name "$PFX-$c" --network "container:$PFX-strict" "$IMAGE" sleep infinity \
		>/dev/null || die "cannot start $PFX-$c"
done
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
[[ -n "$SIP" ]] || die "server container has no bridge address"
SCOPE=/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$PFX-strict").scope
[[ -d $SCOPE ]] || die "cannot find $PFX-strict's cgroup"
IDX=$(docker exec "$PFX-strict" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
[[ -n "$VETH" ]] || die "cannot find the shared veth"

policy() {	# default on_unknown rules
	cat <<POLICY
{ "version": 1, "default": "$1", "on_unknown": "$2", "rules": [ $3 ] }
POLICY
}
STRICT='{ "container": "'$PFX-strict'", "min_version": "1.3", "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] }'
LEGACY='{ "container": "'$PFX-legacy'", "min_version": "1.2", "ciphers": ["0xc02f"] }'
OPEN='{ "container": "'$PFX-strict'", "min_version": "1.2" }'
NOBODY='{ "container": "no-such-container", "min_version": "1.3" }'
policy deny  allow "$STRICT, $LEGACY" >"$OUT/policy-1.json"
policy deny  block "$STRICT, $LEGACY" >"$OUT/policy-2.json"
# Runs 3-5 exercise kernel paths runs 1-2 never reach, in scope, where a
# wrong kernel answer blocks traffic: no cipher list, and the fixed default.
policy deny  allow "$OPEN"   >"$OUT/policy-3.json"
policy allow allow "$NOBODY" >"$OUT/policy-4.json"
policy deny  allow "$NOBODY" >"$OUT/policy-5.json"
for f in "$OUT"/policy-*.json; do python3 -m json.tool "$f" >/dev/null || die "bad generated $f"; done

# Refusals: each must exit non-zero on its own rather than attach and hold.
refusal() {	# name must_mention args...
	local name=$1 mention=$2 rc
	shift 2
	timeout -s INT 5 sudo -n ./skbouncer "$@" >/dev/null 2>"$OUT/$name.err"
	rc=$?
	python3 -c 'import json,sys; print(json.dumps({"name":sys.argv[1],"kind":"refusal",
		"rc":int(sys.argv[2]),"must_mention":sys.argv[3],"stderr":open(sys.argv[4]).read()}))' \
		"$name" "$rc" "$mention" "$OUT/$name.err"
}
{
	refusal no_cgroup    --cgroup  --mode enforce -p "$OUT/policy-1.json" -i "$VETH" --direction ingress
	refusal root_cgroup  root      --mode enforce -p "$OUT/policy-1.json" -i "$VETH" --direction ingress --cgroup /sys/fs/cgroup
	refusal no_policy    polic     --mode enforce --cgroup "$SCOPE" -i "$VETH" --direction ingress
	refusal not_a_veth   veth      --mode enforce --cgroup "$SCOPE" -p "$OUT/policy-1.json" -i lo
} >"$OUT/refusals.jsonl"

# Captured, not piped: `bpftool | grep -q` under pipefail can SIGPIPE.
attached() { local out; out=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); [[ $out == *skb_tc* ]]; }

start_enforce() {	# run
	sudo -n ./skbouncer -i "$VETH" --direction ingress --format json --mode enforce \
		--cgroup "$SCOPE" -p "$OUT/policy-$1.json" >"$OUT/events-$1.jsonl" 2>"$OUT/loader-$1.err" &
	LOADER=$!
	for _ in $(seq 1 20); do
		attached && return 0
		kill -0 "$LOADER" 2>/dev/null || { LOADER=; die "skbouncer exited early: $(head -1 "$OUT/loader-$1.err")"; }
		sleep 0.5
	done
	die "skbouncer never attached to $VETH ingress"
}

: >"$OUT/handshakes.jsonl"
for run in 1 2 3 4 5; do
	start_enforce "$run"
	while IFS='|' read -r r port who args expect verdict why; do
		[[ $r == "$run" ]] || continue
		docker exec "$PFX-$who" sh -c "timeout 4 openssl s_client -brief -connect $SIP:$port $args </dev/null 2>&1" \
			>"$OUT/client-$port.log"
		sleep 0.5
		python3 -c 'import json,sys
port=sys.argv[1]
print(json.dumps({"name": sys.argv[2]+"_"+port, "kind": "handshake", "port": int(port), "run": int(sys.argv[7]),
    "expect": sys.argv[3], "verdict": sys.argv[4], "why": sys.argv[5],
    "established": "CONNECTION ESTABLISHED" in open(sys.argv[6]+"/client-"+port+".log").read(),
    "server_saw_hello": "ClientHello" in open(sys.argv[6]+"/srv/"+port+".log").read()}))' \
			"$port" "$who" "$expect" "$verdict" "$why" "$OUT" "$run" >>"$OUT/handshakes.jsonl"
	done <<<"$CASES"
	sleep 1
	stop_loader
done

# Tag events with their run. A blocked ClientHello keeps being retransmitted
# after its client gives up, so later runs, under other policies, see it too.
python3 -c 'import json,sys
for n in range(1, 6):
    for l in open(f"{sys.argv[1]}/events-{n}.jsonl"):
        if l.startswith("{"):
            e = json.loads(l); e["_run"] = n; print(json.dumps(e))' "$OUT" >"$OUT/events.jsonl"
python3 -c 'import json,sys; print(json.dumps([json.loads(l) for f in sys.argv[1:] for l in open(f)]))' \
	"$OUT/refusals.jsonl" "$OUT/handshakes.jsonl" >"$OUT/cases.json"
python3 tests/check_m6.py "$OUT/events.jsonl" "$OUT/cases.json"
