#!/usr/bin/env bash
# Enforce mode against real clients: every client under three policies,
# three scripted scenarios in audit and enforce mode, and how long a blocked
# client waits; saves raw data. Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR [--clients FILE] [--wait-cap S]" >&2
	exit 2
}

OUT= CLIENTS=$R/eval/clients.txt CAP=300
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--clients) CLIENTS=$2; shift 2 ;;
	--wait-cap) CAP=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ $OUT && -r $CLIENTS && $CAP =~ ^[1-9][0-9]*$ ]] || usage
CLIENTS=$(realpath "$CLIENTS")

SRV_GROUPS=X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM512:MLKEM768:MLKEM1024:X25519:X448:secp256r1:secp384r1:secp521r1
SNI=api.example.com
PFX=skb-enforce-$$
NET=$PFX-net SRV=$PFX-srv
PORT=5000
TMO=15
POLICIES=(min13 ciphers min13_block)
SKBS=()

log() { echo "enforce: $*" >&2; }
die() { log "$*"; exit 1; }

cleanup() {
	trap - EXIT INT TERM
	local p
	for p in "${SKBS[@]}"; do kill -INT "$p" 2>/dev/null; done
	for p in "${SKBS[@]}"; do wait "$p" 2>/dev/null; done
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT/server" "$OUT/clients" "$OUT/skb" "$OUT/policies" "$OUT/scenarios" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
for f in matrix scenarios waits; do : >"$OUT/$f.jsonl"; done
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1
python3 eval/enforce.py policies "$OUT/policies" || die "cannot write the policies"

docker network create -o com.docker.network.driver.mtu=1500 "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" -v "$OUT/server:/logs" skb-tls-test sleep infinity >/dev/null ||
	die "cannot start server"
SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
[[ $SIP ]] || die "no server IP"

python3 - "$OUT/run.json" "$CLIENTS" "$CAP" "${POLICIES[@]}" <<'PY'
import json, sys
f, clients, cap, *pols = sys.argv[1:]
json.dump({"clients": clients, "policies": pols, "wait_cap": int(cap)}, open(f, "w"))
PY

# A listener: one s_server -msg that exits after one connection. Returns
# once the port is in LISTEN (state 0A; s_server binds dual-stack).
listen() { # port [extra]
	local hex i
	hex=$(printf '%04X' "$1")
	docker exec -d "$SRV" sh -c "openssl s_server -quiet -msg -naccept 1 -accept $1 -groups $SRV_GROUPS \
		-cert /cert.pem -key /key.pem ${2:-} >/logs/$1.log 2>&1"
	for i in $(seq 100); do
		docker exec "$SRV" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
			return 0
		sleep 0.05
	done
	die "server never listened on $1"
}

# A blocked ClientHello leaves its s_server waiting; let a finished one
# flush and exit, then stop the rest.
unlisten() { # port
	local i
	for i in $(seq 20); do
		docker exec "$SRV" pgrep -f "accept $1 " >/dev/null || return 0
		sleep 0.1
	done
	docker exec "$SRV" pkill -f "accept $1 " >/dev/null 2>&1
}

start_skb() { # base container mode policy [text]
	local args=(--container "$2" -p "$4") i err=$1.err
	[[ $3 == enforce ]] && args+=(--mode enforce)
	if [[ ${5:-} ]]; then
		err=$5
		sudo -n ./skbouncer "${args[@]}" >"$5" 2>&1 &
	else
		sudo -n ./skbouncer "${args[@]}" --format json >"$1.jsonl" 2>"$err" &
	fi
	SKBS+=($!)
	for i in $(seq 200); do
		grep -q 'Ctrl-C to stop' "$err" && return
		kill -0 "${SKBS[-1]}" 2>/dev/null || die "skbouncer exited: $(cat "$err")"
		sleep 0.05
	done
	die "skbouncer did not start on $2"
}

stop_skbs() {
	local p
	for p in "${SKBS[@]}"; do kill -INT "$p"; done
	for p in "${SKBS[@]}"; do wait "$p"; done
	SKBS=()
}

# One connection from a fresh container on its own veth. Its skbouncer
# (none for mode off) attaches before the client starts; the container is
# removed before skbouncer stops, so no orphaned retransmit can pass once
# enforcement is gone. Sets PORT to the port used. SCENARIO: the scenario
# server; TEXT: a text instance saving to that file instead of JSON (two
# enforcing instances would hide the drop from the second). WAIT: time the
# client under timeout WAIT instead of TMO and leave the marker in WAITED.
pass() { # image cmd mode policy [scenario] [text] [wait]
	local image=$1 cmd=$2 mode=$3 pol=$4 scen=${5:-} text=${6:-} wcap=${7:-} c i
	PORT=$((PORT + 1))
	local extra=
	[[ $scen ]] && extra="-cipher ALL@SECLEVEL=0 -min_protocol TLSv1"
	listen "$PORT" "$extra"
	c=$PFX-c$PORT
	docker run -d --name "$c" --network "$NET" --add-host "$SNI:$SIP" --entrypoint sh "$image" \
		-c 'exec sleep infinity' >/dev/null || die "cannot start client $c"
	cmd=${cmd//@SIP@/$SIP}; cmd=${cmd//@PORT@/$PORT}; cmd=${cmd//@SNI@/$SNI}
	if [[ $mode != off ]]; then
		start_skb "$OUT/skb/$PORT" "$c" "$mode" "$OUT/policies/$pol.json" "$text"
	fi
	if [[ $wcap ]]; then
		WAITED=$(docker exec "$c" sh -c 'read a _ </proc/uptime; timeout "$1" sh -c "$2" >/tmp/client.log 2>&1
			r=$?; read b _ </proc/uptime; echo "$a $b $r"' sh "$wcap" "$cmd")
		docker exec "$c" cat /tmp/client.log >"$OUT/clients/$PORT.log" 2>&1
	else
		docker exec "$c" timeout "$TMO" sh -c "$cmd" >"$OUT/clients/$PORT.log" 2>&1
	fi
	if [[ $text ]]; then
		sleep 1
	elif [[ $mode != off ]]; then
		for i in $(seq 50); do
			grep -q "\"dport\":$PORT[,}]" "$OUT/skb/$PORT.jsonl" && break
			sleep 0.1
		done
	fi
	docker rm -f "$c" >/dev/null
	[[ $mode != off ]] && stop_skbs
	unlisten "$PORT"
}

log "matrix: every client under ${POLICIES[*]}, reference then enforce"
while IFS= read -r line; do
	[[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue
	IFS='|' read -r label image cmd <<<"$line"
	for pol in "${POLICIES[@]}"; do
		pass "$image" "$cmd" off "$pol"; ref=$PORT
		pass "$image" "$cmd" enforce "$pol"; enf=$PORT
		python3 eval/enforce.py matrix "$OUT" "$label" "$pol" "$ref" "$enf" >&2 ||
			die "cannot record $label / $pol"
	done
done <"$CLIENTS"

log "scenarios, audit then enforce, each with JSON and then text output"
OSSL="openssl s_client -connect @SIP@:@PORT@ -servername @SNI@ </dev/null"
SCENARIOS=(
	"legacy|min13|skb-tls-test|$OSSL -min_protocol TLSv1 -max_protocol TLSv1.1 -cipher ALL@SECLEVEL=0"
	"cbc_sha1|ciphers|skb-tls-test|$OSSL -tls1_2 -cipher ECDHE-RSA-AES128-SHA"
	"pq_unknown|min13_block|lexiforest/curl-impersonate:latest|curl_firefox147 -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/"
)
for s in "${SCENARIOS[@]}"; do
	IFS='|' read -r name pol image cmd <<<"$s"
	pass "$image" "$cmd" audit "$pol" 1; a=$PORT
	pass "$image" "$cmd" audit "$pol" 1 "$OUT/scenarios/$name-audit.txt"
	pass "$image" "$cmd" enforce "$pol" 1; e=$PORT
	pass "$image" "$cmd" enforce "$pol" 1 "$OUT/scenarios/$name-enforce.txt"
	python3 eval/enforce.py scenario "$OUT" "$name" "$a" "$e" >&2 || die "cannot record scenario $name"
done

log "wait times under min13, capped at $CAP s"
while IFS= read -r line; do
	[[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue
	IFS='|' read -r label image cmd <<<"$line"
	WAITED=
	pass "$image" "$cmd" enforce min13 "" "" "$CAP"
	[[ $WAITED ]] || die "no wait time for $label"
	python3 eval/enforce.py wait "$OUT" "$label" "$CAP" "$WAITED" >&2 || die "cannot record the wait for $label"
done <"$CLIENTS"

log "saved to $OUT"
