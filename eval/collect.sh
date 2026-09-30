#!/usr/bin/env bash
# Runs TLS clients against a server with skbouncer watching; saves raw data.
# Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR --mtu N [--timestamps on|off] [--n K] [--policy FILE] CLIENTS" >&2
	exit 2
}

OUT= MTU= TS=on N=1 POLICY= CLIENTS=
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--mtu) MTU=$2; shift 2 ;;
	--timestamps) TS=$2; shift 2 ;;
	--n) N=$2; shift 2 ;;
	--policy) POLICY=$(realpath "$2"); shift 2 ;;
	-*) usage ;;
	*) CLIENTS=$(realpath "$1"); shift ;;
	esac
done
[[ $OUT && $MTU =~ ^[0-9]+$ && $N =~ ^[1-9][0-9]*$ && $TS =~ ^(on|off)$ && -r $CLIENTS ]] || usage
[[ -z $POLICY || -r $POLICY ]] || usage

SRV_GROUPS=X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM512:MLKEM768:MLKEM1024:X25519:X448:secp256r1:secp384r1:secp521r1
SNI=api.example.com
PFX=skb-eval-$$
NET=$PFX-net SRV=$PFX-srv ANCHOR=$PFX-anchor
PROBE_PORT=4999 PORT=5000
SKB=

log() { echo "collect: $*" >&2; }
die() { log "$*"; exit 1; }

cleanup() {
	trap - EXIT INT TERM
	if [[ $SKB ]]; then
		kill -INT "$SKB" 2>/dev/null
		wait "$SKB" 2>/dev/null
	fi
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT/server" "$OUT/clients" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
: >"$OUT/manifest.tsv"
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1

docker network create -o com.docker.network.driver.mtu="$MTU" "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" -v "$OUT/server:/logs" skb-tls-test sleep infinity >/dev/null ||
	die "cannot start server"
SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
[[ $SIP ]] || die "no server IP"
tsv=$([[ $TS == on ]] && echo 1 || echo 0)
docker run -d --name "$ANCHOR" --network "$NET" --add-host "$SNI:$SIP" \
	--sysctl net.ipv4.tcp_timestamps="$tsv" python:3-alpine sleep infinity >/dev/null ||
	die "cannot start anchor"

# A listener on the server: one s_server that exits after one connection.
# Returns once the port is in LISTEN (state 0A; s_server binds dual-stack).
listen() {
	local port=$1 cmd=$2 hex i
	hex=$(printf '%04X' "$port")
	docker exec -d "$SRV" sh -c "$cmd"
	for i in $(seq 100); do
		docker exec "$SRV" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
			return 0
		sleep 0.05
	done
	die "server never listened on $port"
}
s_server() { # port [extra]
	echo "openssl s_server -quiet -naccept 1 -accept $1 -groups $SRV_GROUPS -cert /cert.pem -key /key.pem ${2:-}"
}

# The MSS: what the kernel will put in one segment on this path, from a
# connection in the anchor's namespace. Not from skbouncer.
listen $PROBE_PORT "$(s_server $PROBE_PORT) >/dev/null 2>&1"
MSS=$(docker exec "$ANCHOR" python3 -c "
import socket
s = socket.create_connection(('$SIP', $PROBE_PORT), timeout=5)
print(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG))
s.close()") || die "cannot measure the MSS"
MTU_OBS=$(docker exec "$ANCHOR" cat /sys/class/net/eth0/mtu)
log "MTU $MTU_OBS, MSS $MSS, timestamps $TS"

args=(--container "$ANCHOR" --format json)
[[ $POLICY ]] && args+=(-p "$POLICY")
sudo -n ./skbouncer "${args[@]}" >"$OUT/skbouncer.jsonl" 2>"$OUT/skbouncer.err" &
SKB=$!
for i in $(seq 200); do
	grep -q 'Ctrl-C to stop' "$OUT/skbouncer.err" && break
	kill -0 "$SKB" 2>/dev/null || { SKB=; die "skbouncer exited: $(cat "$OUT/skbouncer.err")"; }
	sleep 0.05
done
grep -q 'Ctrl-C to stop' "$OUT/skbouncer.err" || die "skbouncer did not start"

# One connection. The client container stays up (sleeping) until its event
# has been named: skbouncer asks dockerd, which lists running containers only.
run_one() {
	local label=$1 image=$2 cmd=$3 rep=$4 port name i
	PORT=$((PORT + 1)); port=$PORT
	name=$PFX-c$port
	listen "$port" "$(s_server "$port" -msg) >/logs/$port.log 2>&1"
	cmd=${cmd//@SIP@/$SIP}; cmd=${cmd//@PORT@/$port}; cmd=${cmd//@SNI@/$SNI}
	docker run -d --name "$name" --network "container:$ANCHOR" --entrypoint sh "$image" \
		-c "$cmd; echo \"__skb_exit \$?\"; exec sleep 600" >/dev/null ||
		die "cannot start client $name"
	for i in $(seq 1800); do
		[[ $(docker logs "$name" 2>&1) == *__skb_exit* ]] && break
		sleep 0.1
	done
	for i in $(seq 50); do
		grep -q "\"dport\":$port[,}]" "$OUT/skbouncer.jsonl" && break
		sleep 0.1
	done
	docker logs "$name" >"$OUT/clients/$port.log" 2>&1
	docker rm -f "$name" >/dev/null
	printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$image" "$name" "$rep" "$port" >>"$OUT/manifest.tsv"
	log "$port $label (rep $rep)"
}

while IFS= read -r line; do
	[[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue
	IFS='|' read -r label image cmd <<<"$line"
	for rep in $(seq "$N"); do run_one "$label" "$image" "$cmd" "$rep"; done
done <"$CLIENTS"

sleep 0.5
kill -INT "$SKB"
wait "$SKB"
SKB=

python3 "$R/eval/collect.py" "$OUT" "$MTU" "$TS" "$N" "$NET" "$ANCHOR" "$MTU_OBS" "$MSS" ||
	die "cannot write run.json / connections.jsonl"
log "saved to $OUT"
