#!/usr/bin/env bash
# Sends malformed ClientHellos through skbouncer in audit mode, one per TCP
# connection; saves raw data. Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR [--n N] [--seed S]" >&2
	exit 2
}

OUT= N=5000 SEED=1
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--n) N=$2; shift 2 ;;
	--seed) SEED=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ $OUT && $N =~ ^[1-9][0-9]*$ && $SEED =~ ^[0-9]+$ ]] || usage
# Source ports are bound from BASE up, below the ephemeral range.
BASE=20000
((N <= 12000)) || { echo "fuzz: at most 12000 mutants (source ports $BASE-32767)" >&2; exit 2; }

PFX=skb-fuzz-$$
NET=$PFX-net SRV=$PFX-srv ANCHOR=$PFX-anchor
PORT=4433
SKB=

log() { echo "fuzz: $*" >&2; }
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

mkdir -p "$OUT/sink" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
: >"$OUT/sink/sink.log"
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1

python3 eval/fuzz.py gen "$N" "$SEED" >"$OUT/sends.jsonl" || die "cannot generate mutants"

docker network create -o com.docker.network.driver.mtu=1500 "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" -v "$R/eval/fuzz-sink.sh:/sink.sh:ro" -v "$OUT/sink:/logs" \
	skb-tls-test nc -lk -p "$PORT" -e /sink.sh >/dev/null || die "cannot start server"
SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
[[ $SIP ]] || die "no server IP"
docker run -d --name "$ANCHOR" --network "$NET" -v "$R/eval/fuzz.py:/fuzz.py:ro" \
	-v "$OUT/sends.jsonl:/sends.jsonl:ro" python:3-alpine sleep infinity >/dev/null ||
	die "cannot start anchor"

# Listening: state 0A, in tcp or tcp6.
hex=$(printf '%04X' "$PORT")
for i in $(seq 100); do
	docker exec "$SRV" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
		break
	((i == 100)) && die "sink never listened on $PORT"
	sleep 0.05
done

sudo -n ./skbouncer --container "$ANCHOR" --format json >"$OUT/skbouncer.jsonl" 2>"$OUT/skbouncer.err" &
SKB=$!
for i in $(seq 200); do
	grep -q 'Ctrl-C to stop' "$OUT/skbouncer.err" && break
	kill -0 "$SKB" 2>/dev/null || { SKB=; die "skbouncer exited: $(cat "$OUT/skbouncer.err")"; }
	sleep 0.05
done
grep -q 'Ctrl-C to stop' "$OUT/skbouncer.err" || die "skbouncer did not start"
VETH=$(sed -n 's/.*(\(veth[^ ]*\) ingress).*/\1/p' "$OUT/skbouncer.err" | head -1)
[[ $VETH ]] || die "no veth in skbouncer's start line"
log "sink $SIP:$PORT, anchor $ANCHOR on $VETH, $N mutants, seed $SEED"

docker exec "$ANCHOR" python3 /fuzz.py client /sends.jsonl "$SIP" "$PORT" "$BASE" >"$OUT/client.txt" 2>"$OUT/client.err" ||
	die "client failed after $(wc -l <"$OUT/client.txt") connections; see $OUT/client.err"

# The last events reach the jsonl after their connection closes.
sleep 0.5
alive=0
kill -0 "$SKB" 2>/dev/null && alive=1
net=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null)
attached=$(grep -c skb_tc <<<"$net")
log "after $(wc -l <"$OUT/client.txt") connections: alive $alive, $attached skb_tc on $VETH"
kill -INT "$SKB"
wait "$SKB"
SKB=

python3 eval/fuzz.py join "$OUT" "$N" "$SEED" "$alive" "$attached" ||
	die "cannot write run.json / mutants.jsonl"
rm -f "$OUT/sends.jsonl"
log "saved to $OUT"
