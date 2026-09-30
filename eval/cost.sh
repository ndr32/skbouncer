#!/usr/bin/env bash
# TLS handshake throughput with skbouncer off, in audit mode and in enforce
# mode; saves raw data. Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR [--rounds R] [--seconds S] [--policy FILE]" >&2
	exit 2
}

OUT= ROUNDS=10 SECS=30 POLICY=$R/eval/cost-policy.json
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--rounds) ROUNDS=$2; shift 2 ;;
	--seconds) SECS=$2; shift 2 ;;
	--policy) POLICY=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ $OUT && $ROUNDS =~ ^[1-9][0-9]*$ && $SECS =~ ^[1-9][0-9]*$ && -r $POLICY ]] || usage
POLICY=$(realpath "$POLICY")

PFX=skb-cost-$$
NET=$PFX-net SRV=$PFX-srv CLI=$PFX-client
PORT=4433
CONDITIONS=(off audit enforce)
SKB=

log() { echo "cost: $*" >&2; }
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

mkdir -p "$OUT/runs" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
: >"$OUT/runs.jsonl"
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1

# Pinning: CPU 0 is left to the host; the rest one each. Every process in
# a container inherits its cpuset, docker exec included.
NPROC=$(nproc)
STATS=$(sysctl -n kernel.bpf_stats_enabled)
PIN_SRV= PIN_CLI= PIN_SKB= TASKSET=()
if ((NPROC >= 6)); then
	PIN_SKB=1 PIN_SRV=2 PIN_CLI=3
	TASKSET=(taskset -c "$PIN_SKB")
fi

docker network create -o com.docker.network.driver.mtu=1500 "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" ${PIN_SRV:+--cpuset-cpus "$PIN_SRV"} skb-tls-test \
	openssl s_server -quiet -accept "$PORT" -cert /cert.pem -key /key.pem >/dev/null ||
	die "cannot start server"
docker run -d --name "$CLI" --network "$NET" ${PIN_CLI:+--cpuset-cpus "$PIN_CLI"} skb-tls-test \
	sleep infinity >/dev/null || die "cannot start client"
SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
[[ $SIP ]] || die "no server IP"

# Listening: state 0A; s_server binds dual-stack, so it shows in tcp6.
hex=$(printf '%04X' "$PORT")
for i in $(seq 100); do
	docker exec "$SRV" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
		break
	((i == 100)) && die "server never listened on $PORT"
	sleep 0.05
done

# The client's veth: the host end of its eth0.
idx=$(docker exec "$CLI" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -F': ' -v i="$idx" '$1 == i {sub(/@.*/, "", $2); print $2}')
[[ $VETH ]] || die "no veth for $CLI"
log "server $SIP:$PORT, client $CLI on $VETH, $NPROC CPUs, bpf_stats $STATS"

python3 - "$OUT/run.json" "$ROUNDS" "$SECS" "$POLICY" "$NPROC" "$STATS" "$PIN_SRV" "$PIN_CLI" "$PIN_SKB" <<'PY'
import json, sys
f, rounds, secs, policy, nproc, stats, srv, cli, skb = sys.argv[1:]
json.dump({"rounds": int(rounds), "seconds": int(secs), "policy": policy, "nproc": int(nproc),
           "bpf_stats_enabled": stats == "1",
           "pinning": {"server": srv, "client": cli, "skbouncer": skb} if srv else None},
          open(f, "w"))
PY

n_attached() {
	local net
	net=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null)
	grep -c skb_tc <<<"$net"
}

start_skb() { # condition base
	local args=(--container "$CLI" --format json -p "$POLICY") i
	[[ $1 == enforce ]] && args+=(--mode enforce)
	"${TASKSET[@]}" sudo -n ./skbouncer "${args[@]}" >"$2.jsonl" 2>"$2.err" &
	SKB=$!
	for i in $(seq 200); do
		grep -q 'Ctrl-C to stop' "$2.err" && return
		kill -0 "$SKB" 2>/dev/null || { SKB=; die "skbouncer exited: $(cat "$2.err")"; }
		sleep 0.05
	done
	die "skbouncer did not start"
}

stop_skb() {
	kill -INT "$SKB"
	wait "$SKB"
	SKB=
}

# One run. Wall time comes from the client's /proc/uptime (10 ms), read
# either side of s_time, since s_time reports whole seconds only.
run_one() { # round condition
	local base=$OUT/runs/$1-$2 st att bpf=
	[[ $2 != off ]] && start_skb "$2" "$base"
	docker exec "$CLI" sh -c "read a _ </proc/uptime
		openssl s_time -connect $SIP:$PORT -new -time $SECS 2>&1; r=\$?
		read b _ </proc/uptime; echo \"\$a \$b\" >&2; exit \$r" >"$base.s_time.txt" 2>"$base.wall" &
	st=$!
	sleep 1
	att=$(n_attached)
	wait "$st" || die "s_time failed in round $1 $2; see $base.s_time.txt"
	if [[ $2 != off ]]; then
		[[ $STATS == 1 ]] && { bpf=$(sudo -n bpftool -j prog show name skb_tc) || die "bpftool prog show failed"; }
		stop_skb
	fi
	python3 "$R/eval/cost.py" "$OUT" "$1" "$2" "$att" "$bpf" >&2 || die "cannot record round $1 $2"
}

for r in $(seq "$ROUNDS"); do
	k=$(((r - 1) % 3))
	for j in 0 1 2; do
		run_one "$r" "${CONDITIONS[(k + j) % 3]}"
	done
done
rm -f "$OUT"/runs/*.wall
log "saved to $OUT"
