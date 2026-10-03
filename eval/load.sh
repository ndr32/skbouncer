#!/usr/bin/env bash
# skbouncer under load: bulk throughput, handshake latency, policy size,
# saturation and footprint, with skbouncer off, in audit mode and in
# enforce mode; saves raw data. Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR [--runs R] [--seconds S] [--handshakes H] [--max-parallel P]" >&2
	exit 2
}

OUT= RUNS=5 SECS=20 HS=2000 MAXP=8
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--runs) RUNS=$2; shift 2 ;;
	--seconds) SECS=$2; shift 2 ;;
	--handshakes) HS=$2; shift 2 ;;
	--max-parallel) MAXP=$2; shift 2 ;;
	*) usage ;;
	esac
done
for v in "$RUNS" "$SECS" "$HS" "$MAXP"; do [[ $v =~ ^[1-9][0-9]*$ ]] || usage; done
[[ $OUT ]] || usage

PFX=skb-load-$$
NET=$PFX-net SRV=$PFX-srv SINK=$PFX-sink CLI=$PFX-client PYC=$PFX-pyclient
PORT=4433 BULK_PORT=5001
CONDITIONS=(off audit enforce)
SKB=

log() { echo "load: $*" >&2; }
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

mkdir -p "$OUT/runs" "$OUT/policies" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
for f in throughput latency policy saturation; do : >"$OUT/$f.jsonl"; done
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1

# Pinning as in eval/cost.sh: CPU 0 is left to the host; the rest one each.
NPROC=$(nproc)
STATS=$(sysctl -n kernel.bpf_stats_enabled)
PIN_SRV= PIN_CLI= PIN_SKB= TASKSET=()
if ((NPROC >= 6)); then
	PIN_SKB=1 PIN_SRV=2 PIN_CLI=3
	TASKSET=(taskset -c "$PIN_SKB")
fi

# eval/cost-policy.json names skb-cost-*; the same rule for skb-load-*.
POLICY=$OUT/policies/cost.json
python3 eval/load.py policy eval/cost-policy.json 'skb-load-*' 1 "" "$POLICY" || die "cannot write $POLICY"

# Server side: s_server for handshakes, a Python sink for bulk data. Client
# side: skb-tls-test for s_time, python:3-alpine for bulk and timed handshakes.
docker network create -o com.docker.network.driver.mtu=1500 "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" ${PIN_SRV:+--cpuset-cpus "$PIN_SRV"} skb-tls-test \
	openssl s_server -quiet -accept "$PORT" -cert /cert.pem -key /key.pem >/dev/null ||
	die "cannot start server"
for c in "$SINK" "$PYC"; do
	pin=$([[ $c == "$SINK" ]] && echo "$PIN_SRV" || echo "$PIN_CLI")
	docker run -d --name "$c" --network "$NET" ${pin:+--cpuset-cpus "$pin"} \
		-v "$R/eval/load.py:/load.py:ro" python:3-alpine sleep infinity >/dev/null || die "cannot start $c"
done
docker run -d --name "$CLI" --network "$NET" ${PIN_CLI:+--cpuset-cpus "$PIN_CLI"} skb-tls-test \
	sleep infinity >/dev/null || die "cannot start client"
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
SIP=$(ip_of "$SRV") SINK_IP=$(ip_of "$SINK")
[[ $SIP && $SINK_IP ]] || die "no server IP"

# Listening: state 0A; s_server binds dual-stack, so it shows in tcp6.
listening() { # container port
	local hex i
	hex=$(printf '%04X' "$2")
	for i in $(seq 100); do
		docker exec "$1" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
			return 0
		sleep 0.05
	done
	die "$1 never listened on $2"
}
listening "$SRV" "$PORT"

# Each client's veth: the host end of its eth0.
declare -A VETH
for c in "$CLI" "$PYC"; do
	idx=$(docker exec "$c" cat /sys/class/net/eth0/iflink)
	VETH[$c]=$(ip -o link | awk -F': ' -v i="$idx" '$1 == i {sub(/@.*/, "", $2); print $2}')
	[[ ${VETH[$c]} ]] || die "no veth for $c"
done
log "server $SIP:$PORT, sink $SINK_IP:$BULK_PORT, $NPROC CPUs, bpf_stats $STATS"

python3 - "$OUT/run.json" "$RUNS" "$SECS" "$HS" "$MAXP" "$NPROC" "$STATS" "$PIN_SRV" "$PIN_CLI" "$PIN_SKB" <<'PY'
import json, sys
f, runs, secs, hs, maxp, nproc, stats, srv, cli, skb = sys.argv[1:]
json.dump({"runs": int(runs), "seconds": int(secs), "handshakes": int(hs), "max_parallel": int(maxp),
           "nproc": int(nproc), "bpf_stats_enabled": stats == "1",
           "pinning": {"server": srv, "client": cli, "skbouncer": skb} if srv else None},
          open(f, "w"))
PY

n_attached() { # container
	local net
	net=$(sudo -n bpftool net show dev "${VETH[$1]}" 2>/dev/null)
	grep -c skb_tc <<<"$net"
}

start_skb() { # container mode policy base
	local args=(--container "$1" --format json -p "$3") i
	[[ $2 == enforce ]] && args+=(--mode enforce)
	"${TASKSET[@]}" sudo -n ./skbouncer "${args[@]}" >"$4.jsonl" 2>"$4.err" &
	SKB=$!
	for i in $(seq 200); do
		grep -q 'Ctrl-C to stop' "$4.err" && return
		kill -0 "$SKB" 2>/dev/null || { SKB=; die "skbouncer exited: $(cat "$4.err")"; }
		sleep 0.05
	done
	die "skbouncer did not start"
}

stop_skb() {
	kill -INT "$SKB"
	wait "$SKB"
	SKB=
}

# The skbouncer process itself: sudo's descendant.
skb_pid() {
	local p=$SKB c
	while [[ $(cat /proc/"$p"/comm 2>/dev/null) != skbouncer ]]; do
		c=$(pgrep -P "$p" | head -1)
		[[ $c ]] || return 1
		p=$c
	done
	echo "$p"
}

# s_time for S seconds from the skb-tls-test client, P at once. Wall time
# from /proc/uptime either side, as in eval/cost.sh.
s_time() { # base parallel [s_time args]
	local base=$1 p=$2
	shift 2
	docker exec "$CLI" sh -c "read a _ </proc/uptime
		pids=; for i in \$(seq $p); do openssl s_time -connect $SIP:$PORT -new -time $SECS $* >/tmp/st.\$i 2>&1 & pids=\"\$pids \$!\"; done
		r=0; for j in \$pids; do wait \$j || r=1; done
		read b _ </proc/uptime; cat /tmp/st.*; rm -f /tmp/st.*; echo \"\$a \$b\" >&2; exit \$r" \
		>"$base.s_time.txt" 2>"$base.wall"
}

# One measured run: skbouncer per condition on CONTAINER, the workload,
# attached sampled 1 s in, then one row. WORK is a function name.
run_one() { # out.jsonl base container condition policy fields work [args]
	local out=$1 base=$2 c=$3 cond=$4 pol=$5 fields=$6 work=$7 w att bpf=
	shift 7
	[[ $cond != off ]] && start_skb "$c" "$cond" "$pol" "$base"
	"$work" "$base" "$@" &
	w=$!
	sleep 1
	att=$(n_attached "$c")
	wait "$w" || die "workload failed: $base"
	if [[ $cond != off ]]; then
		[[ $STATS == 1 ]] && { bpf=$(sudo -n bpftool -j prog show name skb_tc) || die "bpftool prog show failed"; }
		stop_skb
	fi
	python3 eval/load.py row "$out" "$base" "$att" "$bpf" "$fields" >&2 || die "cannot record $base"
}

bulk() { # base
	docker exec "$SINK" python3 /load.py sink "$BULK_PORT" >"$1.out" 2>"$1.sink.err" &
	local s=$!
	listening "$SINK" "$BULK_PORT"
	docker exec "$PYC" python3 /load.py send "$SINK_IP" "$BULK_PORT" "$SECS" || return 1
	wait "$s"
}

handshakes() { # base
	docker exec "$PYC" python3 /load.py hs "$SIP" "$PORT" "$HS" >"$1.out" 2>"$1.hs.err"
}

rotated() { # round -> the three conditions in this round's order
	local k=$((($1 - 1) % 3)) j
	for j in 0 1 2; do echo "${CONDITIONS[(k + j) % 3]}"; done
}

log "1. throughput (C17), $RUNS x $SECS s per condition"
for r in $(seq "$RUNS"); do
	for c in $(rotated "$r"); do
		run_one "$OUT/throughput.jsonl" "$OUT/runs/tput-$r-$c" "$PYC" "$c" "$POLICY" \
			"{\"_kind\": \"bulk\", \"round\": $r, \"condition\": \"$c\"}" bulk
	done
done

log "2. latency (C18), $RUNS x $HS handshakes per condition"
for r in $(seq "$RUNS"); do
	for c in $(rotated "$r"); do
		run_one "$OUT/latency.jsonl" "$OUT/runs/lat-$r-$c" "$PYC" "$c" "$POLICY" \
			"{\"_kind\": \"hs\", \"round\": $r, \"condition\": \"$c\"}" handshakes
	done
done

# Policy sizes: rules and permitted ciphers. The last rule matches the
# client; with one cipher the client offers only that one.
log "3. policy scalability (C19), enforce, $RUNS x $SECS s per policy"
SIZES=("1 30" "16 30" "64 30" "1 1")
for s in "${SIZES[@]}"; do
	set -- $s
	cipher=$([[ $2 == 1 ]] && echo 0x1301)
	python3 eval/load.py policy eval/cost-policy.json 'skb-load-*' "$1" "$cipher" "$OUT/policies/r$1-c$2.json" ||
		die "cannot write policy r$1-c$2"
done
for r in $(seq "$RUNS"); do
	k=$(((r - 1) % ${#SIZES[@]}))
	for j in $(seq 0 $((${#SIZES[@]} - 1))); do
		set -- ${SIZES[(k + j) % ${#SIZES[@]}]}
		args=()
		[[ $2 == 1 ]] && args=(-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256)
		run_one "$OUT/policy.jsonl" "$OUT/runs/pol-$r-r$1-c$2" "$CLI" enforce "$OUT/policies/r$1-c$2.json" \
			"{\"_kind\": \"s_time\", \"round\": $r, \"rules\": $1, \"ciphers\": $2}" s_time 1 "${args[@]}"
	done
done

log "4. saturation (C20), audit, $SECS s per level up to $MAXP clients"
for ((p = 1; p <= MAXP; p *= 2)); do
	run_one "$OUT/saturation.jsonl" "$OUT/runs/sat-$p" "$CLI" audit "$POLICY" \
		"{\"_kind\": \"s_time\", \"_counters_only\": true, \"parallel\": $p}" s_time "$p"
done

log "5. footprint (C21), audit, $SECS s"
base=$OUT/runs/footprint
start_skb "$CLI" audit "$POLICY" "$base"
s_time "$base" 1 || die "s_time failed during the footprint run"
pid=$(skb_pid) || die "no skbouncer process under $SKB"
prog=$(sudo -n bpftool -j prog show name skb_tc) || die "bpftool prog show failed"
maps=$(sudo -n bpftool -j map show) || die "bpftool map show failed"
# bpftool 7.7 does not print verified_insns, and the kernel shows it only in
# the loader's fdinfo. A separate load of the same object with verifier
# stats (-d) gives it: audit-mode rodata defaults, and a pin path that cannot
# exist (-n: never mount), so the program is freed as bpftool exits.
insns=$(sudo -n bpftool -n -d prog load build/skbouncer.bpf.o "/sys/fs/bpf/$PFX-none/prog" 2>&1 |
	sed -n 's/^processed \([0-9]*\) insns.*/\1/p')
[[ $insns ]] || die "no verifier stats from bpftool -d prog load"
python3 eval/load.py footprint "$OUT/footprint.json" "$prog" "$maps" "$pid" "$SECS" "$insns" ||
	die "cannot write footprint.json"
stop_skb

rm -f "$OUT"/runs/*.wall
log "saved to $OUT"
