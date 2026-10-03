#!/usr/bin/env bash
# Many containers make TLS handshakes at once, half of them sharing network
# namespaces, with one skbouncer per veth in audit mode; saves raw data.
# Scores nothing. Run from anywhere; see usage().
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: $0 --out DIR --containers N [--handshakes K]   (N a multiple of 10)" >&2
	exit 2
}

OUT= N= K=5
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--containers) N=$2; shift 2 ;;
	--handshakes) K=$2; shift 2 ;;
	*) usage ;;
	esac
done
[[ $OUT && $N =~ ^[1-9][0-9]*$ && $K =~ ^[1-9][0-9]*$ ]] && ((N % 10 == 0)) || usage

PFX=skb-attrib-$$
NET=$PFX-net SRV=$PFX-srv
PORT=5000
GROUP=5
SKBS=()

log() { echo "attrib: $*" >&2; }
die() { log "$*"; exit 1; }

cleanup() {
	trap - EXIT INT TERM
	local p
	for p in "${SKBS[@]}"; do kill -INT "$p" 2>/dev/null; done
	for p in "${SKBS[@]}"; do wait "$p" 2>/dev/null; done
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	[[ -d ${OUT:-}/go ]] && rm -rf "$OUT/go"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT/skb" "$OUT/clients" "$OUT/go" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
: >"$OUT/manifest.tsv"
cd "$R"

log "environment"
eval/env.sh >"$OUT/env.txt" 2>&1

docker network create -o com.docker.network.driver.mtu=1500 "$NET" >/dev/null ||
	die "cannot create network $NET"
docker run -d --name "$SRV" --network "$NET" skb-tls-test sleep infinity >/dev/null ||
	die "cannot start server"
SIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
[[ $SIP ]] || die "no server IP"

# Containers: the first half alone, the second half in groups of GROUP on
# one namespace, the first of each group owning the veth. Each has a port.
# OWNER[i] is the container whose veth carries container i's traffic.
NAMES=() OWNER=() SHARED=() DPORT=()
for ((i = 0; i < N; i++)); do
	if ((i < N / 2)); then
		NAMES+=("$PFX-s$((i + 1))") OWNER+=("$PFX-s$((i + 1))") SHARED+=(0)
	else
		g=$(((i - N / 2) / GROUP + 1)) m=$(((i - N / 2) % GROUP + 1))
		NAMES+=("$PFX-g$g-$m") OWNER+=("$PFX-g$g-1") SHARED+=(1)
	fi
	DPORT+=($((PORT + i + 1)))
done

# One s_server per container, each exiting after K connections.
for ((i = 0; i < N; i++)); do
	docker exec -d "$SRV" openssl s_server -quiet -naccept "$K" -accept "${DPORT[i]}" \
		-cert /cert.pem -key /key.pem
done
for ((i = 0; i < N; i++)); do
	hex=$(printf '%04X' "${DPORT[i]}")
	for j in $(seq 100); do
		docker exec "$SRV" grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 &&
			break
		((j == 100)) && die "server never listened on ${DPORT[i]}"
		sleep 0.05
	done
done

# Clients sleep until the run starts; skbouncer names a container only
# while it is running. /go is the start line they all wait on.
declare -A VETH IP
for ((i = 0; i < N; i++)); do
	name=${NAMES[i]} own=${OWNER[i]}
	if [[ $name == "$own" ]]; then
		docker run -d --name "$name" --network "$NET" -v "$OUT/go:/go" skb-tls-test sleep infinity >/dev/null ||
			die "cannot start $name"
		idx=$(docker exec "$name" cat /sys/class/net/eth0/iflink)
		VETH[$name]=$(ip -o link | awk -F': ' -v i="$idx" '$1 == i {sub(/@.*/, "", $2); print $2}')
		IP[$name]=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$name")
		[[ ${VETH[$name]} && ${IP[$name]} ]] || die "no veth or IP for $name"
	else
		docker run -d --name "$name" --network "container:$own" -v "$OUT/go:/go" skb-tls-test sleep infinity >/dev/null ||
			die "cannot start $name"
	fi
	printf '%s\t%s\t%s\t%s\t%s\n' "$name" "${SHARED[i]}" "${VETH[$own]}" "${IP[$own]}" "${DPORT[i]}" >>"$OUT/manifest.tsv"
done

# One skbouncer per veth, all attached before any handshake.
OWNS=($(printf '%s\n' "${OWNER[@]}" | uniq))
for own in "${OWNS[@]}"; do
	base=$OUT/skb/${VETH[$own]}
	sudo -n ./skbouncer --container "$own" --format json >"$base.jsonl" 2>"$base.err" &
	SKBS+=($!)
done
for ((j = 0; j < ${#SKBS[@]}; j++)); do
	base=$OUT/skb/${VETH[${OWNS[j]}]}
	for i in $(seq 200); do
		grep -q 'Ctrl-C to stop' "$base.err" && break
		kill -0 "${SKBS[j]}" 2>/dev/null || die "skbouncer exited: $(cat "$base.err")"
		sleep 0.05
	done
	grep -q 'Ctrl-C to stop' "$base.err" || die "skbouncer did not start on ${base##*/}"
done
log "$N containers, ${#SKBS[@]} veths, $K handshakes each, server $SIP"

# Every container's K handshakes, one after another, from the same start.
CLIS=()
for ((i = 0; i < N; i++)); do
	name=${NAMES[i]}
	docker exec "$name" sh -c "touch /go/ready.$name
		while [ ! -e /go/go ]; do usleep 10000; done
		for k in \$(seq $K); do timeout 30 openssl s_client -brief -connect $SIP:${DPORT[i]} </dev/null; done" \
		>"$OUT/clients/$name.log" 2>&1 &
	CLIS+=($!)
done
for i in $(seq 600); do
	(($(find "$OUT/go" -name 'ready.*' | wc -l) == N)) && break
	((i == 600)) && die "clients not ready"
	sleep 0.05
done
touch "$OUT/go/go"
for p in "${CLIS[@]}"; do wait "$p"; done
log "handshakes done"

# The last events reach the jsonl after their connection closes.
sleep 0.5
for p in "${SKBS[@]}"; do kill -INT "$p"; done
for p in "${SKBS[@]}"; do wait "$p"; done
SKBS=()
rm -rf "$OUT/go"

python3 eval/attrib.py "$OUT" "$K" || die "cannot write run.json / containers.jsonl"
log "saved to $OUT"
