#!/usr/bin/env bash
# M4 oracle. Checks that each event names the container that sent it, using
# the cgroup id rather than the veth: container B shares A's network
# namespace, so both leave through A's veth with the same source address,
# and only the cgroup tells them apart. B also starts after skbouncer, so a
# name cache built at startup would miss it.
#
# Contract for skbouncer: the M3 JSON contract, plus "container": the Docker
# container name for the event's cgroup_id, or null if it belongs to none.
#
# Runs verify-M3.sh first, so M4 cannot pass by breaking M3.
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
PFX=skb-verify-m4
SRV=$PFX-srv A=$PFX-a B=$PFX-b C=$PFX-c
OUT=.loop/verify-M4
LOADER=

die() { echo "verify: $*" >&2; exit 1; }

cleanup() {
	if [[ -n "$LOADER" ]]; then
		kill -INT "$LOADER" 2>/dev/null
		wait "$LOADER" 2>/dev/null
	fi
	docker rm -f "$SRV" "$A" "$B" "$C" >/dev/null 2>&1
}
trap cleanup EXIT

cgroup_inode() {
	stat -c %i "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"
}
handshake() {	# container port
	docker exec "$1" sh -c "timeout 5 openssl s_client -connect $SIP:$2 </dev/null >/dev/null 2>&1"
	sleep 0.3
}
case_json() {	# name port container watched
	local ino=null
	[[ $4 == true ]] && ino=$(cgroup_inode "$3")
	echo "{\"name\":\"$1\",\"port\":$2,\"container\":\"$3\",\"cgroup_id\":$ino,\"watched\":$4}"
}

echo "verify: M3 regression"
scripts/verify-M3.sh | tail -1
[[ ${PIPESTATUS[0]} == 0 ]] || die "M3 verifier fails; M4 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT"
docker rm -f "$SRV" "$A" "$B" "$C" >/dev/null 2>&1

docker run -d --name "$SRV" "$IMAGE" sh -c '
	for p in 4441 4442 4443 4444; do
		openssl s_server -quiet -naccept 1 -accept $p \
			-cert /cert.pem -key /key.pem >/dev/null 2>&1 &
	done
	wait' >/dev/null || die "cannot start server container"
docker run -d --name "$A" "$IMAGE" sleep infinity >/dev/null || die "cannot start $A"
docker run -d --name "$C" "$IMAGE" sleep infinity >/dev/null || die "cannot start $C"
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
[[ -n "$SIP" ]] || die "server container has no bridge address"

IDX=$(docker exec "$A" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
[[ -n "$VETH" ]] || die "cannot find $A's veth"

sudo -n ./skbouncer -i "$VETH" --direction ingress --format json \
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

handshake "$A" 4441
docker run -d --name "$B" --network "container:$A" "$IMAGE" sleep infinity >/dev/null ||
	die "cannot start $B"
sleep 1
handshake "$B" 4442
handshake "$A" 4443
handshake "$C" 4444

{
	echo "["
	case_json a_before_attach 4441 "$A" true;  echo ","
	case_json b_shares_a_netns 4442 "$B" true; echo ","
	case_json a_again 4443 "$A" true;          echo ","
	case_json c_unwatched_veth 4444 "$C" false
	echo "]"
} >"$OUT/cases.json"

sleep 1
kill -INT "$LOADER" 2>/dev/null
wait "$LOADER" 2>/dev/null
LOADER=

python3 tests/check_m4.py "$OUT/events.jsonl" "$OUT/cases.json"
