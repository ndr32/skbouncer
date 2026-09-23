#!/usr/bin/env bash
# M3 oracle. Attaches skbouncer to a client container's veth, sends one
# handshake per case to TLS servers in a second container, and checks the
# events against the ClientHellos the servers logged (tests/check_m3.py).
#
# Contract for skbouncer: `--format json` prints one JSON object per event on
# stdout with at least dport, record_len, captured_len, trunc ("none" |
# "segment" | "snapshot" | "parse"), legacy_version, versions, ciphers and
# ciphers_capped. Non-JSON lines are ignored.
#
# Client and server share docker0, so no internet or gateway is needed.
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
SRV=skb-verify-srv
CLI=skb-verify-cli
OUT=.loop/verify-M3
LOADER=

die() { echo "verify: $*" >&2; exit 1; }

cleanup() {
	if [[ -n "$LOADER" ]]; then
		kill -INT "$LOADER" 2>/dev/null
		wait "$LOADER" 2>/dev/null
	fi
	docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
}
trap cleanup EXIT

# name|port|tls|expect_split|s_client args
CASES='tls12_two|4431|1|0|-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384
tls13_one|4432|1|0|-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519
default_small|4433|1|0|-groups X25519
default_pqc|4434|1|1|
cipher_cap|4435|1|0|-tls1_2 -cipher ALL:@SECLEVEL=0
plaintext|4436|0|0|'

rm -rf "$OUT"
mkdir -p "$OUT/srv"
make -s >/dev/null || die "build failed"
docker image inspect "$IMAGE" >/dev/null 2>&1 ||
	docker build --network host -q -t "$IMAGE" tests/tls >/dev/null ||
	die "cannot build $IMAGE"
docker rm -f "$SRV" "$CLI" >/dev/null 2>&1

# One s_server per case, so events map to cases by destination port.
ports=$(echo "$CASES" | cut -d'|' -f2 | tr '\n' ' ')
docker run -d --name "$SRV" -v "$PWD/$OUT/srv:/logs" "$IMAGE" sh -c "
	for p in $ports; do
		openssl s_server -quiet -msg -naccept 1 -accept \$p \
			-cert /cert.pem -key /key.pem >/logs/\$p.log 2>&1 &
	done
	wait" >/dev/null || die "cannot start server container"
docker run -d --name "$CLI" "$IMAGE" sleep infinity >/dev/null ||
	die "cannot start client container"
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
[[ -n "$SIP" ]] || die "server container has no bridge address"

IDX=$(docker exec "$CLI" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
[[ -n "$VETH" ]] || die "cannot find the client's veth"

sudo -n ./skbouncer -i "$VETH" --direction ingress --format json \
	>"$OUT/events.jsonl" 2>"$OUT/loader.err" &
LOADER=$!
# Capture before matching: `bpftool | grep -q` under pipefail can fail with
# SIGPIPE when bpftool is still writing after grep has matched and exited.
attached() { local out; out=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); [[ $out == *skb_tc* ]]; }
for _ in $(seq 1 20); do
	attached && break
	kill -0 "$LOADER" 2>/dev/null || { LOADER=; die "skbouncer exited early: $(head -1 "$OUT/loader.err")"; }
	sleep 0.5
done
attached || die "skbouncer never attached to $VETH ingress"

json='['
while IFS='|' read -r name port tls split args; do
	if [[ $tls == 1 ]]; then
		docker exec "$CLI" sh -c "timeout 5 openssl s_client -connect $SIP:$port $args </dev/null >/dev/null 2>&1"
	else
		docker exec "$CLI" sh -c "echo 'GET / HTTP/1.0' | timeout 3 nc $SIP $port >/dev/null 2>&1"
	fi
	json+="{\"name\":\"$name\",\"port\":$port,\"tls\":$([[ $tls == 1 ]] && echo true || echo false),\"expect_split\":$([[ $split == 1 ]] && echo true || echo false)},"
	sleep 0.3
done <<<"$CASES"
echo "${json%,}]" >"$OUT/cases.json"

sleep 1
kill -INT "$LOADER" 2>/dev/null
wait "$LOADER" 2>/dev/null
LOADER=

python3 tests/check_m3.py "$OUT/events.jsonl" "$OUT/cases.json" "$OUT/srv"
