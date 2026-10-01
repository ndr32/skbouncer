#!/usr/bin/env bash
# Experiment 1: the functional table. Runs the verifier chain, which covers
# rows 1-13, then what the verifiers do not: row 14 (the control, row 8 with
# skbouncer stopped) and the SSH and random-byte traffic of row 2 (C3).
#
#   eval/functional.sh --out DIR [--random N]
set -uo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)

OUT= RANDOM_N=100
while (($#)); do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--random) RANDOM_N=$2; shift 2 ;;
	*) echo "usage: $0 --out DIR [--random N]" >&2; exit 2 ;;
	esac
done
[[ $OUT && $RANDOM_N =~ ^[0-9]+$ ]] || { echo "usage: $0 --out DIR [--random N]" >&2; exit 2; }

PFX=skb-func-$$
SRV=$PFX-srv CLI=$PFX-cli SINK=$PFX-sink
SKB=

log() { echo "functional: $*" >&2; }
die() { log "$*"; exit 1; }
cleanup() {
	trap - EXIT INT TERM
	[[ $SKB ]] && { kill -INT "$SKB" 2>/dev/null; wait "$SKB" 2>/dev/null; }
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT" || die "cannot create $OUT"
OUT=$(realpath "$OUT")
cd "$R"
eval/env.sh >"$OUT/env.txt" 2>&1

# -- rows 1-13: the verifier chain ------------------------------------------
log "verifier chain (verify-M6.6.sh, M3 to M6.6)"
scripts/verify-M6.6.sh >"$OUT/verify.log" 2>&1
CHAIN=$?

docker run -d --name "$SRV" skb-tls-test sleep infinity >/dev/null || die "cannot start server"
docker run -d --name "$CLI" skb-tls-test sleep infinity >/dev/null || die "cannot start client"
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
idx=$(docker exec "$CLI" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -F': ' -v i="$idx" '$1 == i {sub(/@.*/, "", $2); print $2}')
[[ $SIP && $VETH ]] || die "containers not set up"
n_attached() { local o; o=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); grep -c skb_tc <<<"$o"; }

# -- row 14: row 8's client with skbouncer stopped ---------------------------
log "row 14: control"
docker exec -d "$SRV" sh -c "openssl s_server -quiet -msg -naccept 1 -accept 4500 \
	-cert /cert.pem -key /key.pem >/tmp/4500.log 2>&1"
sleep 1
ATT14=$(n_attached)
c=$(docker exec "$CLI" sh -c "timeout 5 openssl s_client -brief -connect $SIP:4500 -groups X25519 </dev/null 2>&1")
[[ $c == *'CONNECTION ESTABLISHED'* ]] && EST14=true || EST14=false
s=$(docker exec "$SRV" cat /tmp/4500.log)
[[ $s == *ClientHello* ]] && RX14=true || RX14=false

# -- row 2 / C3: SSH and random bytes, skbouncer watching --------------------
log "row 2: SSH and $RANDOM_N random-byte connections"
# Counts what arrives, so "no events" is about traffic that really flowed.
docker run -d --name "$SINK" --network container:"$SRV" python:3-alpine python3 -u -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 9000)); s.listen(64)
while True:
    c, _ = s.accept(); n = 0
    while b := c.recv(65536): n += len(b)
    c.close(); print(n)' >/dev/null || die "cannot start sink"
sudo -n ./skbouncer --container "$CLI" --format json >"$OUT/row2.jsonl" 2>"$OUT/row2.err" &
SKB=$!
for _ in $(seq 100); do grep -q 'Ctrl-C to stop' "$OUT/row2.err" && break; sleep 0.05; done
grep -q 'Ctrl-C to stop' "$OUT/row2.err" || die "skbouncer did not start"
docker exec "$CLI" sh -c "
	printf 'SSH-2.0-OpenSSH_9.9\r\n' | nc -w 1 $SIP 9000
	i=0; while [ \$i -lt $RANDOM_N ]; do
		head -c 4096 /dev/urandom | nc -w 1 $SIP 9000; i=\$((i + 1))
	done"
sleep 1
kill -INT "$SKB"; wait "$SKB"; SKB=
EV2=$(grep -c '^{' "$OUT/row2.jsonl")
docker logs "$SINK" >"$OUT/row2.sink" 2>&1
CONN2=$(grep -c . "$OUT/row2.sink")
BYTES2=$(awk '{b += $1} END {print b + 0}' "$OUT/row2.sink")

python3 - "$OUT" "$CHAIN" "$ATT14" "$EST14" "$RX14" "$RANDOM_N" "$EV2" "$CONN2" "$BYTES2" <<'PY'
import json, sys
out, chain, att, est, rx, n, ev, conns, nbytes = sys.argv[1:]
chain = chain == "0"
c3 = {"ssh_connections": 1, "random_connections": int(n), "events": int(ev),
      "connections_received": int(conns), "bytes_received": int(nbytes)}
row14 = {"attached": int(att), "established": est == "true", "server_got_clienthello": rx == "true"}
ok14 = row14["attached"] == 0 and row14["established"] and row14["server_got_clienthello"]
V = "verify-"
rows = [
    (1, "Detect a ClientHello", V + "M3: one event per TLS case", chain),
    (2, "Ignore other traffic", V + "M3 plaintext (HTTP), " + V + "M6.6 junk; here: "
        f"1 SSH and {n} random-byte connections, {conns} received with {nbytes} bytes, {ev} events",
        chain and c3["events"] == 0 and c3["connections_received"] == int(n) + 1),
    (3, "Read the cipher suites", V + "M3 tls12_two, tls13_one, cipher_cap", chain),
    (4, "Read the versions", V + "M3 tls12_two, tls13_one, default_small", chain),
    (5, "Flag a split ClientHello", V + "M3 default_pqc, versions_cut", chain),
    (6, "Name the container", V + "M4 shared network namespace; " + V + "M5 five containers, one veth", chain),
    (7, "Audit a violation", V + "M5", chain),
    (8, "Enforce a violation", V + "M6 ports 4472, 4473", chain),
    (9, "Fail open", V + "M6 port 4475", chain),
    (10, "Block unknown on request", V + "M6 port 4478", chain),
    (11, "Refuse the root cgroup", V + "M6 refusal root_cgroup", chain),
    (12, "Refuse a non-veth in enforce mode", V + "M6 refusal not_a_veth (lo)", chain),
    (13, "Detach on exit", V + "M6.6 deaths (SIGPIPE, SIGHUP, SIGUSR2), coexist (SIGINT)", chain),
    (14, "Control", "here: row 8's client, skbouncer stopped: "
         f"attached {row14['attached']}, established {row14['established']}, "
         f"server got the ClientHello {row14['server_got_clienthello']}", ok14),
]
json.dump({"chain_passed": chain, "c3": c3, "row14": row14,
           "rows": [{"no": r[0], "function": r[1], "evidence": r[2], "pass": r[3]} for r in rows]},
          open(f"{out}/results.json", "w"), indent=1)
with open(f"{out}/table.md", "w") as f:
    f.write("| No | Function | Evidence | Result |\n|---|---|---|---|\n")
    for r in rows:
        f.write(f"| {r[0]} | {r[1]} | {r[2]} | {'PASS' if r[3] else 'FAIL'} |\n")
print(open(f"{out}/table.md").read())
PY
log "saved to $OUT"
