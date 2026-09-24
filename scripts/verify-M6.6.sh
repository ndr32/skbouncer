#!/usr/bin/env bash
# M6.6 oracle: hardening from the whole-codebase review.
#
#   deaths    skbouncer dying abnormally (SIGPIPE, SIGHUP, an unhandled
#             SIGUSR2 standing in for a crash) leaves nothing attached
#   coexist   an audit and an enforce instance on one veth both work, and
#             either exiting leaves the other attached
#   junk      a mid-connection segment that only looks like a ClientHello
#             header is not treated as one
#   starttls  a real ClientHello mid-connection is still enforced
#   map       the kernel's cgroup_rule map holds only in-scope cgroups
#
# Runs verify-M6.5.sh first (which runs M6 down to M3).
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE=skb-tls-test
PFX=skb-verify-m66
SRV=$PFX-srv A=$PFX-a
OUT=.loop/verify-M6.6
PIDS=()

die() { echo "verify: $*" >&2; exit 1; }
cleanup() {
	for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
	sleep 1
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
}
trap cleanup EXIT

VIOLATE="-groups X25519"	# also offers TLS 1.2; the policy requires 1.3
COMPLY="-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519"

echo "verify: M6.5 regression (includes M6, M5, M4, M3)"
scripts/verify-M6.5.sh | tail -5
[[ ${PIPESTATUS[0]} == 0 ]] || die "M6.5 verifier fails; M6.6 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT/srv"
docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
make -s >/dev/null || die "build failed"

docker run -d --name "$SRV" -v "$PWD/$OUT/srv:/logs" "$IMAGE" sh -c '
	for p in 4601 4602 4603 4604 4605 4606 4611 4612; do
		openssl s_server -quiet -naccept 1 -accept $p -cert /cert.pem -key /key.pem >/dev/null 2>&1 &
	done
	openssl s_server -quiet -msg -naccept 1 -accept 4620 -cert /cert.pem -key /key.pem >/logs/4620.log 2>&1 &
	nc -l -p 4630 >/logs/4630.bin &
	nc -l -p 4631 >/logs/4631.bin &
	wait' >/dev/null || die "cannot start server container"
docker run -d --name "$A" "$IMAGE" sleep infinity >/dev/null || die "cannot start $A"
for i in 1 2 3; do docker run -d --name "$PFX-other$i" "$IMAGE" sleep infinity >/dev/null; done
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
IDX=$(docker exec "$A" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
SCOPE=/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$A").scope
[[ -n $SIP && -n $VETH && -d $SCOPE ]] || die "test containers not set up"

cat >"$OUT/policy.json" <<POLICY
{ "version": 1, "default": "deny",
  "rules": [ { "container": "$A", "min_version": "1.3",
               "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] } ] }
POLICY

# Captured, not piped: `bpftool | grep` under pipefail can SIGPIPE.
n_attached() { local o; o=$(sudo -n bpftool net show dev "$VETH" 2>/dev/null); grep -o skb_tc <<<"$o" | wc -l; }
attached() { (( $(n_attached) > 0 )); }
wait_attached() {	# min_count
	for _ in $(seq 1 20); do (( $(n_attached) >= $1 )) && return 0; sleep 0.5; done
	return 1
}
hs() {	# port args -> True if TLS was established
	docker exec "$A" sh -c "timeout 4 openssl s_client -brief -connect $SIP:$1 $2 </dev/null 2>&1" |
		grep -q 'CONNECTION ESTABLISHED' && echo True || echo False
	sleep 0.3
}
alive() { pgrep -x skbouncer >/dev/null && echo True || echo False; }
py_bool() { "$@" && echo True || echo False; }
count_port() { grep -c "\"dport\": *$2\b" "$1" 2>/dev/null || true; }
enforce_cmd=(sudo -n ./skbouncer --container "$A" --mode enforce -p "$OUT/policy.json")

# -- deaths ----------------------------------------------------------------
DEATHS=()
# SIGPIPE: the reader goes away. Keep causing events until the write fails.
{ "${enforce_cmd[@]}" 2>/dev/null | head -1 >/dev/null; } &
wait_attached 1 || die "enforce instance never attached"
for p in 4601 4602 4603; do hs $p "$VIOLATE" >/dev/null; [[ $(alive) == False ]] && break; done
sleep 2
DEATHS+=("{\"signal\": \"SIGPIPE\", \"alive\": $(alive), \"attached\": $(py_bool attached), \"traffic_after\": $(hs 4604 "$VIOLATE")}")
wait 2>/dev/null

for sig in HUP USR2; do
	port=$([[ $sig == HUP ]] && echo 4605 || echo 4606)
	"${enforce_cmd[@]}" >/dev/null 2>&1 &
	P=$!
	wait_attached 1 || die "enforce instance never attached"
	kill -"$sig" "$P" 2>/dev/null
	sleep 2
	DEATHS+=("{\"signal\": \"SIG$sig\", \"alive\": $(alive), \"attached\": $(py_bool attached), \"traffic_after\": $(hs $port "$VIOLATE")}")
	kill -INT "$P" 2>/dev/null; wait "$P" 2>/dev/null
done

# -- coexist ---------------------------------------------------------------
sudo -n ./skbouncer --container "$A" --format json >"$OUT/auditor.out" 2>"$OUT/auditor.err" &
AUD=$!; PIDS+=("$AUD")
wait_attached 1 || die "audit instance never attached"
"${enforce_cmd[@]}" --format json >"$OUT/enforcer.out" 2>"$OUT/enforcer.err" &
ENF=$!; PIDS+=("$ENF")
wait_attached 2 || sleep 3	# a replacing implementation never shows two
BLOCKED=$( [[ $(hs 4611 "$VIOLATE") == False ]] && echo True || echo False )
sleep 1
AUD_EVENTS=$(count_port "$OUT/auditor.out" 4611)
kill -INT "$ENF"; wait "$ENF" 2>/dev/null; sleep 1
AUD_ATTACHED=$( [[ $(alive) == True ]] && attached && echo True || echo False )
hs 4612 "$COMPLY" >/dev/null; sleep 1
AUD_AFTER=$(count_port "$OUT/auditor.out" 4612)
kill -INT "$AUD"; wait "$AUD" 2>/dev/null; sleep 1
BOTH_GONE_ATTACHED=$(py_bool attached)
PIDS=()

# -- junk and STARTTLS, with one enforce instance --------------------------
# A real ClientHello to replay later: captured before anything is attached.
hs 4620 "$VIOLATE" >/dev/null
CH_OCT=$(python3 - "$OUT/srv/4620.log" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
hdr = re.search(r"RecordHeader \[length 0005\]\n((?:\s+[0-9a-f ]+\n)+)", t)
body = re.search(r"ClientHello\n((?:\s+[0-9a-f ]+\n)+)", t)
b = bytes.fromhex(re.sub(r"\s", "", hdr[1] + body[1]))
print("".join(f"\\{x:03o}" for x in b))
PY
)
[[ -n $CH_OCT ]] || die "could not capture a ClientHello"
# Header says handshake, ClientHello, 64-byte record; but the handshake length
# (16) cannot hold a ClientHello and disagrees with the record. Past that sits
# a cipher list offering 0x0005, which the policy forbids.
JUNK_OCT=$(python3 -c '
b = bytes([0x16,3,3,0,64, 1,0,0,16, 3,3]) + bytes(32) + bytes([0, 0,2,0,5, 1,0])
b += bytes(69 - len(b))
print("".join(f"\\{x:03o}" for x in b))')
PLAIN='EHLO x\r\nSTARTTLS\r\n'

"${enforce_cmd[@]}" --format json >"$OUT/mid.out" 2>"$OUT/mid.err" &
MID=$!; PIDS+=("$MID")
wait_attached 1 || die "enforce instance never attached"
docker exec "$A" sh -c "(printf 'hello\n'; sleep 1; printf '$JUNK_OCT') | nc -w 3 $SIP 4630"
docker exec "$A" sh -c "(printf '$PLAIN'; sleep 1; printf '$CH_OCT') | nc -w 4 $SIP 4631"
sleep 1

# -- map, while the enforce instance runs with other containers present -----
MAP_ENTRIES=$(sudo -n bpftool -j map dump name cgroup_rule 2>/dev/null |
	python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)))
except Exception: print("None")')
IN_SCOPE=$(find "$SCOPE" -type d | wc -l)

kill -INT "$MID"; wait "$MID" 2>/dev/null; PIDS=()

python3 - "$OUT" <<PY
import json, sys
out = sys.argv[1]
def size(p):
    try: return len(open(p, "rb").read())
    except OSError: return 0
def actions(port):
    acts = []
    for l in open(f"{out}/mid.out"):
        if l.startswith("{"):
            e = json.loads(l)
            if e.get("dport") == port: acts.append(e.get("action"))
    return acts
json.dump({
  "deaths": [$(IFS=,; echo "${DEATHS[*]}")],
  "coexist": {"enforcer_blocked": $BLOCKED, "auditor_events": $AUD_EVENTS,
              "auditor_attached_after_enforcer_exit": $AUD_ATTACHED,
              "auditor_events_after": $AUD_AFTER, "attached_after_both": $BOTH_GONE_ATTACHED},
  "junk": {"sent": 6 + 69, "received": size(f"{out}/srv/4630.bin"), "events": len(actions(4630))},
  "starttls": {"plaintext": 18, "received": size(f"{out}/srv/4631.bin"), "actions": actions(4631)},
  "map": {"entries": $MAP_ENTRIES, "in_scope": $IN_SCOPE, "other_containers": 4},
}, open(f"{out}/cases.json", "w"), indent=1)
PY
python3 tests/check_m6_6.py "$OUT"
