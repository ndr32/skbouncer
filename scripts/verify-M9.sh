#!/usr/bin/env bash
# M9 oracle: the command-line round. Userspace only: the kernel program and
# the event format must be unchanged from the latest release tag (v*).
#
#   --list    running containers with their veth and cgroup id (root: the veth
#             is found through /proc/<pid>/root)
#   --check   a policy described rule by rule, or refused, unprivileged
#   summary   on exit, per container, matching the run's own events; the
#             counter line the harnesses parse stays as it was
#   menu      no arguments in a terminal: list, check, enforce declined (nothing
#             attached), audit with live handshakes, Ctrl-C back, quit
#   no menu   no arguments without a terminal: usage and a non-zero exit
#
# Output formats:
#   --list    one line per container: NAME VETH CGROUP_ID ("-" for no veth)
#   --check   "rule N: PATTERN: TLS V or later; ciphers: A, B" (or "any
#             version", "any cipher"), "no rule matches: allow|deny",
#             "unknown verdicts: allow|block"
#   summary   on stderr after the counter line: "skbouncer: summary", then
#             per container "  WHO: N ClientHellos, A allow, V violation,
#             U unknown, B blocked" ("  WHO: N ClientHellos" with no policy)
#   menu      prompts "Choose: ", "Container: ", "Policy file: ",
#             "Continue? [y/N] ", and "Running: skbouncer ..." before a run
#
# Runs verify-M6.6.sh first (the whole chain from M3).
set -uo pipefail
cd "$(dirname "$0")/.."

PFX=skb-verify-m9
SRV=$PFX-srv A=$PFX-a
OUT=.loop/verify-M9
PIDS=()

die() { echo "verify: $*" >&2; exit 1; }
cleanup() {
	for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
	sleep 1
	docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
}
trap cleanup EXIT

REF=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null)
[[ $REF ]] || die "no release tag to compare the kernel side with"
git diff --quiet "$REF" -- src/bpf include ||
	die "the kernel program or the event format changed since $REF; this round is userspace only"

echo "verify: M6.6 regression (includes M6.5 down to M3)"
scripts/verify-M6.6.sh | tail -3
[[ ${PIPESTATUS[0]} == 0 ]] || die "M6.6 verifier fails; M9 cannot pass"

rm -rf "$OUT"
mkdir -p "$OUT"
docker ps -aq --filter "name=$PFX" | xargs -r docker rm -f >/dev/null 2>&1
make -s >/dev/null || die "build failed"

docker run -d --name "$SRV" skb-tls-test openssl s_server -quiet -accept 4433 \
	-cert /cert.pem -key /key.pem >/dev/null || die "cannot start server"
docker run -d --name "$A" skb-tls-test sleep infinity >/dev/null || die "cannot start $A"
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
IDX=$(docker exec "$A" cat /sys/class/net/eth0/iflink)
VETH=$(ip -o link | awk -v i="$IDX" -F': ' '$1+0==i {split($2,a,"@"); print a[1]}')
CGID=$(stat -c %i "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$A").scope")
[[ $SIP && $VETH && $CGID ]] || die "test containers not set up"
sleep 1

AES='"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"'
cat >"$OUT/policy.json" <<EOF
{ "version": 1, "default": "deny",
  "rules": [ { "container": "$A", "min_version": "1.3", "ciphers": [$AES] } ] }
EOF
echo '{ "version": 1, "rules": [ { "container": "x", "ciphers": ["TLS_NO_SUCH_CIPHER"] } ] }' >"$OUT/bad.json"

sudo -n ./skbouncer --list >"$OUT/list.out" 2>"$OUT/list.err"; LIST_RC=$?
# Unprivileged on purpose: checking a policy must not need root or load anything.
./skbouncer --check -p "$OUT/policy.json" >"$OUT/check.out" 2>"$OUT/check.err"; CHECK_RC=$?
./skbouncer --check -p "$OUT/bad.json" >"$OUT/bad.out" 2>"$OUT/bad.err"; BAD_RC=$?
./skbouncer </dev/null >"$OUT/noarg.out" 2>"$OUT/noarg.err"; NOARG_RC=$?

# The summary from a command-line run, against the same run's JSON events.
hs() { docker exec "$A" sh -c "timeout 5 openssl s_client -connect $SIP:4433 $1 </dev/null >/dev/null 2>&1"; }
sudo -n ./skbouncer --container "$A" -p "$OUT/policy.json" --format json \
	>"$OUT/run.jsonl" 2>"$OUT/run.err" &
P=$!; PIDS+=("$P")
for _ in $(seq 100); do grep -q 'Ctrl-C to stop' "$OUT/run.err" && break; sleep 0.05; done
hs ""; hs "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256"; hs "-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256"
sleep 1
kill -INT "$P"; wait "$P"; PIDS=()

# The menu, through a terminal.
timeout 180 python3 tests/m9_menu.py "$OUT" "$A" "$PWD/$OUT/policy.json" "$SIP" "$VETH" ||
	die "menu driver failed; see $OUT/menu.transcript"

python3 - "$OUT" "$LIST_RC" "$CHECK_RC" "$BAD_RC" "$NOARG_RC" "$A" "$VETH" "$CGID" <<'PY'
import json, sys
out, lr, cr, br, nr, a, veth, cgid = sys.argv[1:]
json.dump({"rc": {"list": int(lr), "check": int(cr), "bad": int(br), "noarg": int(nr)},
           "container": a, "veth": veth, "cgroup_id": int(cgid)},
          open(f"{out}/cases.json", "w"))
PY
python3 tests/check_m9.py "$OUT"
