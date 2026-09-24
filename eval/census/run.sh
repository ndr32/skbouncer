#!/usr/bin/env bash
# ClientHello census: one handshake per client config, sizes from the server's view.
set -uo pipefail
C=$(cd "$(dirname "$0")" && pwd)
SRV=skb-census-srv
SRV_GROUPS=X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM512:MLKEM768:MLKEM1024:X25519:X448:secp256r1:secp384r1:secp521r1
SNI=api.example.com
PORT=5000
[[ ${FRESH:-0} == 1 ]] && : >"$C/results.jsonl"

docker rm -f $SRV >/dev/null 2>&1
docker run -d --name $SRV -v "$C/logs:/logs" skb-tls-test sleep infinity >/dev/null
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SRV)

# label | image | command ($SIP, $PORT, $SNI substituted)
run_case() {
	local label=$1 image=$2 cmd=$3
	PORT=$((PORT + 1))
	rm -f "$C/logs/$PORT.log"
	docker exec -d $SRV sh -c "openssl s_server -quiet -msg -naccept 1 -accept $PORT -groups $SRV_GROUPS \
		-cert /cert.pem -key /key.pem >/logs/$PORT.log 2>&1"
	sleep 0.7
	cmd=${cmd//@SIP@/$SIP}; cmd=${cmd//@PORT@/$PORT}; cmd=${cmd//@SNI@/$SNI}
	timeout 180 docker run --rm --add-host "$SNI:$SIP" --entrypoint sh "$image" -c "$cmd" >"$C/logs/$PORT.client" 2>&1
	sleep 0.5
	python3 - "$label" "$image" "$C/logs/$PORT.log" <<'PY' >>"$C/results.jsonl"
import json, sys
sys.path.insert(0, sys.argv[3].rsplit("/logs/", 1)[0])
from parse import parse
recs, hellos = parse(open(sys.argv[3]).read())
h = hellos[0] if hellos else {}
print(json.dumps({"label": sys.argv[1], "image": sys.argv[2], "log": sys.argv[3],
    "cipher_end": h.get("cipher_end"), "versions_end": h.get("versions_end"),
    "ext_order": h.get("ext_order"),
    "record_len": recs[0] if recs else None, "hrr": len(hellos) > 1,
    "ciphers": h.get("ciphers"), "n_ext": h.get("n_ext"),
    "keyshares": h.get("keyshares"), "keyshare_bytes": h.get("keyshare_bytes")}))
PY
	printf "%-40s %s\n" "$label" "$(tail -1 "$C/results.jsonl" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r["record_len"], "B", "HRR!" if r["hrr"] else "", r["keyshares"])')"
}

for f in ${CASEFILES:-openssl.sh others.sh browsers.sh}; do source "$C/$f"; done
docker rm -f $SRV >/dev/null
