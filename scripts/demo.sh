#!/bin/sh
# Demo traffic for skbouncer. Three client containers each make a TLS
# handshake every 3 s, to their own port on tls-server.
#   sh scripts/demo.sh up      start (policy: policy/demo.json)
#   sh scripts/demo.sh down    remove
case "$1" in
up)
	docker run -d --name tls-server skb-tls-test sh -c 'for p in 4431 4432 4433; do
		openssl s_server -quiet -accept $p -cert /cert.pem -key /key.pem & done; wait' >/dev/null
	srv=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tls-server)
	client() {
		docker run -d --name "$1" skb-tls-test sh -c "while true; do
			timeout 5 openssl s_client -connect $srv:$2 $3 </dev/null >/dev/null 2>&1 &&
				echo \$(date +%T) OK || echo \$(date +%T) FAILED; sleep 3; done" >/dev/null
	}
	client payments-api  4431 '-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256'
	client web           4432 ''
	client batch-reports 4433 '-tls1_2 -cipher ECDHE-RSA-AES128-SHA'
	docker ps --format '{{.Names}}' ;;
down)
	docker rm -f tls-server payments-api web batch-reports >/dev/null 2>&1; echo removed ;;
*)
	echo "usage: $0 up|down" >&2; exit 2 ;;
esac
