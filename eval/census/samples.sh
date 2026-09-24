# Sourced by run.sh. Repeated samples: Chrome permutes extension order per connection.
B=lexiforest/curl-impersonate:latest
for p in chrome150 firefox147 safari260; do
	for n in $(seq 1 20); do
		run_case "sample $p" $B "curl_$p -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/" >/dev/null
	done
	echo "sampled $p x20"
done
