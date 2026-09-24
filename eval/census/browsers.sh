# Sourced by run.sh. Real browser ClientHellos via curl-impersonate.
B=lexiforest/curl-impersonate:latest
for p in chrome116 chrome124 chrome131 chrome150 edge101 firefox133 firefox147 safari184 safari260 safari260_ios tor145; do
	run_case "browser $p" $B "curl_$p -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/"
done
