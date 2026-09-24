# Sourced by run.sh. Real HTTP clients with their default TLS settings.
run_case "curl 8.22 (OpenSSL 3.5.8)" curlimages/curl \
	"curl -sk --max-time 5 -o /dev/null https://@SNI@:@PORT@/"
run_case "python 3.14 urllib (OpenSSL 3.5.8)" python:3-alpine \
	"python3 -c \"import ssl,urllib.request as u; c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; u.urlopen('https://@SNI@:@PORT@/', context=c, timeout=5)\""
run_case "node 26 https (OpenSSL 3.5.8)" node:alpine \
	"node -e \"require('https').get({host:'@SNI@',port:@PORT@,rejectUnauthorized:false,timeout:4000},()=>{}).on('error',()=>{})\""
run_case "go 1.27 net/http (crypto/tls)" golang:alpine \
	"echo cGFja2FnZSBtYWluCmltcG9ydCAoImNyeXB0by90bHMiOyAibmV0L2h0dHAiOyAib3MiOyAidGltZSIpCmZ1bmMgbWFpbigpIHsKCWMgOj0gJmh0dHAuQ2xpZW50e1RpbWVvdXQ6IDUgKiB0aW1lLlNlY29uZCwgVHJhbnNwb3J0OiAmaHR0cC5UcmFuc3BvcnR7CgkJRm9yY2VBdHRlbXB0SFRUUDI6IHRydWUsIFRMU0NsaWVudENvbmZpZzogJnRscy5Db25maWd7SW5zZWN1cmVTa2lwVmVyaWZ5OiB0cnVlfX19CgljLkdldCgiaHR0cHM6Ly8iICsgb3MuQXJnc1sxXSArICIvIikKfQ== | base64 -d > /tmp/m.go && cd /tmp && go run m.go @SNI@:@PORT@"
