# TLS client/server for scripts/verify-*.sh. Pinned so ClientHello contents
# stay comparable across runs; bump deliberately and record the new version.
FROM alpine:3.24.2
RUN apk add --no-cache openssl \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=skb-test \
      -keyout /key.pem -out /cert.pem 2>/dev/null
