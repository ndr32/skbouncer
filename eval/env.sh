#!/usr/bin/env bash
# Everything a result set depends on, as key: value lines. Run from the repo root.
set -uo pipefail

imds() {
	local t
	t=$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token \
		-H 'X-aws-ec2-metadata-token-ttl-seconds: 60') || return
	curl -s -m 2 -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1"
}

# ethtool -k, the offloads that decide segment boundaries, on one line.
offloads() {
	ethtool -k "$1" 2>/dev/null |
		awk -F': ' '/^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload):/ {printf "%s=%s ", $1, $2}'
}

echo "date: $(date -Iseconds)"
echo "host: $(hostname)"
echo "instance: $(imds instance-type || echo none) $(imds placement/region || true)"
echo "cpu: $(nproc) x $(lscpu | sed -n 's/^Model name: *//p')"
echo "memory: $(free -g | awk '/^Mem:/ {print $2}') GiB"
echo "os: $(lsb_release -ds)"
echo "kernel: $(uname -r)"
echo "kernel holds: $(apt-mark showhold | grep -c .) packages"
echo "skbouncer: $(./skbouncer --version 2>/dev/null) $(git rev-parse HEAD)"
echo "clang: $(clang --version | sed -n '1s/.*version //p')"
echo "libbpf: $(pkg-config --modversion libbpf)"
echo "libcurl: $(pkg-config --modversion libcurl)"
echo "bpftool: $(bpftool version | sed -n '1s/.* v//p')"
echo "docker: $(docker version --format '{{.Server.Version}}')"
echo "openssl (skb-tls-test): $(docker run --rm skb-tls-test openssl version)"
for i in skb-tls-test node:alpine python:3-alpine golang:alpine \
	lexiforest/curl-impersonate:latest curlimages/curl:latest alpine:3.24.2; do
	echo "image $i: $(docker image inspect --format '{{.Id}}' "$i" 2>/dev/null)"
done

dev=$(ip route show default | awk '{print $5; exit}')
echo "uplink $dev: mtu $(cat /sys/class/net/$dev/mtu) $(offloads "$dev")"
echo "docker0: mtu $(cat /sys/class/net/docker0/mtu)"
echo "tcp_timestamps: $(sysctl -n net.ipv4.tcp_timestamps)"

# A throwaway container's veth, host side: the path skbouncer watches.
c=$(docker run -d --rm skb-tls-test sleep 30)
idx=$(docker exec "$c" cat /sys/class/net/eth0/iflink)
veth=$(ip -o link | awk -F': ' -v i="$idx" '$1 == i {sub(/@.*/, "", $2); print $2}')
echo "container veth: mtu $(cat /sys/class/net/$veth/mtu) $(offloads "$veth")"
docker rm -f "$c" >/dev/null

echo "chrony: $(chronyc tracking 2>/dev/null | awk -F': ' '/^(Reference ID|System time|Leap status)/ {printf "%s; ", $2}')"
