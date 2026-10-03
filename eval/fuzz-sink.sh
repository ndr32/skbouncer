#!/bin/sh
# fuzz.sh's sink, one run per connection under busybox nc -lk -e: reads the
# connection to EOF and logs "peer_port bytes". The peer port comes from the
# inode of the socket on fd 0, looked up in /proc/net/tcp.
ino=$(readlink /proc/self/fd/0)
ino=${ino#socket:[}
ino=${ino%]}
n=$(wc -c)
port=$(awk -v i="$ino" '$10 == i { split($3, a, ":"); print a[2]; exit }' /proc/net/tcp /proc/net/tcp6)
echo "$((0x$port)) $n" >>/logs/sink.log
