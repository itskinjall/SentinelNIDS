#!/usr/bin/env bash
# Benign test services inside the target namespace: HTTP :80, TCP :2222, DNS-like UDP :53 (netcat sink).
set -euo pipefail
NS=sentinel-target; DIR=/tmp/sentinel-www
case "${1:-}" in
  start)
    mkdir -p $DIR/sentinel-test; echo "<h1>SentinelNIDS lab target</h1>" > $DIR/index.html; echo ok > $DIR/sentinel-test/probe
    ip netns exec $NS bash -c "cd $DIR && nohup python3 -m http.server 80 >/tmp/sentinel-http.log 2>&1 & echo \$! > /tmp/sentinel-http.pid"
    ip netns exec $NS bash -c "nohup bash -c 'while true; do nc -l -p 2222 -q0 </dev/null >/dev/null; done' >/dev/null 2>&1 & echo \$! > /tmp/sentinel-nc.pid"
    ip netns exec $NS bash -c "nohup bash -c 'while true; do nc -u -l -p 53 >/dev/null; done' >/dev/null 2>&1 & echo \$! > /tmp/sentinel-dns.pid"
    echo "Target services started in $NS (80, 2222, udp/53)";;
  stop) pkill -f "http.server 80" || true; pkill -f "nc -l -p 2222" || true; pkill -f "nc -u -l -p 53" || true; echo stopped;;
  *) echo "usage: $0 start|stop";;
esac
