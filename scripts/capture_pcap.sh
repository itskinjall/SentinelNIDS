#!/usr/bin/env bash
# Rolling 60 s PCAP files so alerts can be linked to packets. Old files (>30 min) are pruned.
# Files are git-ignored. Usage: sudo ./scripts/capture_pcap.sh veth-sentinel
IF=${1:?interface}; DIR="$(cd "$(dirname "$0")/.." && pwd)/data/pcap"; mkdir -p "$DIR"
( while true; do find "$DIR" -name 'sentinel-*.pcap' -mmin +30 -delete; sleep 300; done ) &
exec tcpdump -i "$IF" -n -s 256 -G 60 -w "$DIR/sentinel-%Y%m%d-%H%M%S.pcap"
