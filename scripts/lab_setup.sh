#!/usr/bin/env bash
# Single-VM lab: a "target" network namespace joined to the Kali host by a veth pair.
# Suricata watches the host side (veth-sentinel). Attacker = Kali host (10.77.0.1), target = ns (10.77.0.2).
# Everything is local and isolated: no packets leave the machine.
# Usage: sudo ./scripts/lab_setup.sh up|down|status
set -euo pipefail
NS=sentinel-target; HOST_IF=veth-sentinel; NS_IF=veth-target
HOST_IP=10.77.0.1/24; NS_IP=10.77.0.2/24
case "${1:-}" in
  up)
    ip netns add $NS 2>/dev/null || true
    ip link add $HOST_IF type veth peer name $NS_IF 2>/dev/null || true
    ip link set $NS_IF netns $NS 2>/dev/null || true
    ip addr add $HOST_IP dev $HOST_IF 2>/dev/null || true
    ip link set $HOST_IF up
    ip netns exec $NS ip addr add $NS_IP dev $NS_IF 2>/dev/null || true
    ip netns exec $NS ip link set $NS_IF up
    ip netns exec $NS ip link set lo up
    # Disable offloads so Suricata sees real packet sizes/checksums on veth
    ethtool -K $HOST_IF rx off tx off gro off gso off tso off 2>/dev/null || true
    ip netns exec $NS ethtool -K $NS_IF rx off tx off gro off gso off tso off 2>/dev/null || true
    echo "Lab up. Monitor interface: $HOST_IF  (set af-packet interface in config/suricata.yaml)"
    echo "Start target services:  sudo ./scripts/target_services.sh start" ;;
  down)
    ip netns del $NS 2>/dev/null || true
    ip link del $HOST_IF 2>/dev/null || true
    echo "Lab removed." ;;
  status) ip netns list; ip -br addr show $HOST_IF ;;
  *) echo "usage: $0 up|down|status"; exit 1 ;;
esac
