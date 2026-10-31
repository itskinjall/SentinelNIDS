#!/usr/bin/env bash
# Controlled traffic generator. ONLY run against your own isolated lab target.
# Usage: ./scripts/run_scenarios.sh [scan|repeat|dns|normal|all]
set -uo pipefail
T=${TARGET:-10.77.0.2}; DNS=${DNS_SERVER:-10.77.0.2}
say(){ printf '\n=== %s ===\n' "$*"; sleep 1; }
scan(){ say "Scenario 1: Nmap scans against $T"
  nmap -sS -p 1-1000 -T4 "$T" >/dev/null; sleep 6
  nmap -sX -p 1-100 -T4 "$T" >/dev/null; sleep 3
  nmap -sN -p 1-100 -T4 "$T" >/dev/null; sleep 3
  nmap -sV -p 80 --script http-title "$T" >/dev/null; }
repeat(){ say "Scenario 2: repeated connections to tcp/2222"
  for i in $(seq 1 12); do nc -z -w1 "$T" 2222; sleep 0.5; done; }
dns(){ say "Scenario 3: suspicious DNS test queries (server $DNS)"
  dig @"$DNS" +time=1 +tries=1 beacon.c2-sim.lab.test >/dev/null 2>&1
  dig @"$DNS" +time=1 +tries=1 "$(head -c 40 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | head -c 55).lab.test" >/dev/null 2>&1
  for i in $(seq 1 30); do dig @"$DNS" +time=1 +tries=1 "q$i.burst.lab.test" >/dev/null 2>&1 & done; wait; }
normal(){ say "Scenario 4: NORMAL traffic (expect zero alerts)"
  curl -s "http://$T/" >/dev/null; curl -s "http://$T/index.html" >/dev/null
  ping -c 4 "$T" >/dev/null
  for h in example.com example.org; do dig @"$DNS" +time=1 +tries=1 "$h" >/dev/null 2>&1; done; }
case "${1:-all}" in scan) scan;; repeat) repeat;; dns) dns;; normal) normal;; all) normal; sleep 12; scan; repeat; dns;; esac
echo "Done. Check the dashboard / data/sentinel.db"
