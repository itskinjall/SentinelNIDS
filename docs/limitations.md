# Limitations (what SentinelNIDS cannot do)

- **Signature IDS only.** It detects what the rules describe. Unknown attacks, new malware, and anything not in `local.rules` are invisible. The rule set is deliberately small and for a lab.
- **No brute-force detection per se.** It sees connection *rate*, not failed logins. Confirm with service/auth logs.
- **No encrypted-payload inspection.** TLS content is opaque; only metadata (SNI etc.) is visible. Payload logging is off.
- **Not a malware or compromised-host detector.** A DNS name on a lab blocklist is a simulated indicator, not threat intelligence.
- **Slow/low-rate or distributed scans** can stay under the thresholds. Thresholds are lab values.
- **Sees only its monitored interface.** Traffic that does not cross `veth-sentinel` is not seen. Offloading, drops and sensor overload can lose packets (check Suricata `stats`).
- **IDS, not IPS.** Nothing is blocked; "action" is always logged/allowed.
- **If Suricata stops, detection stops.** The health banner flags this after ~32 s; the gap itself is a blind spot.
- **Risk score is heuristic**, not a verdict, and correlation by source IP can mis-group NAT'd/shared addresses.
- **Dashboard has no authentication** and binds to localhost; PCAP preview needs tshark/tcpdump and rolling captures started *before* the traffic.
- **Verified here:** backend, correlation, risk scoring, reports, health and dashboard were tested with labelled sample EVE data. The Suricata rules/config must be validated on your Kali VM with `suricata -T` and the scenarios (see tests/test_scenarios.md). Rule behaviour against real traffic is **not yet demonstrated**.
