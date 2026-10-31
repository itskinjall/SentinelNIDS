# Detection logic

All thresholds below are **lab configuration** for a small isolated network, not universal security standards.

## Severity
Suricata puts the rule `priority` in `alert.severity`. Mapping (backend/config.py): 1 critical, 2 high, 3 medium, >=4 low. Severity is chosen by the rule author, i.e. it is a statement about the rule, not about the attacker.

## Rules (`rules/local.rules`)
| SID | Detects | Why it is a reasonable indicator | Known weakness |
|---|---|---|---|
| 9000001 | >=20 SYNs in 5 s from one source | Port scans touch many ports quickly | Fast legit clients / load tests; slow scans (`-T1`) evade it |
| 9000002/3/4 | NULL, XMAS, FIN-only TCP probes | Normal stacks do not send these flag sets | Some middleboxes/odd stacks |
| 9000010 | >=8 connections to tcp/2222 in 30 s | Repeated attempts on one service | Rate only - cannot tell brute force from a busy client |
| 9000011 | >=5 SSH connection attempts in 60 s | Same | Same; real brute-force proof needs auth logs |
| 9000020 | DNS query name >= 50 bytes | Tunnelling/DGA names are long and random | CDNs/DKIM/service names can be long; short tunnels evade |
| 9000021 | Query to `*.c2-sim.lab.test` | Stands in for a threat-intel blocklist (`.test` is reserved, never resolves) | Only as good as the list |
| 9000022 | >=25 DNS queries in 10 s from one source | Bursts differ from normal browsing | Busy resolvers/forwarders |
| 9000030 | >=30 ICMP echo in 5 s | Flood vs normal 4-packet ping | Legit monitoring |
| 9000040/41 | Nmap NSE user-agent; lab probe URI | Scanner fingerprint | User-agent is trivially changed |

A DNS query alone is **not** malicious. Each DNS rule states the property (length, listed zone, rate) that makes the test suspicious.

## Normal vs suspicious
Normal traffic (a few HTTP requests, 4 pings, ordinary DNS) stays below every threshold and matches no content rule, so it produces events (flow/dns/http) but **no alerts**. Scenario 4 verifies this.

## Correlation
Gap-based grouping per source IP: an alert joins the source's newest case if it arrives <= `CASE_WINDOW_SEC` (60 s) after that case's last alert, otherwise it opens a new case. A case with >= `CASE_MIN_ALERTS` (3) alerts is flagged **correlated**. Because rule thresholds already collapse a burst into a few alerts, 3 is used instead of the 5 in the brief's example; both values are env-overridable (`SENTINEL_CASE_WINDOW`, `SENTINEL_CASE_MIN`).

## Risk score (0-100, additive, shown with breakdown)
Highest rule severity (40/30/20/10) + repetition (3 per extra alert, max 15) + signature diversity (5 per extra signature, max 15) + port breadth (>=100: 20, >=20: 14, >=5: 8, >=3: 4) + sensitive port targeted (+5). Bands: <30 Low, 30-54 Moderate, 55-74 Elevated, >=75 High. It ranks cases for attention. It is **not** a verdict, and it cannot see anything Suricata did not log.
