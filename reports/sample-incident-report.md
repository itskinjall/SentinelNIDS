# Incident Report - Case #1

**Investigation status:** Open  
**Data origin:** sample (SAMPLE DATA - not live traffic)

## Incident summary
Correlated incident from 10.77.0.1: 5 alert(s), max severity high.

- Source IP: `10.77.0.1`
- First seen: 2026-10-31 08:01:06 UTC
- Last seen: 2026-10-31 08:01:40 UTC
- IDS max severity (rule-defined): **high**
- Calculated risk score (heuristic, not a verdict): **76/100 (High)**

### Risk score breakdown
| Factor | Detail | Points |
|---|---|---|
| Highest rule severity | high | 30 |
| Repetition | 5 alerts in case | 12 |
| Signature diversity | 4 distinct signatures | 15 |
| Port breadth | 42 distinct destination ports observed | 14 |
| Sensitive service targeted | 22, 25, 139, 445, 2222, 3389 | 5 |

## Evidence
| Time (UTC) | Severity | Signature | Source | Destination | Proto |
|---|---|---|---|---|---|
| 2026-10-31 08:01:06 UTC | high | SENTINEL SCAN TCP SYN scan - 20+ SYNs in 5s from one source | 10.77.0.1:45705 | 10.77.0.2:443 | TCP |
| 2026-10-31 08:01:12 UTC | high | SENTINEL SCAN TCP SYN scan - 20+ SYNs in 5s from one source | 10.77.0.1:45578 | 10.77.0.2:80 | TCP |
| 2026-10-31 08:01:24 UTC | high | SENTINEL SCAN TCP XMAS scan (FIN+PSH+URG) | 10.77.0.1:49037 | 10.77.0.2:22 | TCP |
| 2026-10-31 08:01:32 UTC | high | SENTINEL SCAN TCP NULL scan (no flags set) | 10.77.0.1:35408 | 10.77.0.2:25 | TCP |
| 2026-10-31 08:01:40 UTC | high | SENTINEL HTTP Nmap Scripting Engine user-agent | 10.77.0.1:38219 | 10.77.0.2:80 | TCP |

## Detection rule(s)
**SID 9000001** - Scenario 1: Port scan detection
```
alert tcp any any -> $HOME_NET any (msg:"SENTINEL SCAN TCP SYN scan - 20+ SYNs in 5s from one source"; flags:S,12; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; priority:2; sid:9000001; rev:1; metadata:created_by sentinel, scenario scan;)
```
**SID 9000002** - Scenario 1: Port scan detection
```
alert tcp any any -> $HOME_NET any (msg:"SENTINEL SCAN TCP NULL scan (no flags set)"; flags:0; threshold:type both, track by_src, count 5, seconds 10; classtype:attempted-recon; priority:2; sid:9000002; rev:1; metadata:created_by sentinel, scenario scan;)
```
**SID 9000003** - Scenario 1: Port scan detection
```
alert tcp any any -> $HOME_NET any (msg:"SENTINEL SCAN TCP XMAS scan (FIN+PSH+URG)"; flags:FPU,12; threshold:type both, track by_src, count 5, seconds 10; classtype:attempted-recon; priority:2; sid:9000003; rev:1; metadata:created_by sentinel, scenario scan;)
```
**SID 9000040** - ICMP / HTTP
```
alert http any any -> $HOME_NET any (msg:"SENTINEL HTTP Nmap Scripting Engine user-agent"; flow:to_server; http.user_agent; content:"Nmap Scripting Engine"; classtype:web-application-activity; priority:2; sid:9000040; rev:1; metadata:created_by sentinel, scenario scan;)
```

## Analysis
Source 10.77.0.1 triggered 5 IDS alert(s) across 4 signature(s) over 34 s (2026-10-31 08:01:06 UTC to 2026-10-31 08:01:40 UTC). Destination ports in alerts: 22, 25, 80, 443. Highest rule severity: high. The alerts met the correlation threshold (>= 3 alerts within 60 s gaps; lab configuration). SentinelNIDS calculated a risk score of 76/100 (High). This score is a heuristic triage aid, not a threat verdict: the IDS alerts show that rules matched; whether the activity was malicious or authorised must be confirmed by the analyst.

## Recommended mitigation
- Confirm the scan source is authorised (e.g. your own lab host). If not, block or rate-limit it at the firewall.
- Close or firewall services that do not need to be reachable; scan results show what an attacker would see.
- Keep the rule thresholds tuned so authorised vulnerability scans are tagged, not alerted.

## Analyst notes
_No notes recorded._

> Alerts are Suricata rule matches. The risk score is a SentinelNIDS heuristic and not a confirmed verdict.
