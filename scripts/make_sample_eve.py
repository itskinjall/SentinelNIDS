#!/usr/bin/env python3
"""Generate data/sample/eve.sample.json: SAMPLE events in Suricata's EVE JSON shape for development/demo.
These are NOT captured traffic. The dashboard labels anything loaded from this file as 'sample'.
Addresses are RFC1918 lab addresses only (10.77.0.1 = attacker, 10.77.0.2 = target)."""
import json, random
from datetime import datetime, timedelta, timezone

random.seed(7)
A, T, DNS = "10.77.0.1", "10.77.0.2", "10.77.0.2"
T0 = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)
ev, fid = [], [1000]

def ts(sec):
    return (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")

def base(sec, typ, src, sp, dst, dp, proto, **extra):
    fid[0] += 1
    e = {"timestamp": ts(sec), "flow_id": fid[0], "in_iface": "veth-sentinel", "event_type": typ,
         "src_ip": src, "src_port": sp, "dest_ip": dst, "dest_port": dp, "proto": proto}
    e.update(extra); ev.append(e)

def flow(sec, src, dst, dp, proto="TCP", app=None, pk=(4, 3)):
    f = {"pkts_toserver": pk[0], "pkts_toclient": pk[1], "bytes_toserver": pk[0] * 60, "bytes_toclient": pk[1] * 60,
         "start": ts(sec - 1), "end": ts(sec), "age": 1, "state": "closed", "reason": "timeout", "alerted": False}
    extra = {"flow": f}
    if app: extra["app_proto"] = app
    base(sec, "flow", src, random.randint(32768, 60999), dst, dp, proto, **extra)

CLS = {"attempted-recon": "Attempted Information Leak", "attempted-admin": "Attempted Administrator Privilege Gain",
       "bad-unknown": "Potentially Bad Traffic", "trojan-activity": "A Network Trojan was detected",
       "attempted-dos": "Attempted Denial of Service", "web-application-activity": "Access to a potentially vulnerable web application"}

def alert(sec, src, dst, dp, proto, sid, sig, cls, sev, scen, **extra):
    base(sec, "alert", src, random.randint(32768, 60999), dst, dp, proto,
         alert={"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": sig,
                "category": CLS[cls], "severity": sev, "metadata": {"created_by": ["sentinel"], "scenario": [scen]}}, **extra)

# ---- Scenario 4: normal traffic (t=0..40) -> must produce NO alerts
base(2, "http", A, 40001, T, 80, "TCP", app_proto="http", http={"hostname": T, "url": "/", "http_user_agent": "curl/8.5.0", "http_method": "GET", "status": 200, "length": 33})
base(3, "http", A, 40003, T, 80, "TCP", app_proto="http", http={"hostname": T, "url": "/index.html", "http_user_agent": "curl/8.5.0", "http_method": "GET", "status": 200, "length": 33})
for i, n in enumerate(["example.com", "example.org"]):
    base(5 + i, "dns", A, 50000 + i, DNS, 53, "UDP", app_proto="dns", dns={"version": 2, "type": "query", "id": 100 + i, "rrname": n, "rrtype": "A", "tx_id": 0, "opcode": 0})
for i in range(4):
    base(8 + i, "flow", A, 0, T, 0, "ICMP", flow={"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 98, "bytes_toclient": 98, "start": ts(8 + i), "end": ts(8 + i), "age": 0, "state": "established", "reason": "timeout", "alerted": False})
flow(15, A, T, 80, app="http"); flow(16, A, T, 80, app="http")

# ---- Scenario 1: port scan (t=60..110) from the attacker
alert(66, A, T, 443, "TCP", 9000001, "SENTINEL SCAN TCP SYN scan - 20+ SYNs in 5s from one source", "attempted-recon", 2, "scan")
for i in range(60): flow(60 + i * 0.5, A, T, random.choice([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080] + list(range(1000, 1060))), pk=(1, 1))
alert(72, A, T, 80, "TCP", 9000001, "SENTINEL SCAN TCP SYN scan - 20+ SYNs in 5s from one source", "attempted-recon", 2, "scan")
alert(84, A, T, 22, "TCP", 9000003, "SENTINEL SCAN TCP XMAS scan (FIN+PSH+URG)", "attempted-recon", 2, "scan")
alert(92, A, T, 25, "TCP", 9000002, "SENTINEL SCAN TCP NULL scan (no flags set)", "attempted-recon", 2, "scan")
alert(100, A, T, 80, "TCP", 9000040, "SENTINEL HTTP Nmap Scripting Engine user-agent", "web-application-activity", 2, "scan", app_proto="http",
      http={"hostname": T, "url": "/", "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "http_method": "GET"})

# ---- Scenario 2: repeated connections to tcp/2222 (gap > 60 s -> separate case)
for i in range(12): flow(200 + i * 2, A, T, 2222, pk=(2, 1))
alert(214, A, T, 2222, "TCP", 9000010, "SENTINEL REPEAT 8+ connection attempts to lab service tcp/2222 in 30s", "attempted-recon", 3, "repeat")

# ---- Scenario 3: suspicious DNS (t=300..340)
long = "mfrggzdfmztwq2lknnwg23tpobyxe43uovwgy3bamrxxe3dforzxi.lab.test"
for t_, name in [(300, "beacon.c2-sim.lab.test"), (310, long)]:
    base(t_, "dns", A, 51000 + int(t_), DNS, 53, "UDP", app_proto="dns", dns={"version": 2, "type": "query", "id": t_, "rrname": name, "rrtype": "A", "tx_id": 0, "opcode": 0})
alert(300, A, DNS, 53, "UDP", 9000021, "SENTINEL DNS Query to lab blocklist zone c2-sim.lab.test (simulated threat intel)", "trojan-activity", 1, "dns", app_proto="dns")
alert(310, A, DNS, 53, "UDP", 9000020, "SENTINEL DNS Query name >= 50 bytes (possible tunnelling indicator)", "bad-unknown", 3, "dns", app_proto="dns")
for i in range(30):
    base(320 + i * 0.3, "dns", A, 52000 + i, DNS, 53, "UDP", app_proto="dns", dns={"version": 2, "type": "query", "id": 900 + i, "rrname": f"q{i}.burst.lab.test", "rrtype": "A", "tx_id": 0, "opcode": 0})
alert(329, A, DNS, 53, "UDP", 9000022, "SENTINEL DNS Burst of 25+ queries in 10s from one source", "bad-unknown", 3, "dns", app_proto="dns")

# ---- heartbeat (stats) so the health check has something to read
for i in range(0, 360, 8):
    base(i, "stats", None, None, None, None, None, stats={"uptime": i, "capture": {"kernel_packets": i * 40, "kernel_drops": 0}}) if False else ev.append(
        {"timestamp": ts(i), "event_type": "stats", "stats": {"uptime": i, "capture": {"kernel_packets": i * 40, "kernel_drops": 0}}})

ev.sort(key=lambda e: e["timestamp"])
with open("data/sample/eve.sample.json", "w") as f:
    for e in ev: f.write(json.dumps(e, separators=(",", ":")) + "\n")
print(len(ev), "events")
