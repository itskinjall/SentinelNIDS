"""Transparent risk score (0-100) for an investigation case.

IMPORTANT: this is a *heuristic triage aid computed by SentinelNIDS*. It is NOT a Suricata verdict and
NOT proof of malicious intent. An IDS alert = "a rule matched". The score = "how much attention this
case probably deserves", built from the factors below. Every factor is returned so analysts can audit it.

Factor                      Points                                    Rationale
--------------------------  ----------------------------------------  --------------------------------
Highest rule severity       critical 40 / high 30 / medium 20 / low 10 What the rule author considered serious
Repetition                  +3 per extra alert, max 15                 Persistent behaviour > one-off
Signature diversity         +5 per extra distinct signature, max 15    Multiple techniques from one source
Port breadth                >=100 ports +20, >=20 +14, >=5 +8, >=3 +4  Wide targeting suggests scanning
Sensitive service targeted  +5 if any dest port in SENSITIVE_PORTS     Admin/remote-access/db exposure
Total capped at 100. Bands: 0-29 Low, 30-54 Moderate, 55-74 Elevated, 75-100 High.
"""
import database as db

BASE = {"critical": 40, "high": 30, "medium": 20, "low": 10}
SENSITIVE_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 2222}


def band(score):
    return "High" if score >= 75 else "Elevated" if score >= 55 else "Moderate" if score >= 30 else "Low"


def score_case(con, case_id):
    c = db.one(con, "SELECT * FROM cases WHERE id=?", (case_id,))
    alerts = db.rows(con, "SELECT signature, severity, dest_port FROM alerts WHERE case_id=?", (case_id,))
    if not c or not alerts:
        return 0, []
    f = []
    sev = c["max_severity"]
    f.append({"factor": "Highest rule severity", "detail": sev, "points": BASE.get(sev, 10)})

    extra = len(alerts) - 1
    f.append({"factor": "Repetition", "detail": f"{len(alerts)} alerts in case", "points": min(15, 3 * extra)})

    sigs = {a["signature"] for a in alerts}
    f.append({"factor": "Signature diversity", "detail": f"{len(sigs)} distinct signatures",
              "points": min(15, 5 * (len(sigs) - 1))})

    ports = {r["dest_port"] for r in db.rows(
        con,
        "SELECT DISTINCT dest_port FROM events WHERE src_ip=? AND dest_port IS NOT NULL AND ts BETWEEN ? AND ?"
        " AND event_type IN ('flow','alert')",
        (c["src_ip"], c["first_seen"] - 30, c["last_seen"] + 120))}
    ports |= {a["dest_port"] for a in alerts if a["dest_port"]}
    n = len(ports)
    pts = 20 if n >= 100 else 14 if n >= 20 else 8 if n >= 5 else 4 if n >= 3 else 0
    f.append({"factor": "Port breadth", "detail": f"{n} distinct destination ports observed", "points": pts})

    hit = sorted(ports & SENSITIVE_PORTS)
    f.append({"factor": "Sensitive service targeted", "detail": ", ".join(map(str, hit)) or "none",
              "points": 5 if hit else 0})

    total = min(100, sum(x["points"] for x in f))
    return total, f
