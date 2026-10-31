"""Event correlation: group alerts from the same source IP into investigation cases.

Algorithm (gap-based window):
  * An alert joins the newest case for its source IP if it arrives within CASE_WINDOW_SEC of that case's
    last alert; otherwise it opens a new case.
  * A case is flagged 'correlated' once it holds >= CASE_MIN_ALERTS alerts.
Both numbers are lab configuration choices (backend/config.py), NOT security standards. Note that
rule-level thresholds already collapse a scan burst into a few alerts, so the default min is 3, not 5.
"""
import json

import config
import database as db
import risk_engine

_RANK = {s: i for i, s in enumerate(config.SEVERITY_ORDER)}   # critical=0 ... low=3


def correlate(con, alert_ids):
    touched = set()
    q = ",".join("?" * len(alert_ids))
    for a in db.rows(con, f"SELECT * FROM alerts WHERE id IN ({q}) ORDER BY ts", alert_ids):
        if not a["src_ip"]:
            continue
        c = db.one(con, "SELECT * FROM cases WHERE src_ip=? AND origin=? AND last_seen>=? ORDER BY last_seen DESC LIMIT 1",
                   (a["src_ip"], a["origin"], a["ts"] - config.CASE_WINDOW_SEC))
        if c is None:
            cur = con.execute(
                "INSERT INTO cases(src_ip,first_seen,last_seen,alert_count,max_severity,origin) VALUES(?,?,?,?,?,?)",
                (a["src_ip"], a["ts"], a["ts"], 0, a["severity"], a["origin"]))
            cid, c = cur.lastrowid, {"max_severity": a["severity"], "alert_count": 0}
        else:
            cid = c["id"]
        sev = a["severity"] if _RANK[a["severity"]] < _RANK[c["max_severity"]] else c["max_severity"]
        n = c["alert_count"] + 1
        con.execute("UPDATE cases SET last_seen=MAX(last_seen,?), first_seen=MIN(first_seen,?), alert_count=?,"
                    " max_severity=?, correlated=? WHERE id=?",
                    (a["ts"], a["ts"], n, sev, 1 if n >= config.CASE_MIN_ALERTS else 0, cid))
        con.execute("UPDATE alerts SET case_id=? WHERE id=?", (cid, a["id"]))
        touched.add(cid)
    for cid in touched:
        score, breakdown = risk_engine.score_case(con, cid)
        con.execute("UPDATE cases SET risk_score=?, risk_breakdown=? WHERE id=?", (score, json.dumps(breakdown), cid))
    return touched
