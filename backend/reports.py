"""Incident report + evidence export (JSON / CSV / Markdown) and the rule/mitigation knowledge base."""
import csv
import io
import json
import re
from datetime import datetime, timezone

import config
import database as db
import risk_engine

MITIGATION = {
    "scan": ["Confirm the scan source is authorised (e.g. your own lab host). If not, block or rate-limit it at the firewall.",
             "Close or firewall services that do not need to be reachable; scan results show what an attacker would see.",
             "Keep the rule thresholds tuned so authorised vulnerability scans are tagged, not alerted."],
    "repeat": ["Check the targeted service's own logs (e.g. auth.log) - the IDS sees connection rate, not failed logins.",
               "Apply connection rate limiting / fail2ban-style controls on the service.",
               "Prefer key-based authentication and restrict the service to trusted source ranges."],
    "dns": ["Identify the querying host and the process that issued the queries.",
            "Review the queried names against threat intelligence; a long or random name is an indicator, not proof.",
            "Consider DNS filtering/sinkholing for confirmed-bad zones and restrict outbound DNS to approved resolvers."],
    "icmp": ["Verify whether the traffic is a legitimate monitoring tool, otherwise rate-limit ICMP at the edge."],
    "http": ["Review web server access logs for the same source.", "Restrict or monitor scanner user-agents and probe URIs."],
    "default": ["Validate the alert against packet evidence before acting.", "Contain the source only after confirming it is not authorised."],
}


def load_rules():
    """sid -> {'rule': full line, 'why': rule-specific comment (else section header), 'scenario': str}"""
    rules, section, comment = {}, "", ""
    try:
        with open(config.RULES_PATH, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s.startswith("#"):
                    text = re.sub(r"^\d{7}:\s*", "", s.strip("# -").strip())
                    if s.startswith("# ----------"):
                        section, comment = text, ""
                    else:
                        comment = text
                    continue
                m = re.search(r"sid:(\d+);", s)
                if m:
                    sc = re.search(r"scenario (\w+)", s)
                    rules[int(m.group(1))] = {"rule": s, "why": comment or section, "section": section,
                                              "scenario": sc.group(1) if sc else "default"}
                    comment = ""
    except OSError:
        pass
    return rules


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_case(con, case_id):
    c = db.one(con, "SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return None
    alerts = db.rows(con, "SELECT * FROM alerts WHERE case_id=? ORDER BY ts", (case_id,))
    notes = db.rows(con, "SELECT * FROM notes WHERE case_id=? OR alert_id IN (SELECT id FROM alerts WHERE case_id=?) ORDER BY ts",
                    (case_id, case_id))
    rules = load_rules()
    sids = sorted({a["signature_id"] for a in alerts if a["signature_id"]})
    scenarios = {rules.get(s, {}).get("scenario", "default") for s in sids} or {"default"}
    ports = sorted({a["dest_port"] for a in alerts if a["dest_port"]})
    sigs = sorted({a["signature"] for a in alerts})
    dur = int(c["last_seen"] - c["first_seen"])
    c["risk_breakdown"] = db.loads(c["risk_breakdown"], [])
    c["risk_band"] = risk_engine.band(c["risk_score"])
    analysis = (
        f"Source {c['src_ip']} triggered {len(alerts)} IDS alert(s) across {len(sigs)} signature(s) over {dur} s "
        f"({iso(c['first_seen'])} to {iso(c['last_seen'])}). Destination ports in alerts: "
        f"{', '.join(map(str, ports)) or 'n/a'}. Highest rule severity: {c['max_severity']}. "
        f"{'The alerts met the correlation threshold (>= ' + str(config.CASE_MIN_ALERTS) + ' alerts within ' + str(config.CASE_WINDOW_SEC) + ' s gaps; lab configuration).' if c['correlated'] else 'The alerts did NOT meet the correlation threshold, so this is an isolated case.'} "
        f"SentinelNIDS calculated a risk score of {c['risk_score']}/100 ({c['risk_band']}). "
        "This score is a heuristic triage aid, not a threat verdict: the IDS alerts show that rules matched; "
        "whether the activity was malicious or authorised must be confirmed by the analyst."
    )
    mitig = []
    for sc in sorted(scenarios):
        mitig += [m for m in MITIGATION.get(sc, MITIGATION["default"]) if m not in mitig]
    return {
        "case_id": c["id"], "status": c["status"], "origin": c["origin"],
        "summary": f"{'Correlated incident' if c['correlated'] else 'Isolated activity'} from {c['src_ip']}: {len(alerts)} alert(s), max severity {c['max_severity']}.",
        "case": c, "evidence": alerts,
        "detection_rules": [{"sid": s, **rules[s]} for s in sids if s in rules],
        "analysis": analysis, "recommended_mitigation": mitig,
        "analyst_notes": notes,
        "disclaimer": "Alerts are Suricata rule matches. The risk score is a SentinelNIDS heuristic and not a confirmed verdict.",
    }


def to_markdown(r):
    c = r["case"]
    L = [f"# Incident Report - Case #{r['case_id']}", "",
         f"**Investigation status:** {r['status']}  ", f"**Data origin:** {r['origin']}" + (" (SAMPLE DATA - not live traffic)" if r["origin"] == "sample" else ""), "",
         "## Incident summary", r["summary"], "",
         f"- Source IP: `{c['src_ip']}`", f"- First seen: {iso(c['first_seen'])}", f"- Last seen: {iso(c['last_seen'])}",
         f"- IDS max severity (rule-defined): **{c['max_severity']}**",
         f"- Calculated risk score (heuristic, not a verdict): **{c['risk_score']}/100 ({c['risk_band']})**", "",
         "### Risk score breakdown", "| Factor | Detail | Points |", "|---|---|---|"]
    L += [f"| {f['factor']} | {f['detail']} | {f['points']} |" for f in c["risk_breakdown"]]
    L += ["", "## Evidence", "| Time (UTC) | Severity | Signature | Source | Destination | Proto |", "|---|---|---|---|---|---|"]
    for a in r["evidence"]:
        L.append(f"| {iso(a['ts'])} | {a['severity']} | {a['signature']} | {a['src_ip']}:{a['src_port']} | {a['dest_ip']}:{a['dest_port']} | {a['proto']} |")
    L += ["", "## Detection rule(s)"]
    for d in r["detection_rules"]:
        L += [f"**SID {d['sid']}** - {d['why']}", "```", d["rule"], "```"]
    L += ["", "## Analysis", r["analysis"], "", "## Recommended mitigation"]
    L += [f"- {m}" for m in r["recommended_mitigation"]]
    L += ["", "## Analyst notes"] + ([f"- [{iso(n['ts'])}] {n['author']}: {n['body']}" for n in r["analyst_notes"]] or ["_No notes recorded._"])
    L += ["", f"> {r['disclaimer']}", ""]
    return "\n".join(L)


def to_csv(r):
    buf = io.StringIO()
    cols = ["id", "ts_utc", "severity", "ids_severity", "signature", "signature_id", "category", "src_ip", "src_port",
            "dest_ip", "dest_port", "proto", "action", "status", "case_id", "origin"]
    w = csv.writer(buf)
    w.writerow(cols)
    for a in r["evidence"]:
        w.writerow([a["id"], iso(a["ts"])] + [a[k] for k in cols[2:]])
    return buf.getvalue()


def to_json(r):
    return json.dumps(r, indent=2, default=str)
