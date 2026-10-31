"""SentinelNIDS Flask backend: ingests Suricata EVE JSON, serves the API and the dashboard.

Run:  python backend/app.py                    (live: tails SENTINEL_EVE, default /var/log/suricata/eve.json)
      python backend/app.py --load-sample      (load labelled SAMPLE events for development)
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, abort, jsonify, request, send_from_directory

import config
import database as db
import parser as eve_parser
import pcap
import reports
import risk_engine

app = Flask(__name__, static_folder=None)
STATUSES = ("Open", "Investigating", "Resolved")


def err(msg, code=400):
    return jsonify({"error": msg}), code


# ----------------------------------------------------------------- dashboard
@app.get("/")
def index():
    return send_from_directory(config.ROOT / "dashboard", "index.html")


@app.get("/<path:p>")
def static_files(p):
    if p.startswith("api/"):
        abort(404)
    return send_from_directory(config.ROOT / "dashboard", p)


# ----------------------------------------------------------------- health
@app.get("/api/health")
def health():
    with db.connect() as con:
        st = db.one(con, "SELECT * FROM ingest_state WHERE path=?", (config.EVE_PATH,))
        sample = db.one(con, "SELECT COUNT(*) n FROM events WHERE origin='sample'")["n"]
        live = db.one(con, "SELECT COUNT(*) n FROM events WHERE origin='live'")["n"]
    now = time.time()
    if not os.path.exists(config.EVE_PATH):
        state, msg = "no_file", f"EVE file not found: {config.EVE_PATH}. Is Suricata running / is the path right?"
    elif not st or not st.get("last_stats_ts"):
        state, msg = "waiting", "No Suricata stats heartbeat received yet."
    elif now - st["last_stats_ts"] > config.STALE_AFTER_SEC:
        state, msg = "stale", (f"No Suricata heartbeat for {int(now - st['last_stats_ts'])} s "
                               f"(expected every {config.STATS_INTERVAL_SEC} s). Suricata may have stopped; "
                               "no new alerts can be detected while it is down.")
    else:
        state, msg = "healthy", "Suricata heartbeat OK."
    return jsonify({"state": state, "message": msg, "eve_path": config.EVE_PATH,
                    "last_event_ts": st and st.get("last_event_ts"), "last_stats_ts": st and st.get("last_stats_ts"),
                    "sample_events": sample, "live_events": live})


# ----------------------------------------------------------------- overview
@app.get("/api/overview")
def overview():
    with db.connect() as con:
        sev = {r["severity"]: r["n"] for r in db.rows(con, "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
        return jsonify({
            "total_events": db.one(con, "SELECT COUNT(*) n FROM events WHERE event_type!='stats'")["n"],
            "total_alerts": db.one(con, "SELECT COUNT(*) n FROM alerts")["n"],
            "by_severity": {s: sev.get(s, 0) for s in config.SEVERITY_ORDER},
            "unique_sources": db.one(con, "SELECT COUNT(DISTINCT src_ip) n FROM alerts")["n"],
            "open_cases": db.one(con, "SELECT COUNT(*) n FROM cases WHERE status!='Resolved'")["n"],
            "top_ports": db.rows(con, "SELECT dest_port port, proto, COUNT(*) n FROM alerts WHERE dest_port IS NOT NULL "
                                      "GROUP BY dest_port, proto ORDER BY n DESC LIMIT 8"),
        })


# ----------------------------------------------------------------- alerts
@app.get("/api/alerts")
def alerts():
    where, args = [], []
    for col, key in (("a.severity", "severity"), ("a.status", "status"), ("a.src_ip", "src"), ("a.proto", "proto")):
        v = request.args.get(key)
        if v:
            where.append(f"{col}=?")
            args.append(v)
    q = request.args.get("q")
    if q:
        where.append("(a.signature LIKE ? OR a.src_ip LIKE ? OR a.dest_ip LIKE ?)")
        args += [f"%{q}%"] * 3
    limit = min(int(request.args.get("limit", 200)), 1000)
    with db.connect() as con:
        r = db.rows(con, "SELECT a.*, c.risk_score, c.correlated FROM alerts a LEFT JOIN cases c ON c.id=a.case_id"
                    + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY a.ts DESC LIMIT ?", args + [limit])
    for a in r:
        a["risk_band"] = risk_engine.band(a["risk_score"] or 0)
    return jsonify(r)


@app.get("/api/alerts/<int:aid>")
def alert_detail(aid):
    with db.connect() as con:
        a = db.one(con, "SELECT * FROM alerts WHERE id=?", (aid,))
        if not a:
            return err("not found", 404)
        ev = db.one(con, "SELECT raw FROM events WHERE id=?", (a["event_id"],))
        case = db.one(con, "SELECT * FROM cases WHERE id=?", (a["case_id"],)) if a["case_id"] else None
        if case:
            case["risk_breakdown"] = db.loads(case["risk_breakdown"], [])
            case["risk_band"] = risk_engine.band(case["risk_score"])
        related = db.rows(con, "SELECT id,ts,event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto,summary FROM events "
                          "WHERE (src_ip=? OR dest_ip=?) AND event_type!='stats' AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 300",
                          (a["src_ip"], a["src_ip"], a["ts"] - config.RELATED_WINDOW_SEC, a["ts"] + config.RELATED_WINDOW_SEC))
        notes = db.rows(con, "SELECT * FROM notes WHERE alert_id=? ORDER BY ts", (aid,))
    rule = reports.load_rules().get(a["signature_id"])
    return jsonify({"alert": a, "event": db.loads(ev["raw"]) if ev else None, "case": case, "related": related,
                    "rule": rule, "notes": notes, "pcap": pcap.meta(a)})


def _set_status(table, rid, status):
    if status not in STATUSES:
        return err(f"status must be one of {STATUSES}")
    with db.connect() as con:
        if table == "alerts":
            con.execute("UPDATE alerts SET status=? WHERE id=?", (status, rid))
        else:   # case status propagates to its alerts
            con.execute("UPDATE cases SET status=? WHERE id=?", (status, rid))
            con.execute("UPDATE alerts SET status=? WHERE case_id=?", (status, rid))
    return jsonify({"ok": True, "status": status})


def _add_note(alert_id=None, case_id=None):
    body = ((request.get_json(silent=True) or {}).get("body") or "").strip()
    if not body:
        return err("note body required")
    with db.connect() as con:
        con.execute("INSERT INTO notes(alert_id,case_id,ts,body) VALUES(?,?,?,?)", (alert_id, case_id, time.time(), body[:4000]))
    return jsonify({"ok": True})


@app.post("/api/alerts/<int:aid>/status")
def alert_status(aid):
    return _set_status("alerts", aid, (request.get_json(silent=True) or {}).get("status"))


@app.post("/api/alerts/<int:aid>/notes")
def alert_note(aid):
    return _add_note(alert_id=aid)


@app.get("/api/alerts/<int:aid>/packets")
def alert_packets(aid):
    with db.connect() as con:
        a = db.one(con, "SELECT * FROM alerts WHERE id=?", (aid,))
    if not a or not a["src_ip"] or not a["dest_ip"]:
        return err("not found", 404)
    try:
        return jsonify(pcap.packets(a))
    except Exception as exc:
        return err(f"packet extraction failed: {exc}", 500)


@app.get("/api/alerts/<int:aid>/pcap")
def alert_pcap(aid):
    with db.connect() as con:
        a = db.one(con, "SELECT * FROM alerts WHERE id=?", (aid,))
    data = pcap.filtered_pcap(a) if a and a["src_ip"] and a["dest_ip"] else None
    if not data:
        return err("no PCAP available (or tcpdump missing)", 404)
    return Response(data, mimetype="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": f"attachment; filename=alert-{aid}.pcap"})


# ----------------------------------------------------------------- cases / incident reports
@app.get("/api/cases")
def cases():
    with db.connect() as con:
        r = db.rows(con, "SELECT * FROM cases ORDER BY last_seen DESC LIMIT 500")
        for c in r:
            c["risk_band"] = risk_engine.band(c["risk_score"])
            c["signatures"] = [x["signature"] for x in db.rows(con, "SELECT DISTINCT signature FROM alerts WHERE case_id=?", (c["id"],))]
            c.pop("risk_breakdown", None)
    return jsonify(r)


@app.get("/api/cases/<int:cid>")
def case_detail(cid):
    with db.connect() as con:
        r = reports.build_case(con, cid)
    return jsonify(r) if r else err("not found", 404)


@app.post("/api/cases/<int:cid>/status")
def case_status(cid):
    return _set_status("cases", cid, (request.get_json(silent=True) or {}).get("status"))


@app.post("/api/cases/<int:cid>/notes")
def case_note(cid):
    return _add_note(case_id=cid)


@app.get("/api/cases/<int:cid>/export")
def case_export(cid):
    fmt = request.args.get("format", "json")
    with db.connect() as con:
        r = reports.build_case(con, cid)
    if not r:
        return err("not found", 404)
    conv = {"json": (reports.to_json, "application/json"), "csv": (reports.to_csv, "text/csv"),
            "md": (reports.to_markdown, "text/markdown")}
    if fmt not in conv:
        return err("format must be json, csv or md")
    fn, mime = conv[fmt]
    return Response(fn(r), mimetype=mime, headers={"Content-Disposition": f"attachment; filename=case-{cid}.{fmt}"})


# ----------------------------------------------------------------- analytics
@app.get("/api/analytics")
def analytics():
    with db.connect() as con:
        span = db.one(con, "SELECT MIN(ts) lo, MAX(ts) hi FROM alerts")
        lo, hi = span["lo"], span["hi"]
        bucket = 60
        if lo is not None:
            s = hi - lo
            bucket = 60 if s <= 3 * 3600 else 900 if s <= 36 * 3600 else 3600
        series = {}
        for r in db.rows(con, "SELECT CAST(ts/? AS INTEGER)*? b, severity, COUNT(*) n FROM alerts GROUP BY b, severity", (bucket, bucket)):
            series.setdefault(r["b"], {})[r["severity"]] = r["n"]
        return jsonify({
            "bucket_sec": bucket,
            "over_time": [{"t": b, **{s: v.get(s, 0) for s in config.SEVERITY_ORDER}} for b, v in sorted(series.items())],
            "top_sources": db.rows(con, "SELECT src_ip, COUNT(*) n FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT 8"),
            "protocols": db.rows(con, "SELECT UPPER(COALESCE(NULLIF(app_proto,'failed'),proto)) p, COUNT(*) n FROM events "
                                      "WHERE event_type IN ('flow','dns','http','tls','alert') AND COALESCE(app_proto,proto) IS NOT NULL "
                                      "GROUP BY p ORDER BY n DESC LIMIT 8"),
            "categories": db.rows(con, "SELECT category, COUNT(*) n FROM alerts GROUP BY category ORDER BY n DESC LIMIT 8"),
            "event_types": db.rows(con, "SELECT event_type, COUNT(*) n FROM events GROUP BY event_type ORDER BY n DESC"),
        })


# ----------------------------------------------------------------- sample data / ingest control
def load_sample():
    with open(config.SAMPLE_EVE, encoding="utf-8") as f:
        return eve_parser.ingest_lines(f.read().splitlines(), origin="sample")


@app.post("/api/sample/load")
def sample_load():
    n = load_sample()
    return jsonify({"events": n[0], "alerts": n[1]})


@app.post("/api/sample/clear")
def sample_clear():
    with db.connect() as con:
        for t in ("notes", "alerts", "cases", "events"):
            if t == "notes":
                con.execute("DELETE FROM notes WHERE alert_id IN (SELECT id FROM alerts WHERE origin='sample') "
                            "OR case_id IN (SELECT id FROM cases WHERE origin='sample')")
            else:
                con.execute(f"DELETE FROM {t} WHERE origin='sample'")
    return jsonify({"ok": True})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")   # local only by default: there is no authentication
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--load-sample", action="store_true", help="load labelled sample events (not live traffic)")
    ap.add_argument("--no-ingest", action="store_true", help="do not tail the EVE file")
    a = ap.parse_args()
    db.init_db()
    if a.load_sample:
        print("[sample] loaded", load_sample())
    if not a.no_ingest:
        threading.Thread(target=eve_parser.tail_forever, daemon=True).start()
    print(f"SentinelNIDS: http://{a.host}:{a.port}   EVE: {config.EVE_PATH}")
    app.run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()
