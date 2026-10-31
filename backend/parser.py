"""EVE JSON parsing and ingestion.

Suricata writes one JSON object per line. We
  1. tail the file (remembering byte offset + inode, so restarts and log rotation are safe),
  2. normalise each line into a flat dict,
  3. store every event (for context/"related events") and every alert (for triage),
  4. hand new alerts to the correlation engine.
Malformed or partial lines are skipped, never fatal.
"""
import json
import os
import time
from datetime import datetime

import config
import correlation
import database as db


def parse_ts(s):
    """EVE timestamps look like 2026-10-31T10:26:01.123456+0000 (offset without colon)."""
    try:
        if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def severity_label(ids_sev):
    try:
        return config.SEVERITY_MAP.get(int(ids_sev), "low")
    except (TypeError, ValueError):
        return "low"


def summarize(e):
    t = e.get("event_type")
    if t == "alert":
        return e["alert"].get("signature", "")
    if t == "dns":
        d = e.get("dns", {})
        q = (d.get("queries") or [{}])[0]
        name = d.get("rrname") or q.get("rrname", "")
        return f'{d.get("type", "")} {d.get("rrtype") or q.get("rrtype", "")} {name}'.strip()
    if t == "http":
        h = e.get("http", {})
        return f'{h.get("http_method", "")} {h.get("hostname", "")}{h.get("url", "")}'.strip()
    if t == "tls":
        return e.get("tls", {}).get("sni", "") or ""
    if t == "flow":
        f = e.get("flow", {})
        return f'{f.get("state", "")} pkts {f.get("pkts_toserver", 0)}/{f.get("pkts_toclient", 0)}'
    if t == "stats":
        return "suricata engine stats (heartbeat)"
    return t or ""


def normalise(line):
    try:
        e = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(e, dict) or "event_type" not in e or "timestamp" not in e:
        return None
    ts = parse_ts(e["timestamp"])
    if ts is None:
        return None
    return {
        "ts": ts, "event_type": e["event_type"],
        "src_ip": e.get("src_ip"), "src_port": e.get("src_port"),
        "dest_ip": e.get("dest_ip"), "dest_port": e.get("dest_port"),
        "proto": (e.get("proto") or "").upper() or None,
        "app_proto": e.get("app_proto"), "flow_id": e.get("flow_id"),
        "summary": summarize(e), "raw": e,
    }


def store(con, ev, origin):
    cur = con.execute(
        "INSERT INTO events(ts,event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto,flow_id,summary,origin,raw)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (ev["ts"], ev["event_type"], ev["src_ip"], ev["src_port"], ev["dest_ip"], ev["dest_port"],
         ev["proto"], ev["app_proto"], ev["flow_id"], ev["summary"][:300], origin,
         json.dumps(ev["raw"], separators=(",", ":"))))
    event_id = cur.lastrowid
    if ev["event_type"] != "alert":
        return event_id, None
    a = ev["raw"].get("alert", {})
    sev = a.get("severity")
    cur = con.execute(
        "INSERT INTO alerts(event_id,ts,signature,signature_id,category,ids_severity,severity,src_ip,src_port,"
        "dest_ip,dest_port,proto,action,origin) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, ev["ts"], a.get("signature", "unknown"), a.get("signature_id"), a.get("category", "Uncategorized"),
         sev, severity_label(sev), ev["src_ip"], ev["src_port"], ev["dest_ip"], ev["dest_port"], ev["proto"],
         a.get("action", "allowed"), origin))
    return event_id, cur.lastrowid


def ingest_lines(lines, origin="live"):
    """Parse + store lines, then correlate. Returns (events, alerts, skipped)."""
    n_ev = n_al = skipped = 0
    new_alert_ids, last_stats, last_ts = [], None, None
    with db.connect() as con:
        for line in lines:
            ev = normalise(line)
            if ev is None:
                if line.strip():
                    skipped += 1
                continue
            _, alert_id = store(con, ev, origin)
            n_ev += 1
            last_ts = ev["ts"]
            if ev["event_type"] == "stats":
                last_stats = ev["ts"]
            if alert_id:
                n_al += 1
                new_alert_ids.append(alert_id)
        if new_alert_ids:
            correlation.correlate(con, new_alert_ids)
    return n_ev, n_al, skipped, last_ts, last_stats


def ingest_file_once(path=None, origin="live"):
    """Read any new complete lines since the stored offset. Safe against truncation/rotation."""
    path = path or config.EVE_PATH
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    with db.connect() as con:
        state = db.one(con, "SELECT * FROM ingest_state WHERE path=?", (path,)) or {"offset": 0, "inode": st.st_ino}
        offset = state["offset"]
        if state.get("inode") != st.st_ino or st.st_size < offset:   # rotated or truncated
            offset = 0
    lines, new_offset = [], offset
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n")             # only consume complete lines
    if end >= 0:
        chunk = data[: end + 1]
        new_offset = offset + len(chunk)
        lines = chunk.decode("utf-8", "replace").splitlines()
    n_ev, n_al, skipped, last_ts, last_stats = ingest_lines(lines, origin)
    with db.connect() as con:
        prev = db.one(con, "SELECT * FROM ingest_state WHERE path=?", (path,)) or {}
        con.execute(
            "INSERT OR REPLACE INTO ingest_state(path,inode,offset,last_event_ts,last_stats_ts,last_read_wall)"
            " VALUES(?,?,?,?,?,?)",
            (path, st.st_ino, new_offset, last_ts or prev.get("last_event_ts"),
             last_stats or prev.get("last_stats_ts"), time.time()))
    return {"events": n_ev, "alerts": n_al, "skipped": skipped}


def tail_forever(path=None, stop=None):
    path = path or config.EVE_PATH
    while not (stop and stop.is_set()):
        try:
            ingest_file_once(path)
        except Exception as exc:    # never let the collector thread die
            print(f"[ingest] error: {exc}")
        time.sleep(config.POLL_INTERVAL_SEC)
