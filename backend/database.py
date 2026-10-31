"""SQLite storage. One connection per call (Flask threads + ingest thread share the file safely via WAL)."""
import json
import sqlite3
from contextlib import contextmanager

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,                 -- epoch seconds (UTC)
  event_type TEXT NOT NULL,
  src_ip TEXT, src_port INTEGER, dest_ip TEXT, dest_port INTEGER,
  proto TEXT, app_proto TEXT, flow_id INTEGER,
  summary TEXT,
  origin TEXT NOT NULL DEFAULT 'live',   -- 'live' (real Suricata) or 'sample'
  raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_ip TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  alert_count INTEGER NOT NULL DEFAULT 0,
  max_severity TEXT NOT NULL DEFAULT 'low',
  correlated INTEGER NOT NULL DEFAULT 0,   -- 1 when alert_count >= CASE_MIN_ALERTS
  status TEXT NOT NULL DEFAULT 'Open',
  risk_score INTEGER NOT NULL DEFAULT 0,
  risk_breakdown TEXT NOT NULL DEFAULT '[]',
  origin TEXT NOT NULL DEFAULT 'live'
);
CREATE INDEX IF NOT EXISTS ix_cases_src ON cases(src_ip, last_seen);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL REFERENCES events(id),
  ts REAL NOT NULL,
  signature TEXT NOT NULL, signature_id INTEGER, category TEXT,
  ids_severity INTEGER, severity TEXT NOT NULL,
  src_ip TEXT, src_port INTEGER, dest_ip TEXT, dest_port INTEGER, proto TEXT,
  action TEXT,
  status TEXT NOT NULL DEFAULT 'Open',
  case_id INTEGER REFERENCES cases(id),
  origin TEXT NOT NULL DEFAULT 'live'
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_alerts_case ON alerts(case_id);

CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER, case_id INTEGER,
  ts REAL NOT NULL, author TEXT NOT NULL DEFAULT 'analyst', body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_state (
  path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER NOT NULL DEFAULT 0,
  last_event_ts REAL, last_stats_ts REAL, last_read_wall REAL
);
"""


@contextmanager
def connect():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with connect() as con:
        con.executescript(SCHEMA)


def rows(con, sql, args=()):
    return [dict(r) for r in con.execute(sql, args).fetchall()]


def one(con, sql, args=()):
    r = con.execute(sql, args).fetchone()
    return dict(r) if r else None


def loads(s, default=None):
    try:
        return json.loads(s)
    except Exception:
        return default
