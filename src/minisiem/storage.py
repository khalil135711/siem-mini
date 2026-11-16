"""SQLite-Speicher fuer Events und Alerts."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT, source TEXT, host TEXT, user TEXT,
  src_ip TEXT, action TEXT, outcome TEXT, raw TEXT, extra TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, rule_id TEXT, title TEXT, severity TEXT, mitre TEXT,
  grp TEXT, first_seen TEXT, last_seen TEXT, count INTEGER, evidence TEXT);
"""


class Store:
    def __init__(self, path: str = "minisiem.db"):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def add_events(self, events) -> int:
        rows = [
            (e.ts.isoformat(), e.source, e.host, e.user, e.src_ip, e.action,
             e.outcome, e.raw, json.dumps(e.extra))
            for e in events
        ]
        self.db.executemany(
            "INSERT INTO events(ts,source,host,user,src_ip,action,outcome,raw,extra) VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self.db.commit()
        return len(rows)

    def events(self) -> list[Event]:
        cur = self.db.execute(
            "SELECT ts,source,host,user,src_ip,action,outcome,raw,extra FROM events ORDER BY ts")
        return [Event(datetime.fromisoformat(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7],
                      json.loads(r[8])) for r in cur]

    def replace_alerts(self, alerts: list[Alert]) -> None:
        self.db.execute("DELETE FROM alerts")
        self.db.executemany(
            "INSERT INTO alerts(rule_id,title,severity,mitre,grp,first_seen,last_seen,count,evidence)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            [(a.rule_id, a.title, a.severity, json.dumps(a.mitre), a.group,
              a.first_seen.isoformat(), a.last_seen.isoformat(), a.count, json.dumps(a.evidence))
             for a in alerts],
        )
        self.db.commit()

    def alerts(self) -> list[Alert]:
        cur = self.db.execute(
            "SELECT rule_id,title,severity,mitre,grp,first_seen,last_seen,count,evidence FROM alerts")
        return [Alert(r[0], r[1], r[2], json.loads(r[3]), r[4], datetime.fromisoformat(r[5]),
                      datetime.fromisoformat(r[6]), r[7], json.loads(r[8])) for r in cur]
