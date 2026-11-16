from __future__ import annotations

import argparse
import os
from pathlib import Path

from . import __version__
from .engine import detect, load_rules
from .models import SEVERITY_ORDER
from .parsers import PARSERS
from .report import render
from .storage import Store


def _ingest(store: Store, path: str, kind: str, year: int) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return store.add_events(PARSERS[kind](fh, year))


def _detect(store: Store, rules_dir: str):
    alerts = detect(store.events(), load_rules(rules_dir))
    store.replace_alerts(alerts)
    return alerts


def _print(alerts, min_sev: str = "low"):
    for a in alerts:
        if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[min_sev]:
            print(f"[{a.severity.upper():8}] {a.first_seen:%Y-%m-%d %H:%M:%S} {a.rule_id:24} "
                  f"{a.group:16} x{a.count}  {a.title}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="minisiem", description="Mini-SIEM: Logs -> Alerts")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--db", default="minisiem.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("ingest", help="Logdatei einlesen")
    i.add_argument("file")
    i.add_argument("--type", choices=PARSERS, required=True)
    i.add_argument("--year", type=int, default=2026, help="Jahr fuer syslog-Zeitstempel")

    d = sub.add_parser("detect", help="Regeln auf gespeicherte Events anwenden")
    d.add_argument("--rules", default="rules")
    d.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low")

    r = sub.add_parser("report", help="HTML-Report erzeugen")
    r.add_argument("-o", "--output", default="report.html")

    sub.add_parser("demo", help="Sample-Logs einlesen, Regeln anwenden, Report erzeugen")

    a = p.parse_args(argv)
    if a.cmd == "demo" and os.path.exists(a.db):
        os.remove(a.db)
    store = Store(a.db)

    if a.cmd == "ingest":
        print(f"{_ingest(store, a.file, a.type, a.year)} Events gespeichert")
    elif a.cmd == "detect":
        _print(_detect(store, a.rules), a.min_severity)
    elif a.cmd == "report":
        Path(a.output).write_text(render(store.alerts(), len(store.events())), encoding="utf-8")
        print(f"Report: {a.output}")
    elif a.cmd == "demo":
        _ingest(store, "samples/auth.log", "auth", 2026)
        _ingest(store, "samples/access.log", "nginx", 2026)
        alerts = _detect(store, "rules")
        _print(alerts)
        Path("report.html").write_text(render(alerts, len(store.events())), encoding="utf-8")
        print("Report: report.html")
    return 0
