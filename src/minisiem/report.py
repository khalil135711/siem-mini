"""Statischer HTML-Report."""
from __future__ import annotations

from collections import Counter
from html import escape

from .models import Alert

CSS = """body{font-family:system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e6e6e6}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #2a3340;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#1b2430}.critical{color:#ff5370}.high{color:#f78c6c}.medium{color:#ffcb6b}.low{color:#89ddff}
code{font-size:.8rem;color:#9aa5b1}a{color:#82aaff}"""


def render(alerts: list[Alert], n_events: int) -> str:
    sev = Counter(a.severity for a in alerts)
    rows = []
    for a in alerts:
        mitre = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{escape(t.replace(".", "/"))}/">{escape(t)}</a>'
            for t in a.mitre)
        ev = "<br>".join(f"<code>{escape(e)}</code>" for e in a.evidence[:3])
        rows.append(
            f'<tr><td class="{escape(a.severity)}">{escape(a.severity.upper())}</td>'
            f"<td>{escape(a.title)}<br><small>{escape(a.rule_id)}</small></td><td>{escape(a.group)}</td>"
            f"<td>{a.count}</td><td>{a.first_seen:%Y-%m-%d %H:%M:%S}</td><td>{mitre}</td><td>{ev}</td></tr>")
    summary = ", ".join(f"{k}: {v}" for k, v in sev.most_common()) or "keine"
    return (f"<!doctype html><meta charset=utf-8><title>MiniSIEM Report</title><style>{CSS}</style>"
            f"<h1>MiniSIEM Report</h1><p>{n_events} Events, {len(alerts)} Alerts ({escape(summary)})</p>"
            "<table><tr><th>Severity</th><th>Regel</th><th>Quelle</th><th>#</th><th>Zeit</th>"
            f"<th>MITRE</th><th>Beweise</th></tr>{''.join(rows)}</table>")
