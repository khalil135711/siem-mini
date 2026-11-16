"""Detection-Engine: YAML-Regeln (match / threshold / sequence) auf Events."""
from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

import yaml

from .models import SEVERITY_ORDER, Alert, Event

REQUIRED = {"id", "title", "severity", "type"}
TYPES = {"match", "threshold", "sequence"}


def load_rules(path: str | Path) -> list[dict]:
    rules = []
    for f in sorted(Path(path).glob("*.y*ml")):
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
        missing = REQUIRED - rule.keys()
        if missing or rule["type"] not in TYPES or rule["severity"] not in SEVERITY_ORDER:
            raise ValueError(f"Ungueltige Regel {f.name}: fehlend={sorted(missing)}")
        rules.append(rule)
    return rules


def _one(value: str, pattern) -> bool:
    pattern = str(pattern)
    if pattern.startswith("re:"):
        return re.search(pattern[3:], value) is not None
    return value == pattern


def matches(event: Event, flt: dict) -> bool:
    f = event.fields()
    for key, pat in flt.items():
        val = str(f.get(key, ""))
        ok = any(_one(val, p) for p in pat) if isinstance(pat, list) else _one(val, pat)
        if not ok:
            return False
    return True


def _alert(rule: dict, group: str, evs: list[Event]) -> Alert:
    return Alert(rule["id"], rule["title"], rule["severity"], rule.get("mitre", []), group,
                 evs[0].ts, evs[-1].ts, len(evs), [e.raw for e in evs[:5]])


def run_match(rule, events):
    for e in events:
        if matches(e, rule["filter"]):
            yield _alert(rule, e.src_ip or e.user or "-", [e])


def run_threshold(rule, events):
    groups = defaultdict(list)
    for e in events:
        if matches(e, rule["filter"]):
            groups[e.fields().get(rule["group_by"], "-")].append(e)
    window, need = rule["window"], rule["threshold"]
    for key, evs in groups.items():
        dq: deque[Event] = deque()
        current: Alert | None = None
        for e in evs:
            dq.append(e)
            while (e.ts - dq[0].ts).total_seconds() > window:
                dq.popleft()
            if len(dq) >= need:
                if current is None:
                    current = _alert(rule, key, list(dq))
                else:
                    current.last_seen, current.count = e.ts, current.count + 1
                    if len(current.evidence) < 5:
                        current.evidence.append(e.raw)
            else:
                if current:
                    yield current
                current = None
        if current:
            yield current


def run_sequence(rule, events):
    """N x 'first' gefolgt von 'then' innerhalb des Zeitfensters (je group_by)."""
    seen = defaultdict(deque)
    window = rule["window"]
    for e in events:
        key = e.fields().get(rule["group_by"], "-")
        dq = seen[key]
        while dq and (e.ts - dq[0].ts).total_seconds() > window:
            dq.popleft()
        if matches(e, rule["first"]):
            dq.append(e)
        elif matches(e, rule["then"]) and len(dq) >= rule["min_count"]:
            yield _alert(rule, key, list(dq) + [e])
            dq.clear()


RUNNERS = {"match": run_match, "threshold": run_threshold, "sequence": run_sequence}


def detect(events: list[Event], rules: list[dict]) -> list[Alert]:
    events = sorted(events, key=lambda e: e.ts)
    alerts = [a for r in rules for a in RUNNERS[r["type"]](r, events)]
    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen))
