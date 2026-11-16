from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Event:
    """Normalisiertes Log-Event (einheitliches Schema fuer alle Quellen)."""

    ts: datetime
    source: str            # auth | nginx
    host: str = ""
    user: str = ""
    src_ip: str = ""
    action: str = ""       # ssh_login, sudo, user_created, http_request
    outcome: str = ""      # success | failure | ""
    raw: str = ""
    extra: dict = field(default_factory=dict)

    def fields(self) -> dict:
        base = {
            "source": self.source, "host": self.host, "user": self.user,
            "src_ip": self.src_ip, "action": self.action, "outcome": self.outcome,
        }
        base.update(self.extra)
        return base


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: list
    group: str
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list = field(default_factory=list)
