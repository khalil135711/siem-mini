"""Parser: Rohlogs -> normalisierte Events."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .models import Event

AUTH_LINE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
SUDO = re.compile(r"(?P<user>\S+)\s+: .*COMMAND=(?P<cmd>.*)$")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")

NGINX_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_auth(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = AUTH_LINE.match(line)
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        proc, msg, host = m["proc"], m["msg"], m["host"]
        if proc == "sshd":
            if (s := SSH_FAIL.search(msg)):
                yield Event(ts, "auth", host, s["user"], s["ip"], "ssh_login", "failure", line)
            elif (s := SSH_OK.search(msg)):
                yield Event(ts, "auth", host, s["user"], s["ip"], "ssh_login", "success", line)
        elif proc == "sudo" and (s := SUDO.search(msg)):
            yield Event(ts, "auth", host, s["user"], "", "sudo", "success", line, {"cmd": s["cmd"].strip()})
        elif proc == "useradd" and (s := USERADD.search(msg)):
            yield Event(ts, "auth", host, s["user"], "", "user_created", "success", line)


def parse_nginx(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = NGINX_LINE.match(line)
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).replace(tzinfo=None)
        yield Event(
            ts, "nginx", "", "", m["ip"], "http_request", "", line,
            {"method": m["method"], "path": m["path"], "status": m["status"], "ua": m["ua"]},
        )


PARSERS = {"auth": parse_auth, "nginx": parse_nginx}
