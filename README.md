# MiniSIEM:
Ein kleines, lesbares SIEM in Python: Logs einlesen → in ein einheitliches Schema normalisieren → mit YAML-Regeln (angelehnt an Sigma) auswerten → Alerts mit MITRE-ATT&CK-Mapping als CLI-Ausgabe und HTML-Report.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Features

- **Parser** für Linux `auth.log` (SSH, sudo, useradd) und nginx/Apache Access-Logs
- **Normalisiertes Event-Schema** (`ts, source, host, user, src_ip, action, outcome, ...`)
- **3 Regeltypen** in YAML: `match` (Einzel-Event), `threshold` (N Events im Zeitfenster pro Gruppe), `sequence` (z. B. 5 fehlgeschlagene Logins gefolgt von einem erfolgreichen)
- **9 Beispiel-Regeln** mit MITRE-ATT&CK-Technique-IDs
- **SQLite-Speicher**, **HTML-Report** (HTML-escaped), Docker, CI mit Tests

## Quickstart

```bash
pip install -e .
minisiem demo          # Sample-Logs -> Alerts -> report.html
```

Eigene Logs:

```bash
minisiem ingest /var/log/auth.log --type auth --year 2026
minisiem ingest /var/log/nginx/access.log --type nginx
minisiem detect --min-severity medium
minisiem report -o report.html
```

Docker: `docker build -t minisiem . && docker run --rm minisiem`

## Beispiel-Ausgabe (Demo)

```
[CRITICAL] 2026-11-16 09:30:10 ssh-bruteforce-success   203.0.113.5   x7  Erfolgreicher SSH-Login nach Brute-Force
[HIGH    ] 2026-11-16 09:30:10 ssh-bruteforce           203.0.113.5   x6  SSH Brute-Force
[HIGH    ] 2026-11-16 09:31:40 new-user-created         backdoor      x1  Neuer lokaler Benutzer angelegt
...
```

## Eigene Regel schreiben

```yaml
id: ssh-bruteforce
title: SSH Brute-Force
severity: high
mitre: [T1110]
type: threshold
filter: {action: ssh_login, outcome: failure}
group_by: src_ip
threshold: 5
window: 60        # Sekunden
```

Filterwerte sind exakte Strings oder Regex mit Präfix `re:`; Listen bedeuten "eines davon".

## Architektur

```
Logfile -> parsers.py -> Event -> storage.py (SQLite) -> engine.py (rules/*.yml) -> Alert -> cli / report.py
```

## Grenzen / Ideen

- Keine Echtzeit-Ingestion (Batch); Idee: `tail -f`-Modus oder Syslog-Listener
- Weitere Parser: Windows Event Logs (EVTX), Suricata `eve.json`, Zeek
- Sigma-Import, GeoIP-Anreicherung, Alert-Weiterleitung (Slack/Mail)
- Zeitstempel aus syslog haben kein Jahr (`--year`) und werden als UTC behandelt

## Lizenz

MIT
