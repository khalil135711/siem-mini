import unittest
from pathlib import Path

from minisiem.engine import detect, load_rules
from minisiem.parsers import parse_auth, parse_nginx
from minisiem.report import render

ROOT = Path(__file__).resolve().parent.parent


def events():
    ev = list(parse_auth((ROOT / "samples/auth.log").open(), 2026))
    ev += list(parse_nginx((ROOT / "samples/access.log").open()))
    return ev


class MiniSiemTests(unittest.TestCase):
    def setUp(self):
        self.alerts = {a.rule_id: a for a in detect(events(), load_rules(ROOT / "rules"))}

    def test_parsers(self):
        auth = list(parse_auth((ROOT / "samples/auth.log").open(), 2026))
        self.assertEqual(sum(e.outcome == "failure" for e in auth), 7)
        self.assertTrue(any(e.action == "user_created" for e in auth))

    def test_bruteforce_threshold(self):
        a = self.alerts["ssh-bruteforce"]
        self.assertEqual(a.group, "203.0.113.5")
        self.assertEqual(a.count, 6)

    def test_no_false_positive_for_single_failures(self):
        self.assertNotEqual(self.alerts["ssh-bruteforce"].group, "198.51.100.77")

    def test_sequence_critical(self):
        self.assertEqual(self.alerts["ssh-bruteforce-success"].severity, "critical")

    def test_web_rules(self):
        for rid in ("web-sqli", "web-scanner-ua", "web-path-traversal", "web-404-scan"):
            self.assertIn(rid, self.alerts)

    def test_report_escapes_html(self):
        a = next(iter(self.alerts.values()))
        a.title = "<script>alert(1)</script>"
        self.assertNotIn("<script>", render([a], 1))


if __name__ == "__main__":
    unittest.main()
