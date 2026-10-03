"""
test_ids.py
Unit tests for the IDS engine. Run with:
    python -m pytest tests/
or:
    python -m unittest tests/test_ids.py
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from ids import IntrusionDetectionSystem, IDSConfig
from alerter import Alerter
from log_parser import parse_log_line, LogEntry


def _make_entry(ip: str, path: str, status: int = 200, ua: str = "Mozilla/5.0") -> LogEntry:
    decoded = path.replace("%20", " ").replace("%27", "'").replace("%3C", "<").replace("%3E", ">")
    return LogEntry(
        ip=ip, timestamp=datetime(2026, 10, 10, 13, 0, 0),
        method="GET", path=decoded.lower(), raw_path=path,
        status=status, size=0, user_agent=ua,
    )


class TestLogParser(unittest.TestCase):
    def test_parses_basic_line(self):
        line = '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1024'
        entry = parse_log_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "10.0.0.1")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.status, 200)

    def test_url_decoded_path(self):
        line = '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /test%20path HTTP/1.1" 200 100'
        entry = parse_log_line(line)
        self.assertIn("test path", entry.decoded_path())

    def test_rejects_blank_lines(self):
        self.assertIsNone(parse_log_line(""))
        self.assertIsNone(parse_log_line("# comment"))


class TestSQLInjectionRule(unittest.TestCase):
    def setUp(self):
        self.alerter = Alerter(silent=True)
        self.ids = IntrusionDetectionSystem(alerter=self.alerter)

    def test_detects_union_select(self):
        entry = _make_entry("10.0.0.1", "/page?id=1 UNION SELECT * FROM users")
        hits = self.ids.process(entry)
        self.assertTrue(any(h.rule_name == "SQLInjection" for h in hits))

    def test_detects_or_1_1(self):
        entry = _make_entry("10.0.0.1", "/login?user=admin' OR '1'='1")
        hits = self.ids.process(entry)
        self.assertTrue(any(h.rule_name == "SQLInjection" for h in hits))


class TestXSSRule(unittest.TestCase):
    def setUp(self):
        self.alerter = Alerter(silent=True)
        self.ids = IntrusionDetectionSystem(alerter=self.alerter)

    def test_detects_script_tag(self):
        entry = _make_entry("10.0.0.1", "/search?q=<script>alert(1)</script>")
        hits = self.ids.process(entry)
        self.assertTrue(any(h.rule_name == "XSSAttempt" for h in hits))

    def test_detects_onerror(self):
        entry = _make_entry("10.0.0.1", "/img?src=x onerror=alert(1)")
        hits = self.ids.process(entry)
        self.assertTrue(any(h.rule_name == "XSSAttempt" for h in hits))


class TestPathTraversalRule(unittest.TestCase):
    def test_detects_dotdot(self):
        alerter = Alerter(silent=True)
        ids = IntrusionDetectionSystem(alerter=alerter)
        entry = _make_entry("10.0.0.1", "/../../../etc/passwd")
        hits = ids.process(entry)
        self.assertTrue(any(h.rule_name == "PathTraversal" for h in hits))


class TestBruteForce(unittest.TestCase):
    def test_raises_after_threshold(self):
        alerter = Alerter(silent=True)
        cfg = IDSConfig(brute_force_threshold=3, brute_force_window=timedelta(minutes=5))
        ids = IntrusionDetectionSystem(config=cfg, alerter=alerter)
        for i in range(5):
            entry = _make_entry("45.33.32.156", "/login", status=401)
            entry.timestamp = datetime(2026, 10, 10, 13, 0, i)
            ids.process(entry)
        self.assertTrue(any("BruteForce" in h.rule_name for h in alerter.hits))


class TestSuspiciousUserAgent(unittest.TestCase):
    def test_detects_sqlmap(self):
        alerter = Alerter(silent=True)
        ids = IntrusionDetectionSystem(alerter=alerter)
        entry = _make_entry("10.0.0.1", "/api", ua="sqlmap/1.5.2")
        hits = ids.process(entry)
        self.assertTrue(any(h.rule_name == "SuspiciousUserAgent" for h in hits))


class TestAnomalyScoring(unittest.TestCase):
    def test_score_accumulates(self):
        alerter = Alerter(silent=True)
        ids = IntrusionDetectionSystem(alerter=alerter)
        ids.process(_make_entry("10.0.0.1", "/x?id=1 UNION SELECT 1"))
        ids.process(_make_entry("10.0.0.1", "/x?q=<script>alert(1)</script>"))
        self.assertGreater(ids.anomaly_score("10.0.0.1"), 30)


if __name__ == "__main__":
    unittest.main()