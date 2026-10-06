"""
tests/test_port_scan_detector.py
Unit tests for the PortScanDetector rule.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

from port_scan_detector import PortScanDetector


def _entry(ip: str, path: str, ts: datetime) -> SimpleNamespace:
    return SimpleNamespace(ip=ip, path=path, timestamp=ts)


def test_no_alert_below_threshold():
    det = PortScanDetector(window_seconds=60, distinct_paths=20)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(10):
        hit = det.match(_entry("1.2.3.4", f"/page{i}", base + timedelta(seconds=i)), ids=None)
        assert hit is None


def test_alert_when_threshold_exceeded():
    det = PortScanDetector(window_seconds=60, distinct_paths=20)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(25):
        det.match(_entry("1.2.3.4", f"/path{i}", base + timedelta(seconds=i)), ids=None)
    hit = det.match(_entry("1.2.3.4", "/trigger", base + timedelta(seconds=26)), ids=None)
    assert hit is not None
    assert hit.rule_name == "PortScan"
    assert hit.severity == "high"
    assert hit.ip == "1.2.3.4"


def test_old_entries_fall_outside_window():
    det = PortScanDetector(window_seconds=10, distinct_paths=5)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        det.match(_entry("5.6.7.8", f"/old{i}", base), ids=None)
    # Jump far into the future — old entries should be pruned.
    future = base + timedelta(seconds=120)
    new_hit = det.match(_entry("5.6.7.8", "/fresh", future), ids=None)
    assert new_hit is None


def test_reset_clears_state():
    det = PortScanDetector(window_seconds=60, distinct_paths=3)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        det.match(_entry("9.9.9.9", f"/p{i}", base + timedelta(seconds=i)), ids=None)
    det.reset("9.9.9.9")
    # After reset, one new request shouldn't trip anything.
    hit = det.match(_entry("9.9.9.9", "/solo", base + timedelta(seconds=10)), ids=None)
    assert hit is None


def test_independent_ips():
    det = PortScanDetector(window_seconds=60, distinct_paths=5)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(3):
        det.match(_entry("1.1.1.1", f"/a{i}", base + timedelta(seconds=i)), ids=None)
    hit = det.match(_entry("2.2.2.2", "/single", base + timedelta(seconds=4)), ids=None)
    assert hit is None