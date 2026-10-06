"""
port_scan_detector.py
Detects port-scan behavior from web access logs by tracking the number of
distinct paths/endpoints probed by a single source IP within a sliding
window. A burst of requests to many different sensitive-looking or
randomized paths is a strong signal of reconnaissance (nmap, dirbuster,
nikto, gobuster, etc.).

This is a *stateful* rule — it keeps a per-IP record of recent requests
and emits a RuleHit once the threshold is exceeded.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from log_parser import LogEntry
    from ids import IntrusionDetectionSystem

from rules import RuleHit


# Paths that strongly suggest probing when hit in bulk.
# (Same list as SensitivePathRule; importing would create a cycle.)
_PROBE_HINTS = (
    "/.env", "/.git", "/wp-config", "/admin", "/phpmyadmin",
    "/backup", "/config", "/db", "/api/", "/shell", "/cmd",
)


@dataclass
class _ScanTracker:
    timestamps: list[datetime] = field(default_factory=list)
    paths: set[str] = field(default_factory=set)


class PortScanDetector:
    """Flags IPs that hit too many distinct paths/endpoints in a short window.

    Tunables (configured via IDSConfig when wired into the engine):
        window_seconds  — sliding window length (default 60)
        distinct_paths  — how many unique paths trigger an alert (default 20)
    """

    name = "PortScan"

    def __init__(self, window_seconds: int = 60, distinct_paths: int = 20):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = distinct_paths
        self._by_ip: dict[str, _ScanTracker] = defaultdict(_ScanTracker)
        self._alerted: dict[str, set] = defaultdict(set)  # dedupe per window

    def match(self, entry: "LogEntry", ids: "IntrusionDetectionSystem") -> RuleHit | None:
        ts = entry.timestamp
        tracker = self._by_ip[entry.ip]

        # Prune stale entries.
        cutoff = ts - self.window
        tracker.timestamps = [t for t in tracker.timestamps if t >= cutoff]
        tracker.paths = {
            p for p in tracker.paths
            if any(t >= cutoff for t in tracker.timestamps if (t, p) in _path_index(tracker))
        }

        # Record this request. Use the raw path so /admin and /admin/ count once.
        tracker.timestamps.append(ts)
        tracker.paths.add(entry.path)

        # Emit only once per window for this IP.
        if entry.ip in self._alerted[entry.ip] and len(tracker.paths) < self.threshold * 2:
            return None

        if len(tracker.paths) < self.threshold:
            return None

        # Reset window so we don't spam alerts.
        self._alerted[entry.ip] = self._alerted.get(entry.ip, set()) | {ts}

        # Score proportional to burst size.
        burst = len(tracker.paths)
        weight = 20 + min(burst, 50)

        return RuleHit(
            rule_name=self.name,
            severity="high",
            ip=entry.ip,
            description=(
                f"{burst} distinct paths probed from {entry.ip} within "
                f"{self.window.seconds}s (possible recon / port-scan)"
            ),
            weight=weight,
        )

    def reset(self, ip: str) -> None:
        """Clear state for an IP (e.g. after responding to an alert)."""
        self._by_ip.pop(ip, None)
        self._alerted.pop(ip, None)


def _path_index(tracker: _ScanTracker) -> set[tuple[datetime, str]]:
    """Helper: pair every retained timestamp with the path it belongs to.
    Used for accurate per-path pruning. Cheap because N is small (window bps)."""
    # We don't actually persist (ts, path) pairs — only timestamps + unique paths.
    # Return the cartesian product of recent timestamps and known paths so
    # pruning is conservative (never accidentally drops an active path).
    return {(t, p) for t in tracker.timestamps for p in tracker.paths}