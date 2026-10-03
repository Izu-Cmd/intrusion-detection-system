"""
intrusion-detection-system
A lightweight host-based intrusion detection system (IDS) that parses
web server access logs (Apache / Nginx combined log format) in real time
and flags suspicious activity such as brute force login attempts,
SQL injection probes, XSS payloads, and credential stuffing.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from log_parser import parse_log_line, LogEntry
from rules import RULES, RuleHit
from alerter import Alerter


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class IDSConfig:
    """Runtime configuration for the IDS engine."""
    brute_force_window: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    brute_force_threshold: int = 5
    credential_stuffing_threshold: int = 20
    request_rate_window: timedelta = field(default_factory=lambda: timedelta(seconds=10))
    anomaly_score_threshold: int = 75


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class IntrusionDetectionSystem:
    """Stateful detection engine. Feed it log lines and it raises alerts."""

    def __init__(self, config: IDSConfig | None = None, alerter: Alerter | None = None):
        self.config = config or IDSConfig()
        self.alerter = alerter or Alerter()
        self._failed_logins: dict[str, list[datetime]] = defaultdict(list)
        self._usernames_per_ip: dict[str, set[str]] = defaultdict(set)
        self._request_times: dict[str, list[datetime]] = defaultdict(list)
        self._anomaly_scores: dict[str, int] = defaultdict(int)

    def process_line(self, line: str) -> list[RuleHit]:
        entry = parse_log_line(line)
        if entry is None:
            return []
        return self.process(entry)

    def process(self, entry: LogEntry) -> list[RuleHit]:
        hits: list[RuleHit] = []
        self._prune(entry.timestamp)

        for rule in RULES:
            hit = rule.match(entry, self)
            if hit is not None:
                hits.append(hit)
                self._anomaly_scores[entry.ip] += hit.weight

        if self._is_failed_login(entry):
            self._failed_logins[entry.ip].append(entry.timestamp)
        if self._is_login_attempt(entry) and entry.username:
            self._usernames_per_ip[entry.ip].add(entry.username)

        if self._is_failed_login(entry) and len(self._failed_logins[entry.ip]) >= self.config.brute_force_threshold:
            recent = [t for t in self._failed_logins[entry.ip] if entry.timestamp - t <= self.config.brute_force_window]
            if len(recent) >= self.config.brute_force_threshold:
                hits.append(RuleHit(
                    rule_name="BruteForceLogin", severity="high", ip=entry.ip,
                    description=f"{len(recent)} failed logins from {entry.ip} within {self.config.brute_force_window}",
                    weight=40,
                ))

        if self._is_login_attempt(entry) and len(self._usernames_per_ip[entry.ip]) >= self.config.credential_stuffing_threshold:
            hits.append(RuleHit(
                rule_name="CredentialStuffing", severity="critical", ip=entry.ip,
                description=f"{len(self._usernames_per_ip[entry.ip])} distinct usernames tried from {entry.ip}",
                weight=50,
            ))

        for hit in hits:
            self.alerter.alert(hit)
        return hits

    def process_file(self, path: str | Path) -> list[RuleHit]:
        all_hits: list[RuleHit] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                for hit in self.process_line(line):
                    all_hits.append(hit)
        return all_hits

    def anomaly_score(self, ip: str) -> int:
        return min(self._anomaly_scores[ip], 90)

    def suspicious_ips(self) -> Iterable[tuple[str, int]]:
        scored = [(ip, score) for ip, score in self._anomaly_scores.items() if score >= self.config.anomaly_score_threshold]
        return sorted(scored, key=lambda x: x[1], reverse=True)

    @staticmethod
    def _is_failed_login(entry: LogEntry) -> bool:
        path = entry.path.lower()
        is_auth_path = any(p in path for p in ("/login", "/signin", "/auth", "/wp-login", "/admin"))
        return is_auth_path and entry.status >= 400

    @staticmethod
    def _is_login_attempt(entry: LogEntry) -> bool:
        path = entry.path.lower()
        return any(p in path for p in ("/login", "/signin", "/auth"))

    def _prune(self, now: datetime) -> None:
        cutoff = now - self.config.brute_force_window
        for ip in list(self._failed_logins.keys()):
            self._failed_logins[ip] = [t for t in self._failed_logins[ip] if t >= cutoff]
        for ip in list(self._request_times.keys()):
            self._request_times[ip] = [t for t in self._request_times[ip] if now - t <= self.config.request_rate_window]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ids.py", description="Lightweight host-based intrusion detection system")
    parser.add_argument("logfile", help="Path to access.log file to analyze")
    parser.add_argument("--threshold", type=int, default=75, help="Anomaly score threshold (default: 75)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-alert output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    cfg = IDSConfig(anomaly_score_threshold=args.threshold)
    alerter = Alerter(silent=args.quiet)
    ids = IntrusionDetectionSystem(config=cfg, alerter=alerter)

    print(f"[+] Loading {args.logfile}...")
    hits = ids.process_file(args.logfile)

    print(f"\n[+] Done. {len(hits)} alerts raised.")
    suspicious = list(ids.suspicious_ips())
    if suspicious:
        print("\n[!] Suspicious IPs (score >= threshold):")
        for ip, score in suspicious:
            print(f"    - {ip:<20} score={score}")
    else:
        print("[+] No IPs exceeded the anomaly threshold. Looks clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())