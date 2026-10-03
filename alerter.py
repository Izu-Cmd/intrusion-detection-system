"""
alerter.py
Handles output of RuleHit events and aggregates them into reports.
"""

from __future__ import annotations

from collections import Counter

from rules import RuleHit


SEVERITY_COLOR = {
    "low": "\033[36m", "medium": "\033[33m",
    "high": "\033[31m", "critical": "\033[1;31m",
}
COLOR_ENABLED = "\033[0m"


class Alerter:
    def __init__(self, silent: bool = False, use_color: bool = True):
        self.silent = silent
        self.use_color = use_color
        self.hits: list[RuleHit] = []

    def alert(self, hit: RuleHit) -> None:
        self.hits.append(hit)
        if not self.silent:
            line = str(hit)
            if self.use_color:
                color = SEVERITY_COLOR.get(hit.severity, "")
                line = f"{color}{line}{COLOR_ENABLED}"
            print(line)

    def summary(self) -> dict:
        by_severity = Counter(h.severity for h in self.hits)
        by_rule = Counter(h.rule_name for h in self.hits)
        by_ip = Counter(h.ip for h in self.hits)
        return {
            "total_alerts": len(self.hits),
            "by_severity": dict(by_severity),
            "by_rule": dict(by_rule),
            "top_offending_ips": by_ip.most_common(10),
        }

    def format_report(self) -> str:
        s = self.summary()
        lines = ["=" * 60, "IDS REPORT", "=" * 60, f"Total alerts:        {s['total_alerts']}", "", "By severity:"]
        for sev in ("critical", "high", "medium", "low"):
            lines.append(f"  {sev:<10} {s['by_severity'].get(sev, 0)}")
        lines.append("")
        lines.append("By rule:")
        for rule, count in sorted(s["by_rule"].items(), key=lambda x: -x[1]):
            lines.append(f"  {rule:<25} {count}")
        lines.append("")
        lines.append("Top offending IPs:")
        for ip, count in s["top_offending_ips"]:
            lines.append(f"  {ip:<20} {count}")
        lines.append("=" * 60)
        return "\n".join(lines)