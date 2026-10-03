"""
rules.py
Signature-based detection rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from log_parser import LogEntry
    from ids import IntrusionDetectionSystem


@dataclass
class RuleHit:
    rule_name: str
    severity: str
    ip: str
    description: str
    weight: int = 10

    def __str__(self) -> str:
        return f"[{self.severity.upper():<8}] {self.rule_name:<22} {self.ip:<18} {self.description}"


class Rule(Protocol):
    name: str
    def match(self, entry: "LogEntry", ids: "IntrusionDetectionSystem") -> RuleHit | None: ...


SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1=1", re.IGNORECASE),
    re.compile(r"'\s*or\s*'", re.IGNORECASE),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"sleep\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"benchmark\(", re.IGNORECASE),
    re.compile(r"information_schema", re.IGNORECASE),
    re.compile(r"load_file\(", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"</script>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"alert\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e/", re.IGNORECASE),
]

SHELL_INJECTION_PATTERNS = [
    re.compile(r";\s*(?:ls|cat|wget|curl|nc|bash|sh)\b", re.IGNORECASE),
    re.compile(r"\|\s*(?:ls|cat|wget|curl|nc|bash|sh)\b", re.IGNORECASE),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\([^)]+\)"),
]

SENSITIVE_PATHS = [
    "/.env", "/wp-config.php", "/.git/config", "/etc/passwd",
    "/admin", "/phpmyadmin", "/server-status", "/.aws/credentials",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "wpscan",
    "dirbuster", "gobuster", "nessus", "burp",
]


class SQLInjectionRule:
    name = "SQLInjection"
    def match(self, entry, ids):
        target = entry.decoded_path()
        for pat in SQLI_PATTERNS:
            if pat.search(target):
                return RuleHit(rule_name=self.name, severity="high", ip=entry.ip,
                               description=f"SQLi signature in {entry.method} {entry.raw_path}", weight=30)
        return None


class XSSRule:
    name = "XSSAttempt"
    def match(self, entry, ids):
        target = entry.decoded_path()
        for pat in XSS_PATTERNS:
            if pat.search(target):
                return RuleHit(rule_name=self.name, severity="medium", ip=entry.ip,
                               description=f"XSS payload in {entry.method} {entry.raw_path}", weight=20)
        return None


class PathTraversalRule:
    name = "PathTraversal"
    def match(self, entry, ids):
        target = entry.decoded_path()
        for pat in PATH_TRAVERSAL_PATTERNS:
            if pat.search(target):
                return RuleHit(rule_name=self.name, severity="high", ip=entry.ip,
                               description=f"Path traversal in {entry.method} {entry.raw_path}", weight=25)
        return None


class ShellInjectionRule:
    name = "ShellInjection"
    def match(self, entry, ids):
        target = entry.decoded_path()
        for pat in SHELL_INJECTION_PATTERNS:
            if pat.search(target):
                return RuleHit(rule_name=self.name, severity="critical", ip=entry.ip,
                               description=f"Shell injection in {entry.method} {entry.raw_path}", weight=35)
        return None


class SensitivePathRule:
    name = "SensitivePathProbe"
    def match(self, entry, ids):
        path = entry.path.lower()
        for sp in SENSITIVE_PATHS:
            if sp in path and entry.status >= 400:
                return RuleHit(rule_name=self.name, severity="medium", ip=entry.ip,
                               description=f"Probing sensitive path {entry.raw_path}", weight=15)
        return None


class SuspiciousUserAgentRule:
    name = "SuspiciousUserAgent"
    def match(self, entry, ids):
        ua = entry.user_agent.lower()
        for sus in SUSPICIOUS_USER_AGENTS:
            if sus in ua:
                return RuleHit(rule_name=self.name, severity="high", ip=entry.ip,
                               description=f"Suspicious UA '{entry.user_agent[:60]}'", weight=25)
        return None


class HighErrorRateRule:
    name = "HighErrorRate"
    def match(self, entry, ids):
        if entry.status >= 500:
            score = ids.anomaly_score(entry.ip)
            if score >= 50:
                return RuleHit(rule_name=self.name, severity="medium", ip=entry.ip,
                               description=f"5xx error from {entry.ip} with elevated score {score}", weight=10)
        return None


RULES = [
    SQLInjectionRule(), XSSRule(), PathTraversalRule(), ShellInjectionRule(),
    SensitivePathRule(), SuspiciousUserAgentRule(), HighErrorRateRule(),
]