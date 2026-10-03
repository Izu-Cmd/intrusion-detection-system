"""
log_parser.py
Parses Apache / Nginx combined access log format into structured entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

COMMON_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

MINIMAL_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})'
)


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    raw_path: str
    status: int
    size: int
    referer: str = ""
    user_agent: str = ""
    username: Optional[str] = None

    def decoded_path(self) -> str:
        return unquote_plus(self.raw_path)


def _parse_timestamp(raw: str) -> datetime:
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")


def parse_log_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        m = COMMON_LOG_PATTERN.match(line)
    if not m:
        m = MINIMAL_PATTERN.search(line)
    if not m:
        return None

    g = m.groupdict()
    try:
        ts = _parse_timestamp(g["time"]).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None
    try:
        status = int(g["status"])
        size = int(g.get("size") or 0)
    except (ValueError, TypeError):
        return None

    raw_path = g["path"]
    path = unquote_plus(raw_path).lower()
    username = None
    if "username=" in path or "user=" in path or "email=" in path:
        for key in ("username", "user", "email"):
            token = f"{key}="
            idx = path.find(token)
            if idx >= 0:
                tail = path[idx + len(token):]
                username = tail.split("&")[0].split(" ")[0][:64]
                break

    return LogEntry(
        ip=g["ip"], timestamp=ts, method=g["method"], path=path, raw_path=raw_path,
        status=status, size=size,
        referer=(g.get("referer") or ""), user_agent=(g.get("ua") or ""), username=username,
    )