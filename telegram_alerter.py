"""
telegram_alerter.py
Optional Telegram notifier. Drop-in replacement for the default Alerter
that forwards every detected RuleHit to a Telegram chat via the Bot API.

Setup:
    1. Message @BotFather on Telegram, send /newbot, copy the token.
    2. Send any message to your new bot, then visit
         https://api.telegram.org/bot<TOKEN>/getUpdates
       to find your chat id.
    3. Export the env vars before running:
         export TELEGRAM_BOT_TOKEN="..."
         export TELEGRAM_CHAT_ID="..."

Usage:
    from telegram_alerter import TelegramAlerter
    alerter = TelegramAlerter()
    ids = IntrusionDetectionSystem(alerter=alerter)

Stdlib-only — no extra dependencies. Uses urllib so it stays compatible
with the rest of this project, which has no third-party packages.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from alerter import Alerter
from rules import RuleHit


SEVERITY_ICONS = {
    "low": "🟡",
    "medium": "🟠",
    "high": "🔴",
    "critical": "🚨",
}


class TelegramAlerter(Alerter):
    """Forwards every RuleHit to a Telegram chat in real time.

    Inherits all reporting/aggregation behaviour from Alerter and adds
    a side-channel notification on each alert().
    """

    def __init__(
        self,
        token: str | None = None,
        chat_id: str | None = None,
        silent: bool = False,
        timeout: float = 5.0,
    ):
        super().__init__(silent=silent)
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.timeout = timeout
        if not self.token or not self.chat_id:
            # Don't crash the whole IDS just because Telegram isn't configured.
            # The user still gets the standard Alerter output.
            self._enabled = False
        else:
            self._enabled = True

    def alert(self, hit: RuleHit) -> None:
        super().alert(hit)
        if self._enabled:
            try:
                self._send(self._format(hit))
            except Exception as exc:  # never let Telegram break detection
                if not self.silent:
                    print(f"[telegram_alerter] send failed: {exc}")

    def _format(self, hit: RuleHit) -> str:
        icon = SEVERITY_ICONS.get(hit.severity.lower(), "⚠️")
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"{icon} *IDS ALERT* \u2014 `{hit.severity.upper()}`\n"
            f"\n"
            f"*Rule:* `{hit.rule_name}`\n"
            f"*Source IP:* `{hit.ip}`\n"
            f"*Detail:* {hit.description}\n"
            f"*Time:* `{ts}`"
        )

    def _send(self, text: str) -> None:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            # Telegram returns 200 + JSON body on success.
            resp.read()