"""
tests/test_telegram_alerter.py
Unit tests for TelegramAlerter. Mocks the network layer so no real
HTTP requests are made during tests.
"""

from unittest.mock import MagicMock, patch

from rules import RuleHit
from telegram_alerter import TelegramAlerter


def _hit(severity: str = "high", ip: str = "1.2.3.4", rule: str = "SQLInjection") -> RuleHit:
    return RuleHit(
        rule_name=rule,
        severity=severity,
        ip=ip,
        description="unit-test description",
        weight=20,
    )


def test_disabled_when_no_credentials():
    al = TelegramAlerter(token="", chat_id="")
    assert al._enabled is False
    # Calling alert() should NOT raise, even with no network.
    al.alert(_hit())
    # It should still aggregate hits via the parent class.
    assert len(al.hits) == 1


def test_enabled_when_credentials_present():
    monkeypatch = {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}
    with patch.dict("os.environ", monkeypatch, clear=True):
        al = TelegramAlerter(token="abc", chat_id="123")
        assert al._enabled is True


def test_alert_calls_super_and_sends():
    with patch.dict("os.environ", {}, clear=True):
        al = TelegramAlerter(token="abc", chat_id="123", silent=True)
        with patch.object(al, "_send") as mock_send:
            al.alert(_hit())
            assert mock_send.called
            assert len(al.hits) == 1
            sent_text = mock_send.call_args[0][0]
            assert "IDS ALERT" in sent_text
            assert "1.2.3.4" in sent_text
            assert "SQLInjection" in sent_text


def test_format_includes_severity_icon():
    with patch.dict("os.environ", {}, clear=True):
        al = TelegramAlerter(token="abc", chat_id="123")
        text = al._format(_hit(severity="critical"))
        assert "🚨" in text
        assert "CRITICAL" in text


def test_send_failure_does_not_propagate():
    with patch.dict("os.environ", {}, clear=True):
        al = TelegramAlerter(token="abc", chat_id="123", silent=True)
        with patch.object(al, "_send", side_effect=RuntimeError("boom")):
            # Should NOT raise — Telegram failures must never break the IDS.
            al.alert(_hit())
        assert len(al.hits) == 1


def test_report_still_works():
    """TelegramAlerter should produce the same summary report as Alerter."""
    with patch.dict("os.environ", {}, clear=True):
        al = TelegramAlerter(token="abc", chat_id="123", silent=True)
        with patch.object(al, "_send"):
            al.alert(_hit(severity="high", rule="SQLInjection"))
            al.alert(_hit(severity="low", rule="XSSAttempt", ip="5.6.7.8"))
        report = al.format_report()
        assert "IDS REPORT" in report
        assert "high" in report
        assert "SQLInjection" in report