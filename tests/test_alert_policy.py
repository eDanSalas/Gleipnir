"""Unit tests for IDS alert throttling policy."""

from __future__ import annotations

import unittest
from unittest.mock import Mock

from src.alert_policy import (
    AlertPolicy,
    AlertRequest,
    PolicyAlertSender,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)


class AlertPolicyTests(unittest.TestCase):
    def test_repeated_event_inside_cooldown_is_suppressed(self) -> None:
        clock = _Clock(1000.0)
        policy = AlertPolicy(cooldown_seconds=300, max_per_minute=5, clock=clock)
        send_alert = Mock()
        sender = PolicyAlertSender(policy=policy, send_alert=send_alert)

        first = sender(*_unauthorized_email())
        second = sender(*_unauthorized_email())

        self.assertTrue(first.sent)
        self.assertFalse(first.suppressed)
        self.assertFalse(second.sent)
        self.assertTrue(second.suppressed)
        self.assertEqual(second.reason, "cooldown")
        send_alert.assert_called_once()

    def test_repeated_event_outside_cooldown_is_sent_again(self) -> None:
        clock = _Clock(1000.0)
        policy = AlertPolicy(cooldown_seconds=300, max_per_minute=5, clock=clock)
        send_alert = Mock()
        sender = PolicyAlertSender(policy=policy, send_alert=send_alert)

        first = sender(*_unauthorized_email())
        clock.value = 1301.0
        second = sender(*_unauthorized_email())

        self.assertTrue(first.sent)
        self.assertTrue(second.sent)
        self.assertFalse(second.suppressed)
        self.assertEqual(send_alert.call_count, 2)

    def test_max_per_minute_suppresses_extra_alerts(self) -> None:
        clock = _Clock(2000.0)
        policy = AlertPolicy(cooldown_seconds=0, max_per_minute=2, clock=clock)
        send_alert = Mock()
        sender = PolicyAlertSender(policy=policy, send_alert=send_alert)

        first = sender(*_unauthorized_email(source_ip="192.168.1.10"))
        clock.value = 2010.0
        second = sender(*_unauthorized_email(source_ip="192.168.1.11"))
        clock.value = 2020.0
        third = sender(*_unauthorized_email(source_ip="192.168.1.12"))

        self.assertTrue(first.sent)
        self.assertTrue(second.sent)
        self.assertFalse(third.sent)
        self.assertTrue(third.suppressed)
        self.assertEqual(third.reason, "rate_limit")
        self.assertEqual(send_alert.call_count, 2)

    def test_critical_severity_bypasses_cooldown_and_rate_limit(self) -> None:
        clock = _Clock(3000.0)
        policy = AlertPolicy(cooldown_seconds=300, max_per_minute=1, clock=clock)
        request = AlertRequest(
            subject="Gleipnir IDS: CRITICAL_EVENT",
            message="Critical IDS event",
            recipient="admin@example.org",
            severity=SEVERITY_CRITICAL,
            group_key="critical|same",
        )

        first = policy.evaluate(request)
        second = policy.evaluate(request)

        self.assertTrue(first.sent)
        self.assertTrue(second.sent)
        self.assertFalse(second.suppressed)
        self.assertEqual(second.severity, SEVERITY_CRITICAL)

    def test_critical_event_type_is_detected_from_subject(self) -> None:
        clock = _Clock(4000.0)
        policy = AlertPolicy(cooldown_seconds=300, max_per_minute=1, clock=clock)
        sender = PolicyAlertSender(policy=policy, send_alert=Mock())
        email = (
            "Gleipnir IDS: CRITICAL_EVENT",
            "Critical IDS event",
            "admin@example.org",
        )

        first = sender(*email)
        second = sender(*email)

        self.assertTrue(first.sent)
        self.assertTrue(second.sent)
        self.assertEqual(second.severity, SEVERITY_CRITICAL)

    def test_blacklisted_alert_uses_high_severity(self) -> None:
        policy = AlertPolicy(cooldown_seconds=300, max_per_minute=5)
        sender = PolicyAlertSender(policy=policy, send_alert=Mock())

        decision = sender(*_blacklisted_email())

        self.assertTrue(decision.sent)
        self.assertEqual(decision.severity, SEVERITY_HIGH)


class _Clock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _unauthorized_email(
    *,
    source_ip: str = "192.168.1.10",
    source_mac: str = "aa:bb:cc:dd:ee:ff",
):
    subject = "Gleipnir IDS: UNAUTHORIZED_DEVICE"
    body = (
        "Unauthorized device detected\n\n"
        "Resumen:\n"
        f"- IP origen: {source_ip}\n"
        f"- MAC origen: {source_mac}\n"
        "- IP destino: 8.8.8.8\n"
        "- MAC destino: 66:55:44:33:22:11\n"
        "- Protocolo: TCP\n"
        "- Timestamp: 1710000000.25\n"
    )
    return subject, body, "admin@example.org"


def _blacklisted_email():
    subject = "Gleipnir IDS: BLACKLISTED_EXTERNAL_IP"
    body = (
        "Se detecto trafico hacia una IP externa en blacklist.\n\n"
        "Resumen:\n"
        "- Timestamp: 1710000000.25\n"
        "- IP origen: 192.168.1.10\n"
        "- IP destino: 8.8.8.8\n"
        "- Protocolo: TCP\n"
        "- Motivo: Malware C2\n"
        "- Severidad: ALTA\n"
    )
    return subject, body, "admin@example.org"


if __name__ == "__main__":
    unittest.main()
