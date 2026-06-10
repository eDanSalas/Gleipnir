
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from src import whitelist
from src.alert_policy import AlertDecision
from src.detector import (
    AUTHORIZED_DEVICE,
    BLACKLISTED_EXTERNAL_IP,
    BLACKLISTED_EXTERNAL_IP_INBOUND,
    BLACKLISTED_EXTERNAL_IP_OUTBOUND,
    BLACKLISTED_EXTERNAL_IP_SEVERITY,
    BLACKLISTED_PRIVATE_IP,
    DIRECTION_INBOUND,
    DIRECTION_LOCAL,
    DIRECTION_OUTBOUND,
    UNAUTHORIZED_DEVICE,
    BlacklistedExternalIPEvent,
    DetectorError,
    DeviceDetector,
    ExternalIPBlacklistDetector,
    detect_blacklisted_external_ip,
    detect_packet,
)
from src.mailer import MailerError
from src.sniffer import PacketEvent, parse_packet
from src.blacklist import BlacklistEntry


class DetectorTests(unittest.TestCase):
    def test_authorized_device_generates_authorized_event(self) -> None:
        packet = _synthetic_packet("192.168.1.10", "aa:bb:cc:dd:ee:ff")
        authorization_checker = Mock(return_value=True)
        alert_sender = Mock()
        detector = DeviceDetector(
            alert_recipient="admin@example.org",
            authorization_checker=authorization_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, AUTHORIZED_DEVICE)
        self.assertFalse(detection.alert_sent)
        self.assertEqual(detection.authorized_by, whitelist.AUTHORIZED_BY_IP_MAC)
        self.assertIn("Authorized device", detection.message)
        self.assertIn("authorized_by=ip_mac", detection.message)
        authorization_checker.assert_called_once_with(
            packet.ip_origen,
            packet.mac_origen,
        )
        alert_sender.assert_not_called()

    def test_unauthorized_device_generates_event_and_sends_alert(self) -> None:
        packet = _synthetic_packet("192.168.1.11", "00:11:22:33:44:55")
        authorization_checker = Mock(return_value=False)
        alert_sender = Mock()
        detector = DeviceDetector(
            alert_recipient="admin@example.org",
            authorization_checker=authorization_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertTrue(detection.alert_sent)
        self.assertEqual(detection.unauthorized_reason, whitelist.REASON_IP_MAC_PAIR_MISMATCH)
        self.assertIn(packet.ip_origen, detection.message)
        self.assertIn(packet.mac_origen, detection.message)
        self.assertIn("reason=ip_mac_pair_mismatch", detection.message)
        alert_sender.assert_called_once()

        subject, body, recipient = alert_sender.call_args.args
        self.assertIn(UNAUTHORIZED_DEVICE, subject)
        self.assertIn(packet.ip_origen, body)
        self.assertIn(packet.mac_origen, body)
        self.assertIn("Motivo: ip_mac_pair_mismatch", body)
        self.assertEqual(recipient, "admin@example.org")

    def test_strict_policy_real_whitelist_authorizes_matching_ip_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = _synthetic_packet("192.168.1.10", "aa:bb:cc:dd:ee:ff")
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                alert_sender=alert_sender,
            )

            detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, AUTHORIZED_DEVICE)
            self.assertEqual(detection.authorized_by, whitelist.AUTHORIZED_BY_IP_MAC)
            self.assertFalse(detection.alert_sent)
            alert_sender.assert_not_called()

    def test_strict_policy_rejects_authorized_ip_with_different_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = _synthetic_packet("192.168.1.10", "00:11:22:33:44:55")
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                alert_sender=alert_sender,
            )

            detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
            self.assertEqual(
                detection.unauthorized_reason,
                whitelist.REASON_MAC_NOT_IN_WHITELIST,
            )
            self.assertTrue(detection.alert_sent)
            alert_sender.assert_called_once()

    def test_strict_policy_rejects_authorized_mac_with_different_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = _synthetic_packet("192.168.1.20", "aa:bb:cc:dd:ee:ff")
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                alert_sender=alert_sender,
            )

            detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
            self.assertEqual(
                detection.unauthorized_reason,
                whitelist.REASON_IP_NOT_IN_WHITELIST,
            )
            self.assertTrue(detection.alert_sent)

    def test_strict_policy_rejects_missing_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = PacketEvent(
                timestamp=1710000000.25,
                mac_origen=None,
                mac_destino=None,
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                protocolo="TCP",
                link_layer_type="raw_ip",
            )
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                alert_sender=alert_sender,
            )

            detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
            self.assertEqual(
                detection.unauthorized_reason,
                whitelist.REASON_MAC_MISSING_STRICT_POLICY,
            )
            self.assertTrue(detection.alert_sent)

    def test_ip_fallback_policy_authorizes_known_ip_when_mac_is_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = PacketEvent(
                timestamp=1710000000.25,
                mac_origen=None,
                mac_destino=None,
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                protocolo="TCP",
                link_layer_type="raw_ip",
            )
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                authorization_policy=whitelist.AUTH_POLICY_IP_FALLBACK,
                alert_sender=alert_sender,
            )

            with self.assertLogs("gleipnir.detector", level="INFO") as logs:
                detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, AUTHORIZED_DEVICE)
            self.assertEqual(
                detection.authorized_by,
                whitelist.AUTHORIZED_BY_IP_FALLBACK,
            )
            self.assertIn("IP fallback", "\n".join(logs.output))
            alert_sender.assert_not_called()

    def test_ip_fallback_policy_rejects_unknown_ip_when_mac_is_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            _write_whitelist(Path(temp_dir), "192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n")
            packet = PacketEvent(
                timestamp=1710000000.25,
                mac_origen=None,
                mac_destino=None,
                ip_origen="192.168.1.20",
                ip_destino="8.8.8.8",
                protocolo="TCP",
                link_layer_type="raw_ip",
            )
            alert_sender = Mock()
            detector = DeviceDetector(
                alert_recipient="admin@example.org",
                authorization_policy=whitelist.AUTH_POLICY_IP_FALLBACK,
                alert_sender=alert_sender,
            )

            detection = detector.analyze(packet)

            self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
            self.assertEqual(
                detection.unauthorized_reason,
                whitelist.REASON_IP_NOT_IN_WHITELIST,
            )
            self.assertTrue(detection.alert_sent)

    def test_authorized_ip_with_unknown_mac_does_not_break_and_alerts(self) -> None:
        packet = PacketEvent(
            timestamp=1710000000.25,
            mac_origen=None,
            mac_destino=None,
            ip_origen="192.168.1.10",
            ip_destino="8.8.8.8",
            protocolo="TCP",
            link_layer_type="raw_ip",
        )
        authorization_checker = Mock(return_value=False)
        alert_sender = Mock()
        detector = DeviceDetector(
            alert_recipient="admin@example.org",
            authorization_checker=authorization_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertTrue(detection.alert_sent)
        self.assertIn("mac=unknown", detection.message)
        authorization_checker.assert_called_once_with("192.168.1.10", None)
        subject, body, recipient = alert_sender.call_args.args
        self.assertIn(UNAUTHORIZED_DEVICE, subject)
        self.assertIn("MAC origen: unknown", body)
        self.assertEqual(recipient, "admin@example.org")

    def test_authorized_mac_with_unknown_ip_is_unauthorized_and_alerts(self) -> None:
        packet = _synthetic_packet("192.168.1.99", "aa:bb:cc:dd:ee:ff")
        authorization_checker = Mock(return_value=False)
        alert_sender = Mock()
        detector = DeviceDetector(
            alert_recipient="admin@example.org",
            authorization_checker=authorization_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertTrue(detection.alert_sent)
        authorization_checker.assert_called_once_with(
            "192.168.1.99",
            "aa:bb:cc:dd:ee:ff",
        )
        alert_sender.assert_called_once()

    def test_unauthorized_device_can_skip_email_for_offline_tests(self) -> None:
        packet = _synthetic_packet("192.168.1.12", "00:11:22:33:44:56")
        alert_sender = Mock()
        detector = DeviceDetector(
            send_email=False,
            authorization_checker=Mock(return_value=False),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertFalse(detection.alert_sent)
        alert_sender.assert_not_called()

    def test_unauthorized_device_without_recipient_does_not_send_email(self) -> None:
        packet = _synthetic_packet("192.168.1.13", "00:11:22:33:44:57")
        alert_sender = Mock()
        detector = DeviceDetector(
            authorization_checker=Mock(return_value=False),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertFalse(detection.alert_sent)
        alert_sender.assert_not_called()

    def test_mailer_error_is_wrapped_without_losing_detection_context(self) -> None:
        packet = _synthetic_packet("192.168.1.14", "00:11:22:33:44:58")
        alert_sender = Mock(side_effect=MailerError("smtp failed"))
        detector = DeviceDetector(
            alert_recipient="admin@example.org",
            authorization_checker=Mock(return_value=False),
            alert_sender=alert_sender,
        )

        with self.assertRaisesRegex(DetectorError, "alert"):
            detector.analyze(packet)

    def test_detect_packet_uses_default_detector_path(self) -> None:
        packet = _synthetic_packet("192.168.1.15", "00:11:22:33:44:59")

        detection = detect_packet(packet, send_email=False)

        self.assertEqual(detection.event_type, UNAUTHORIZED_DEVICE)
        self.assertFalse(detection.alert_sent)

    def test_external_ip_not_in_blacklist_is_allowed(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.20",
            "00:11:22:33:44:60",
            ip_destino="8.8.8.8",
        )
        blacklist_checker = Mock(return_value=False)
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            blacklist_checker=blacklist_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertIsNone(detection)
        blacklist_checker.assert_called_once_with("8.8.8.8")
        alert_sender.assert_not_called()

    def test_blacklisted_external_ip_generates_event_and_alert(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.21",
            "00:11:22:33:44:61",
            ip_destino="8.8.4.4",
            protocolo="udp",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="8.8.4.4", reason="Malware C2")
            ),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertIsInstance(detection, BlacklistedExternalIPEvent)
        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(detection.timestamp, packet.timestamp)
        self.assertEqual(detection.ip_origen, packet.ip_origen)
        self.assertEqual(detection.ip_destino, packet.ip_destino)
        self.assertEqual(detection.protocolo, packet.protocolo)
        self.assertEqual(detection.motivo, "Malware")
        self.assertEqual(detection.severidad, BLACKLISTED_EXTERNAL_IP_SEVERITY)
        self.assertTrue(detection.alert_sent)
        alert_sender.assert_called_once()

        subject, body, recipient = alert_sender.call_args.args
        self.assertIn(BLACKLISTED_EXTERNAL_IP, subject)
        self.assertIn("ALERTA DE EMERGENCIA", subject)
        self.assertIn("IP peligrosa detectada", subject)
        self.assertIn(packet.ip_origen, body)
        self.assertIn(packet.ip_destino, body)
        self.assertIn("Malware", body)
        self.assertIn("Tipo de riesgo", body)
        self.assertIn("Recomendacion", body)
        self.assertIn(BLACKLISTED_EXTERNAL_IP_SEVERITY, body)
        self.assertEqual(recipient, "admin@example.org")

    def test_blacklisted_external_ip_alert_supports_botnet_risk(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.28",
            "00:11:22:33:44:68",
            ip_destino="8.8.8.8",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="8.8.8.8", reason="Riesgo: Botnet")
            ),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(detection.motivo, "Botnet")
        self.assertEqual(detection.severidad, BLACKLISTED_EXTERNAL_IP_SEVERITY)
        subject, body, recipient = alert_sender.call_args.args
        self.assertIn("ALERTA DE EMERGENCIA", subject)
        self.assertIn("Botnet", body)
        self.assertIn(packet.ip_destino, body)
        self.assertEqual(recipient, "admin@example.org")

    def test_blacklisted_external_ip_alert_supports_virus_risk(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.29",
            "00:11:22:33:44:69",
            ip_destino="1.1.1.1",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="1.1.1.1", reason="Riesgo: Virus")
            ),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(detection.motivo, "Virus")
        self.assertTrue(detection.alert_sent)
        subject, body, _recipient = alert_sender.call_args.args
        self.assertIn("ALERTA DE EMERGENCIA", subject)
        self.assertIn("Virus", body)

    def test_blacklisted_external_ip_without_risk_uses_unknown(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.30",
            "00:11:22:33:44:70",
            ip_destino="1.0.0.1",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(return_value=BlacklistEntry(ip="1.0.0.1")),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(detection.motivo, "Unknown")
        subject, body, recipient = alert_sender.call_args.args
        self.assertIn("ALERTA DE EMERGENCIA", subject)
        self.assertIn("Tipo de riesgo: Unknown", body)
        self.assertEqual(recipient, "admin@example.org")

    def test_private_destination_ip_is_ignored_even_if_checker_would_match(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.22",
            "00:11:22:33:44:62",
            ip_destino="192.168.1.1",
        )
        blacklist_checker = Mock(return_value=True)
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            blacklist_checker=blacklist_checker,
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertIsNone(detection)
        blacklist_checker.assert_not_called()
        alert_sender.assert_not_called()

    def test_blacklisted_external_ip_can_skip_email_for_tests(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.23",
            "00:11:22:33:44:63",
            ip_destino="1.1.1.1",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            send_email=False,
            blacklist_checker=Mock(return_value=True),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertFalse(detection.alert_sent)
        alert_sender.assert_not_called()

    def test_blacklisted_external_ip_without_recipient_does_not_send_email(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.24",
            "00:11:22:33:44:64",
            ip_destino="9.9.9.9",
        )
        alert_sender = Mock()
        detector = ExternalIPBlacklistDetector(
            blacklist_checker=Mock(return_value=True),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertFalse(detection.alert_sent)
        alert_sender.assert_not_called()

    def test_blacklisted_external_ip_records_policy_suppressed_alert(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.27",
            "00:11:22:33:44:67",
            ip_destino="8.8.8.8",
        )
        alert_sender = Mock(
            return_value=AlertDecision(
                sent=False,
                suppressed=True,
                severity="high",
                group_key="BLACKLISTED_EXTERNAL_IP|dst=8.8.8.8",
                timestamp=1710000000.25,
                reason="cooldown",
            )
        )
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="8.8.8.8", reason="Repeated C2")
            ),
            alert_sender=alert_sender,
        )

        detection = detector.analyze(packet)

        self.assertFalse(detection.alert_sent)
        self.assertTrue(detection.alert_suppressed)
        self.assertEqual(detection.alert_suppression_reason, "cooldown")
        self.assertEqual(detection.alert_severity, "high")
        self.assertEqual(detection.motivo, "Unknown")
        self.assertEqual(detection.severidad, BLACKLISTED_EXTERNAL_IP_SEVERITY)
        alert_sender.assert_called_once()

    def test_blacklisted_external_ip_mailer_error_is_wrapped(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.25",
            "00:11:22:33:44:65",
            ip_destino="8.8.8.8",
        )
        detector = ExternalIPBlacklistDetector(
            alert_recipient="admin@example.org",
            blacklist_checker=Mock(return_value=True),
            alert_sender=Mock(side_effect=MailerError("smtp failed")),
        )

        with self.assertRaisesRegex(DetectorError, "blacklisted IP"):
            detector.analyze(packet)

    def test_detect_blacklisted_external_ip_uses_default_detector_path(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.26",
            "00:11:22:33:44:66",
            ip_destino="192.168.1.1",
        )

        detection = detect_blacklisted_external_ip(packet, send_email=False)

        self.assertIsNone(detection)

    def test_blacklisted_destination_is_outbound(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.40",
            "00:11:22:33:44:80",
            ip_destino="8.8.8.8",
        )
        detector = ExternalIPBlacklistDetector(
            send_email=False,
            blacklist_checker=Mock(return_value=True),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="8.8.8.8", reason="Botnet")
            ),
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.event_type, BLACKLISTED_EXTERNAL_IP)
        self.assertEqual(detection.directional_event_type, BLACKLISTED_EXTERNAL_IP_OUTBOUND)
        self.assertEqual(detection.direccion, DIRECTION_OUTBOUND)
        self.assertEqual(detection.ip_peligrosa, "8.8.8.8")
        self.assertEqual(detection.motivo, "Botnet")

    def test_blacklisted_source_is_inbound(self) -> None:
        packet = _synthetic_packet(
            "8.8.8.8",
            "00:11:22:33:44:81",
            ip_destino="192.168.1.10",
        )
        checker = Mock(side_effect=lambda ip: ip == "8.8.8.8")
        detector = ExternalIPBlacklistDetector(
            send_email=False,
            blacklist_checker=checker,
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="8.8.8.8", reason="Malware")
            ),
        )

        detection = detector.analyze(packet)

        self.assertEqual(detection.directional_event_type, BLACKLISTED_EXTERNAL_IP_INBOUND)
        self.assertEqual(detection.direccion, DIRECTION_INBOUND)
        self.assertEqual(detection.ip_peligrosa, "8.8.8.8")
        self.assertEqual(detection.motivo, "Malware")

    def test_private_blacklisted_ip_ignored_when_check_private_false(self) -> None:
        packet = _synthetic_packet(
            "10.0.0.9",
            "00:11:22:33:44:82",
            ip_destino="10.0.0.5",
        )
        checker = Mock(return_value=True)
        detector = ExternalIPBlacklistDetector(
            send_email=False,
            blacklist_checker=checker,
            check_private=False,
        )

        detection = detector.analyze(packet)

        self.assertIsNone(detection)
        checker.assert_not_called()

    def test_private_blacklisted_ip_detected_when_check_private_true(self) -> None:
        packet = _synthetic_packet(
            "10.0.0.9",
            "00:11:22:33:44:83",
            ip_destino="10.0.0.5",
        )
        detector = ExternalIPBlacklistDetector(
            send_email=False,
            blacklist_checker=Mock(side_effect=lambda ip: ip == "10.0.0.5"),
            blacklist_lookup=Mock(
                return_value=BlacklistEntry(ip="10.0.0.5", reason="Virus")
            ),
            check_private=True,
        )

        detection = detector.analyze(packet)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.directional_event_type, BLACKLISTED_PRIVATE_IP)
        self.assertEqual(detection.direccion, DIRECTION_LOCAL)
        self.assertEqual(detection.motivo, "Virus")


def _synthetic_packet(
    ip_origen: str,
    mac_origen: str,
    *,
    ip_destino: str = "8.8.8.8",
    protocolo: str = "tcp",
):
    return parse_packet(
        {
            "timestamp": "1710000000.25",
            "mac_origen": mac_origen,
            "mac_destino": "66:55:44:33:22:11",
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "protocolo": protocolo,
        }
    )


def _write_whitelist(root: Path, rows: str) -> None:
    whitelist_file = root / "whitelist.csv"
    whitelist_file.write_text(
        "ip,mac,description\n" + rows,
        encoding="utf-8",
    )
    whitelist.validate_whitelist_file(whitelist_file)


if __name__ == "__main__":
    unittest.main()
