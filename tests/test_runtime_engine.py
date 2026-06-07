"""Unit tests for the central IDS runtime engine."""

from __future__ import annotations

import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from src.config import Config
from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.runtime.engine import IDSEngine, RuntimeEngineError
from src.sniffer import parse_packet
from src.storage import ALERT_SENT, ALERT_SUPPRESSED, SQLiteEventStore
from src.threat_intel import STATUS_OK, ThreatIntelResult


class IDSEngineTests(unittest.TestCase):
    def test_from_config_loads_lists_and_processes_authorized_packet(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "10.0.0.5,00:11:22:33:44:55,Servidor\n")
            _write_blacklist(root, "")
            config = _config(root)
            engine = IDSEngine.from_config(
                config=config,
                send_email=False,
                enable_threat_intel=False,
                console_stream=io.StringIO(),
            )

            result = engine.process_packet_event(
                _packet("10.0.0.5", "00:11:22:33:44:55", ip_destino="192.168.1.1")
            )

            self.assertEqual(result.detection_event.event_type, AUTHORIZED_DEVICE)
            self.assertIsNone(result.blacklist_event)
            self.assertEqual(result.dns_http_events, ())
            self.assertEqual(result.threat_intel_results, {})
            self.assertTrue((root / "logs" / "gleipnir.log").exists())
            self.assertTrue((root / "events.db").exists())

            engine.shutdown()

    def test_process_packet_event_enriches_blacklisted_external_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "")
            _write_blacklist(root, "# reason: Malware C2\n8.8.8.8\n")
            config = _config(root)
            alert_sender = Mock()
            threat_result = ThreatIntelResult(
                service="abuseipdb",
                ip="8.8.8.8",
                status=STATUS_OK,
                data={"score": 50},
            )

            def enrich_event(event, *, config):
                return type(event)(
                    **{
                        **event.__dict__,
                        "threat_intel_results": {"abuseipdb": threat_result},
                    }
                )

            enricher = Mock(side_effect=enrich_event)
            engine = IDSEngine.from_config(
                config=config,
                alert_sender=alert_sender,
                threat_intel_enricher=enricher,
                console_stream=io.StringIO(),
            )

            result = engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:ff", ip_destino="8.8.8.8")
            )

            self.assertEqual(result.detection_event.event_type, UNAUTHORIZED_DEVICE)
            self.assertIsNotNone(result.blacklist_event)
            self.assertEqual(result.blacklist_event.event_type, BLACKLISTED_EXTERNAL_IP)
            self.assertEqual(result.blacklist_event.motivo, "Malware C2")
            self.assertEqual(result.blacklist_event.severidad, "ALTA")
            self.assertEqual(result.threat_intel_results["abuseipdb"], threat_result)
            self.assertEqual(
                result.blacklist_event.threat_intel_results["abuseipdb"],
                threat_result,
            )
            self.assertEqual(alert_sender.call_count, 2)
            enricher.assert_called_once()
            self.assertEqual(enricher.call_args.args[0].ip_destino, "8.8.8.8")
            engine.shutdown()

    def test_repeated_alert_is_suppressed_and_persisted(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "")
            _write_blacklist(root, "")
            config = _config(root)
            alert_sender = Mock()
            engine = IDSEngine.from_config(
                config=config,
                alert_sender=alert_sender,
                enable_threat_intel=False,
                console_stream=io.StringIO(),
            )
            packet = _packet(
                "192.168.1.60",
                "aa:bb:cc:dd:ee:60",
                ip_destino="192.168.1.1",
            )

            first = engine.process_packet_event(packet)
            second = engine.process_packet_event(packet)
            engine.shutdown()

            store = SQLiteEventStore(config.ids_db_path)
            sent_events = store.fetch_events(ALERT_SENT)
            suppressed_events = store.fetch_events(ALERT_SUPPRESSED)
            store.close()

            self.assertTrue(first.detection_event.alert_sent)
            self.assertFalse(second.detection_event.alert_sent)
            self.assertTrue(second.detection_event.alert_suppressed)
            self.assertEqual(second.detection_event.alert_suppression_reason, "cooldown")
            alert_sender.assert_called_once()
            self.assertEqual(len(sent_events), 1)
            self.assertEqual(len(suppressed_events), 1)

    def test_threat_intel_can_be_disabled_for_blacklisted_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "")
            _write_blacklist(root, "8.8.8.8\n")
            config = _config(root)
            enricher = Mock()
            engine = IDSEngine.from_config(
                config=config,
                send_email=False,
                enable_threat_intel=False,
                threat_intel_enricher=enricher,
                console_stream=io.StringIO(),
            )

            result = engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:ff", ip_destino="8.8.8.8")
            )

            self.assertEqual(result.threat_intel_results, {})
            enricher.assert_not_called()
            engine.shutdown()

    def test_process_packet_event_accepts_dns_http_source(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "192.168.1.30,00:11:22:33:44:55,Laptop\n")
            _write_blacklist(root, "")
            config = _config(root)
            engine = IDSEngine.from_config(
                config=config,
                send_email=False,
                enable_threat_intel=False,
                console_stream=io.StringIO(),
            )
            synthetic_packet = {
                "timestamp": 1710000000.25,
                "mac_origen": "00:11:22:33:44:55",
                "mac_destino": "66:55:44:33:22:11",
                "ip_origen": "192.168.1.30",
                "ip_destino": "93.184.216.34",
                "protocolo": "tcp",
                "dns_domain": "Example.ORG.",
                "dns_query_type": "a",
                "http_host": "Example.ORG",
                "http_method": "get",
                "http_path": "index.html",
            }

            result = engine.process_packet_event(
                parse_packet(synthetic_packet),
                dns_http_source=synthetic_packet,
            )

            self.assertEqual(len(result.dns_http_events), 2)
            self.assertEqual(result.dns_http_events[0].dominio_consultado, "example.org")
            self.assertEqual(result.dns_http_events[1].host, "example.org")
            engine.shutdown()

    def test_threat_intel_failure_does_not_stop_packet_processing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "")
            _write_blacklist(root, "8.8.4.4\n")
            config = _config(root)
            engine = IDSEngine.from_config(
                config=config,
                send_email=False,
                enable_threat_intel=True,
                threat_intel_enricher=Mock(side_effect=RuntimeError("api down")),
                console_stream=io.StringIO(),
            )

            result = engine.process_packet_event(
                _packet("192.168.1.40", "aa:bb:cc:dd:ee:11", ip_destino="8.8.4.4")
            )

            self.assertIsNotNone(result.blacklist_event)
            self.assertEqual(result.threat_intel_results, {})
            engine.shutdown()

    def test_shutdown_rejects_future_processing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_whitelist(root, "")
            _write_blacklist(root, "")
            engine = IDSEngine.from_config(
                config=_config(root),
                send_email=False,
                enable_threat_intel=False,
                console_stream=io.StringIO(),
            )

            engine.shutdown()

            with self.assertRaisesRegex(RuntimeEngineError, "shut down"):
                engine.process_packet_event(
                    _packet("192.168.1.50", "aa:bb:cc:dd:ee:22")
                )


def _config(root: Path) -> Config:
    return Config(
        smtp_host="smtp.example.org",
        smtp_port=587,
        smtp_user="alerts@example.org",
        smtp_password="test-password",
        admin_email="admin@example.org",
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
        log_dir=root / "logs",
        report_dir=root / "reports",
        ids_db_path=root / "events.db",
    )


def _write_whitelist(root: Path, rows: str) -> None:
    (root / "whitelist.csv").write_text(
        "ip,mac,description\n" + rows,
        encoding="utf-8",
    )


def _write_blacklist(root: Path, content: str) -> None:
    (root / "blacklist.txt").write_text(content, encoding="utf-8")


def _packet(
    ip_origen: str,
    mac_origen: str,
    *,
    ip_destino: str = "8.8.8.8",
):
    return parse_packet(
        {
            "timestamp": 1710000000.25,
            "mac_origen": mac_origen,
            "mac_destino": "66:55:44:33:22:11",
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "protocolo": "tcp",
        }
    )


if __name__ == "__main__":
    unittest.main()
