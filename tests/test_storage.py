
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from src.detector import (
    BLACKLISTED_EXTERNAL_IP,
    UNAUTHORIZED_DEVICE,
    BlacklistedExternalIPEvent,
    DetectionEvent,
)
from src.dns_http_monitor import DNSTrafficEvent, HTTPTrafficEvent
from src.reports import ReportFilters
from src.sniffer import PacketEvent
from src.storage import ALERT_SENT, ALERT_SUPPRESSED, DNS_EVENT, HTTP_EVENT
from src.storage import THREAT_INTEL_RESULT
from src.storage import SQLiteEventStore
from src.threat_intel import STATUS_OK, ThreatIntelResult


class SQLiteEventStoreTests(unittest.TestCase):
    def test_initializes_database_and_stores_processing_result(self) -> None:
        with TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "missing" / "gleipnir_events.db"
            store = SQLiteEventStore(db_path)

            stored_ids = store.save_packet_processing_result(_processing_result())
            events = store.fetch_events()
            db_exists = db_path.exists()

            store.close()

        event_types = [event.event_type for event in events]
        self.assertTrue(db_exists)
        self.assertEqual(len(stored_ids), 7)
        self.assertIn(UNAUTHORIZED_DEVICE, event_types)
        self.assertIn(DNS_EVENT, event_types)
        self.assertIn(HTTP_EVENT, event_types)
        self.assertIn(BLACKLISTED_EXTERNAL_IP, event_types)
        self.assertIn(THREAT_INTEL_RESULT, event_types)
        self.assertEqual(event_types.count(ALERT_SENT), 2)

    def test_raw_json_redacts_secret_like_fields(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteEventStore(Path(temp_dir) / "events.db")

            store.save_event(
                event_type="CUSTOM_EVENT",
                raw={
                    "api_key": "real-api-key",
                    "nested": {"token": "real-token", "note": "safe"},
                },
            )
            raw_json = store.fetch_events("CUSTOM_EVENT")[0].raw_json
            store.close()

        self.assertNotIn("real-api-key", raw_json)
        self.assertNotIn("real-token", raw_json)
        self.assertIn("[REDACTED]", raw_json)
        self.assertIn("safe", raw_json)

    def test_get_event_fetches_one_event_by_id(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteEventStore(Path(temp_dir) / "events.db")
            first_id = store.save_event(event_type=DNS_EVENT, message="first")
            second_id = store.save_event(event_type=HTTP_EVENT, message="second")

            first_event = store.get_event(first_id)
            second_event = store.get_event(second_id)
            missing_event = store.get_event(999)
            store.close()

        self.assertIsNotNone(first_event)
        self.assertIsNotNone(second_event)
        self.assertEqual(first_event.event_type, DNS_EVENT)
        self.assertEqual(second_event.message, "second")
        self.assertIsNone(missing_event)

    def test_build_report_data_uses_accumulated_events(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteEventStore(Path(temp_dir) / "events.db")
            store.save_packet_processing_result(_processing_result())

            report_data = store.build_report_data()
            store.close()

        self.assertEqual(len(report_data.unauthorized_devices), 1)
        self.assertEqual(len(report_data.dns_events), 1)
        self.assertEqual(len(report_data.http_events), 1)
        self.assertEqual(len(report_data.blacklisted_external_ips), 1)
        self.assertEqual(len(report_data.threat_intel_results), 1)
        self.assertEqual(len(report_data.alert_events), 2)
        self.assertEqual(
            report_data.blacklisted_external_ips[0]["motivo"],
            "Malware C2",
        )
        self.assertEqual(
            report_data.threat_intel_results[0]["service"],
            "abuseipdb",
        )

    def test_build_report_data_applies_sqlite_filters(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteEventStore(Path(temp_dir) / "events.db")
            store.save_event(
                event_type=DNS_EVENT,
                timestamp=1780444800.0,
                severity="INFO",
                source_ip="192.168.1.10",
                destination_ip="8.8.8.8",
                protocol="DNS",
                domain="ejemplo.com",
                message="DNS query observed: ejemplo.com",
                raw={"tipo_consulta": "A"},
            )
            store.save_event(
                event_type=DNS_EVENT,
                timestamp=1780963200.0,
                severity="INFO",
                source_ip="192.168.1.20",
                destination_ip="1.1.1.1",
                protocol="DNS",
                domain="otro.com",
                message="DNS query observed: otro.com",
                raw={"tipo_consulta": "AAAA"},
            )

            report_data = store.build_report_data(
                filters=ReportFilters(
                    event_type=DNS_EVENT,
                    since=1780272000.0,
                    until=1780876799.999999,
                    source_ip="192.168.1.10",
                    domain="ejemplo",
                    severity="INFO",
                )
            )
            store.close()

        self.assertEqual(len(report_data.dns_events), 1)
        self.assertEqual(
            report_data.dns_events[0]["dominio_consultado"],
            "ejemplo.com",
        )

    def test_suppressed_alert_is_persisted(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = SQLiteEventStore(Path(temp_dir) / "events.db")
            packet = PacketEvent(
                timestamp=1710000000.25,
                mac_origen="aa:bb:cc:dd:ee:ff",
                mac_destino="66:55:44:33:22:11",
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                protocolo="TCP",
            )
            detection_event = DetectionEvent(
                event_type=UNAUTHORIZED_DEVICE,
                packet=packet,
                alert_sent=False,
                message="Unauthorized device detected",
                alert_suppressed=True,
                alert_suppression_reason="cooldown",
                alert_severity="medium",
            )

            store.save_packet_processing_result(
                SimpleNamespace(
                    detection_event=detection_event,
                    dns_http_events=(),
                    blacklist_event=None,
                    threat_intel_results={},
                )
            )
            suppressed_events = store.fetch_events(ALERT_SUPPRESSED)
            report_data = store.build_report_data()
            store.close()

        self.assertEqual(len(suppressed_events), 1)
        self.assertIn("cooldown", suppressed_events[0].message)
        self.assertEqual(len(report_data.alert_events), 1)
        self.assertFalse(report_data.alert_events[0]["alert_sent"])


def _processing_result() -> SimpleNamespace:
    packet = PacketEvent(
        timestamp=1710000000.25,
        mac_origen="aa:bb:cc:dd:ee:ff",
        mac_destino="66:55:44:33:22:11",
        ip_origen="192.168.1.10",
        ip_destino="8.8.8.8",
        protocolo="TCP",
    )
    detection_event = DetectionEvent(
        event_type=UNAUTHORIZED_DEVICE,
        packet=packet,
        alert_sent=True,
        message="Unauthorized device detected",
    )
    dns_event = DNSTrafficEvent(
        timestamp=1710000000.25,
        ip_origen="192.168.1.10",
        ip_destino="8.8.8.8",
        dominio_consultado="example.org",
        tipo_consulta="A",
    )
    http_event = HTTPTrafficEvent(
        timestamp=1710000000.30,
        ip_origen="192.168.1.10",
        ip_destino="93.184.216.34",
        host="example.org",
        metodo="GET",
        ruta="/",
    )
    threat_result = ThreatIntelResult(
        service="abuseipdb",
        ip="8.8.8.8",
        status=STATUS_OK,
        data={"abuseConfidenceScore": 75},
    )
    blacklist_event = BlacklistedExternalIPEvent(
        event_type=BLACKLISTED_EXTERNAL_IP,
        timestamp=1710000000.35,
        ip_origen="192.168.1.10",
        ip_destino="8.8.8.8",
        protocolo="TCP",
        motivo="Malware C2",
        severidad="ALTA",
        alert_sent=True,
        threat_intel_results={"abuseipdb": threat_result},
    )

    return SimpleNamespace(
        detection_event=detection_event,
        dns_http_events=(dns_event, http_event),
        blacklist_event=blacklist_event,
        threat_intel_results={"abuseipdb": threat_result},
    )


if __name__ == "__main__":
    unittest.main()
