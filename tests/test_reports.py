"""Unit tests for IDS report generation."""

from __future__ import annotations

import csv
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from src.detector import (
    AUTHORIZED_DEVICE,
    BLACKLISTED_EXTERNAL_IP,
    UNAUTHORIZED_DEVICE,
    BlacklistedExternalIPEvent,
    DetectionEvent,
)
from src.dns_http_monitor import DNSTrafficEvent, HTTPTrafficEvent
from src.reports import (
    ReportData,
    ReportFilters,
    build_report_payload,
    generate_reports,
)
from src.sniffer import PacketEvent
from src.threat_intel import STATUS_OK, ThreatIntelResult


class ReportsTests(unittest.TestCase):
    def test_generate_reports_writes_json_and_csv(self) -> None:
        generated_at = datetime(2026, 6, 6, 20, 10, 0, tzinfo=timezone.utc)

        with TemporaryDirectory() as temp_dir:
            report_paths = generate_reports(
                _sample_report_data(),
                output_dir=temp_dir,
                generated_at=generated_at,
            )

            json_payload = json.loads(report_paths.json_path.read_text(encoding="utf-8"))
            with report_paths.csv_path.open("r", encoding="utf-8", newline="") as csv_file:
                csv_rows = list(csv.DictReader(csv_file))

        self.assertTrue(report_paths.json_path.name.endswith(".json"))
        self.assertTrue(report_paths.csv_path.name.endswith(".csv"))
        self.assertEqual(json_payload["generated_at"], "2026-06-06T20:10:00+00:00")
        self.assertEqual(json_payload["summary"]["authorized_devices"], 1)
        self.assertEqual(json_payload["summary"]["unauthorized_devices"], 1)
        self.assertEqual(json_payload["summary"]["dns_events"], 1)
        self.assertEqual(json_payload["summary"]["http_events"], 1)
        self.assertEqual(
            json_payload["dns_events"][0]["dominio_consultado"],
            "example.org",
        )
        self.assertEqual(
            json_payload["http_events"][0]["host"],
            "example.org",
        )
        self.assertEqual(json_payload["summary"]["blacklisted_external_ips"], 1)
        self.assertEqual(json_payload["summary"]["threat_intel_results"], 1)
        self.assertEqual(json_payload["summary"]["alert_events"], 0)
        self.assertEqual(len(csv_rows), 6)
        self.assertEqual(csv_rows[0]["category"], "authorized_device")
        self.assertIn("ip_origen", csv_rows[0])
        dns_row = next(row for row in csv_rows if row["category"] == "dns_event")
        http_row = next(row for row in csv_rows if row["category"] == "http_event")
        self.assertEqual(dns_row["dominio_consultado"], "example.org")
        self.assertEqual(http_row["host"], "example.org")

    def test_generate_reports_uses_config_report_dir_and_creates_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir) / "missing" / "reports"
            config = SimpleNamespace(report_dir=report_dir, log_dir=Path(temp_dir))

            report_paths = generate_reports(ReportData(), config=config)

            self.assertTrue(report_dir.is_dir())
            self.assertTrue(report_paths.json_path.is_file())
            self.assertTrue(report_paths.csv_path.is_file())

    def test_generate_reports_can_write_a_single_format(self) -> None:
        with TemporaryDirectory() as temp_dir:
            json_paths = generate_reports(
                ReportData(),
                output_dir=temp_dir,
                output_format="json",
            )
            csv_paths = generate_reports(
                ReportData(),
                output_dir=temp_dir,
                output_format="csv",
                filename_prefix="csv_only",
            )

            self.assertIsNotNone(json_paths.json_path)
            self.assertIsNone(json_paths.csv_path)
            self.assertTrue(json_paths.json_path.is_file())
            self.assertIsNone(csv_paths.json_path)
            self.assertIsNotNone(csv_paths.csv_path)
            self.assertTrue(csv_paths.csv_path.is_file())

    def test_build_report_payload_redacts_secret_fields(self) -> None:
        report_data = ReportData(
            threat_intel_results=[
                {
                    "service": "custom",
                    "ip": "8.8.8.8",
                    "status": "ok",
                    "api_key": "real-api-key",
                    "data": {
                        "token": "real-token",
                        "note": "safe",
                    },
                }
            ]
        )

        payload = build_report_payload(report_data)
        payload_text = json.dumps(payload)

        self.assertNotIn("real-api-key", payload_text)
        self.assertNotIn("real-token", payload_text)
        self.assertIn("[REDACTED]", payload_text)
        self.assertIn("safe", payload_text)

    def test_build_report_payload_includes_applied_filters(self) -> None:
        filters = ReportFilters(
            event_type=UNAUTHORIZED_DEVICE,
            since=1780272000.0,
            until=1780876799.999999,
            source_ip="192.168.1.10",
            domain="ejemplo.com",
            severity="ALTA",
            since_label="2026-06-01",
            until_label="2026-06-07",
        )

        payload = build_report_payload(ReportData(), filters=filters)

        self.assertEqual(payload["filters"]["type"], UNAUTHORIZED_DEVICE)
        self.assertEqual(payload["filters"]["since"], "2026-06-01")
        self.assertEqual(payload["filters"]["until"], "2026-06-07")
        self.assertEqual(payload["filters"]["severity"], "ALTA")

    def test_csv_flattens_packet_fields_from_detection_event(self) -> None:
        with TemporaryDirectory() as temp_dir:
            report_paths = generate_reports(
                ReportData(authorized_devices=[_authorized_detection()]),
                output_dir=temp_dir,
            )

            with report_paths.csv_path.open("r", encoding="utf-8", newline="") as csv_file:
                row = next(csv.DictReader(csv_file))

        self.assertEqual(row["event_type"], AUTHORIZED_DEVICE)
        self.assertEqual(row["ip_origen"], "192.168.1.10")
        self.assertEqual(row["mac_origen"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(row["protocolo"], "TCP")


def _sample_report_data() -> ReportData:
    return ReportData(
        authorized_devices=[_authorized_detection()],
        unauthorized_devices=[_unauthorized_detection()],
        dns_events=[
            DNSTrafficEvent(
                timestamp=1710000000.25,
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                dominio_consultado="example.org",
                tipo_consulta="A",
            )
        ],
        http_events=[
            HTTPTrafficEvent(
                timestamp=1710000000.30,
                ip_origen="192.168.1.10",
                ip_destino="93.184.216.34",
                host="example.org",
                metodo="GET",
                ruta="/",
            )
        ],
        blacklisted_external_ips=[
            BlacklistedExternalIPEvent(
                event_type=BLACKLISTED_EXTERNAL_IP,
                timestamp=1710000000.35,
                ip_origen="192.168.1.10",
                ip_destino="8.8.4.4",
                protocolo="UDP",
                motivo="Destination external IP appears in the configured blacklist",
                severidad="ALTA",
                alert_sent=True,
            )
        ],
        threat_intel_results=[
            ThreatIntelResult(
                service="abuseipdb",
                ip="8.8.4.4",
                status=STATUS_OK,
                data={"abuseConfidenceScore": 10},
            )
        ],
    )


def _authorized_detection() -> DetectionEvent:
    return DetectionEvent(
        event_type=AUTHORIZED_DEVICE,
        packet=_packet_event(),
        alert_sent=False,
        message="Authorized device observed",
    )


def _unauthorized_detection() -> DetectionEvent:
    return DetectionEvent(
        event_type=UNAUTHORIZED_DEVICE,
        packet=_packet_event(mac_origen="00:11:22:33:44:55"),
        alert_sent=True,
        message="Unauthorized device detected",
    )


def _packet_event(mac_origen: str = "aa:bb:cc:dd:ee:ff") -> PacketEvent:
    return PacketEvent(
        timestamp=1710000000.25,
        mac_origen=mac_origen,
        mac_destino="66:55:44:33:22:11",
        ip_origen="192.168.1.10",
        ip_destino="8.8.8.8",
        protocolo="TCP",
    )


if __name__ == "__main__":
    unittest.main()
