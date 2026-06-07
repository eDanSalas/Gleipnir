"""Unit tests for offline DNS and HTTP traffic registration."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.dns_http_monitor import (
    DNSTrafficEvent,
    HTTPTrafficEvent,
    detect_dns,
    detect_http,
    register_traffic,
)
from src.sniffer import PacketEvent, parse_packet


class DnsHttpMonitorTests(unittest.TestCase):
    def test_register_traffic_detects_dns_query_from_synthetic_packet(self) -> None:
        packet = _base_packet(
            dns_domain="WWW.Example.ORG.",
            dns_query_type="a",
        )

        events = register_traffic(packet)

        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0],
            DNSTrafficEvent(
                timestamp=1710000000.25,
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                dominio_consultado="www.example.org",
                tipo_consulta="A",
            ),
        )

    def test_register_traffic_detects_http_request_from_synthetic_packet(self) -> None:
        packet = _base_packet(
            protocolo="tcp",
            http_host="Portal.Example.ORG",
            http_method="get",
            http_path="index.html",
        )

        events = register_traffic(packet)

        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0],
            HTTPTrafficEvent(
                timestamp=1710000000.25,
                ip_origen="192.168.1.10",
                ip_destino="8.8.8.8",
                host="portal.example.org",
                metodo="GET",
                ruta="/index.html",
            ),
        )

    def test_register_traffic_can_return_dns_and_http_from_same_synthetic_packet(
        self,
    ) -> None:
        packet = _base_packet(
            dns={"domain": "api.example.org", "qtype": "AAAA"},
            http={"host": "api.example.org", "method": "POST", "path": "/v1"},
        )

        events = register_traffic(packet)

        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], DNSTrafficEvent)
        self.assertIsInstance(events[1], HTTPTrafficEvent)

    def test_packet_event_without_application_metadata_returns_no_events(self) -> None:
        packet = PacketEvent(
            timestamp=1710000000.25,
            mac_origen="aa:bb:cc:dd:ee:ff",
            mac_destino="66:55:44:33:22:11",
            ip_origen="192.168.1.10",
            ip_destino="8.8.8.8",
            protocolo="UDP",
        )

        self.assertEqual(register_traffic(packet), ())
        self.assertIsNone(detect_dns(packet))
        self.assertIsNone(detect_http(packet))

    def test_detect_dns_accepts_nested_dns_metadata(self) -> None:
        packet = _base_packet(dns={"qname": "mail.example.org.", "type": "mx"})

        event = detect_dns(packet)

        self.assertEqual(event.dominio_consultado, "mail.example.org")
        self.assertEqual(event.tipo_consulta, "MX")

    def test_detect_http_accepts_nested_http_metadata_without_optional_fields(self) -> None:
        packet = _base_packet(http={"host": "intranet.example.org"})

        event = detect_http(packet)

        self.assertEqual(event.host, "intranet.example.org")
        self.assertIsNone(event.metodo)
        self.assertIsNone(event.ruta)

    def test_register_traffic_uses_sniffer_parse_packet_for_synthetic_input(self) -> None:
        packet = _base_packet(dns_query="example.net")

        with patch("src.dns_http_monitor.parse_packet", wraps=parse_packet) as parser:
            events = register_traffic(packet)

        parser.assert_called_once_with(packet)
        self.assertEqual(events[0].ip_origen, "192.168.1.10")

    def test_register_traffic_logs_detected_events(self) -> None:
        packet = _base_packet(dns_query="example.net", http_host="example.net")

        with self.assertLogs("gleipnir.dns_http_monitor", level="INFO") as logs:
            register_traffic(packet)

        emitted_text = "\n".join(logs.output)
        self.assertIn("DNS_TRAFFIC", emitted_text)
        self.assertIn("HTTP_TRAFFIC", emitted_text)
        self.assertIn("example.net", emitted_text)

    def test_detect_dns_accepts_scapy_compatible_dns_packet(self) -> None:
        dns_layer = object()

        class FakeDnsQuery:
            qname = b"Scapy.Example.ORG."
            qtype = 1

        class FakeDnsLayer:
            qd = FakeDnsQuery()

        class FakeScapyPacket:
            def __contains__(self, layer: object) -> bool:
                return layer is dns_layer

            def __getitem__(self, layer: object) -> object:
                if layer is dns_layer:
                    return FakeDnsLayer()
                raise KeyError(layer)

        with patch("src.dns_http_monitor.parse_packet", return_value=_packet_event()):
            with patch(
                "src.dns_http_monitor._load_scapy_app_layers",
                return_value={
                    "DNS": dns_layer,
                    "HTTPRequest": object(),
                    "Raw": object(),
                },
            ):
                event = detect_dns(FakeScapyPacket())

        self.assertEqual(event.dominio_consultado, "scapy.example.org")
        self.assertEqual(event.tipo_consulta, "A")

    def test_detect_http_accepts_scapy_compatible_raw_http_packet(self) -> None:
        raw_layer = object()

        class FakeRawLayer:
            load = b"GET /status HTTP/1.1\r\nHost: API.Example.ORG\r\n\r\n"

        class FakeScapyPacket:
            def __contains__(self, layer: object) -> bool:
                return layer is raw_layer

            def __getitem__(self, layer: object) -> object:
                if layer is raw_layer:
                    return FakeRawLayer()
                raise KeyError(layer)

        with patch("src.dns_http_monitor.parse_packet", return_value=_packet_event()):
            with patch(
                "src.dns_http_monitor._load_scapy_app_layers",
                return_value={
                    "DNS": object(),
                    "HTTPRequest": object(),
                    "Raw": raw_layer,
                },
            ):
                event = detect_http(FakeScapyPacket())

        self.assertEqual(event.host, "api.example.org")
        self.assertEqual(event.metodo, "GET")
        self.assertEqual(event.ruta, "/status")


def _base_packet(**extra):
    packet = {
        "timestamp": "1710000000.25",
        "mac_origen": "aa:bb:cc:dd:ee:ff",
        "mac_destino": "66:55:44:33:22:11",
        "ip_origen": "192.168.1.10",
        "ip_destino": "8.8.8.8",
        "protocolo": "udp",
    }
    packet.update(extra)
    return packet


def _packet_event() -> PacketEvent:
    return PacketEvent(
        timestamp=1710000000.25,
        mac_origen="aa:bb:cc:dd:ee:ff",
        mac_destino="66:55:44:33:22:11",
        ip_origen="192.168.1.10",
        ip_destino="8.8.8.8",
        protocolo="UDP",
    )


if __name__ == "__main__":
    unittest.main()
