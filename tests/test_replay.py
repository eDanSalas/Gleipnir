"""Unit tests for offline replay mode."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from src.detector import DetectionEvent, UNAUTHORIZED_DEVICE
from src.dns_http_monitor import DNSTrafficEvent, HTTPTrafficEvent
from src.replay import replay_events, replay_pcap
from src.sniffer import PacketEvent


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class ReplayTests(unittest.TestCase):
    def test_replay_pcap_sends_each_packet_to_detector_and_monitor(self) -> None:
        frames = [_fixture_frame("ipv4_tcp"), _fixture_frame("ipv6_udp")]
        detector_handler = Mock(side_effect=_detection_for_packet)
        traffic_monitor = Mock(return_value=())

        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "sample.pcap"
            pcap_path.write_bytes(_build_pcap(frames))

            result = replay_pcap(
                pcap_path,
                detector_handler=detector_handler,
                traffic_monitor=traffic_monitor,
            )

        self.assertEqual(result.packet_count, 2)
        self.assertEqual(len(result.detection_events), 2)
        self.assertEqual(result.traffic_events, ())
        self.assertEqual(detector_handler.call_count, 2)
        self.assertEqual(traffic_monitor.call_count, 2)
        self.assertIsInstance(detector_handler.call_args_list[0].args[0], PacketEvent)
        self.assertIsInstance(traffic_monitor.call_args_list[0].args[0], PacketEvent)

    def test_replay_events_applies_delay_between_packets_only(self) -> None:
        packets = [
            _synthetic_packet("192.168.1.10"),
            _synthetic_packet("192.168.1.11"),
            _synthetic_packet("192.168.1.12"),
        ]
        sleep = Mock()

        replay_events(
            packets,
            delay_seconds=0.25,
            detector_handler=Mock(side_effect=_detection_for_packet),
            traffic_monitor=Mock(return_value=()),
            sleep_func=sleep,
        )

        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(0.25)

    def test_replay_events_preserves_synthetic_dns_http_metadata_for_monitor(self) -> None:
        packet = _synthetic_packet(
            "192.168.1.20",
            dns_query="portal.example.org",
            dns_query_type="a",
            http_host="portal.example.org",
            http_method="get",
            http_path="/index.html",
        )

        result = replay_events(
            [packet],
            detector_handler=Mock(side_effect=_detection_for_packet),
            sleep_func=Mock(),
        )

        self.assertEqual(result.packet_count, 1)
        self.assertEqual(len(result.traffic_events), 2)
        self.assertIsInstance(result.traffic_events[0], DNSTrafficEvent)
        self.assertIsInstance(result.traffic_events[1], HTTPTrafficEvent)
        self.assertEqual(result.traffic_events[0].dominio_consultado, "portal.example.org")
        self.assertEqual(result.traffic_events[1].host, "portal.example.org")

    def test_replay_events_can_use_central_packet_processor(self) -> None:
        packet = _synthetic_packet("192.168.1.30")
        detection = _detection_for_packet(PacketEvent(
            timestamp=1710000000.25,
            mac_origen="aa:bb:cc:dd:ee:ff",
            mac_destino="66:55:44:33:22:11",
            ip_origen="192.168.1.30",
            ip_destino="8.8.8.8",
            protocolo="TCP",
        ))
        dns_event = DNSTrafficEvent(
            timestamp=1710000000.25,
            ip_origen="192.168.1.30",
            ip_destino="8.8.8.8",
            dominio_consultado="portal.example.org",
            tipo_consulta="A",
        )
        processor = Mock(
            return_value=SimpleProcessingResult(
                detection_event=detection,
                dns_http_events=(dns_event,),
            )
        )

        result = replay_events([packet], packet_processor=processor)

        self.assertEqual(result.packet_count, 1)
        self.assertEqual(result.detection_events, (detection,))
        self.assertEqual(result.traffic_events, (dns_event,))
        self.assertEqual(len(result.packet_results), 1)
        processor.assert_called_once()
        self.assertIsInstance(processor.call_args.args[0], PacketEvent)
        self.assertIs(processor.call_args.args[1], packet)

    def test_replay_events_continues_after_packet_processor_error(self) -> None:
        packets = [_synthetic_packet("192.168.1.40"), _synthetic_packet("192.168.1.41")]
        detection = _detection_for_packet(PacketEvent(
            timestamp=1710000000.25,
            mac_origen="aa:bb:cc:dd:ee:ff",
            mac_destino="66:55:44:33:22:11",
            ip_origen="192.168.1.41",
            ip_destino="8.8.8.8",
            protocolo="TCP",
        ))
        processor = Mock(
            side_effect=[
                RuntimeError("engine failed"),
                SimpleProcessingResult(detection_event=detection, dns_http_events=()),
            ]
        )

        result = replay_events(packets, packet_processor=processor)

        self.assertEqual(result.packet_count, 2)
        self.assertEqual(result.errors, 1)
        self.assertEqual(result.detection_events, (detection,))
        self.assertEqual(processor.call_count, 2)

    def test_replay_pcap_rejects_negative_delay(self) -> None:
        with self.assertRaisesRegex(ValueError, "delay_seconds"):
            replay_pcap("unused.pcap", delay_seconds=-1)


class SimpleProcessingResult:
    def __init__(self, *, detection_event, dns_http_events):
        self.detection_event = detection_event
        self.dns_http_events = dns_http_events


def _detection_for_packet(packet: PacketEvent) -> DetectionEvent:
    return DetectionEvent(
        event_type=UNAUTHORIZED_DEVICE,
        packet=packet,
        alert_sent=False,
        message=f"simulated detection for {packet.ip_origen}",
    )


def _synthetic_packet(ip_origen: str, **extra):
    packet = {
        "timestamp": "1710000000.25",
        "mac_origen": "aa:bb:cc:dd:ee:ff",
        "mac_destino": "66:55:44:33:22:11",
        "ip_origen": ip_origen,
        "ip_destino": "8.8.8.8",
        "protocolo": "tcp",
    }
    packet.update(extra)
    return packet


def _fixture_frame(name: str) -> bytes:
    for line in (FIXTURES_DIR / "offline_packets.hex").read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith(f"{name}="):
            return bytes.fromhex(line.split("=", maxsplit=1)[1])

    raise AssertionError(f"Missing fixture: {name}")


def _build_pcap(frames: list[bytes]) -> bytes:
    pcap = bytearray()
    pcap.extend(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    for index, frame in enumerate(frames, start=1):
        pcap.extend(struct.pack("<IIII", index, 250_000 * index, len(frame), len(frame)))
        pcap.extend(frame)

    return bytes(pcap)


if __name__ == "__main__":
    unittest.main()
