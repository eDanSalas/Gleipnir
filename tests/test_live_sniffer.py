"""Unit tests for Scapy live capture orchestration."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from src.detector import DetectionEvent, UNAUTHORIZED_DEVICE
from src.sniffer import (
    LIVE_CAPTURE_FILTER,
    PacketEvent,
    SnifferError,
    parse_packet,
    start_live_capture,
    start_live_capture_forever,
)


class LiveSnifferTests(unittest.TestCase):
    def test_start_live_capture_configures_scapy_and_dispatches_events(self) -> None:
        packets = [_synthetic_packet("192.168.1.10"), _synthetic_packet("192.168.1.11")]
        sniff = _sniff_that_replays(packets)
        detector = Mock(side_effect=_detection_for_packet)
        monitor = Mock(return_value=())

        result = start_live_capture(
            "eth0",
            packet_count=2,
            timeout=5,
            detector_handler=detector,
            traffic_monitor=monitor,
            scapy_sniff=sniff,
        )

        sniff.assert_called_once()
        sniff_options = sniff.call_args.kwargs
        self.assertEqual(sniff_options["iface"], "eth0")
        self.assertEqual(sniff_options["filter"], LIVE_CAPTURE_FILTER)
        self.assertEqual(sniff_options["count"], 2)
        self.assertEqual(sniff_options["timeout"], 5.0)
        self.assertFalse(sniff_options["store"])
        self.assertEqual(result.packets_received, 2)
        self.assertEqual(result.packet_events_processed, 2)
        self.assertEqual(result.detection_events_processed, 2)
        self.assertEqual(detector.call_count, 2)
        self.assertIsInstance(detector.call_args_list[0].args[0], PacketEvent)
        self.assertEqual(monitor.call_count, 2)

    def test_start_live_capture_processes_dns_http_with_real_monitor(self) -> None:
        sniff = _sniff_that_replays(
            [
                _synthetic_packet(
                    "192.168.1.20",
                    dns_query="portal.example.org",
                    dns_query_type="a",
                    http_host="portal.example.org",
                    http_method="get",
                    http_path="/index.html",
                )
            ]
        )

        result = start_live_capture(
            "eth0",
            detector_handler=Mock(side_effect=_detection_for_packet),
            scapy_sniff=sniff,
        )

        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(result.traffic_events_processed, 2)

    def test_start_live_capture_can_dispatch_to_central_packet_processor(self) -> None:
        sniff = _sniff_that_replays([_synthetic_packet("192.168.1.25")])
        detection = _detection_for_packet(parse_packet(_synthetic_packet("192.168.1.25")))
        processor = Mock(
            return_value=SimpleProcessingResult(
                detection_event=detection,
                dns_http_events=(object(), object()),
            )
        )
        detector = Mock(side_effect=RuntimeError("should not be called"))
        monitor = Mock(side_effect=RuntimeError("should not be called"))

        result = start_live_capture(
            "eth0",
            detector_handler=detector,
            traffic_monitor=monitor,
            packet_processor=processor,
            scapy_sniff=sniff,
        )

        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(result.detection_events_processed, 1)
        self.assertEqual(result.traffic_events_processed, 2)
        processor.assert_called_once()
        self.assertIsInstance(processor.call_args.args[0], PacketEvent)
        self.assertIsInstance(processor.call_args.args[1], dict)
        detector.assert_not_called()
        monitor.assert_not_called()

    def test_start_live_capture_continues_after_packet_parse_error(self) -> None:
        invalid_packet = {"ip_origen": "192.168.1.10"}
        valid_packet = _synthetic_packet("192.168.1.30")
        detector = Mock(side_effect=_detection_for_packet)

        result = start_live_capture(
            "eth0",
            detector_handler=detector,
            traffic_monitor=Mock(return_value=()),
            scapy_sniff=_sniff_that_replays([invalid_packet, valid_packet]),
        )

        self.assertEqual(result.packets_received, 2)
        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(result.errors, 1)
        detector.assert_called_once()

    def test_start_live_capture_continues_after_detector_and_monitor_errors(self) -> None:
        detector = Mock(side_effect=RuntimeError("detector failed"))
        monitor = Mock(side_effect=RuntimeError("monitor failed"))

        result = start_live_capture(
            "eth0",
            detector_handler=detector,
            traffic_monitor=monitor,
            scapy_sniff=_sniff_that_replays([_synthetic_packet("192.168.1.40")]),
        )

        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(result.errors, 2)
        detector.assert_called_once()
        monitor.assert_called_once()

    def test_start_live_capture_continues_after_packet_processor_error(self) -> None:
        processor = Mock(
            side_effect=[
                RuntimeError("engine failed"),
                SimpleProcessingResult(
                    detection_event=_detection_for_packet(
                        parse_packet(_synthetic_packet("192.168.1.42"))
                    ),
                    dns_http_events=(),
                ),
            ]
        )

        result = start_live_capture(
            "eth0",
            packet_processor=processor,
            scapy_sniff=_sniff_that_replays(
                [_synthetic_packet("192.168.1.41"), _synthetic_packet("192.168.1.42")]
            ),
        )

        self.assertEqual(result.packets_received, 2)
        self.assertEqual(result.packet_events_processed, 2)
        self.assertEqual(result.detection_events_processed, 1)
        self.assertEqual(result.errors, 1)
        self.assertEqual(processor.call_count, 2)

    def test_start_live_capture_rejects_invalid_arguments(self) -> None:
        with self.assertRaisesRegex(SnifferError, "interface"):
            start_live_capture("", scapy_sniff=Mock())

        with self.assertRaisesRegex(SnifferError, "packet_count"):
            start_live_capture("eth0", packet_count=0, scapy_sniff=Mock())

        with self.assertRaisesRegex(SnifferError, "timeout"):
            start_live_capture("eth0", timeout=-1, scapy_sniff=Mock())

    def test_start_live_capture_wraps_scapy_capture_errors(self) -> None:
        sniff = Mock(side_effect=OSError("permission denied"))

        with self.assertRaisesRegex(SnifferError, "Live capture failed"):
            start_live_capture("eth0", scapy_sniff=sniff)

    def test_start_live_capture_forever_retries_after_temporary_capture_error(
        self,
    ) -> None:
        sniff = Mock()

        def sniff_with_temporary_error(**kwargs):
            if sniff.call_count == 1:
                raise OSError("temporary libpcap failure")
            callback = kwargs["prn"]
            callback(_synthetic_packet("192.168.1.50"))

        sniff.side_effect = sniff_with_temporary_error
        processor = Mock(
            return_value=SimpleProcessingResult(
                detection_event=_detection_for_packet(
                    parse_packet(_synthetic_packet("192.168.1.50"))
                ),
                dns_http_events=(),
            )
        )
        logger = Mock()
        sleeper = Mock()

        result = start_live_capture_forever(
            "eth0",
            packet_processor=processor,
            scapy_sniff=sniff,
            health_log_interval_seconds=1,
            retry_seconds=0.1,
            restart_sleep_seconds=0,
            max_cycles=1,
            sleep=sleeper,
            monotonic=_monotonic_values([0, 1, 2]),
            logger=logger,
        )

        self.assertEqual(result.capture_cycles, 1)
        self.assertEqual(result.packets_received, 1)
        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(result.detection_events_processed, 1)
        self.assertEqual(result.errors, 1)
        self.assertEqual(sniff.call_count, 2)
        self.assertEqual(processor.call_count, 1)
        sleeper.assert_called_with(0.1)
        logger.warning.assert_called()

    def test_start_live_capture_forever_does_not_hide_critical_errors(self) -> None:
        sniff = Mock(side_effect=OSError("Operation not permitted"))
        logger = Mock()

        with self.assertRaisesRegex(SnifferError, "Live capture failed"):
            start_live_capture_forever(
                "eth0",
                scapy_sniff=sniff,
                health_log_interval_seconds=1,
                max_cycles=1,
                sleep=Mock(),
                logger=logger,
            )

        logger.error.assert_called()

    def test_start_live_capture_forever_logs_periodic_health(self) -> None:
        sniff = _sniff_that_replays([_synthetic_packet("192.168.1.60")])
        logger = Mock()

        result = start_live_capture_forever(
            "eth0",
            packet_processor=Mock(
                return_value=SimpleProcessingResult(
                    detection_event=None,
                    dns_http_events=(),
                )
            ),
            scapy_sniff=sniff,
            health_log_interval_seconds=1,
            restart_sleep_seconds=0,
            max_cycles=1,
            sleep=Mock(),
            monotonic=_monotonic_values([0, 1]),
            logger=logger,
        )

        self.assertEqual(result.capture_cycles, 1)
        self.assertTrue(
            any(
                "LIVE_CAPTURE_HEALTH" in call.args[0]
                for call in logger.info.call_args_list
            )
        )

    def test_parse_packet_accepts_scapy_compatible_arp_packet(self) -> None:
        ether_layer = object()
        arp_layer = object()

        class FakeEther:
            src = "aa:bb:cc:dd:ee:ff"
            dst = "ff:ff:ff:ff:ff:ff"

        class FakeArp:
            psrc = "192.168.1.10"
            pdst = "192.168.1.1"
            hwsrc = "aa:bb:cc:dd:ee:ff"
            hwdst = "00:00:00:00:00:00"

        class FakeScapyPacket:
            time = 11.5

            def __contains__(self, layer: object) -> bool:
                return layer in {ether_layer, arp_layer}

            def __getitem__(self, layer: object) -> object:
                if layer is ether_layer:
                    return FakeEther()
                if layer is arp_layer:
                    return FakeArp()
                raise KeyError(layer)

        with patch(
            "src.sniffer._load_scapy_layers",
            return_value={
                "Ether": ether_layer,
                "ARP": arp_layer,
                "IP": object(),
                "IPv6": object(),
            },
        ):
            packet = parse_packet(FakeScapyPacket())

        self.assertEqual(packet.timestamp, 11.5)
        self.assertEqual(packet.protocolo, "ARP")
        self.assertEqual(packet.ip_origen, "192.168.1.10")
        self.assertEqual(packet.ip_destino, "192.168.1.1")
        self.assertEqual(packet.mac_destino, "ff:ff:ff:ff:ff:ff")


def _sniff_that_replays(packets):
    sniff = Mock()

    def replay_packets(**kwargs):
        callback = kwargs["prn"]
        for packet in packets:
            callback(packet)

    sniff.side_effect = replay_packets
    return sniff


def _monotonic_values(values):
    sequence = iter(values)
    last_value = values[-1]

    def get_time():
        nonlocal last_value
        try:
            last_value = next(sequence)
        except StopIteration:
            pass
        return last_value

    return get_time


def _detection_for_packet(packet: PacketEvent) -> DetectionEvent:
    return DetectionEvent(
        event_type=UNAUTHORIZED_DEVICE,
        packet=packet,
        alert_sent=False,
        message=f"simulated detection for {packet.ip_origen}",
    )


class SimpleProcessingResult:
    def __init__(self, *, detection_event, dns_http_events):
        self.detection_event = detection_event
        self.dns_http_events = dns_http_events


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


if __name__ == "__main__":
    unittest.main()
