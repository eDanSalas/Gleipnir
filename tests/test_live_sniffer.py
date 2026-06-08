"""Unit tests for Scapy live capture orchestration."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.detector import DetectionEvent, UNAUTHORIZED_DEVICE
from src.sniffer import (
    IgnoredPacketError,
    LINK_LAYER_COOKED_LINUX,
    LINK_LAYER_ETHERNET,
    LINK_LAYER_RAW_IP,
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
        self.assertEqual(result.parse_errors, 1)
        self.assertEqual(result.errors, 1)
        detector.assert_called_once()

    def test_start_live_capture_counts_ignored_unsupported_and_parse_errors(self) -> None:
        scapy = _load_scapy_or_skip(self)
        ignored_packet = scapy.TCP()
        unsupported_packet = bytes.fromhex("001122334455aabbccddeeff1234") + b"\x00" * 20
        incomplete_packet = b"\x00\x01"

        result = start_live_capture(
            "eth0",
            scapy_sniff=_sniff_that_replays(
                [ignored_packet, unsupported_packet, incomplete_packet]
            ),
        )

        self.assertEqual(result.packets_received, 3)
        self.assertEqual(result.ignored_packets, 1)
        self.assertEqual(result.unsupported_packets, 1)
        self.assertEqual(result.parse_errors, 1)
        self.assertEqual(result.packet_events_processed, 0)
        self.assertEqual(result.engine_errors, 0)
        self.assertEqual(result.errors, 2)

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
        self.assertEqual(result.engine_errors, 2)
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
        self.assertEqual(result.engine_errors, 1)
        self.assertEqual(result.errors, 1)
        self.assertEqual(processor.call_count, 2)

    def test_start_live_capture_debug_packets_outputs_safe_summary(self) -> None:
        scapy = _load_scapy_or_skip(self)
        debug_lines: list[str] = []

        result = start_live_capture(
            "eth0",
            packet_processor=Mock(
                return_value=SimpleProcessingResult(
                    detection_event=None,
                    dns_http_events=(),
                )
            ),
            scapy_sniff=_sniff_that_replays(
                [
                    scapy.Ether(
                        src="aa:bb:cc:dd:ee:ff",
                        dst="66:55:44:33:22:11",
                    )
                    / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
                    / scapy.TCP()
                ]
            ),
            debug_packets=True,
            debug_output=debug_lines.append,
        )

        self.assertEqual(result.packet_events_processed, 1)
        self.assertEqual(len(debug_lines), 1)
        self.assertIn("DEBUG_PACKET", debug_lines[0])
        self.assertIn("packet_event=yes", debug_lines[0])
        self.assertIn("link_layer=ethernet", debug_lines[0])

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

    def test_parse_packet_accepts_real_scapy_ethernet_packets(self) -> None:
        scapy = _load_scapy_or_skip(self)
        cases = (
            (
                "ether_ip_tcp",
                scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="66:55:44:33:22:11")
                / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
                / scapy.TCP(),
                "TCP",
            ),
            (
                "ether_ip_udp",
                scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="66:55:44:33:22:11")
                / scapy.IP(src="192.168.1.10", dst="8.8.4.4")
                / scapy.UDP(),
                "UDP",
            ),
            (
                "ether_ip_udp_dns",
                scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="66:55:44:33:22:11")
                / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
                / scapy.UDP(dport=53)
                / scapy.DNS(qd=scapy.DNSQR(qname="example.org")),
                "UDP",
            ),
            (
                "ether_ipv6_tcp",
                scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="66:55:44:33:22:11")
                / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
                / scapy.TCP(),
                "TCP",
            ),
        )

        for name, packet, expected_protocol in cases:
            with self.subTest(name=name):
                event = parse_packet(packet)

            self.assertEqual(event.link_layer_type, LINK_LAYER_ETHERNET)
            self.assertEqual(event.mac_origen, "aa:bb:cc:dd:ee:ff")
            self.assertEqual(event.mac_destino, "66:55:44:33:22:11")
            self.assertEqual(event.protocolo, expected_protocol)

    def test_parse_packet_accepts_real_scapy_ethernet_arp(self) -> None:
        scapy = _load_scapy_or_skip(self)

        event = parse_packet(
            scapy.Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
            / scapy.ARP(
                psrc="192.168.1.10",
                pdst="192.168.1.1",
                hwsrc="aa:bb:cc:dd:ee:ff",
                hwdst="00:00:00:00:00:00",
            )
        )

        self.assertEqual(event.link_layer_type, LINK_LAYER_ETHERNET)
        self.assertEqual(event.protocolo, "ARP")
        self.assertEqual(event.mac_origen, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(event.mac_destino, "ff:ff:ff:ff:ff:ff")

    def test_parse_packet_accepts_scapy_raw_ip_without_ether(self) -> None:
        scapy = _load_scapy_or_skip(self)

        ipv4_event = parse_packet(
            scapy.IP(src="192.168.1.10", dst="8.8.8.8") / scapy.TCP()
        )
        ipv6_event = parse_packet(
            scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / scapy.TCP()
        )

        self.assertEqual(ipv4_event.link_layer_type, LINK_LAYER_RAW_IP)
        self.assertEqual(ipv4_event.mac_origen, None)
        self.assertEqual(ipv4_event.mac_destino, None)
        self.assertEqual(ipv4_event.protocolo, "TCP")
        self.assertEqual(ipv6_event.link_layer_type, LINK_LAYER_RAW_IP)
        self.assertEqual(ipv6_event.mac_origen, None)
        self.assertEqual(ipv6_event.mac_destino, None)
        self.assertEqual(ipv6_event.protocolo, "TCP")

    def test_parse_packet_accepts_scapy_cooked_linux_packets(self) -> None:
        scapy = _load_scapy_or_skip(self)
        cooked_classes = [
            cls
            for cls in (scapy.CookedLinux, scapy.CookedLinuxV2)
            if cls is not None
        ]
        if not cooked_classes:
            self.skipTest("Scapy CookedLinux layers are not available")

        for cooked_class in cooked_classes:
            with self.subTest(cooked=cooked_class.__name__):
                event = parse_packet(
                    cooked_class()
                    / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
                    / scapy.TCP()
                )

            self.assertEqual(event.link_layer_type, LINK_LAYER_COOKED_LINUX)
            self.assertEqual(event.ip_origen, "192.168.1.10")
            self.assertEqual(event.ip_destino, "8.8.8.8")
            self.assertEqual(event.mac_destino, None)
            self.assertEqual(event.protocolo, "TCP")

    def test_parse_packet_ignores_non_target_scapy_packet(self) -> None:
        scapy = _load_scapy_or_skip(self)

        with self.assertRaises(IgnoredPacketError):
            parse_packet(scapy.TCP())

    def test_parse_packet_rejects_incomplete_scapy_packet(self) -> None:
        ip_layer = object()

        class FakeIp:
            src = None
            dst = "8.8.8.8"
            proto = 6

        class FakeScapyPacket:
            time = 12.5

            def __contains__(self, layer: object) -> bool:
                return layer is ip_layer

            def __getitem__(self, layer: object) -> object:
                if layer is ip_layer:
                    return FakeIp()
                raise KeyError(layer)

            def summary(self) -> str:
                return "FakeScapyPacket incomplete IP"

            def layers(self) -> list[object]:
                return [FakeIp]

        with patch(
            "src.sniffer._load_scapy_layers",
            return_value={"Ether": object(), "ARP": object(), "IP": ip_layer, "IPv6": object()},
        ):
            with self.assertRaises(SnifferError):
                parse_packet(FakeScapyPacket())


def _sniff_that_replays(packets):
    sniff = Mock()

    def replay_packets(**kwargs):
        callback = kwargs["prn"]
        for packet in packets:
            callback(packet)

    sniff.side_effect = replay_packets
    return sniff


def _load_scapy_or_skip(test_case: unittest.TestCase) -> SimpleNamespace:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP, Ether
        from scapy.layers import l2
    except ImportError as exc:
        test_case.skipTest(f"Scapy is not available: {exc}")

    return SimpleNamespace(
        ARP=ARP,
        DNS=DNS,
        DNSQR=DNSQR,
        Ether=Ether,
        IP=IP,
        IPv6=IPv6,
        TCP=TCP,
        UDP=UDP,
        CookedLinux=getattr(l2, "CookedLinux", None),
        CookedLinuxV2=getattr(l2, "CookedLinuxV2", None),
    )


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
