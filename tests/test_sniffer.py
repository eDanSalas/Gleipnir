"""Unit tests for the offline sniffer."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src.sniffer import (
    PacketEvent,
    SnifferError,
    parse_packet,
    parse_pcap,
    process_ethernet_frame,
    process_pcap,
    process_synthetic_packet,
)


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class SnifferTests(unittest.TestCase):
    def test_process_synthetic_packet_normalizes_fields(self) -> None:
        packet = process_synthetic_packet(
            {
                "timestamp": "1710000000.25",
                "ip_origen": "2001:db8:0:0:0:0:0:1",
                "ip_destino": "2001:db8::2",
                "mac_origen": "AA-BB-CC-DD-EE-FF",
                "mac_destino": "00:11:22:33:44:55",
                "protocolo": "tcp",
            }
        )

        self.assertEqual(
            packet,
            PacketEvent(
                timestamp=1710000000.25,
                mac_origen="aa:bb:cc:dd:ee:ff",
                mac_destino="00:11:22:33:44:55",
                ip_origen="2001:db8::1",
                ip_destino="2001:db8::2",
                protocolo="TCP",
            ),
        )

    def test_process_synthetic_packet_requires_fields(self) -> None:
        with self.assertRaisesRegex(SnifferError, "mac_destino"):
            process_synthetic_packet(
                {
                    "ip_origen": "192.168.1.10",
                    "ip_destino": "8.8.8.8",
                    "mac_origen": "aa:bb:cc:dd:ee:ff",
                    "protocolo": "TCP",
                }
            )

    def test_process_ethernet_frame_extracts_ipv4_metadata(self) -> None:
        frame = _fixture_frame("ipv4_tcp")

        packet = process_ethernet_frame(frame)

        self.assertEqual(packet.timestamp, 0.0)
        self.assertEqual(packet.ip_origen, "192.168.1.10")
        self.assertEqual(packet.ip_destino, "8.8.8.8")
        self.assertEqual(packet.mac_origen, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet.mac_destino, "66:55:44:33:22:11")
        self.assertEqual(packet.protocolo, "TCP")

    def test_process_ethernet_frame_extracts_ipv6_metadata(self) -> None:
        frame = _fixture_frame("ipv6_udp")

        packet = process_ethernet_frame(frame)

        self.assertEqual(packet.timestamp, 0.0)
        self.assertEqual(packet.ip_origen, "2001:db8::1")
        self.assertEqual(packet.ip_destino, "2001:db8::2")
        self.assertEqual(packet.mac_origen, "de:ad:be:ef:00:01")
        self.assertEqual(packet.mac_destino, "00:11:22:33:44:55")
        self.assertEqual(packet.protocolo, "UDP")

    def test_process_pcap_extracts_packets_from_offline_file(self) -> None:
        frames = [_fixture_frame("ipv4_tcp"), _fixture_frame("ipv6_udp")]

        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "sample.pcap"
            pcap_path.write_bytes(_build_pcap(frames))

            packets = process_pcap(pcap_path)

        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0].timestamp, 1.25)
        self.assertEqual(packets[0].ip_origen, "192.168.1.10")
        self.assertEqual(packets[0].ip_destino, "8.8.8.8")
        self.assertEqual(packets[0].protocolo, "TCP")
        self.assertEqual(packets[1].timestamp, 2.5)
        self.assertEqual(packets[1].ip_origen, "2001:db8::1")
        self.assertEqual(packets[1].ip_destino, "2001:db8::2")
        self.assertEqual(packets[1].protocolo, "UDP")

    def test_parse_packet_accepts_raw_ethernet_bytes_with_timestamp(self) -> None:
        packet = parse_packet(_fixture_frame("ipv4_tcp"), timestamp=123.5)

        self.assertEqual(packet.timestamp, 123.5)
        self.assertEqual(packet.mac_origen, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet.ip_destino, "8.8.8.8")

    def test_parse_pcap_is_primary_pcap_api(self) -> None:
        frames = [_fixture_frame("ipv4_tcp")]

        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "sample.pcap"
            pcap_path.write_bytes(_build_pcap(frames))

            packets = parse_pcap(pcap_path)

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].timestamp, 1.25)
        self.assertEqual(packets[0].protocolo, "TCP")

    def test_parse_packet_accepts_scapy_compatible_packet(self) -> None:
        ether_layer = object()
        ip_layer = object()

        class FakeEther:
            src = "AA-BB-CC-DD-EE-FF"
            dst = "00:11:22:33:44:55"

        class FakeIp:
            src = "192.168.1.10"
            dst = "8.8.8.8"
            proto = 6

        class FakeScapyPacket:
            time = 44.25

            def __contains__(self, layer: object) -> bool:
                return layer in {ether_layer, ip_layer}

            def __getitem__(self, layer: object) -> object:
                if layer is ether_layer:
                    return FakeEther()
                if layer is ip_layer:
                    return FakeIp()
                raise KeyError(layer)

        with patch(
            "src.sniffer._load_scapy_layers",
            return_value={"Ether": ether_layer, "IP": ip_layer, "IPv6": object()},
        ):
            packet = parse_packet(FakeScapyPacket())

        self.assertEqual(packet.timestamp, 44.25)
        self.assertEqual(packet.mac_origen, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet.mac_destino, "00:11:22:33:44:55")
        self.assertEqual(packet.ip_origen, "192.168.1.10")
        self.assertEqual(packet.ip_destino, "8.8.8.8")
        self.assertEqual(packet.protocolo, "TCP")

    def test_parse_packet_accepts_scapy_compatible_ipv6_packet(self) -> None:
        ether_layer = object()
        ipv6_layer = object()

        class FakeEther:
            src = "de:ad:be:ef:00:01"
            dst = "00:11:22:33:44:55"

        class FakeIpv6:
            src = "2001:db8:0:0:0:0:0:1"
            dst = "2001:db8::2"
            nh = 17

        class FakeScapyPacket:
            time = 55.5

            def __contains__(self, layer: object) -> bool:
                return layer in {ether_layer, ipv6_layer}

            def __getitem__(self, layer: object) -> object:
                if layer is ether_layer:
                    return FakeEther()
                if layer is ipv6_layer:
                    return FakeIpv6()
                raise KeyError(layer)

        with patch(
            "src.sniffer._load_scapy_layers",
            return_value={"Ether": ether_layer, "IP": object(), "IPv6": ipv6_layer},
        ):
            packet = parse_packet(FakeScapyPacket())

        self.assertEqual(packet.timestamp, 55.5)
        self.assertEqual(packet.ip_origen, "2001:db8::1")
        self.assertEqual(packet.ip_destino, "2001:db8::2")
        self.assertEqual(packet.protocolo, "UDP")

    def test_parse_packet_reports_unsupported_object_without_scapy(self) -> None:
        with patch("src.sniffer._load_scapy_layers", side_effect=ImportError):
            with self.assertRaisesRegex(SnifferError, "Install Scapy"):
                parse_packet(object())

    def test_parse_packet_rejects_invalid_synthetic_values(self) -> None:
        invalid_packet = {
            "timestamp": "-1",
            "ip_origen": "192.168.1.10",
            "ip_destino": "8.8.8.8",
            "mac_origen": "aa:bb:cc:dd:ee:ff",
            "mac_destino": "00:11:22:33:44:55",
            "protocolo": "TCP",
        }

        with self.assertRaisesRegex(SnifferError, "timestamp"):
            parse_packet(invalid_packet)

    def test_parse_ethernet_frame_accepts_vlan_tagged_ipv4(self) -> None:
        frame = _fixture_frame("ipv4_tcp")
        vlan_frame = frame[:12] + bytes.fromhex("810000010800") + frame[14:]

        packet = parse_packet(vlan_frame)

        self.assertEqual(packet.mac_origen, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet.ip_origen, "192.168.1.10")
        self.assertEqual(packet.protocolo, "TCP")

    def test_parse_ethernet_frame_rejects_short_frame(self) -> None:
        with self.assertRaisesRegex(SnifferError, "too short"):
            parse_packet(b"\x00\x01")

    def test_parse_ethernet_frame_rejects_unsupported_ethertype(self) -> None:
        frame = (
            bytes.fromhex("001122334455aabbccddeeff1234")
            + b"\x00" * 28
        )

        with self.assertRaisesRegex(SnifferError, "ethertype"):
            parse_packet(frame)

    def test_parse_pcap_rejects_unsupported_linktype(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "unsupported-linktype.pcap"
            pcap_path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
            )

            with self.assertRaisesRegex(SnifferError, "Ethernet"):
                parse_pcap(pcap_path)

    def test_parse_pcap_rejects_truncated_packet_header(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "truncated-header.pcap"
            pcap_path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + b"\x00\x00"
            )

            with self.assertRaisesRegex(SnifferError, "packet header"):
                parse_pcap(pcap_path)

    def test_parse_pcap_rejects_truncated_packet_payload(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "truncated-payload.pcap"
            pcap_path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + struct.pack("<IIII", 1, 0, 100, 100)
                + b"\x00\x01"
            )

            with self.assertRaisesRegex(SnifferError, "packet payload"):
                parse_pcap(pcap_path)

    def test_process_pcap_rejects_invalid_magic(self) -> None:
        with TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "invalid.pcap"
            pcap_path.write_bytes(b"not a pcap header payload")

            with self.assertRaisesRegex(SnifferError, "magic"):
                process_pcap(pcap_path)


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
