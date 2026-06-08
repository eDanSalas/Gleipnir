"""Packet parsing, normalization, and live capture for Gleipnir IDS.

Offline helpers process synthetic packets, Scapy-compatible packet objects, raw
Ethernet frames, and classic PCAP files without opening network interfaces.
Live capture is only started when ``start_live_capture`` is called explicitly.
"""

from __future__ import annotations

import ipaddress
import logging
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from src.logger import get_logger

ETHERNET_LINKTYPE = 1
ETHERNET_HEADER_LENGTH = 14
VLAN_TAG_LENGTH = 4
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = {0x8100, 0x88A8}
LIVE_CAPTURE_FILTER = "arp or ip or ip6"
DEFAULT_FOREVER_RETRY_SECONDS = 5.0
DEFAULT_FOREVER_RESTART_SLEEP_SECONDS = 1.0
DEFAULT_HEALTH_LOG_INTERVAL_SECONDS = 300
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}
DEBUG_PACKET_SUMMARY_LIMIT = 220
MAX_DIAGNOSTIC_PACKET_LOGS = 10
LINK_LAYER_ETHERNET = "ethernet"
LINK_LAYER_COOKED_LINUX = "cooked_linux"
LINK_LAYER_RAW_IP = "raw_ip"
LINK_LAYER_UNKNOWN = "unknown"
_LOGGER = get_logger("sniffer")
_LOGGER.addHandler(logging.NullHandler())


class SnifferError(ValueError):
    """Raised when offline packet data cannot be processed."""


class IgnoredPacketError(SnifferError):
    """Raised when a packet is valid but outside the IDS live-capture scope."""


class UnsupportedPacketError(SnifferError):
    """Raised when a packet uses a link-layer format not yet supported."""


@dataclass(frozen=True)
class PacketEvent:
    """Normalized packet metadata extracted by the offline sniffer."""

    timestamp: float
    mac_origen: str | None
    mac_destino: str | None
    ip_origen: str
    ip_destino: str
    protocolo: str
    link_layer_type: str = LINK_LAYER_UNKNOWN


PacketInfo = PacketEvent
DetectorHandler = Callable[[PacketEvent], Any]
TrafficMonitor = Callable[[Any], tuple[Any, ...]]
PacketProcessor = Callable[[PacketEvent, Any], Any]
ScapySniff = Callable[..., Any]


@dataclass(frozen=True)
class LiveCaptureResult:
    """Summary of a completed live capture session."""

    packets_received: int
    ignored_packets: int
    unsupported_packets: int
    parse_errors: int
    packet_events_processed: int
    engine_errors: int
    detection_events_processed: int
    traffic_events_processed: int
    errors: int


@dataclass(frozen=True)
class LiveCaptureForeverResult:
    """Summary accumulated by a supervised live capture session."""

    capture_cycles: int
    packets_received: int
    ignored_packets: int
    unsupported_packets: int
    parse_errors: int
    packet_events_processed: int
    engine_errors: int
    detection_events_processed: int
    traffic_events_processed: int
    errors: int


def parse_packet(packet: Any, timestamp: float | None = None) -> PacketEvent:
    """Parse a synthetic, Scapy-compatible, or raw Ethernet packet offline."""
    if isinstance(packet, Mapping):
        return _parse_synthetic_packet(packet)

    if isinstance(packet, (bytes, bytearray, memoryview)):
        return _parse_ethernet_frame(bytes(packet), timestamp=timestamp)

    return _parse_scapy_packet(packet)


def parse_pcap(file_path: str | Path) -> tuple[PacketEvent, ...]:
    """Parse a classic PCAP file and return normalized packet events."""
    data = Path(file_path).read_bytes()
    byte_order, linktype, timestamp_resolution = _parse_pcap_global_header(data)

    if linktype != ETHERNET_LINKTYPE:
        raise SnifferError("Only Ethernet PCAP files are supported")

    events: list[PacketEvent] = []
    offset = 24

    while offset < len(data):
        if offset + 16 > len(data):
            raise SnifferError("Truncated PCAP packet header")

        ts_sec, ts_fraction, included_length, _original_length = struct.unpack(
            f"{byte_order}IIII",
            data[offset : offset + 16],
        )
        offset += 16

        if offset + included_length > len(data):
            raise SnifferError("Truncated PCAP packet payload")

        frame = data[offset : offset + included_length]
        offset += included_length
        event_timestamp = ts_sec + (ts_fraction / timestamp_resolution)
        events.append(_parse_ethernet_frame(frame, timestamp=event_timestamp))

    return tuple(events)


def start_live_capture(
    interface: str,
    packet_count: int | None = None,
    timeout: float | None = None,
    *,
    detector_handler: DetectorHandler | None = None,
    traffic_monitor: TrafficMonitor | None = None,
    packet_processor: PacketProcessor | None = None,
    scapy_sniff: ScapySniff | None = None,
    debug_packets: bool = False,
    debug_output: Callable[[str], Any] | None = None,
) -> LiveCaptureResult:
    """Capture live packets with Scapy and process them defensively.

    This function does not perform attacks, spoofing, evasion, or exploitation.
    On Linux it may require root privileges or packet-capture capabilities.
    """
    capture_interface = _validate_interface(interface)
    count = _validate_packet_count(packet_count)
    capture_timeout = _validate_timeout(timeout)
    sniff = scapy_sniff or _load_scapy_sniff()
    detect = (
        None
        if packet_processor is not None
        else detector_handler or _load_detector_handler()
    )
    monitor = (
        None
        if packet_processor is not None
        else traffic_monitor or _load_traffic_monitor()
    )

    packets_received = 0
    ignored_packets = 0
    unsupported_packets = 0
    parse_errors = 0
    packet_events_processed = 0
    engine_errors = 0
    detection_events_processed = 0
    traffic_events_processed = 0
    diagnostic_logs_emitted = 0
    mac_unavailable_logs_emitted = 0

    def handle_packet(packet: Any) -> None:
        nonlocal packets_received
        nonlocal ignored_packets
        nonlocal unsupported_packets
        nonlocal parse_errors
        nonlocal packet_events_processed
        nonlocal engine_errors
        nonlocal detection_events_processed
        nonlocal traffic_events_processed
        nonlocal diagnostic_logs_emitted
        nonlocal mac_unavailable_logs_emitted

        packets_received += 1

        try:
            packet_event = parse_packet(packet)
            packet_events_processed += 1
            if packet_event.mac_origen is None or packet_event.mac_destino is None:
                mac_unavailable_logs_emitted = _log_mac_unavailable_if_sampled(
                    packet,
                    packet_event,
                    mac_unavailable_logs_emitted,
                )
            _debug_live_packet(
                debug_packets,
                debug_output,
                packet,
                packet_event=packet_event,
                status="packet_event",
            )
        except IgnoredPacketError as exc:
            ignored_packets += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="ignored",
                logs_emitted=diagnostic_logs_emitted,
            )
            _debug_live_packet(
                debug_packets,
                debug_output,
                packet,
                status="ignored",
                error=exc,
            )
            return
        except UnsupportedPacketError as exc:
            unsupported_packets += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="unsupported",
                logs_emitted=diagnostic_logs_emitted,
            )
            _debug_live_packet(
                debug_packets,
                debug_output,
                packet,
                status="unsupported",
                error=exc,
            )
            return
        except SnifferError as exc:
            parse_errors += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="parse_error",
                logs_emitted=diagnostic_logs_emitted,
            )
            _debug_live_packet(
                debug_packets,
                debug_output,
                packet,
                status="parse_error",
                error=exc,
            )
            return
        except Exception as exc:
            parse_errors += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="parse_error",
                logs_emitted=diagnostic_logs_emitted,
            )
            _debug_live_packet(
                debug_packets,
                debug_output,
                packet,
                status="parse_error",
                error=exc,
            )
            return

        if packet_processor is not None:
            try:
                processing_result = packet_processor(packet_event, packet)
                if getattr(processing_result, "detection_event", None) is not None:
                    detection_events_processed += 1
                traffic_events_processed += len(
                    getattr(processing_result, "dns_http_events", ())
                )
            except Exception as exc:
                engine_errors += 1
                diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                    packet,
                    exc,
                    category="engine_error",
                    logs_emitted=diagnostic_logs_emitted,
                )
                _debug_live_packet(
                    debug_packets,
                    debug_output,
                    packet,
                    packet_event=packet_event,
                    status="engine_error",
                    error=exc,
                )
            return

        try:
            assert detect is not None
            detection_event = detect(packet_event)
            if detection_event is not None:
                detection_events_processed += 1
        except Exception as exc:
            engine_errors += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="engine_error",
                logs_emitted=diagnostic_logs_emitted,
            )

        try:
            assert monitor is not None
            traffic_events = monitor(packet)
            traffic_events_processed += len(traffic_events)
        except Exception as exc:
            engine_errors += 1
            diagnostic_logs_emitted = _log_live_packet_problem_if_sampled(
                packet,
                exc,
                category="engine_error",
                logs_emitted=diagnostic_logs_emitted,
            )

    sniff_options: dict[str, Any] = {
        "iface": capture_interface,
        "filter": LIVE_CAPTURE_FILTER,
        "prn": handle_packet,
        "store": False,
    }
    if count is not None:
        sniff_options["count"] = count
    if capture_timeout is not None:
        sniff_options["timeout"] = capture_timeout

    try:
        sniff(**sniff_options)
    except Exception as exc:
        _LOGGER.exception("LIVE_CAPTURE | Scapy capture failed: %s", exc)
        raise SnifferError(
            "Live capture failed. Verify interface name and capture permissions."
        ) from exc

    return LiveCaptureResult(
        packets_received=packets_received,
        ignored_packets=ignored_packets,
        unsupported_packets=unsupported_packets,
        parse_errors=parse_errors,
        packet_events_processed=packet_events_processed,
        engine_errors=engine_errors,
        detection_events_processed=detection_events_processed,
        traffic_events_processed=traffic_events_processed,
        errors=unsupported_packets + parse_errors + engine_errors,
    )


def start_live_capture_forever(
    interface: str,
    packet_count: int | None = None,
    timeout: float | None = None,
    *,
    detector_handler: DetectorHandler | None = None,
    traffic_monitor: TrafficMonitor | None = None,
    packet_processor: PacketProcessor | None = None,
    scapy_sniff: ScapySniff | None = None,
    debug_packets: bool = False,
    debug_output: Callable[[str], Any] | None = None,
    health_log_interval_seconds: int = DEFAULT_HEALTH_LOG_INTERVAL_SECONDS,
    retry_seconds: float = DEFAULT_FOREVER_RETRY_SECONDS,
    restart_sleep_seconds: float = DEFAULT_FOREVER_RESTART_SLEEP_SECONDS,
    max_cycles: int | None = None,
    sleep: Callable[[float], Any] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    logger: logging.Logger | None = None,
) -> LiveCaptureForeverResult:
    """Run live capture in supervised cycles suitable for systemd 24/7 use."""
    _validate_interface(interface)
    _validate_packet_count(packet_count)
    _validate_timeout(timeout)
    health_interval = _validate_positive_interval(
        health_log_interval_seconds,
        name="health_log_interval_seconds",
    )
    retry_delay = _validate_non_negative_delay(retry_seconds, name="retry_seconds")
    restart_delay = _validate_non_negative_delay(
        restart_sleep_seconds,
        name="restart_sleep_seconds",
    )
    if max_cycles is not None and max_cycles < 1:
        raise SnifferError("max_cycles must be a positive integer or None")

    capture_timeout = timeout if timeout is not None else float(health_interval)
    if capture_timeout <= 0:
        raise SnifferError("timeout must be greater than zero when --forever is active")

    capture_logger = logger or _LOGGER
    totals = {
        "capture_cycles": 0,
        "packets_received": 0,
        "ignored_packets": 0,
        "unsupported_packets": 0,
        "parse_errors": 0,
        "packet_events_processed": 0,
        "engine_errors": 0,
        "detection_events_processed": 0,
        "traffic_events_processed": 0,
        "errors": 0,
    }
    next_health_log = monotonic() + health_interval

    capture_logger.info(
        "LIVE_CAPTURE_FOREVER | started interface=%s health_interval_seconds=%s",
        interface,
        health_interval,
    )

    while max_cycles is None or totals["capture_cycles"] < max_cycles:
        try:
            result = start_live_capture(
                interface,
                packet_count=packet_count,
                timeout=capture_timeout,
                detector_handler=detector_handler,
                traffic_monitor=traffic_monitor,
                packet_processor=packet_processor,
                scapy_sniff=scapy_sniff,
                debug_packets=debug_packets,
                debug_output=debug_output,
            )
        except SnifferError as exc:
            totals["errors"] += 1
            if not _is_recoverable_live_capture_error(exc):
                capture_logger.error(
                    "LIVE_CAPTURE_FOREVER | critical capture error: %s",
                    exc,
                )
                raise

            capture_logger.warning(
                "LIVE_CAPTURE_FOREVER | recoverable capture error; retrying in %.1fs: %s",
                retry_delay,
                exc,
            )
            _log_forever_health(capture_logger, interface, totals)
            sleep(retry_delay)
            continue

        totals["capture_cycles"] += 1
        totals["packets_received"] += result.packets_received
        totals["ignored_packets"] += result.ignored_packets
        totals["unsupported_packets"] += result.unsupported_packets
        totals["parse_errors"] += result.parse_errors
        totals["packet_events_processed"] += result.packet_events_processed
        totals["engine_errors"] += result.engine_errors
        totals["detection_events_processed"] += result.detection_events_processed
        totals["traffic_events_processed"] += result.traffic_events_processed
        totals["errors"] += result.errors

        now = monotonic()
        if now >= next_health_log:
            _log_forever_health(capture_logger, interface, totals)
            next_health_log = now + health_interval

        if max_cycles is None or totals["capture_cycles"] < max_cycles:
            sleep(restart_delay)

    capture_logger.info(
        "LIVE_CAPTURE_FOREVER | stopped after max_cycles=%s",
        max_cycles,
    )
    return LiveCaptureForeverResult(**totals)


def process_synthetic_packet(packet: Mapping[str, str]) -> PacketEvent:
    """Validate and normalize a synthetic packet mapping."""
    return parse_packet(packet)


def process_ethernet_frame(frame: bytes) -> PacketEvent:
    """Extract packet metadata from a raw Ethernet frame."""
    return _parse_ethernet_frame(frame, timestamp=0.0)


def process_pcap(file_path: str | Path) -> tuple[PacketEvent, ...]:
    """Process a classic PCAP file and return extracted packet metadata."""
    return parse_pcap(file_path)


def _parse_synthetic_packet(packet: Mapping[str, Any]) -> PacketEvent:
    return PacketEvent(
        timestamp=_normalize_timestamp(packet.get("timestamp", 0.0)),
        mac_origen=_normalize_mac(_required_field(packet, "mac_origen")),
        mac_destino=_normalize_mac(_required_field(packet, "mac_destino")),
        ip_origen=_normalize_ip(_required_field(packet, "ip_origen")),
        ip_destino=_normalize_ip(_required_field(packet, "ip_destino")),
        protocolo=_normalize_protocol(_required_field(packet, "protocolo")),
    )


def _parse_ethernet_frame(frame: bytes, timestamp: float | None = None) -> PacketEvent:
    if len(frame) < ETHERNET_HEADER_LENGTH:
        raise SnifferError("Ethernet frame is too short")

    mac_destino = _format_mac(frame[0:6])
    mac_origen = _format_mac(frame[6:12])
    ethertype = int.from_bytes(frame[12:14], byteorder="big")
    payload_offset = ETHERNET_HEADER_LENGTH

    if ethertype in ETHERTYPE_VLAN:
        if len(frame) < ETHERNET_HEADER_LENGTH + VLAN_TAG_LENGTH:
            raise SnifferError("VLAN-tagged Ethernet frame is too short")
        ethertype = int.from_bytes(frame[16:18], byteorder="big")
        payload_offset += VLAN_TAG_LENGTH

    if ethertype == ETHERTYPE_IPV4:
        ip_origen, ip_destino, protocolo = _parse_ipv4(frame[payload_offset:])
    elif ethertype == ETHERTYPE_IPV6:
        ip_origen, ip_destino, protocolo = _parse_ipv6(frame[payload_offset:])
    else:
        raise UnsupportedPacketError(
            f"Unsupported Ethernet ethertype: 0x{ethertype:04x}"
        )

    return PacketEvent(
        timestamp=_normalize_timestamp(0.0 if timestamp is None else timestamp),
        mac_origen=mac_origen,
        mac_destino=mac_destino,
        ip_origen=ip_origen,
        ip_destino=ip_destino,
        protocolo=protocolo,
        link_layer_type=LINK_LAYER_ETHERNET,
    )


def _parse_scapy_packet(packet: Any) -> PacketEvent:
    try:
        layers = _load_scapy_layers()
    except ImportError as exc:
        raise SnifferError(
            "Unsupported packet type. Install Scapy or provide bytes/mapping input."
        ) from exc

    ether_layer = _get_scapy_layer(packet, layers["Ether"])
    arp_layer = (
        _get_scapy_layer(packet, layers["ARP"]) if "ARP" in layers else None
    )
    ip_layer = _get_scapy_layer(packet, layers["IP"])
    ipv6_layer = _get_scapy_layer(packet, layers["IPv6"])
    cooked_layer = _get_scapy_layer(packet, layers.get("CookedLinux"))
    cooked_v2_layer = _get_scapy_layer(packet, layers.get("CookedLinuxV2"))
    cooked_source = cooked_layer if cooked_layer is not None else cooked_v2_layer
    link_layer_type = _scapy_link_layer_type(
        ether_layer=ether_layer,
        cooked_layer=cooked_layer,
        cooked_v2_layer=cooked_v2_layer,
        ip_layer=ip_layer,
        ipv6_layer=ipv6_layer,
    )

    if arp_layer is None and ip_layer is None and ipv6_layer is None:
        raise IgnoredPacketError("Scapy packet does not contain ARP, IPv4, or IPv6")

    if arp_layer is not None:
        ip_origen = _normalize_ip(arp_layer.psrc)
        ip_destino = _normalize_ip(arp_layer.pdst)
        protocolo = "ARP"
        mac_origen = _scapy_source_mac(ether_layer, cooked_source, arp_layer)
        mac_destino = _scapy_destination_mac(ether_layer, arp_layer)
    elif ip_layer is not None:
        ip_origen = _normalize_ip(ip_layer.src)
        ip_destino = _normalize_ip(ip_layer.dst)
        protocolo = _protocol_name(int(ip_layer.proto))
        mac_origen = _scapy_source_mac(ether_layer, cooked_source, None)
        mac_destino = _scapy_destination_mac(ether_layer, None)
    elif ipv6_layer is not None:
        ip_origen = _normalize_ip(ipv6_layer.src)
        ip_destino = _normalize_ip(ipv6_layer.dst)
        protocolo = _protocol_name(int(ipv6_layer.nh))
        mac_origen = _scapy_source_mac(ether_layer, cooked_source, None)
        mac_destino = _scapy_destination_mac(ether_layer, None)
    else:
        raise IgnoredPacketError("Scapy packet does not contain ARP, IPv4, or IPv6")

    return PacketEvent(
        timestamp=_normalize_timestamp(getattr(packet, "time", 0.0)),
        mac_origen=mac_origen,
        mac_destino=mac_destino,
        ip_origen=ip_origen,
        ip_destino=ip_destino,
        protocolo=protocolo,
        link_layer_type=link_layer_type,
    )


def _parse_pcap_global_header(data: bytes) -> tuple[str, int, int]:
    if len(data) < 24:
        raise SnifferError("PCAP file is too short")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        byte_order = "<"
        timestamp_resolution = 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        byte_order = "<"
        timestamp_resolution = 1_000_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        byte_order = ">"
        timestamp_resolution = 1_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        byte_order = ">"
        timestamp_resolution = 1_000_000_000
    else:
        raise SnifferError("Unsupported PCAP magic number")

    _magic, _version_major, _version_minor, _zone, _sigfigs, _snaplen, linktype = (
        struct.unpack(f"{byte_order}IHHIIII", data[:24])
    )

    return byte_order, linktype, timestamp_resolution


def _parse_ipv4(payload: bytes) -> tuple[str, str, str]:
    if len(payload) < 20:
        raise SnifferError("IPv4 packet is too short")

    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4:
        raise SnifferError("Invalid IPv4 version")
    if ihl < 20 or len(payload) < ihl:
        raise SnifferError("Invalid IPv4 header length")

    protocolo = _protocol_name(payload[9])
    ip_origen = str(ipaddress.IPv4Address(payload[12:16]))
    ip_destino = str(ipaddress.IPv4Address(payload[16:20]))

    return ip_origen, ip_destino, protocolo


def _parse_ipv6(payload: bytes) -> tuple[str, str, str]:
    if len(payload) < 40:
        raise SnifferError("IPv6 packet is too short")

    version = payload[0] >> 4
    if version != 6:
        raise SnifferError("Invalid IPv6 version")

    protocolo = _protocol_name(payload[6])
    ip_origen = str(ipaddress.IPv6Address(payload[8:24]))
    ip_destino = str(ipaddress.IPv6Address(payload[24:40]))

    return ip_origen, ip_destino, protocolo


def _protocol_name(protocol_number: int) -> str:
    return PROTOCOL_NAMES.get(protocol_number, f"IP-{protocol_number}")


def _scapy_link_layer_type(
    *,
    ether_layer: Any | None,
    cooked_layer: Any | None,
    cooked_v2_layer: Any | None,
    ip_layer: Any | None,
    ipv6_layer: Any | None,
) -> str:
    if ether_layer is not None:
        return LINK_LAYER_ETHERNET
    if cooked_layer is not None or cooked_v2_layer is not None:
        return LINK_LAYER_COOKED_LINUX
    if ip_layer is not None or ipv6_layer is not None:
        return LINK_LAYER_RAW_IP

    return LINK_LAYER_UNKNOWN


def _scapy_source_mac(
    ether_layer: Any | None,
    cooked_layer: Any | None,
    arp_layer: Any | None,
) -> str | None:
    if ether_layer is not None:
        return _normalize_optional_mac(getattr(ether_layer, "src", None))
    if cooked_layer is not None:
        return _normalize_optional_mac(getattr(cooked_layer, "src", None))
    if arp_layer is not None:
        return _normalize_optional_mac(getattr(arp_layer, "hwsrc", None))

    return None


def _scapy_destination_mac(
    ether_layer: Any | None,
    arp_layer: Any | None,
) -> str | None:
    if ether_layer is not None:
        return _normalize_optional_mac(getattr(ether_layer, "dst", None))
    if arp_layer is not None:
        return _normalize_optional_mac(getattr(arp_layer, "hwdst", None))

    return None


def _required_field(packet: Mapping[str, Any], field_name: str) -> str:
    value = packet.get(field_name)
    if value is None or not str(value).strip():
        raise SnifferError(f"Synthetic packet is missing field: {field_name}")

    return str(value).strip()


def _normalize_timestamp(value: Any) -> float:
    try:
        timestamp = float(value)
    except (TypeError, ValueError) as exc:
        raise SnifferError(f"Invalid timestamp: {value}") from exc

    if timestamp < 0:
        raise SnifferError(f"Invalid timestamp: {value}")

    return timestamp


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise SnifferError(f"Invalid IP address: {value}") from exc


def _normalize_mac(value: str) -> str:
    cleaned = value.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) != 6:
        raise SnifferError(f"Invalid MAC address: {value}")

    for part in parts:
        if len(part) != 2:
            raise SnifferError(f"Invalid MAC address: {value}")
        try:
            int(part, 16)
        except ValueError as exc:
            raise SnifferError(f"Invalid MAC address: {value}") from exc

    return ":".join(parts)


def _normalize_optional_mac(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        if len(value) < 6:
            return None
        return _format_mac(value[:6])

    cleaned = str(value).strip()
    if not cleaned:
        return None

    try:
        return _normalize_mac(cleaned)
    except SnifferError:
        return None


def _normalize_protocol(value: str) -> str:
    protocol = value.strip().upper()
    if not protocol:
        raise SnifferError("Invalid protocol")

    return protocol


def _format_mac(raw_mac: bytes) -> str:
    if len(raw_mac) != 6:
        raise SnifferError("Invalid raw MAC length")

    return ":".join(f"{byte:02x}" for byte in raw_mac)


def _load_scapy_layers() -> dict[str, Any]:
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers import l2
    from scapy.layers.l2 import ARP, Ether

    layers: dict[str, Any] = {"Ether": Ether, "ARP": ARP, "IP": IP, "IPv6": IPv6}
    cooked_linux = getattr(l2, "CookedLinux", None)
    cooked_linux_v2 = getattr(l2, "CookedLinuxV2", None)
    if cooked_linux is not None:
        layers["CookedLinux"] = cooked_linux
    if cooked_linux_v2 is not None:
        layers["CookedLinuxV2"] = cooked_linux_v2

    return layers


def _get_scapy_layer(packet: Any, layer: Any) -> Any:
    if layer is None:
        return None

    try:
        if layer in packet:
            return packet[layer]
    except (KeyError, TypeError):
        return None

    return None


def _log_live_packet_problem_if_sampled(
    packet: Any,
    exc: Exception,
    *,
    category: str,
    logs_emitted: int,
) -> int:
    if logs_emitted >= MAX_DIAGNOSTIC_PACKET_LOGS:
        return logs_emitted

    _LOGGER.warning(
        "LIVE_CAPTURE | packet_%s | exception_type=%s message=%s summary=%s layers=%s",
        category,
        type(exc).__name__,
        str(exc),
        _packet_summary(packet),
        _packet_layers_summary(packet),
    )
    return logs_emitted + 1


def _log_mac_unavailable_if_sampled(
    packet: Any,
    packet_event: PacketEvent,
    logs_emitted: int,
) -> int:
    if logs_emitted >= MAX_DIAGNOSTIC_PACKET_LOGS:
        return logs_emitted

    _LOGGER.info(
        "LIVE_CAPTURE | mac_unavailable | link_layer=%s src_mac=%s dst_mac=%s "
        "summary=%s layers=%s",
        packet_event.link_layer_type,
        packet_event.mac_origen or "unknown",
        packet_event.mac_destino or "unknown",
        _packet_summary(packet),
        _packet_layers_summary(packet),
    )
    return logs_emitted + 1


def _debug_live_packet(
    enabled: bool,
    output: Callable[[str], Any] | None,
    packet: Any,
    *,
    status: str,
    packet_event: PacketEvent | None = None,
    error: Exception | None = None,
) -> None:
    if not enabled:
        return

    writer = output or _LOGGER.info
    generated_event = packet_event is not None
    ignored = status == "ignored"
    link_layer = (
        packet_event.link_layer_type
        if packet_event is not None
        else _packet_layers_summary(packet)
    )
    parts = [
        "DEBUG_PACKET",
        f"status={status}",
        f"summary={_packet_summary(packet)}",
        f"layers={_packet_layers_summary(packet)}",
        f"link_layer={link_layer}",
        f"packet_event={'yes' if generated_event else 'no'}",
        f"ignored={'yes' if ignored else 'no'}",
    ]
    if error is not None:
        parts.append(f"exception_type={type(error).__name__}")
        parts.append(f"cause={str(error)}")
    writer(" | ".join(parts))


def _packet_summary(packet: Any) -> str:
    try:
        summary = packet.summary()
    except Exception:
        summary = packet.__class__.__name__

    return _truncate_diagnostic_text(str(summary))


def _packet_layers_summary(packet: Any) -> str:
    try:
        layers = packet.layers()
    except Exception:
        return packet.__class__.__name__

    layer_names: list[str] = []
    for layer in layers:
        layer_names.append(getattr(layer, "__name__", str(layer)))

    if not layer_names:
        return packet.__class__.__name__

    return ">".join(layer_names)


def _truncate_diagnostic_text(value: str) -> str:
    cleaned = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if len(cleaned) <= DEBUG_PACKET_SUMMARY_LIMIT:
        return cleaned

    return f"{cleaned[:DEBUG_PACKET_SUMMARY_LIMIT]}..."


def _validate_interface(interface: str) -> str:
    if not interface or not interface.strip():
        raise SnifferError("A network interface name is required for live capture")

    return interface.strip()


def _validate_packet_count(packet_count: int | None) -> int | None:
    if packet_count is None:
        return None

    if not isinstance(packet_count, int) or packet_count < 1:
        raise SnifferError("packet_count must be a positive integer or None")

    return packet_count


def _validate_timeout(timeout: float | None) -> float | None:
    if timeout is None:
        return None

    try:
        parsed_timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise SnifferError("timeout must be a non-negative number or None") from exc

    if parsed_timeout < 0:
        raise SnifferError("timeout must be a non-negative number or None")

    return parsed_timeout


def _validate_positive_interval(value: int | float, *, name: str) -> int:
    try:
        parsed_value = int(value)
    except (TypeError, ValueError) as exc:
        raise SnifferError(f"{name} must be a positive integer") from exc

    if parsed_value < 1:
        raise SnifferError(f"{name} must be a positive integer")

    return parsed_value


def _validate_non_negative_delay(value: int | float, *, name: str) -> float:
    try:
        parsed_value = float(value)
    except (TypeError, ValueError) as exc:
        raise SnifferError(f"{name} must be a non-negative number") from exc

    if parsed_value < 0:
        raise SnifferError(f"{name} must be a non-negative number")

    return parsed_value


def _is_recoverable_live_capture_error(exc: SnifferError) -> bool:
    cause = exc.__cause__
    diagnostic = str(cause if cause is not None else exc).lower()
    critical_markers = (
        "interface name is required",
        "packet_count",
        "timeout",
        "scapy is required",
        "permission",
        "operation not permitted",
        "no such device",
        "not found",
        "does not exist",
    )
    return not any(marker in diagnostic for marker in critical_markers)


def _log_forever_health(
    logger: logging.Logger,
    interface: str,
    totals: Mapping[str, int],
) -> None:
    logger.info(
        "LIVE_CAPTURE_HEALTH | interface=%s cycles=%s received=%s ignored=%s "
        "unsupported=%s parse_errors=%s packet_events=%s engine_errors=%s "
        "detections=%s dns_http_events=%s errors=%s",
        interface,
        totals["capture_cycles"],
        totals["packets_received"],
        totals["ignored_packets"],
        totals["unsupported_packets"],
        totals["parse_errors"],
        totals["packet_events_processed"],
        totals["engine_errors"],
        totals["detection_events_processed"],
        totals["traffic_events_processed"],
        totals["errors"],
    )


def _load_scapy_sniff() -> ScapySniff:
    try:
        from scapy.sendrecv import sniff
    except ImportError as exc:
        raise SnifferError("Scapy is required for live capture") from exc

    return sniff


def _load_detector_handler() -> DetectorHandler:
    from src.detector import detect_packet

    return detect_packet


def _load_traffic_monitor() -> TrafficMonitor:
    from src.dns_http_monitor import register_traffic

    return register_traffic
