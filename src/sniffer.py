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
_LOGGER = get_logger("sniffer")
_LOGGER.addHandler(logging.NullHandler())


class SnifferError(ValueError):
    """Raised when offline packet data cannot be processed."""


@dataclass(frozen=True)
class PacketEvent:
    """Normalized packet metadata extracted by the offline sniffer."""

    timestamp: float
    mac_origen: str
    mac_destino: str
    ip_origen: str
    ip_destino: str
    protocolo: str


PacketInfo = PacketEvent
DetectorHandler = Callable[[PacketEvent], Any]
TrafficMonitor = Callable[[Any], tuple[Any, ...]]
PacketProcessor = Callable[[PacketEvent, Any], Any]
ScapySniff = Callable[..., Any]


@dataclass(frozen=True)
class LiveCaptureResult:
    """Summary of a completed live capture session."""

    packets_received: int
    packet_events_processed: int
    detection_events_processed: int
    traffic_events_processed: int
    errors: int


@dataclass(frozen=True)
class LiveCaptureForeverResult:
    """Summary accumulated by a supervised live capture session."""

    capture_cycles: int
    packets_received: int
    packet_events_processed: int
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
    packet_events_processed = 0
    detection_events_processed = 0
    traffic_events_processed = 0
    errors = 0

    def handle_packet(packet: Any) -> None:
        nonlocal packets_received
        nonlocal packet_events_processed
        nonlocal detection_events_processed
        nonlocal traffic_events_processed
        nonlocal errors

        packets_received += 1

        try:
            packet_event = parse_packet(packet)
            packet_events_processed += 1
        except SnifferError as exc:
            errors += 1
            _LOGGER.warning("LIVE_CAPTURE | packet parse failed: %s", exc)
            return
        except Exception as exc:
            errors += 1
            _LOGGER.exception("LIVE_CAPTURE | unexpected packet parse error: %s", exc)
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
                errors += 1
                _LOGGER.exception("LIVE_CAPTURE | packet processor failed: %s", exc)
            return

        try:
            assert detect is not None
            detection_event = detect(packet_event)
            if detection_event is not None:
                detection_events_processed += 1
        except Exception as exc:
            errors += 1
            _LOGGER.exception("LIVE_CAPTURE | detector failed: %s", exc)

        try:
            assert monitor is not None
            traffic_events = monitor(packet)
            traffic_events_processed += len(traffic_events)
        except Exception as exc:
            errors += 1
            _LOGGER.exception("LIVE_CAPTURE | DNS/HTTP monitor failed: %s", exc)

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
        packet_events_processed=packet_events_processed,
        detection_events_processed=detection_events_processed,
        traffic_events_processed=traffic_events_processed,
        errors=errors,
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
        "packet_events_processed": 0,
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
        totals["packet_events_processed"] += result.packet_events_processed
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
        raise SnifferError(f"Unsupported Ethernet ethertype: 0x{ethertype:04x}")

    return PacketEvent(
        timestamp=_normalize_timestamp(0.0 if timestamp is None else timestamp),
        mac_origen=mac_origen,
        mac_destino=mac_destino,
        ip_origen=ip_origen,
        ip_destino=ip_destino,
        protocolo=protocolo,
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

    if ether_layer is None and arp_layer is None:
        raise SnifferError("Scapy packet does not contain an Ethernet layer")

    if arp_layer is not None:
        ip_origen = _normalize_ip(arp_layer.psrc)
        ip_destino = _normalize_ip(arp_layer.pdst)
        protocolo = "ARP"
        mac_origen = _normalize_mac(
            getattr(ether_layer, "src", getattr(arp_layer, "hwsrc", ""))
        )
        mac_destino = _normalize_mac(
            getattr(ether_layer, "dst", getattr(arp_layer, "hwdst", ""))
        )
    elif ip_layer is not None:
        ip_origen = _normalize_ip(ip_layer.src)
        ip_destino = _normalize_ip(ip_layer.dst)
        protocolo = _protocol_name(int(ip_layer.proto))
        mac_origen = _normalize_mac(ether_layer.src)
        mac_destino = _normalize_mac(ether_layer.dst)
    elif ipv6_layer is not None:
        ip_origen = _normalize_ip(ipv6_layer.src)
        ip_destino = _normalize_ip(ipv6_layer.dst)
        protocolo = _protocol_name(int(ipv6_layer.nh))
        mac_origen = _normalize_mac(ether_layer.src)
        mac_destino = _normalize_mac(ether_layer.dst)
    else:
        raise SnifferError("Scapy packet does not contain IPv4 or IPv6")

    return PacketEvent(
        timestamp=_normalize_timestamp(getattr(packet, "time", 0.0)),
        mac_origen=mac_origen,
        mac_destino=mac_destino,
        ip_origen=ip_origen,
        ip_destino=ip_destino,
        protocolo=protocolo,
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
    from scapy.layers.l2 import ARP, Ether

    return {"Ether": Ether, "ARP": ARP, "IP": IP, "IPv6": IPv6}


def _get_scapy_layer(packet: Any, layer: Any) -> Any:
    try:
        if layer in packet:
            return packet[layer]
    except (KeyError, TypeError):
        return None

    return None


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
        "LIVE_CAPTURE_HEALTH | interface=%s cycles=%s received=%s packet_events=%s "
        "detections=%s dns_http_events=%s errors=%s",
        interface,
        totals["capture_cycles"],
        totals["packets_received"],
        totals["packet_events_processed"],
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
