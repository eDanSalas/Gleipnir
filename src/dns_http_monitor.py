
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, TypeAlias

from src.logger import get_logger
from src.sniffer import PacketEvent, parse_packet


DNS_TRAFFIC = "DNS_TRAFFIC"
HTTP_TRAFFIC = "HTTP_TRAFFIC"

_LOGGER = get_logger("dns_http_monitor")
_LOGGER.addHandler(logging.NullHandler())


@dataclass(frozen=True)
class DNSTrafficEvent:

    timestamp: float
    ip_origen: str
    ip_destino: str
    dominio_consultado: str
    tipo_consulta: str | None = None


@dataclass(frozen=True)
class HTTPTrafficEvent:

    timestamp: float
    ip_origen: str
    ip_destino: str
    host: str
    metodo: str | None = None
    ruta: str | None = None


TrafficEvent: TypeAlias = DNSTrafficEvent | HTTPTrafficEvent


# FUN-053
def register_traffic(packet: Any) -> tuple[TrafficEvent, ...]:
    packet_event, metadata = _coerce_packet(packet)
    events: list[TrafficEvent] = []

    dns_event = _build_dns_event(packet_event, metadata)
    if dns_event is not None:
        _LOGGER.info(
            "%s | timestamp=%s src=%s dst=%s domain=%s qtype=%s",
            DNS_TRAFFIC,
            dns_event.timestamp,
            dns_event.ip_origen,
            dns_event.ip_destino,
            dns_event.dominio_consultado,
            dns_event.tipo_consulta or "UNKNOWN",
        )
        events.append(dns_event)

    http_event = _build_http_event(packet_event, metadata)
    if http_event is not None:
        _LOGGER.info(
            "%s | timestamp=%s src=%s dst=%s host=%s method=%s path=%s",
            HTTP_TRAFFIC,
            http_event.timestamp,
            http_event.ip_origen,
            http_event.ip_destino,
            http_event.host,
            http_event.metodo or "UNKNOWN",
            http_event.ruta or "UNKNOWN",
        )
        events.append(http_event)

    return tuple(events)


# FUN-054
def detect_dns(packet: Any) -> DNSTrafficEvent | None:
    packet_event, metadata = _coerce_packet(packet)
    return _build_dns_event(packet_event, metadata)


# FUN-055
def detect_http(packet: Any) -> HTTPTrafficEvent | None:
    packet_event, metadata = _coerce_packet(packet)
    return _build_http_event(packet_event, metadata)


def _coerce_packet(
    packet: Any,
) -> tuple[PacketEvent, Mapping[str, Any]]:
    if isinstance(packet, PacketEvent):
        return packet, {}

    packet_event = parse_packet(packet)
    if isinstance(packet, Mapping):
        return packet_event, packet

    return packet_event, _extract_scapy_metadata(packet)


def _build_dns_event(
    packet_event: PacketEvent,
    metadata: Mapping[str, Any],
) -> DNSTrafficEvent | None:
    domain = _first_value(
        metadata,
        "dns_domain",
        "dns_query",
        "dns_qname",
        "dominio_consultado",
        "domain",
        nested=("dns", "domain", "query", "qname"),
    )
    if domain is None:
        return None

    query_type = _first_value(
        metadata,
        "dns_query_type",
        "dns_qtype",
        "tipo_consulta",
        "query_type",
        "qtype",
        nested=("dns", "query_type", "qtype", "type"),
    )

    return DNSTrafficEvent(
        timestamp=packet_event.timestamp,
        ip_origen=packet_event.ip_origen,
        ip_destino=packet_event.ip_destino,
        dominio_consultado=_normalize_domain(domain),
        tipo_consulta=_normalize_optional_text(query_type, uppercase=True),
    )


def _build_http_event(
    packet_event: PacketEvent,
    metadata: Mapping[str, Any],
) -> HTTPTrafficEvent | None:
    host = _first_value(
        metadata,
        "http_host",
        "host",
        nested=("http", "host"),
    )
    if host is None:
        return None

    method = _first_value(
        metadata,
        "http_method",
        "method",
        "metodo",
        nested=("http", "method", "metodo"),
    )
    path = _first_value(
        metadata,
        "http_path",
        "path",
        "ruta",
        nested=("http", "path", "ruta"),
    )

    return HTTPTrafficEvent(
        timestamp=packet_event.timestamp,
        ip_origen=packet_event.ip_origen,
        ip_destino=packet_event.ip_destino,
        host=_normalize_host(host),
        metodo=_normalize_optional_text(method, uppercase=True),
        ruta=_normalize_optional_path(path),
    )


def _first_value(
    metadata: Mapping[str, Any],
    *keys: str,
    nested: tuple[str, ...] = (),
) -> str | None:
    for key in keys:
        value = metadata.get(key)
        normalized = _normalize_optional_text(value)
        if normalized is not None:
            return normalized

    for container_key in nested[:1]:
        container = metadata.get(container_key)
        if not isinstance(container, Mapping):
            continue

        for nested_key in nested[1:]:
            value = container.get(nested_key)
            normalized = _normalize_optional_text(value)
            if normalized is not None:
                return normalized

    return None


def _normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    if not domain:
        raise ValueError("DNS domain cannot be empty")

    return domain


def _normalize_host(value: str) -> str:
    host = value.strip().lower()
    if not host:
        raise ValueError("HTTP host cannot be empty")

    return host


def _normalize_optional_text(value: Any, *, uppercase: bool = False) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    return text.upper() if uppercase else text


def _normalize_optional_path(value: Any) -> str | None:
    path = _normalize_optional_text(value)
    if path is None:
        return None

    return path if path.startswith("/") else f"/{path}"


def _extract_scapy_metadata(packet: Any) -> dict[str, str]:
    try:
        layers = _load_scapy_app_layers()
    except ImportError:
        return {}

    metadata: dict[str, str] = {}
    dns_layer = _get_scapy_layer(packet, layers["DNS"])
    if dns_layer is not None:
        metadata.update(_metadata_from_dns_layer(dns_layer))

    http_layer = _get_scapy_layer(packet, layers["HTTPRequest"])
    if http_layer is not None:
        metadata.update(_metadata_from_http_request_layer(http_layer))
    else:
        raw_layer = _get_scapy_layer(packet, layers["Raw"])
        if raw_layer is not None:
            metadata.update(_metadata_from_raw_http_payload(getattr(raw_layer, "load", b"")))

    return metadata


def _metadata_from_dns_layer(dns_layer: Any) -> dict[str, str]:
    query = getattr(dns_layer, "qd", None)
    if query is None:
        return {}

    qname = _decode_packet_text(getattr(query, "qname", None))
    if qname is None:
        return {}

    metadata = {"dns_query": qname}
    qtype = getattr(query, "qtype", None)
    if qtype is not None:
        metadata["dns_query_type"] = _dns_query_type_name(qtype)

    return metadata


def _metadata_from_http_request_layer(http_layer: Any) -> dict[str, str]:
    metadata: dict[str, str] = {}
    host = _decode_packet_text(getattr(http_layer, "Host", None))
    method = _decode_packet_text(getattr(http_layer, "Method", None))
    path = _decode_packet_text(getattr(http_layer, "Path", None))

    if host:
        metadata["http_host"] = host
    if method:
        metadata["http_method"] = method
    if path:
        metadata["http_path"] = path

    return metadata


def _metadata_from_raw_http_payload(payload: Any) -> dict[str, str]:
    text = _decode_packet_text(payload)
    if not text:
        return {}

    lines = text.splitlines()
    if not lines:
        return {}

    parts = lines[0].split()
    if len(parts) < 2 or parts[0].upper() not in _http_methods():
        return {}

    metadata = {
        "http_method": parts[0],
        "http_path": parts[1],
    }
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            metadata["http_host"] = line.split(":", maxsplit=1)[1].strip()
            break

    return metadata if "http_host" in metadata else {}


def _decode_packet_text(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").strip()

    return str(value).strip()


def _dns_query_type_name(value: Any) -> str:
    query_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    try:
        return query_types.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _http_methods() -> set[str]:
    return {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _load_scapy_app_layers() -> dict[str, Any]:
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTPRequest
    from scapy.packet import Raw

    return {"DNS": DNS, "HTTPRequest": HTTPRequest, "Raw": Raw}


def _get_scapy_layer(packet: Any, layer: Any) -> Any:
    try:
        if layer in packet:
            return packet[layer]
    except (KeyError, TypeError):
        return None

    return None
