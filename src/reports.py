
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_REPORT_PREFIX = "gleipnir_report"
REPORT_FORMAT_BOTH = "both"
REPORT_FORMAT_JSON = "json"
REPORT_FORMAT_CSV = "csv"
REPORT_FORMATS = (REPORT_FORMAT_BOTH, REPORT_FORMAT_JSON, REPORT_FORMAT_CSV)
CSV_FIELDS = (
    "category",
    "event_type",
    "timestamp",
    "ip_origen",
    "ip_destino",
    "mac_origen",
    "mac_destino",
    "protocolo",
    "dominio_consultado",
    "tipo_consulta",
    "host",
    "metodo",
    "ruta",
    "motivo",
    "severidad",
    "service",
    "status",
    "cached",
    "rate_limited",
    "alert_sent",
    "message",
    "error",
    "data_json",
)
SECRET_WORDS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "token",
    "secret",
    "smtp_password",
)
REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class ReportData:

    authorized_devices: Sequence[Any] = field(default_factory=tuple)
    unauthorized_devices: Sequence[Any] = field(default_factory=tuple)
    dns_events: Sequence[Any] = field(default_factory=tuple)
    http_events: Sequence[Any] = field(default_factory=tuple)
    blacklisted_external_ips: Sequence[Any] = field(default_factory=tuple)
    threat_intel_results: Sequence[Any] = field(default_factory=tuple)
    alert_events: Sequence[Any] = field(default_factory=tuple)
    ips_events: Sequence[Any] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReportFilters:

    event_type: str | None = None
    since: float | None = None
    until: float | None = None
    source_ip: str | None = None
    domain: str | None = None
    severity: str | None = None
    since_label: str | None = None
    until_label: str | None = None

    # FUN-091
    def as_query_kwargs(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "since": self.since,
            "until": self.until,
            "source_ip": self.source_ip,
            "domain": self.domain,
            "severity": self.severity,
        }

    # FUN-092
    def as_payload(self) -> dict[str, Any]:
        payload = {
            "type": self.event_type,
            "since": self.since_label if self.since_label is not None else self.since,
            "until": self.until_label if self.until_label is not None else self.until,
            "source_ip": self.source_ip,
            "domain": self.domain,
            "severity": self.severity,
        }
        return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True)
class ReportPaths:

    json_path: Path | None
    csv_path: Path | None


# FUN-093
def generate_reports(
    report_data: ReportData,
    *,
    output_dir: str | Path | None = None,
    config: Any | None = None,
    generated_at: datetime | None = None,
    filename_prefix: str = DEFAULT_REPORT_PREFIX,
    output_format: str = REPORT_FORMAT_BOTH,
    filters: ReportFilters | Mapping[str, Any] | None = None,
) -> ReportPaths:
    selected_format = _normalize_report_format(output_format)
    report_dir = _resolve_report_dir(output_dir, config)
    report_dir.mkdir(parents=True, exist_ok=True)

    created_at = generated_at or datetime.now(timezone.utc)
    timestamp_slug = created_at.strftime("%Y%m%dT%H%M%SZ")
    json_path = (
        report_dir / f"{filename_prefix}_{timestamp_slug}.json"
        if selected_format in (REPORT_FORMAT_BOTH, REPORT_FORMAT_JSON)
        else None
    )
    csv_path = (
        report_dir / f"{filename_prefix}_{timestamp_slug}.csv"
        if selected_format in (REPORT_FORMAT_BOTH, REPORT_FORMAT_CSV)
        else None
    )

    payload = build_report_payload(
        report_data,
        generated_at=created_at,
        filters=filters,
    )
    if json_path is not None:
        json_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    if csv_path is not None:
        _write_csv(csv_path, payload)

    return ReportPaths(json_path=json_path, csv_path=csv_path)


# FUN-094
def build_report_payload(
    report_data: ReportData,
    *,
    generated_at: datetime | None = None,
    filters: ReportFilters | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    created_at = generated_at or datetime.now(timezone.utc)
    payload = {
        "generated_at": created_at.isoformat(),
        "authorized_devices": [_redact(_to_plain_dict(item)) for item in report_data.authorized_devices],
        "unauthorized_devices": [_redact(_to_plain_dict(item)) for item in report_data.unauthorized_devices],
        "dns_events": [_redact(_to_plain_dict(item)) for item in report_data.dns_events],
        "http_events": [_redact(_to_plain_dict(item)) for item in report_data.http_events],
        "blacklisted_external_ips": [
            _redact(_to_plain_dict(item)) for item in report_data.blacklisted_external_ips
        ],
        "threat_intel_results": [
            _redact(_to_plain_dict(item)) for item in report_data.threat_intel_results
        ],
        "alert_events": [_redact(_to_plain_dict(item)) for item in report_data.alert_events],
        "ips_events": [_redact(_to_plain_dict(item)) for item in report_data.ips_events],
    }
    payload["summary"] = {
        "authorized_devices": len(payload["authorized_devices"]),
        "unauthorized_devices": len(payload["unauthorized_devices"]),
        "dns_events": len(payload["dns_events"]),
        "http_events": len(payload["http_events"]),
        "blacklisted_external_ips": len(payload["blacklisted_external_ips"]),
        "threat_intel_results": len(payload["threat_intel_results"]),
        "alert_events": len(payload["alert_events"]),
        "ips_events": len(payload["ips_events"]),
    }
    payload["filters"] = _filters_to_plain_dict(filters)
    return payload


# FUN-095
def summarize_report_data(report_data: ReportData) -> dict[str, int]:
    return {
        "authorized_devices": len(report_data.authorized_devices),
        "unauthorized_devices": len(report_data.unauthorized_devices),
        "dns_events": len(report_data.dns_events),
        "http_events": len(report_data.http_events),
        "blacklisted_external_ips": len(report_data.blacklisted_external_ips),
        "threat_intel_results": len(report_data.threat_intel_results),
        "alert_events": len(report_data.alert_events),
        "ips_events": len(report_data.ips_events),
    }


def _write_csv(csv_path: Path, payload: Mapping[str, Any]) -> None:
    rows = list(_payload_to_rows(payload))
    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _payload_to_rows(payload: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    categories = (
        ("authorized_device", payload["authorized_devices"]),
        ("unauthorized_device", payload["unauthorized_devices"]),
        ("dns_event", payload["dns_events"]),
        ("http_event", payload["http_events"]),
        ("blacklisted_external_ip", payload["blacklisted_external_ips"]),
        ("threat_intel", payload["threat_intel_results"]),
        ("alert_event", payload["alert_events"]),
        ("ips_event", payload.get("ips_events", [])),
    )

    for category, items in categories:
        for item in items:
            yield _event_to_csv_row(category, item)


def _event_to_csv_row(category: str, item: Mapping[str, Any]) -> dict[str, Any]:
    row = {field: "" for field in CSV_FIELDS}
    row["category"] = category
    row["event_type"] = item.get("event_type", "")
    row["timestamp"] = item.get("timestamp", "")
    row["ip_origen"] = item.get("ip_origen", "")
    row["ip_destino"] = item.get("ip_destino", "")
    row["mac_origen"] = item.get("mac_origen", "")
    row["mac_destino"] = item.get("mac_destino", "")
    row["protocolo"] = item.get("protocolo", "")
    row["dominio_consultado"] = item.get("dominio_consultado", "")
    row["tipo_consulta"] = item.get("tipo_consulta", "")
    row["host"] = item.get("host", "")
    row["metodo"] = item.get("metodo", "")
    row["ruta"] = item.get("ruta", "")
    row["motivo"] = item.get("motivo", "")
    row["severidad"] = item.get("severidad", "")
    row["service"] = item.get("service", "")
    row["status"] = item.get("status", "")
    row["cached"] = item.get("cached", "")
    row["rate_limited"] = item.get("rate_limited", "")
    row["alert_sent"] = item.get("alert_sent", "")
    row["message"] = item.get("message", "")
    row["error"] = item.get("error", "")

    data = item.get("data")
    if data not in (None, "", {}):
        row["data_json"] = json.dumps(data, sort_keys=True)

    packet = item.get("packet")
    if isinstance(packet, Mapping):
        row["timestamp"] = row["timestamp"] or packet.get("timestamp", "")
        row["ip_origen"] = row["ip_origen"] or packet.get("ip_origen", "")
        row["ip_destino"] = row["ip_destino"] or packet.get("ip_destino", "")
        row["mac_origen"] = row["mac_origen"] or packet.get("mac_origen", "")
        row["mac_destino"] = row["mac_destino"] or packet.get("mac_destino", "")
        row["protocolo"] = row["protocolo"] or packet.get("protocolo", "")

    return row


def _to_plain_dict(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)

    if isinstance(value, Mapping):
        return dict(value)

    if hasattr(value, "__dict__"):
        return dict(vars(value))

    return {"value": value}


def _redact(value: Any, key_name: str = "") -> Any:
    if _is_secret_key(key_name):
        return REDACTED

    if isinstance(value, Mapping):
        return {str(key): _redact(item, str(key)) for key, item in value.items()}

    if isinstance(value, list):
        return [_redact(item, key_name) for item in value]

    if isinstance(value, tuple):
        return [_redact(item, key_name) for item in value]

    return value


def _is_secret_key(key_name: str) -> bool:
    normalized = key_name.lower().replace("-", "_")
    return any(secret_word in normalized for secret_word in SECRET_WORDS)


def _resolve_report_dir(output_dir: str | Path | None, config: Any | None) -> Path:
    if output_dir is not None:
        return Path(output_dir)

    if config is not None:
        report_dir = getattr(config, "report_dir", None)
        if report_dir is not None:
            return Path(report_dir)

        log_dir = getattr(config, "log_dir", None)
        if log_dir is not None:
            return Path(log_dir)

    from src.config import load_config

    runtime_config = load_config()
    return Path(getattr(runtime_config, "report_dir", runtime_config.log_dir))


def _normalize_report_format(output_format: str) -> str:
    normalized = output_format.strip().lower()
    if normalized not in REPORT_FORMATS:
        allowed = ", ".join(REPORT_FORMATS)
        raise ValueError(f"Unsupported report format: {output_format}. Use: {allowed}")

    return normalized


def _filters_to_plain_dict(
    filters: ReportFilters | Mapping[str, Any] | None,
) -> dict[str, Any]:
    if filters is None:
        return {}

    if isinstance(filters, ReportFilters):
        return filters.as_payload()

    return {str(key): value for key, value in filters.items() if value is not None}
