"""SQLite persistence for IDS events."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.reports import ReportData, ReportFilters


DNS_EVENT = "DNS_EVENT"
HTTP_EVENT = "HTTP_EVENT"
THREAT_INTEL_RESULT = "THREAT_INTEL_RESULT"
ALERT_SENT = "ALERT_SENT"
ALERT_SUPPRESSED = "ALERT_SUPPRESSED"

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "BAJA"
SEVERITY_MEDIUM = "MEDIA"
REDACTED = "[REDACTED]"
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

CREATE_EVENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS ids_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    event_type TEXT NOT NULL,
    severity TEXT,
    source_ip TEXT,
    source_mac TEXT,
    destination_ip TEXT,
    destination_mac TEXT,
    protocol TEXT,
    domain TEXT,
    message TEXT,
    raw_json TEXT NOT NULL
)
"""

CREATE_INDEXES_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_ids_events_timestamp ON ids_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_ids_events_event_type ON ids_events(event_type)",
)


class StorageError(RuntimeError):
    """Raised when IDS event persistence fails."""


@dataclass(frozen=True)
class StoredEvent:
    """One event stored in the SQLite database."""

    id: int
    timestamp: float | None
    event_type: str
    severity: str | None
    source_ip: str | None
    source_mac: str | None
    destination_ip: str | None
    destination_mac: str | None
    protocol: str | None
    domain: str | None
    message: str | None
    raw_json: str

    @property
    def raw(self) -> dict[str, Any]:
        """Return the sanitized JSON payload as a dictionary."""
        try:
            parsed = json.loads(self.raw_json)
        except json.JSONDecodeError:
            return {}

        return parsed if isinstance(parsed, dict) else {"value": parsed}


class SQLiteEventStore:
    """Persist normalized IDS events into a local SQLite database."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path).expanduser()
        self._connection: sqlite3.Connection | None = None
        self._initialized = False

    @classmethod
    def from_config(cls, config: Any) -> "SQLiteEventStore":
        """Build the event store from runtime configuration."""
        db_path = getattr(config, "ids_db_path", Path("data/gleipnir_events.db"))
        return cls(db_path)

    def initialize(self) -> None:
        """Create the events table and indexes when they do not exist."""
        connection = self._connect()
        connection.execute(CREATE_EVENTS_TABLE_SQL)
        for statement in CREATE_INDEXES_SQL:
            connection.execute(statement)
        connection.commit()
        self._initialized = True

    def save_event(
        self,
        *,
        event_type: str,
        timestamp: float | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        source_mac: str | None = None,
        destination_ip: str | None = None,
        destination_mac: str | None = None,
        protocol: str | None = None,
        domain: str | None = None,
        message: str | None = None,
        raw: Any | None = None,
    ) -> int:
        """Store one sanitized IDS event and return its database id."""
        self._ensure_initialized()
        raw_json = _safe_json(raw if raw is not None else {})

        cursor = self._connect().execute(
            """
            INSERT INTO ids_events (
                timestamp,
                event_type,
                severity,
                source_ip,
                source_mac,
                destination_ip,
                destination_mac,
                protocol,
                domain,
                message,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                severity,
                source_ip,
                source_mac,
                destination_ip,
                destination_mac,
                protocol,
                domain,
                message,
                raw_json,
            ),
        )
        self._connect().commit()
        return int(cursor.lastrowid)

    def save_packet_processing_result(self, result: Any) -> tuple[int, ...]:
        """Persist all events produced by one IDSEngine packet result."""
        stored_ids: list[int] = []

        detection_event = getattr(result, "detection_event", None)
        if detection_event is not None:
            stored_ids.append(self.save_detection_event(detection_event))
            if getattr(detection_event, "alert_sent", False):
                stored_ids.append(self.save_alert_sent_event(detection_event))
            elif getattr(detection_event, "alert_suppressed", False):
                stored_ids.append(self.save_alert_suppressed_event(detection_event))

        for traffic_event in getattr(result, "dns_http_events", ()) or ():
            stored_ids.append(self.save_traffic_event(traffic_event))

        blacklist_event = getattr(result, "blacklist_event", None)
        if blacklist_event is not None:
            stored_ids.append(self.save_blacklist_event(blacklist_event))
            if getattr(blacklist_event, "alert_sent", False):
                stored_ids.append(self.save_alert_sent_event(blacklist_event))
            elif getattr(blacklist_event, "alert_suppressed", False):
                stored_ids.append(self.save_alert_suppressed_event(blacklist_event))

        threat_intel_results = getattr(result, "threat_intel_results", None)
        if not threat_intel_results and blacklist_event is not None:
            threat_intel_results = getattr(blacklist_event, "threat_intel_results", None)

        for threat_result in _iter_threat_intel_results(threat_intel_results):
            stored_ids.append(self.save_threat_intel_result(threat_result))

        return tuple(stored_ids)

    def save_detection_event(self, event: Any) -> int:
        """Persist an AUTHORIZED_DEVICE or UNAUTHORIZED_DEVICE event."""
        packet = getattr(event, "packet")
        severity = (
            SEVERITY_LOW
            if getattr(event, "event_type", None) == AUTHORIZED_DEVICE
            else SEVERITY_MEDIUM
        )
        return self.save_event(
            event_type=getattr(event, "event_type"),
            timestamp=getattr(packet, "timestamp", None),
            severity=severity,
            source_ip=getattr(packet, "ip_origen", None),
            source_mac=getattr(packet, "mac_origen", None),
            destination_ip=getattr(packet, "ip_destino", None),
            destination_mac=getattr(packet, "mac_destino", None),
            protocol=getattr(packet, "protocolo", None),
            message=getattr(event, "message", None),
            raw=event,
        )

    def save_traffic_event(self, event: Any) -> int:
        """Persist one DNS_EVENT or HTTP_EVENT."""
        if hasattr(event, "dominio_consultado"):
            event_type = DNS_EVENT
            domain = getattr(event, "dominio_consultado", None)
            protocol = "DNS"
            message = f"DNS query observed: {domain}"
        elif hasattr(event, "host"):
            event_type = HTTP_EVENT
            domain = getattr(event, "host", None)
            protocol = "HTTP"
            method = getattr(event, "metodo", None) or "UNKNOWN"
            path = getattr(event, "ruta", None) or "UNKNOWN"
            message = f"HTTP request observed: {method} {domain}{path}"
        else:
            raise StorageError("Unsupported traffic event type")

        return self.save_event(
            event_type=event_type,
            timestamp=getattr(event, "timestamp", None),
            severity=SEVERITY_INFO,
            source_ip=getattr(event, "ip_origen", None),
            destination_ip=getattr(event, "ip_destino", None),
            protocol=protocol,
            domain=domain,
            message=message,
            raw=event,
        )

    def save_blacklist_event(self, event: Any) -> int:
        """Persist a BLACKLISTED_EXTERNAL_IP event."""
        return self.save_event(
            event_type=BLACKLISTED_EXTERNAL_IP,
            timestamp=getattr(event, "timestamp", None),
            severity=getattr(event, "severidad", None),
            source_ip=getattr(event, "ip_origen", None),
            destination_ip=getattr(event, "ip_destino", None),
            protocol=getattr(event, "protocolo", None),
            message=getattr(event, "motivo", None),
            raw=event,
        )

    def save_threat_intel_result(self, result: Any) -> int:
        """Persist one threat intelligence service result."""
        raw = _to_plain_data(result)
        status = _mapping_value(raw, "status")
        service = _mapping_value(raw, "service")
        error = _mapping_value(raw, "error")
        message = f"{service or 'threat_intel'} status={status or 'unknown'}"
        if error:
            message = f"{message} error={error}"

        return self.save_event(
            event_type=THREAT_INTEL_RESULT,
            severity=_severity_for_threat_status(status),
            destination_ip=_mapping_value(raw, "ip"),
            message=message,
            raw=raw,
        )

    def save_alert_sent_event(self, source_event: Any) -> int:
        """Persist an ALERT_SENT event derived from a detector event."""
        fields = _alert_event_fields(source_event)

        return self.save_event(
            event_type=ALERT_SENT,
            timestamp=fields["timestamp"],
            severity=fields["severity"],
            source_ip=fields["source_ip"],
            source_mac=fields["source_mac"],
            destination_ip=fields["destination_ip"],
            destination_mac=fields["destination_mac"],
            protocol=fields["protocol"],
            message=f"Alert sent for {fields['source_event_type']}",
            raw={"source_event": fields["raw"]},
        )

    def save_alert_suppressed_event(self, source_event: Any) -> int:
        """Persist an ALERT_SUPPRESSED event derived from a detector event."""
        fields = _alert_event_fields(source_event)
        reason = _mapping_value(fields["raw"], "alert_suppression_reason")
        message = f"Alert suppressed for {fields['source_event_type']}"
        if reason:
            message = f"{message}: {reason}"

        return self.save_event(
            event_type=ALERT_SUPPRESSED,
            timestamp=fields["timestamp"],
            severity=fields["severity"],
            source_ip=fields["source_ip"],
            source_mac=fields["source_mac"],
            destination_ip=fields["destination_ip"],
            destination_mac=fields["destination_mac"],
            protocol=fields["protocol"],
            message=message,
            raw={"source_event": fields["raw"], "reason": reason},
        )

    def fetch_events(
        self,
        event_type: str | None = None,
        *,
        since: float | None = None,
        until: float | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_mac: str | None = None,
        domain: str | None = None,
        protocol: str | None = None,
        severity: str | None = None,
    ) -> tuple[StoredEvent, ...]:
        """Fetch stored events, ordered by insertion id."""
        self._ensure_initialized()
        where_sql, parameters = _build_where_clause(
            event_type=event_type,
            since=since,
            until=until,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_mac=source_mac,
            domain=domain,
            protocol=protocol,
            severity=severity,
        )
        rows = self._connect().execute(
            f"SELECT * FROM ids_events{where_sql} ORDER BY id ASC",
            parameters,
        )

        return tuple(_stored_event_from_row(row) for row in rows.fetchall())

    def get_event(self, event_id: int) -> StoredEvent | None:
        """Fetch one stored event by id."""
        self._ensure_initialized()
        try:
            row = self._connect().execute(
                "SELECT * FROM ids_events WHERE id = ?",
                (int(event_id),),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("Unable to fetch IDS event") from exc

        return _stored_event_from_row(row) if row is not None else None

    def delete_events_older_than(self, cutoff_timestamp: float) -> int:
        """Delete events with timestamps older than the cutoff and return count."""
        self._ensure_initialized()
        try:
            cursor = self._connect().execute(
                "DELETE FROM ids_events WHERE timestamp IS NOT NULL AND timestamp < ?",
                (float(cutoff_timestamp),),
            )
            self._connect().commit()
        except sqlite3.Error as exc:
            raise StorageError("Unable to delete old IDS events") from exc

        return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def build_report_data(
        self,
        filters: ReportFilters | None = None,
        **filter_kwargs: Any,
    ) -> ReportData:
        """Build report input data from accumulated SQLite events."""
        authorized_devices: list[dict[str, Any]] = []
        unauthorized_devices: list[dict[str, Any]] = []
        dns_events: list[dict[str, Any]] = []
        http_events: list[dict[str, Any]] = []
        blacklisted_external_ips: list[dict[str, Any]] = []
        threat_intel_results: list[dict[str, Any]] = []
        alert_events: list[dict[str, Any]] = []

        query_filters = _merge_report_filters(filters, filter_kwargs)
        for event in self.fetch_events(**query_filters):
            item = _stored_event_to_report_item(event)
            if event.event_type == AUTHORIZED_DEVICE:
                authorized_devices.append(item)
            elif event.event_type == UNAUTHORIZED_DEVICE:
                unauthorized_devices.append(item)
            elif event.event_type == DNS_EVENT:
                dns_events.append(item)
            elif event.event_type == HTTP_EVENT:
                http_events.append(item)
            elif event.event_type == BLACKLISTED_EXTERNAL_IP:
                blacklisted_external_ips.append(item)
            elif event.event_type == THREAT_INTEL_RESULT:
                threat_intel_results.append(item)
            elif event.event_type in (ALERT_SENT, ALERT_SUPPRESSED):
                alert_events.append(item)

        return ReportData(
            authorized_devices=tuple(authorized_devices),
            unauthorized_devices=tuple(unauthorized_devices),
            dns_events=tuple(dns_events),
            http_events=tuple(http_events),
            blacklisted_external_ips=tuple(blacklisted_external_ips),
            threat_intel_results=tuple(threat_intel_results),
            alert_events=tuple(alert_events),
        )

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._connection is None:
            return

        self._connection.close()
        self._connection = None
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        if self._connection is None:
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                self._connection = sqlite3.connect(self.db_path)
                self._connection.row_factory = sqlite3.Row
            except sqlite3.Error as exc:
                raise StorageError("Unable to open IDS SQLite database") from exc

        return self._connection

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()


def _stored_event_from_row(row: sqlite3.Row) -> StoredEvent:
    return StoredEvent(
        id=int(row["id"]),
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        severity=row["severity"],
        source_ip=row["source_ip"],
        source_mac=row["source_mac"],
        destination_ip=row["destination_ip"],
        destination_mac=row["destination_mac"],
        protocol=row["protocol"],
        domain=row["domain"],
        message=row["message"],
        raw_json=row["raw_json"],
    )


def _build_where_clause(
    *,
    event_type: str | None,
    since: float | None,
    until: float | None,
    source_ip: str | None,
    destination_ip: str | None,
    source_mac: str | None,
    domain: str | None,
    protocol: str | None,
    severity: str | None,
) -> tuple[str, tuple[Any, ...]]:
    conditions: list[str] = []
    parameters: list[Any] = []

    if event_type:
        conditions.append("UPPER(event_type) = UPPER(?)")
        parameters.append(event_type)
    if since is not None:
        conditions.append("timestamp >= ?")
        parameters.append(since)
    if until is not None:
        conditions.append("timestamp <= ?")
        parameters.append(until)
    if source_ip:
        conditions.append("source_ip = ?")
        parameters.append(source_ip)
    if destination_ip:
        conditions.append("destination_ip = ?")
        parameters.append(destination_ip)
    if source_mac:
        conditions.append("LOWER(source_mac) = LOWER(?)")
        parameters.append(source_mac)
    if domain:
        conditions.append("LOWER(domain) LIKE ?")
        parameters.append(f"%{domain.lower()}%")
    if protocol:
        conditions.append("UPPER(protocol) = UPPER(?)")
        parameters.append(protocol)
    if severity:
        severity_values = _severity_aliases(severity)
        placeholders = ", ".join("UPPER(?)" for _ in severity_values)
        conditions.append(f"UPPER(severity) IN ({placeholders})")
        parameters.extend(severity_values)

    if not conditions:
        return "", ()

    return f" WHERE {' AND '.join(conditions)}", tuple(parameters)


def _severity_aliases(severity: str) -> tuple[str, ...]:
    normalized = severity.strip().lower()
    aliases = {
        "high": ("high", "alta"),
        "alta": ("high", "alta"),
        "medium": ("medium", "media"),
        "media": ("medium", "media"),
        "low": ("low", "baja"),
        "baja": ("low", "baja"),
        "critical": ("critical", "critica", "crítica"),
        "critica": ("critical", "critica", "crítica"),
        "crítica": ("critical", "critica", "crítica"),
        "info": ("info",),
    }
    return aliases.get(normalized, (severity,))


def _merge_report_filters(
    filters: ReportFilters | None,
    filter_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    query_filters = filters.as_query_kwargs() if filters is not None else {}
    query_filters.update(
        {
            key: value
            for key, value in filter_kwargs.items()
            if key in {
                "event_type",
                "since",
                "until",
                "source_ip",
                "destination_ip",
                "source_mac",
                "domain",
                "protocol",
                "severity",
            }
        }
    )
    return {key: value for key, value in query_filters.items() if value is not None}


def _stored_event_to_report_item(event: StoredEvent) -> dict[str, Any]:
    raw = event.raw
    item: dict[str, Any] = {
        "id": event.id,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "ip_origen": event.source_ip or "",
        "mac_origen": event.source_mac or "",
        "ip_destino": event.destination_ip or "",
        "mac_destino": event.destination_mac or "",
        "protocolo": event.protocol or "",
        "domain": event.domain or "",
        "message": event.message or "",
        "severidad": event.severity or "",
    }

    if event.event_type == DNS_EVENT:
        item["dominio_consultado"] = event.domain or ""
        item["tipo_consulta"] = _mapping_value(raw, "tipo_consulta") or ""
    elif event.event_type == HTTP_EVENT:
        item["host"] = event.domain or ""
        item["metodo"] = _mapping_value(raw, "metodo") or ""
        item["ruta"] = _mapping_value(raw, "ruta") or ""
    elif event.event_type == BLACKLISTED_EXTERNAL_IP:
        item["motivo"] = event.message or _mapping_value(raw, "motivo") or ""
        item["alert_sent"] = _mapping_value(raw, "alert_sent")
    elif event.event_type in (AUTHORIZED_DEVICE, UNAUTHORIZED_DEVICE):
        item["alert_sent"] = _mapping_value(raw, "alert_sent")
    elif event.event_type == THREAT_INTEL_RESULT:
        item.update(raw)
    elif event.event_type in (ALERT_SENT, ALERT_SUPPRESSED):
        item["alert_sent"] = event.event_type == ALERT_SENT
        item["motivo"] = _mapping_value(raw, "reason") or ""

    return item


def _alert_event_fields(source_event: Any) -> dict[str, Any]:
    raw = _to_plain_data(source_event)
    event_type = _mapping_value(raw, "event_type") or "IDS event"
    packet = raw.get("packet") if isinstance(raw.get("packet"), Mapping) else {}

    if event_type == BLACKLISTED_EXTERNAL_IP:
        timestamp = _mapping_value(raw, "timestamp")
        source_ip = _mapping_value(raw, "ip_origen")
        source_mac = None
        destination_ip = _mapping_value(raw, "ip_destino")
        destination_mac = None
        protocol = _mapping_value(raw, "protocolo")
        severity = _mapping_value(raw, "alert_severity") or _mapping_value(
            raw,
            "severidad",
        )
    else:
        timestamp = _mapping_value(packet, "timestamp")
        source_ip = _mapping_value(packet, "ip_origen")
        source_mac = _mapping_value(packet, "mac_origen")
        destination_ip = _mapping_value(packet, "ip_destino")
        destination_mac = _mapping_value(packet, "mac_destino")
        protocol = _mapping_value(packet, "protocolo")
        severity = _mapping_value(raw, "alert_severity") or SEVERITY_MEDIUM

    return {
        "raw": raw,
        "source_event_type": event_type,
        "timestamp": _to_optional_float(timestamp),
        "severity": severity or SEVERITY_INFO,
        "source_ip": source_ip,
        "source_mac": source_mac,
        "destination_ip": destination_ip,
        "destination_mac": destination_mac,
        "protocol": protocol,
    }


def _iter_threat_intel_results(results: Any) -> Iterable[Any]:
    if results is None:
        return ()

    if isinstance(results, Mapping):
        return tuple(results.values())

    if isinstance(results, (list, tuple, set)):
        return tuple(results)

    return (results,)


def _severity_for_threat_status(status: Any) -> str:
    normalized = str(status or "").strip().lower()
    if normalized in {"error", "rate_limited"}:
        return SEVERITY_MEDIUM

    return SEVERITY_INFO


def _safe_json(value: Any) -> str:
    plain_value = _redact(_to_plain_data(value))
    return json.dumps(plain_value, sort_keys=True, default=str)


def _to_plain_data(value: Any) -> Any:
    if is_dataclass(value):
        return _to_plain_data(asdict(value))

    if isinstance(value, Mapping):
        return {str(key): _to_plain_data(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_to_plain_data(item) for item in value]

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    if hasattr(value, "__dict__"):
        return _to_plain_data(vars(value))

    return str(value)


def _redact(value: Any, key_name: str = "") -> Any:
    if _is_secret_key(key_name):
        return REDACTED

    if isinstance(value, Mapping):
        return {str(key): _redact(item, str(key)) for key, item in value.items()}

    if isinstance(value, list):
        return [_redact(item, key_name) for item in value]

    return value


def _is_secret_key(key_name: str) -> bool:
    normalized = key_name.lower().replace("-", "_")
    return any(secret_word in normalized for secret_word in SECRET_WORDS)


def _mapping_value(mapping: Any, key: str) -> Any:
    if not isinstance(mapping, Mapping):
        return None

    return mapping.get(key)


def _to_optional_float(value: Any) -> float | None:
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None
