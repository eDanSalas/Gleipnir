
from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from src.logger import get_logger


SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
ALERT_SEVERITIES = (
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
DEFAULT_ALERT_COOLDOWN_SECONDS = 300
DEFAULT_ALERT_MAX_PER_MINUTE = 5

_LOGGER = get_logger("alert_policy")
_FIELD_PATTERN = re.compile(r"(?im)^\s*-\s*(?P<name>[^:]+):\s*(?P<value>.+?)\s*$")


@dataclass(frozen=True)
class AlertRequest:

    subject: str
    message: str
    recipient: str
    severity: str
    group_key: str
    event_type: str | None = None
    timestamp: float | None = None


@dataclass(frozen=True)
class AlertDecision:

    sent: bool
    suppressed: bool
    severity: str
    group_key: str
    timestamp: float
    reason: str | None = None


class AlertPolicy:

    # FUN-001
    def __init__(
        self,
        *,
        cooldown_seconds: int = DEFAULT_ALERT_COOLDOWN_SECONDS,
        max_per_minute: int = DEFAULT_ALERT_MAX_PER_MINUTE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if cooldown_seconds < 0:
            raise ValueError("Alert cooldown must be greater than or equal to 0")
        if max_per_minute < 1:
            raise ValueError("Alert max per minute must be greater than or equal to 1")

        self.cooldown_seconds = cooldown_seconds
        self.max_per_minute = max_per_minute
        self._clock = clock
        self._last_sent_by_key: dict[str, float] = {}
        self._sent_timestamps: deque[float] = deque()

    # FUN-002
    @classmethod
    def from_config(cls, config: Any) -> "AlertPolicy":
        return cls(
            cooldown_seconds=int(
                getattr(config, "alert_cooldown_seconds", DEFAULT_ALERT_COOLDOWN_SECONDS)
            ),
            max_per_minute=int(
                getattr(config, "alert_max_per_minute", DEFAULT_ALERT_MAX_PER_MINUTE)
            ),
        )

    # FUN-003
    def evaluate(self, request: AlertRequest) -> AlertDecision:
        now = request.timestamp if request.timestamp is not None else self._clock()
        severity = normalize_severity(request.severity)

        # EXP-017
        if severity == SEVERITY_CRITICAL:
            self._record_sent(request.group_key, now)
            return AlertDecision(
                sent=True,
                suppressed=False,
                severity=severity,
                group_key=request.group_key,
                timestamp=now,
            )

        self._prune_sent_window(now)
        last_sent = self._last_sent_by_key.get(request.group_key)
        if last_sent is None:
            self._record_sent(request.group_key, now)
            return AlertDecision(
                sent=True,
                suppressed=False,
                severity=severity,
                group_key=request.group_key,
                timestamp=now,
            )

        if (
            self.cooldown_seconds > 0
            and now - last_sent < self.cooldown_seconds
        ):
            return AlertDecision(
                sent=False,
                suppressed=True,
                severity=severity,
                group_key=request.group_key,
                timestamp=now,
                reason="cooldown",
            )

        if len(self._sent_timestamps) >= self.max_per_minute:
            return AlertDecision(
                sent=False,
                suppressed=True,
                severity=severity,
                group_key=request.group_key,
                timestamp=now,
                reason="rate_limit",
            )

        self._record_sent(request.group_key, now)
        return AlertDecision(
            sent=True,
            suppressed=False,
            severity=severity,
            group_key=request.group_key,
            timestamp=now,
        )

    def _record_sent(self, group_key: str, timestamp: float) -> None:
        self._prune_sent_window(timestamp)
        self._last_sent_by_key[group_key] = timestamp
        self._sent_timestamps.append(timestamp)

    def _prune_sent_window(self, now: float) -> None:
        window_start = now - 60
        while self._sent_timestamps and self._sent_timestamps[0] <= window_start:
            self._sent_timestamps.popleft()


class PolicyAlertSender:

    # FUN-004
    def __init__(
        self,
        *,
        policy: AlertPolicy,
        send_alert: Callable[[str, str, str], Any],
    ) -> None:
        self._policy = policy
        self._send_alert = send_alert

    # FUN-005
    def __call__(self, subject: str, message: str, recipient: str) -> AlertDecision:
        request = build_alert_request(subject, message, recipient)
        decision = self._policy.evaluate(request)
        if decision.suppressed:
            _LOGGER.warning(
                "ALERT_SUPPRESSED | key=%s severity=%s reason=%s",
                decision.group_key,
                decision.severity,
                decision.reason,
            )
            return decision

        self._send_alert(subject, message, recipient)
        _LOGGER.info(
            "ALERT_SENT | key=%s severity=%s",
            decision.group_key,
            decision.severity,
        )
        return decision


# FUN-006
def build_alert_request(subject: str, message: str, recipient: str) -> AlertRequest:
    event_type = _event_type_from_subject(subject)
    fields = _extract_message_fields(message)
    severity = _severity_for_event(event_type, fields)
    group_key = _group_key(event_type, fields, subject, recipient)

    return AlertRequest(
        subject=subject,
        message=message,
        recipient=recipient,
        severity=severity,
        group_key=group_key,
        event_type=event_type,
    )


# FUN-007
def normalize_severity(value: str | None) -> str:
    normalized = (value or SEVERITY_MEDIUM).strip().lower()
    aliases = {
        "baja": SEVERITY_LOW,
        "low": SEVERITY_LOW,
        "media": SEVERITY_MEDIUM,
        "medium": SEVERITY_MEDIUM,
        "alta": SEVERITY_HIGH,
        "high": SEVERITY_HIGH,
        "critica": SEVERITY_CRITICAL,
        "crítica": SEVERITY_CRITICAL,
        "critical": SEVERITY_CRITICAL,
    }
    severity = aliases.get(normalized)
    if severity is None:
        raise ValueError(f"Unsupported alert severity: {value}")

    return severity


def _event_type_from_subject(subject: str) -> str | None:
    for event_type in ("BLACKLISTED_EXTERNAL_IP", "UNAUTHORIZED_DEVICE"):
        if event_type in subject:
            return event_type

    if ":" not in subject:
        return None

    event_type = subject.rsplit(":", maxsplit=1)[1].strip()
    return event_type or None


def _extract_message_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _FIELD_PATTERN.finditer(message):
        key = _normalize_field_name(match.group("name"))
        fields[key] = match.group("value").strip()

    return fields


def _normalize_field_name(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace(" ", "_")
        .replace("á", "a")
        .replace("é", "e")
        .replace("í", "i")
        .replace("ó", "o")
        .replace("ú", "u")
    )


def _severity_for_event(event_type: str | None, fields: dict[str, str]) -> str:
    explicit_severity = fields.get("severidad") or fields.get("severity")
    if explicit_severity:
        return normalize_severity(explicit_severity)

    if event_type and "CRITICAL" in event_type.upper():
        return SEVERITY_CRITICAL
    if event_type == "BLACKLISTED_EXTERNAL_IP":
        return SEVERITY_HIGH
    if event_type == "UNAUTHORIZED_DEVICE":
        return SEVERITY_MEDIUM

    return SEVERITY_LOW


def _group_key(
    event_type: str | None,
    fields: dict[str, str],
    subject: str,
    recipient: str,
) -> str:
    if event_type == "BLACKLISTED_EXTERNAL_IP":
        destination_ip = (
            fields.get("ip_destino")
            or fields.get("destination_ip")
            or fields.get("ip_peligrosa")
            or fields.get("ip_destino_peligrosa")
        )
        if destination_ip:
            return f"{event_type}|dst={destination_ip}"

    if event_type == "UNAUTHORIZED_DEVICE":
        source_ip = fields.get("ip_origen") or fields.get("source_ip")
        source_mac = fields.get("mac_origen") or fields.get("source_mac")
        if source_ip or source_mac:
            return f"{event_type}|src={source_ip or ''}|mac={source_mac or ''}"

    return f"{recipient}|{subject}"
