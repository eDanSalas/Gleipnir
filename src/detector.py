"""Device authorization detector for normalized packet events."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from src import blacklist, mailer, whitelist
from src.alert_policy import AlertDecision, SEVERITY_HIGH, SEVERITY_MEDIUM
from src.logger import get_logger
from src.mailer import MailerError
from src.sniffer import PacketEvent


AUTHORIZED_DEVICE = "AUTHORIZED_DEVICE"
UNAUTHORIZED_DEVICE = "UNAUTHORIZED_DEVICE"
# Family/base event type kept for storage, reports, and dashboard compatibility.
BLACKLISTED_EXTERNAL_IP = "BLACKLISTED_EXTERNAL_IP"
# Directional/private classifications carried on the event for honest evidence.
BLACKLISTED_EXTERNAL_IP_OUTBOUND = "BLACKLISTED_EXTERNAL_IP_OUTBOUND"
BLACKLISTED_EXTERNAL_IP_INBOUND = "BLACKLISTED_EXTERNAL_IP_INBOUND"
BLACKLISTED_PRIVATE_IP = "BLACKLISTED_PRIVATE_IP"
BLACKLISTED_EXTERNAL_IP_SEVERITY = "ALTA"
DIRECTION_OUTBOUND = "outbound"
DIRECTION_INBOUND = "inbound"
DIRECTION_LOCAL = "local"
DIRECTION_UNKNOWN = "unknown"
ACTION_DETECTED = "detected"
ACTION_ALERTED = "alerted"
_LOGGER = get_logger("detector")
_LOGGER.addHandler(logging.NullHandler())


class DetectorError(RuntimeError):
    """Raised when detector processing fails."""


@dataclass(frozen=True)
class DetectionEvent:
    """Authorization result produced from a PacketEvent."""

    event_type: str
    packet: PacketEvent
    alert_sent: bool
    message: str
    alert_suppressed: bool = False
    alert_suppression_reason: str | None = None
    alert_severity: str = SEVERITY_MEDIUM
    authorized_by: str | None = None
    unauthorized_reason: str | None = None


@dataclass(frozen=True)
class BlacklistedExternalIPEvent:
    """Threat event produced when a destination IP matches the blacklist."""

    event_type: str
    timestamp: float
    ip_origen: str
    ip_destino: str
    protocolo: str
    motivo: str
    severidad: str
    alert_sent: bool
    threat_intel_results: Mapping[str, Any] = field(default_factory=dict)
    alert_suppressed: bool = False
    alert_suppression_reason: str | None = None
    alert_severity: str = SEVERITY_HIGH
    direccion: str = DIRECTION_OUTBOUND
    directional_event_type: str = BLACKLISTED_EXTERNAL_IP_OUTBOUND
    ip_peligrosa: str = ""
    accion: str = ACTION_DETECTED


@dataclass(frozen=True)
class _AlertOutcome:
    sent: bool
    suppressed: bool
    reason: str | None
    severity: str


class DeviceDetector:
    """Compare packet source identity against the loaded whitelist."""

    def __init__(
        self,
        *,
        alert_recipient: str | None = None,
        send_email: bool = True,
        authorization_checker: Callable[[str, str | None], Any] | None = None,
        authorization_policy: str = whitelist.AUTH_POLICY_STRICT,
        alert_sender: Callable[[str, str, str], None] = mailer.send_alert,
    ) -> None:
        self._alert_recipient = alert_recipient
        self._send_email = send_email
        self._authorization_checker = authorization_checker
        self._authorization_policy = whitelist.normalize_auth_policy(
            authorization_policy
        )
        self._alert_sender = alert_sender
        self._logger = _LOGGER

    def analyze(self, packet: PacketEvent) -> DetectionEvent:
        """Analyze one normalized packet event."""
        source_mac = _format_optional_mac(packet.mac_origen)
        destination_mac = _format_optional_mac(packet.mac_destino)
        if packet.mac_origen is None:
            self._logger.info(
                "Packet source MAC unavailable: ip=%s link_layer=%s",
                packet.ip_origen,
                getattr(packet, "link_layer_type", "unknown"),
            )

        authorization = self._check_authorization(packet)
        if authorization.authorized:
            if authorization.authorized_by == whitelist.AUTHORIZED_BY_IP_FALLBACK:
                self._logger.info(
                    "Whitelist IP fallback authorization used: ip=%s link_layer=%s",
                    packet.ip_origen,
                    getattr(packet, "link_layer_type", "unknown"),
                )
            message = (
                "Authorized device observed: "
                f"ip={packet.ip_origen} mac={source_mac} "
                f"dst={packet.ip_destino} protocol={packet.protocolo} "
                f"authorized_by={authorization.authorized_by}"
            )
            self._logger.info("%s | %s", AUTHORIZED_DEVICE, message)
            return DetectionEvent(
                event_type=AUTHORIZED_DEVICE,
                packet=packet,
                alert_sent=False,
                message=message,
                authorized_by=authorization.authorized_by,
            )

        message = (
            "Unauthorized device detected: "
            f"ip={packet.ip_origen} mac={source_mac} "
            f"dst={packet.ip_destino} dst_mac={destination_mac} "
            f"protocol={packet.protocolo} timestamp={packet.timestamp} "
            f"reason={authorization.reason}"
        )
        self._logger.warning("%s | %s", UNAUTHORIZED_DEVICE, message)
        alert_outcome = self._send_unauthorized_alert(
            packet,
            message,
            authorization.reason,
        )

        return DetectionEvent(
            event_type=UNAUTHORIZED_DEVICE,
            packet=packet,
            alert_sent=alert_outcome.sent,
            message=message,
            alert_suppressed=alert_outcome.suppressed,
            alert_suppression_reason=alert_outcome.reason,
            alert_severity=alert_outcome.severity,
            unauthorized_reason=authorization.reason,
        )

    def _check_authorization(
        self,
        packet: PacketEvent,
    ) -> whitelist.AuthorizationResult:
        if self._authorization_checker is None:
            return whitelist.check_authorization(
                packet.ip_origen,
                packet.mac_origen,
                policy=self._authorization_policy,
            )

        result = self._authorization_checker(packet.ip_origen, packet.mac_origen)
        if isinstance(result, whitelist.AuthorizationResult):
            return result

        if result:
            return whitelist.AuthorizationResult(
                authorized=True,
                authorized_by=whitelist.AUTHORIZED_BY_IP_MAC,
            )

        return whitelist.AuthorizationResult(
            authorized=False,
            reason=whitelist.REASON_IP_MAC_PAIR_MISMATCH,
        )

    def _send_unauthorized_alert(
        self,
        packet: PacketEvent,
        message: str,
        unauthorized_reason: str | None,
    ) -> _AlertOutcome:
        if not self._send_email:
            return _AlertOutcome(False, False, None, SEVERITY_MEDIUM)

        if not self._alert_recipient:
            self._logger.warning(
                "%s | alert email skipped because no recipient was configured",
                UNAUTHORIZED_DEVICE,
            )
            return _AlertOutcome(False, False, None, SEVERITY_MEDIUM)

        subject = f"Gleipnir IDS: {UNAUTHORIZED_DEVICE}"
        body = (
            f"{message}\n\n"
            "Resumen:\n"
            f"- IP origen: {packet.ip_origen}\n"
            f"- MAC origen: {_format_optional_mac(packet.mac_origen)}\n"
            f"- IP destino: {packet.ip_destino}\n"
            f"- MAC destino: {_format_optional_mac(packet.mac_destino)}\n"
            f"- Protocolo: {packet.protocolo}\n"
            f"- Timestamp: {packet.timestamp}\n"
            f"- Motivo: {unauthorized_reason or 'unknown'}\n"
        )

        try:
            result = self._alert_sender(subject, body, self._alert_recipient)
        except MailerError as exc:
            self._logger.error("%s | alert email failed: %s", UNAUTHORIZED_DEVICE, exc)
            raise DetectorError("Unable to send unauthorized device alert") from exc

        outcome = _coerce_alert_outcome(result, default_severity=SEVERITY_MEDIUM)
        if outcome.suppressed:
            self._logger.warning(
                "%s | alert email suppressed: reason=%s",
                UNAUTHORIZED_DEVICE,
                outcome.reason,
            )
            return outcome

        self._logger.info(
            "%s | alert email sent to %s",
            UNAUTHORIZED_DEVICE,
            self._alert_recipient,
        )
        return outcome


class ExternalIPBlacklistDetector:
    """Detect packets whose external destination IP is blacklisted."""

    def __init__(
        self,
        *,
        alert_recipient: str | None = None,
        send_email: bool = True,
        blacklist_checker: Callable[[str], bool] = blacklist.is_blacklisted,
        blacklist_lookup: Callable[[str], blacklist.BlacklistEntry | None] = (
            blacklist.get_blacklist_entry
        ),
        alert_sender: Callable[[str, str, str], None] = mailer.send_alert,
        check_private: bool = False,
    ) -> None:
        self._alert_recipient = alert_recipient
        self._send_email = send_email
        self._blacklist_checker = blacklist_checker
        self._blacklist_lookup = blacklist_lookup
        self._alert_sender = alert_sender
        self._check_private = check_private
        self._logger = _LOGGER

    def analyze(self, packet: PacketEvent) -> BlacklistedExternalIPEvent | None:
        """Return a blacklist event when source or destination is dangerous.

        Destination (outbound) is evaluated first, then source (inbound).
        Private/local IPs are only checked when ``check_private`` is enabled.
        """
        for candidate_ip, role in (
            (packet.ip_destino, "destination"),
            (packet.ip_origen, "source"),
        ):
            if not self._should_check_ip(candidate_ip):
                continue
            if not self._blacklist_checker(candidate_ip):
                self._logger.info(
                    "%s | not blacklisted: role=%s ip=%s",
                    BLACKLISTED_EXTERNAL_IP,
                    role,
                    candidate_ip,
                )
                continue

            return self._build_event(packet, candidate_ip, role)

        return None

    def _should_check_ip(self, ip_address: str) -> bool:
        if _is_external_ip(ip_address):
            return True
        if self._check_private:
            return True

        self._logger.info(
            "%s | private/non-external ip ignored (BLACKLIST_CHECK_PRIVATE=false): ip=%s",
            BLACKLISTED_EXTERNAL_IP,
            ip_address,
        )
        return False

    def _build_event(
        self,
        packet: PacketEvent,
        dangerous_ip: str,
        role: str,
    ) -> BlacklistedExternalIPEvent:
        direccion, directional_type = _classify_direction(dangerous_ip, role)
        motivo = self._blacklist_reason(dangerous_ip)
        severidad = BLACKLISTED_EXTERNAL_IP_SEVERITY
        message = (
            f"{directional_type} | "
            f"timestamp={packet.timestamp} "
            f"src={packet.ip_origen} dst={packet.ip_destino} "
            f"dangerous={dangerous_ip} direction={direccion} "
            f"protocol={packet.protocolo} severity={severidad} reason={motivo}"
        )
        self._logger.warning(message)
        alert_outcome = self._send_blacklist_alert(
            packet, motivo, severidad, direccion, dangerous_ip
        )

        return BlacklistedExternalIPEvent(
            event_type=BLACKLISTED_EXTERNAL_IP,
            timestamp=packet.timestamp,
            ip_origen=packet.ip_origen,
            ip_destino=packet.ip_destino,
            protocolo=packet.protocolo,
            motivo=motivo,
            severidad=severidad,
            alert_sent=alert_outcome.sent,
            alert_suppressed=alert_outcome.suppressed,
            alert_suppression_reason=alert_outcome.reason,
            alert_severity=alert_outcome.severity,
            direccion=direccion,
            directional_event_type=directional_type,
            ip_peligrosa=dangerous_ip,
            accion=ACTION_ALERTED if alert_outcome.sent else ACTION_DETECTED,
        )

    def _blacklist_reason(self, ip_destino: str) -> str:
        entry = self._blacklist_lookup(ip_destino)
        if entry is not None:
            return blacklist.normalize_risk(entry.reason)

        return blacklist.DEFAULT_RISK

    def _send_blacklist_alert(
        self,
        packet: PacketEvent,
        motivo: str,
        severidad: str,
        direccion: str,
        dangerous_ip: str,
    ) -> _AlertOutcome:
        if not self._send_email:
            return _AlertOutcome(False, False, None, SEVERITY_HIGH)

        if not self._alert_recipient:
            self._logger.warning(
                "%s | alert email skipped because no recipient was configured",
                BLACKLISTED_EXTERNAL_IP,
            )
            return _AlertOutcome(False, False, None, SEVERITY_HIGH)

        subject = (
            "Gleipnir IDS: ALERTA DE EMERGENCIA - IP peligrosa detectada - "
            f"{BLACKLISTED_EXTERNAL_IP}"
        )
        body = (
            "ALERTA DE EMERGENCIA: se detecto trafico relacionado con una IP "
            "en blacklist.\n\n"
            "Resumen:\n"
            f"- Timestamp: {packet.timestamp}\n"
            f"- Direccion del flujo: {direccion}\n"
            f"- IP origen: {packet.ip_origen}\n"
            f"- IP destino: {packet.ip_destino}\n"
            f"- IP peligrosa: {dangerous_ip}\n"
            f"- Protocolo: {packet.protocolo}\n"
            f"- Tipo de riesgo: {motivo}\n"
            f"- Severidad: {severidad}\n"
            "\nRecomendacion: revisar el equipo involucrado, validar si la "
            "conexion fue autorizada y consultar el reporte forense del IDS.\n"
        )

        try:
            result = self._alert_sender(subject, body, self._alert_recipient)
        except MailerError as exc:
            self._logger.error(
                "%s | alert email failed: %s",
                BLACKLISTED_EXTERNAL_IP,
                exc,
            )
            raise DetectorError("Unable to send blacklisted IP alert") from exc

        outcome = _coerce_alert_outcome(result, default_severity=SEVERITY_HIGH)
        if outcome.suppressed:
            self._logger.warning(
                "%s | alert email suppressed: reason=%s",
                BLACKLISTED_EXTERNAL_IP,
                outcome.reason,
            )
            return outcome

        self._logger.info(
            "%s | alert email sent to %s",
            BLACKLISTED_EXTERNAL_IP,
            self._alert_recipient,
        )
        return outcome


def detect_packet(
    packet: PacketEvent,
    *,
    alert_recipient: str | None = None,
    send_email: bool = True,
) -> DetectionEvent:
    """Analyze a single PacketEvent with the default detector."""
    detector = DeviceDetector(
        alert_recipient=alert_recipient,
        send_email=send_email,
    )
    return detector.analyze(packet)


def detect_blacklisted_external_ip(
    packet: PacketEvent,
    *,
    alert_recipient: str | None = None,
    send_email: bool = True,
    check_private: bool = False,
) -> BlacklistedExternalIPEvent | None:
    """Analyze one PacketEvent against the configured external IP blacklist."""
    detector = ExternalIPBlacklistDetector(
        alert_recipient=alert_recipient,
        send_email=send_email,
        check_private=check_private,
    )
    return detector.analyze(packet)


def _classify_direction(dangerous_ip: str, role: str) -> tuple[str, str]:
    """Return (direccion, directional_event_type) for a matched blacklist IP."""
    if not _is_external_ip(dangerous_ip):
        return DIRECTION_LOCAL, BLACKLISTED_PRIVATE_IP
    if role == "source":
        return DIRECTION_INBOUND, BLACKLISTED_EXTERNAL_IP_INBOUND
    return DIRECTION_OUTBOUND, BLACKLISTED_EXTERNAL_IP_OUTBOUND


def _is_external_ip(ip_address: str) -> bool:
    return ipaddress.ip_address(ip_address).is_global


def _format_optional_mac(value: str | None) -> str:
    return value if value is not None else "unknown"


def _coerce_alert_outcome(
    result: Any,
    *,
    default_severity: str,
) -> _AlertOutcome:
    if isinstance(result, AlertDecision):
        return _AlertOutcome(
            sent=result.sent,
            suppressed=result.suppressed,
            reason=result.reason,
            severity=result.severity,
        )

    if result is False:
        return _AlertOutcome(
            sent=False,
            suppressed=True,
            reason="alert_sender_suppressed",
            severity=default_severity,
        )

    return _AlertOutcome(
        sent=True,
        suppressed=False,
        reason=None,
        severity=default_severity,
    )
