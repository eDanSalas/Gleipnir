"""Central runtime orchestration for Gleipnir IDS."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from src import blacklist, firewall, ips_config, mailer, threat_intel, whitelist
from src.alert_policy import AlertPolicy, PolicyAlertSender
from src.config import Config, load_config
from src.detector import (
    UNAUTHORIZED_DEVICE,
    BlacklistedExternalIPEvent,
    DetectionEvent,
    DeviceDetector,
    ExternalIPBlacklistDetector,
)
from src.dns_http_monitor import TrafficEvent, register_traffic
from src.firewall import (
    ACTION_ALERTED,
    ACTION_BLOCKED,
    ACTION_DRY_RUN_BLOCK,
    ALLOWLIST_BLOCK_UNREGISTERED,
    BLACKLIST_BLOCK,
    DIRECTION_BOTH,
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    IPS_BLOCKED_BLACKLISTED_IP,
    IPS_BLOCKED_UNREGISTERED_DEVICE,
    FirewallResult,
    IPSActionEvent,
    IPSSettings,
)
from src.logger import get_logger, setup_logging
from src.sniffer import PacketEvent
from src.storage import SQLiteEventStore
from src.threat_intel import ThreatIntelResult


FirewallBlocker = Callable[[str, str], FirewallResult]


TrafficMonitor = Callable[[Any], tuple[TrafficEvent, ...]]
AlertSender = Callable[[str, str, str], Any]
ThreatIntelEnricher = Callable[..., BlacklistedExternalIPEvent]


class RuntimeEngineError(RuntimeError):
    """Raised when the IDS runtime cannot be initialized or executed."""


@dataclass(frozen=True)
class PacketProcessingResult:
    """Events produced while processing one PacketEvent."""

    packet: PacketEvent
    detection_event: DetectionEvent
    dns_http_events: tuple[TrafficEvent, ...] = ()
    blacklist_event: BlacklistedExternalIPEvent | None = None
    threat_intel_results: Mapping[str, ThreatIntelResult] = field(default_factory=dict)
    ips_events: tuple[IPSActionEvent, ...] = ()


class IDSEngine:
    """Coordinate configuration, lists, detection, alerting, and enrichment."""

    def __init__(
        self,
        *,
        config: Config,
        logger: logging.Logger,
        device_detector: DeviceDetector,
        blacklist_detector: ExternalIPBlacklistDetector,
        traffic_monitor: TrafficMonitor = register_traffic,
        threat_intel_enricher: ThreatIntelEnricher = threat_intel.enrich_blacklisted_ip_event,
        enable_threat_intel: bool = True,
        event_store: SQLiteEventStore | None = None,
        forensic_alert_recipient: str | None = None,
        forensic_alert_sender: AlertSender | None = None,
        send_forensic_email: bool = False,
        ips_settings: IPSSettings | None = None,
        firewall_block: FirewallBlocker | None = None,
        auth_policy: str = whitelist.AUTH_POLICY_STRICT,
    ) -> None:
        self.config = config
        self.logger = logger
        self._device_detector = device_detector
        self._blacklist_detector = blacklist_detector
        self._traffic_monitor = traffic_monitor
        self._threat_intel_enricher = threat_intel_enricher
        self._enable_threat_intel = enable_threat_intel
        self._event_store = event_store
        self._forensic_alert_recipient = forensic_alert_recipient
        self._forensic_alert_sender = forensic_alert_sender
        self._send_forensic_email = send_forensic_email
        self._ips_settings = ips_settings or IPSSettings()
        self._auth_policy = whitelist.normalize_auth_policy(auth_policy)
        self._firewall_block = firewall_block or (
            lambda ip, direction: firewall.block_ip(ip, self._ips_settings)
        )
        self._shutdown = False

    @classmethod
    def from_config(
        cls,
        *,
        env_file: str | Path = ".env",
        config: Config | None = None,
        send_email: bool = True,
        enable_threat_intel: bool = True,
        alert_sender: AlertSender = mailer.send_alert,
        traffic_monitor: TrafficMonitor = register_traffic,
        threat_intel_enricher: ThreatIntelEnricher = threat_intel.enrich_blacklisted_ip_event,
        event_store: SQLiteEventStore | None = None,
        alert_policy: AlertPolicy | None = None,
        enable_storage: bool = True,
        console_stream: TextIO | None = None,
        ips_settings: IPSSettings | None = None,
        firewall_block: FirewallBlocker | None = None,
    ) -> "IDSEngine":
        """Build an engine from validated configuration and configured lists."""
        runtime_config = config or load_config(env_file)
        logger = setup_logging(runtime_config, console_stream=console_stream)
        engine_logger = get_logger("runtime.engine")

        try:
            whitelist_entries = whitelist.validate_whitelist_file(
                runtime_config.whitelist_file
            )
            blacklist_entries = blacklist.validate_blacklist_file(
                runtime_config.blacklist_file
            )
        except Exception as exc:
            engine_logger.error("IDS runtime list loading failed: %s", exc)
            raise RuntimeEngineError("Unable to load IDS whitelist/blacklist") from exc

        engine_logger.info(
            "IDS runtime initialized: whitelist_entries=%s blacklist_entries=%s",
            len(whitelist_entries),
            len(blacklist_entries),
        )
        runtime_event_store = event_store
        if enable_storage and runtime_event_store is None:
            runtime_event_store = SQLiteEventStore.from_config(runtime_config)
        if enable_storage and runtime_event_store is not None:
            try:
                runtime_event_store.initialize()
            except Exception as exc:
                engine_logger.error("IDS event storage initialization failed: %s", exc)
                raise RuntimeEngineError("Unable to initialize IDS event storage") from exc
        runtime_alert_sender = alert_sender
        if send_email:
            runtime_alert_sender = PolicyAlertSender(
                policy=alert_policy or AlertPolicy.from_config(runtime_config),
                send_alert=alert_sender,
            )

        resolved_ips_settings = ips_settings or ips_config.build_ips_settings(runtime_config)

        return cls(
            config=runtime_config,
            logger=logger,
            device_detector=DeviceDetector(
                alert_recipient=runtime_config.admin_email,
                send_email=send_email,
                authorization_policy=runtime_config.whitelist_auth_policy,
                alert_sender=runtime_alert_sender,
            ),
            blacklist_detector=ExternalIPBlacklistDetector(
                alert_recipient=runtime_config.admin_email,
                send_email=send_email,
                blacklist_checker=blacklist.is_blacklisted,
                alert_sender=runtime_alert_sender,
                check_private=resolved_ips_settings.blacklist_check_private,
            ),
            traffic_monitor=traffic_monitor,
            threat_intel_enricher=threat_intel_enricher,
            enable_threat_intel=enable_threat_intel,
            event_store=runtime_event_store if enable_storage else None,
            forensic_alert_recipient=runtime_config.admin_email,
            forensic_alert_sender=runtime_alert_sender,
            send_forensic_email=send_email and enable_threat_intel,
            ips_settings=resolved_ips_settings,
            firewall_block=firewall_block,
            auth_policy=runtime_config.whitelist_auth_policy,
        )

    def process_packet_event(
        self,
        event: PacketEvent,
        *,
        dns_http_source: Any | None = None,
    ) -> PacketProcessingResult:
        """Run the central IDS flow for one normalized packet event."""
        self._ensure_running()
        detection_event = self._device_detector.analyze(event)
        dns_http_events = self.process_dns_http_event(
            event if dns_http_source is None else dns_http_source
        )
        blacklist_event = self._blacklist_detector.analyze(event)
        blacklist_event = self._enrich_blacklisted_event(blacklist_event)
        self._send_forensic_report(blacklist_event)
        threat_intel_results = (
            blacklist_event.threat_intel_results if blacklist_event is not None else {}
        )

        ips_events, blacklist_event = self._apply_ips_policies(
            detection_event, blacklist_event
        )

        get_logger("runtime.engine").info(
            "IDS packet processed: src=%s dst=%s detection=%s dns_http=%s blacklist=%s ips=%s",
            event.ip_origen,
            event.ip_destino,
            detection_event.event_type,
            len(dns_http_events),
            bool(blacklist_event),
            len(ips_events),
        )

        result = PacketProcessingResult(
            packet=event,
            detection_event=detection_event,
            dns_http_events=dns_http_events,
            blacklist_event=blacklist_event,
            threat_intel_results=threat_intel_results,
            ips_events=ips_events,
        )
        self._persist_packet_result(result)
        return result

    def _apply_ips_policies(
        self,
        detection_event: DetectionEvent,
        blacklist_event: BlacklistedExternalIPEvent | None,
    ) -> tuple[tuple[IPSActionEvent, ...], BlacklistedExternalIPEvent | None]:
        """Apply optional defensive enforcement. No-op unless IPS is enabled."""
        settings = self._ips_settings
        if not settings.enabled:
            return (), blacklist_event

        events: list[IPSActionEvent] = []

        if (
            blacklist_event is not None
            and settings.blacklist_policy == BLACKLIST_BLOCK
            and self._direction_enabled(blacklist_event.direccion, settings.block_direction)
        ):
            ips_event = self._enforce_block(
                event_type=IPS_BLOCKED_BLACKLISTED_IP,
                ip=blacklist_event.ip_peligrosa or blacklist_event.ip_destino,
                ip_origen=blacklist_event.ip_origen,
                ip_destino=blacklist_event.ip_destino,
                direccion=blacklist_event.direccion,
                protocolo=blacklist_event.protocolo,
                motivo=blacklist_event.motivo,
                severidad=blacklist_event.severidad,
                timestamp=blacklist_event.timestamp,
            )
            events.append(ips_event)
            blacklist_event = replace(blacklist_event, accion=ips_event.accion)

        if (
            detection_event.event_type == UNAUTHORIZED_DEVICE
            and settings.allowlist_policy == ALLOWLIST_BLOCK_UNREGISTERED
        ):
            ips_event = self._enforce_unregistered_block(detection_event)
            if ips_event is not None:
                events.append(ips_event)

        return tuple(events), blacklist_event

    def _enforce_unregistered_block(
        self,
        detection_event: DetectionEvent,
    ) -> IPSActionEvent | None:
        packet = detection_event.packet
        # Never auto-block when the MAC is unavailable under the strict policy:
        # we only have a partial identity, so we alert instead of blocking.
        if packet.mac_origen is None and self._auth_policy == whitelist.AUTH_POLICY_STRICT:
            get_logger("runtime.engine").info(
                "IPS skip unregistered block: MAC unavailable under strict policy ip=%s",
                packet.ip_origen,
            )
            return IPSActionEvent(
                event_type=IPS_BLOCKED_UNREGISTERED_DEVICE,
                timestamp=packet.timestamp,
                ip_origen=packet.ip_origen,
                ip_destino=packet.ip_destino,
                direccion=DIRECTION_INBOUND,
                protocolo=packet.protocolo,
                motivo="unregistered_device",
                severidad="MEDIA",
                accion=ACTION_ALERTED,
                dry_run=self._ips_settings.dry_run,
                applied=False,
                message="MAC no disponible bajo politica strict: solo alerta, no se bloquea.",
            )

        return self._enforce_block(
            event_type=IPS_BLOCKED_UNREGISTERED_DEVICE,
            ip=packet.ip_origen,
            ip_origen=packet.ip_origen,
            ip_destino=packet.ip_destino,
            direccion=DIRECTION_INBOUND,
            protocolo=packet.protocolo,
            motivo="unregistered_device",
            severidad="MEDIA",
            timestamp=packet.timestamp,
        )

    def _enforce_block(
        self,
        *,
        event_type: str,
        ip: str,
        ip_origen: str,
        ip_destino: str,
        direccion: str,
        protocolo: str,
        motivo: str,
        severidad: str,
        timestamp: float,
    ) -> IPSActionEvent:
        settings = self._ips_settings
        if settings.dry_run:
            get_logger("runtime.engine").info(
                "IPS dry-run block: type=%s ip=%s direction=%s",
                event_type,
                ip,
                direccion,
            )
            return IPSActionEvent(
                event_type=event_type,
                timestamp=timestamp,
                ip_origen=ip_origen,
                ip_destino=ip_destino,
                direccion=direccion,
                protocolo=protocolo,
                motivo=motivo,
                severidad=severidad,
                accion=ACTION_DRY_RUN_BLOCK,
                dry_run=True,
                applied=False,
                message=f"dry-run: se bloquearia {ip} ({direccion}).",
            )

        try:
            result = self._firewall_block(ip, direccion)
        except Exception as exc:  # pragma: no cover - defensive
            get_logger("runtime.engine").error("IPS block failed: ip=%s error=%s", ip, exc)
            result = FirewallResult(applied=False, dry_run=False, reason="engine_error", error=str(exc))

        applied = bool(getattr(result, "applied", False))
        accion = ACTION_BLOCKED if applied else ACTION_ALERTED
        message = (
            f"IPS bloqueo aplicado: {ip} ({direccion})."
            if applied
            else f"IPS no pudo aplicar bloqueo para {ip}: {getattr(result, 'reason', 'unknown')}."
        )
        get_logger("runtime.engine").warning(message)
        return IPSActionEvent(
            event_type=event_type,
            timestamp=timestamp,
            ip_origen=ip_origen,
            ip_destino=ip_destino,
            direccion=direccion,
            protocolo=protocolo,
            motivo=motivo,
            severidad=severidad,
            accion=accion,
            dry_run=False,
            applied=applied,
            message=message,
        )

    @staticmethod
    def _direction_enabled(direccion: str, block_direction: str) -> bool:
        if block_direction == DIRECTION_BOTH:
            return True
        if block_direction == DIRECTION_OUTBOUND:
            return direccion == DIRECTION_OUTBOUND
        if block_direction == DIRECTION_INBOUND:
            return direccion == DIRECTION_INBOUND
        return True

    def process_dns_http_event(self, event: Any) -> tuple[TrafficEvent, ...]:
        """Run DNS/HTTP detection for a PacketEvent, mapping, or Scapy packet."""
        self._ensure_running()
        return self._traffic_monitor(event)

    def shutdown(self) -> None:
        """Flush runtime logs and mark the engine as stopped."""
        if self._shutdown:
            return

        get_logger("runtime.engine").info("IDS runtime shutdown")
        if self._event_store is not None:
            try:
                self._event_store.close()
            except Exception as exc:
                get_logger("runtime.engine").error(
                    "IDS event storage shutdown failed: %s",
                    exc,
                )

        for handler in self.logger.handlers[:]:
            handler.flush()
            self.logger.removeHandler(handler)
            handler.close()

        self._shutdown = True

    def _enrich_blacklisted_event(
        self,
        blacklist_event: BlacklistedExternalIPEvent | None,
    ) -> BlacklistedExternalIPEvent | None:
        if blacklist_event is None or not self._enable_threat_intel:
            return blacklist_event

        try:
            return self._threat_intel_enricher(
                blacklist_event,
                config=self.config,
            )
        except Exception as exc:
            get_logger("runtime.engine").exception(
                "Threat intelligence enrichment failed: ip=%s",
                blacklist_event.ip_destino,
            )
            return blacklist_event

    def _send_forensic_report(
        self,
        blacklist_event: BlacklistedExternalIPEvent | None,
    ) -> None:
        if (
            blacklist_event is None
            or not self._send_forensic_email
            or not blacklist_event.threat_intel_results
            or not self._forensic_alert_recipient
            or self._forensic_alert_sender is None
        ):
            return

        subject = (
            "Gleipnir IDS: Reporte Forense - "
            f"IP peligrosa {blacklist_event.ip_destino}"
        )
        body = _build_forensic_report_body(blacklist_event)
        try:
            result = self._forensic_alert_sender(
                subject,
                body,
                self._forensic_alert_recipient,
            )
        except Exception as exc:
            get_logger("runtime.engine").error(
                "Forensic alert email failed: ip=%s error=%s",
                blacklist_event.ip_destino,
                exc,
            )
            return

        if getattr(result, "suppressed", False):
            get_logger("runtime.engine").warning(
                "Forensic alert email suppressed: ip=%s reason=%s",
                blacklist_event.ip_destino,
                getattr(result, "reason", "unknown"),
            )
            return

        get_logger("runtime.engine").info(
            "Forensic alert email sent: ip=%s recipient=%s",
            blacklist_event.ip_destino,
            self._forensic_alert_recipient,
        )

    def _persist_packet_result(self, result: PacketProcessingResult) -> None:
        if self._event_store is None:
            return

        try:
            self._event_store.save_packet_processing_result(result)
        except Exception as exc:
            get_logger("runtime.engine").error(
                "IDS event persistence failed: %s",
                exc,
            )

    def _ensure_running(self) -> None:
        if self._shutdown:
            raise RuntimeEngineError("IDS engine has been shut down")


def _build_forensic_report_body(event: BlacklistedExternalIPEvent) -> str:
    sections = [
        "Reporte forense automatico para IP peligrosa detectada.",
        "",
        "Resumen:",
        f"- Timestamp: {event.timestamp}",
        f"- IP origen interna: {event.ip_origen}",
        f"- IP peligrosa: {event.ip_destino}",
        f"- Protocolo: {event.protocolo}",
        f"- Tipo de riesgo: {event.motivo}",
        f"- Severidad: {event.severidad}",
        "",
        "Fuentes consultadas:",
    ]
    for result in event.threat_intel_results.values():
        sections.extend(_format_threat_intel_result(result))

    abuse_contact = _first_abuse_contact(event.threat_intel_results.values())
    if abuse_contact:
        sections.extend(("", f"Contacto de abuso sugerido: {abuse_contact}"))

    sections.extend(
        (
            "",
            "Recomendacion: revisar el equipo origen, conservar evidencias "
            "del evento y reportar al proveedor/hosting si el trafico no fue "
            "autorizado.",
        )
    )
    return "\n".join(sections)


def _format_threat_intel_result(result: Any) -> list[str]:
    service = getattr(result, "service", "unknown")
    status = getattr(result, "status", "unknown")
    error = getattr(result, "error", None)
    data = getattr(result, "data", {}) or {}
    lines = [f"- {service}: status={status}"]
    if error:
        lines.append(f"  error={error}")
    if not isinstance(data, Mapping):
        return lines

    for key, value in _threat_intel_summary_fields(data):
        lines.append(f"  {key}={value}")
    return lines


def _threat_intel_summary_fields(data: Mapping[str, Any]) -> list[tuple[str, Any]]:
    selected: list[tuple[str, Any]] = []
    for key in (
        "abuseConfidenceScore",
        "totalReports",
        "countryCode",
        "usageType",
        "isp",
        "domain",
        "organization",
        "provider",
        "asn",
        "abuse_contact",
        "emails",
        "last_analysis_stats",
    ):
        value = _nested_value(data, key)
        if value not in (None, "", {}, []):
            selected.append((key, _compact_forensic_value(value)))
    return selected


def _nested_value(data: Mapping[str, Any], key: str) -> Any:
    if key in data:
        return data[key]
    nested_data = data.get("data")
    if isinstance(nested_data, Mapping) and key in nested_data:
        return nested_data[key]
    attributes = nested_data.get("attributes") if isinstance(nested_data, Mapping) else None
    if isinstance(attributes, Mapping) and key in attributes:
        return attributes[key]
    return None


def _compact_forensic_value(value: Any) -> str:
    if isinstance(value, Mapping):
        return ", ".join(f"{key}:{value[key]}" for key in sorted(value)[:8])
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in list(value)[:8])
    return str(value)


def _first_abuse_contact(results: Any) -> str | None:
    for result in results:
        data = getattr(result, "data", {}) or {}
        if not isinstance(data, Mapping):
            continue
        contact = _nested_value(data, "abuse_contact")
        if contact:
            return _compact_forensic_value(contact)
        emails = _nested_value(data, "emails")
        if isinstance(emails, (list, tuple)) and emails:
            return str(emails[0])
    return None
