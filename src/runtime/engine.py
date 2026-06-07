"""Central runtime orchestration for Gleipnir IDS."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from src import blacklist, mailer, threat_intel, whitelist
from src.alert_policy import AlertPolicy, PolicyAlertSender
from src.config import Config, load_config
from src.detector import (
    BlacklistedExternalIPEvent,
    DetectionEvent,
    DeviceDetector,
    ExternalIPBlacklistDetector,
)
from src.dns_http_monitor import TrafficEvent, register_traffic
from src.logger import get_logger, setup_logging
from src.sniffer import PacketEvent
from src.storage import SQLiteEventStore
from src.threat_intel import ThreatIntelResult


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
    ) -> None:
        self.config = config
        self.logger = logger
        self._device_detector = device_detector
        self._blacklist_detector = blacklist_detector
        self._traffic_monitor = traffic_monitor
        self._threat_intel_enricher = threat_intel_enricher
        self._enable_threat_intel = enable_threat_intel
        self._event_store = event_store
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

        return cls(
            config=runtime_config,
            logger=logger,
            device_detector=DeviceDetector(
                alert_recipient=runtime_config.admin_email,
                send_email=send_email,
                authorization_checker=whitelist.is_authorized,
                alert_sender=runtime_alert_sender,
            ),
            blacklist_detector=ExternalIPBlacklistDetector(
                alert_recipient=runtime_config.admin_email,
                send_email=send_email,
                blacklist_checker=blacklist.is_blacklisted,
                alert_sender=runtime_alert_sender,
            ),
            traffic_monitor=traffic_monitor,
            threat_intel_enricher=threat_intel_enricher,
            enable_threat_intel=enable_threat_intel,
            event_store=runtime_event_store if enable_storage else None,
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
        threat_intel_results = (
            blacklist_event.threat_intel_results if blacklist_event is not None else {}
        )

        get_logger("runtime.engine").info(
            "IDS packet processed: src=%s dst=%s detection=%s dns_http=%s blacklist=%s",
            event.ip_origen,
            event.ip_destino,
            detection_event.event_type,
            len(dns_http_events),
            bool(blacklist_event),
        )

        result = PacketProcessingResult(
            packet=event,
            detection_event=detection_event,
            dns_http_events=dns_http_events,
            blacklist_event=blacklist_event,
            threat_intel_results=threat_intel_results,
        )
        self._persist_packet_result(result)
        return result

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
