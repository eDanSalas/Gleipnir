
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from src import detector, dns_http_monitor
from src.detector import DetectionEvent
from src.dns_http_monitor import TrafficEvent
from src.logger import get_logger
from src.sniffer import PacketEvent, parse_packet, parse_pcap


DetectorHandler = Callable[[PacketEvent], DetectionEvent]
TrafficMonitor = Callable[[PacketEvent | Mapping[str, Any]], tuple[TrafficEvent, ...]]
PacketProcessor = Callable[[PacketEvent, PacketEvent | Mapping[str, Any]], Any]
SleepFunction = Callable[[float], None]
_LOGGER = get_logger("replay")


@dataclass(frozen=True)
class ReplayResult:

    packet_count: int
    detection_events: tuple[DetectionEvent, ...]
    traffic_events: tuple[TrafficEvent, ...]
    packet_results: tuple[Any, ...] = ()
    errors: int = 0


# FUN-089
def replay_pcap(
    pcap_path: str | Path,
    delay_seconds: float = 0,
    *,
    detector_handler: DetectorHandler | None = None,
    traffic_monitor: TrafficMonitor | None = None,
    packet_processor: PacketProcessor | None = None,
    sleep_func: SleepFunction = time.sleep,
) -> ReplayResult:
    _validate_delay(delay_seconds)
    packet_events = parse_pcap(pcap_path)
    return replay_events(
        packet_events,
        delay_seconds=delay_seconds,
        detector_handler=detector_handler,
        traffic_monitor=traffic_monitor,
        packet_processor=packet_processor,
        sleep_func=sleep_func,
    )


# FUN-090
def replay_events(
    packets: Iterable[PacketEvent | Mapping[str, Any]],
    delay_seconds: float = 0,
    *,
    detector_handler: DetectorHandler | None = None,
    traffic_monitor: TrafficMonitor | None = None,
    packet_processor: PacketProcessor | None = None,
    sleep_func: SleepFunction = time.sleep,
) -> ReplayResult:
    delay = _validate_delay(delay_seconds)
    detect = (
        None if packet_processor is not None else detector_handler or detector.detect_packet
    )
    monitor = (
        None
        if packet_processor is not None
        else traffic_monitor or dns_http_monitor.register_traffic
    )

    packet_items = tuple(packets)
    detection_events: list[DetectionEvent] = []
    traffic_events: list[TrafficEvent] = []
    packet_results: list[Any] = []
    errors = 0

    for index, packet in enumerate(packet_items):
        packet_event = _to_packet_event(packet)

        try:
            if packet_processor is not None:
                result = packet_processor(packet_event, packet)
                packet_results.append(result)
                _collect_processor_result(
                    result,
                    detection_events=detection_events,
                    traffic_events=traffic_events,
                )
            else:
                assert detect is not None
                assert monitor is not None
                detection_events.append(detect(packet_event))
                traffic_events.extend(monitor(packet))
        except Exception as exc:
            errors += 1
            _LOGGER.exception("REPLAY | packet processing failed: %s", exc)

        if delay > 0 and index < len(packet_items) - 1:
            sleep_func(delay)

    return ReplayResult(
        packet_count=len(packet_items),
        detection_events=tuple(detection_events),
        traffic_events=tuple(traffic_events),
        packet_results=tuple(packet_results),
        errors=errors,
    )


def _to_packet_event(packet: PacketEvent | Mapping[str, Any]) -> PacketEvent:
    if isinstance(packet, PacketEvent):
        return packet

    return parse_packet(packet)


def _validate_delay(delay_seconds: float) -> float:
    try:
        delay = float(delay_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("delay_seconds must be a non-negative number") from exc

    if delay < 0:
        raise ValueError("delay_seconds must be a non-negative number")

    return delay


def _collect_processor_result(
    result: Any,
    *,
    detection_events: list[DetectionEvent],
    traffic_events: list[TrafficEvent],
) -> None:
    detection_event = getattr(result, "detection_event", None)
    if detection_event is not None:
        detection_events.append(detection_event)

    dns_http_events = getattr(result, "dns_http_events", ())
    traffic_events.extend(dns_http_events)
