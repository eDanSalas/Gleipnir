
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from src.dashboard.app import (
    DashboardFilters,
    _filters_from_query,
    _load_dashboard_data,
    _load_event_detail,
    _render_event_detail_html,
    _render_event_not_found_html,
    _render_event_row,
)
from src.detector import AUTHORIZED_DEVICE, UNAUTHORIZED_DEVICE
from src.storage import (
    ALERT_SENT,
    ALERT_SUPPRESSED,
    DNS_EVENT,
    HTTP_EVENT,
    SQLiteEventStore,
    StoredEvent,
)


def test_dashboard_filter_by_event_type(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)

    data = _load_dashboard_data(
        _config(db_path),
        filters=DashboardFilters(event_type=UNAUTHORIZED_DEVICE),
    )

    assert data.summary["total_events"] == 1
    assert data.latest_events[0]["event_type"] == UNAUTHORIZED_DEVICE


def test_dashboard_filter_by_severity_alias(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)

    data = _load_dashboard_data(_config(db_path), filters=DashboardFilters(severity="high"))

    assert data.summary["total_events"] == 1
    assert data.latest_events[0]["severity"] == "ALTA"


def test_dashboard_filter_by_source_destination_mac_domain_and_protocol(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)

    data = _load_dashboard_data(
        _config(db_path),
        filters=DashboardFilters(
            source_ip="192.168.1.20",
            destination_ip="8.8.8.8",
            source_mac="aa:bb:cc:dd:ee:02",
            domain="example.com",
            protocol="DNS",
        ),
    )

    assert data.summary["total_events"] == 1
    assert data.latest_events[0]["event_type"] == DNS_EVENT
    assert data.latest_events[0]["domain"] == "example.com"


def test_dashboard_filter_by_date_range(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)
    filters = _filters_from_query(
        {
            "since": "2026-06-01",
            "until": "2026-06-07",
        }
    )

    data = _load_dashboard_data(_config(db_path), filters=filters)

    assert data.summary["total_events"] == 2
    assert {event["event_type"] for event in data.latest_events} == {
        HTTP_EVENT,
        DNS_EVENT,
    }


def test_dashboard_combined_query_params(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)
    filters = _filters_from_query(
        {
            "type": "dns_event",
            "severity": "info",
            "source_ip": "192.168.1.20",
            "domain": "example",
            "protocol": "dns",
        }
    )

    data = _load_dashboard_data(_config(db_path), filters=filters)

    assert data.summary["total_events"] == 1
    assert data.filters.as_payload()["type"] == "DNS_EVENT"
    assert data.filters.as_payload()["protocol"] == "DNS"


def test_dashboard_without_filters_shows_latest_50_events(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    for index in range(55):
        store.save_event(
            event_type=DNS_EVENT,
            timestamp=float(index),
            message=f"event {index}",
        )
    store.close()

    data = _load_dashboard_data(_config(db_path))

    assert data.summary["total_events"] == 55
    assert len(data.latest_events) == 50
    assert data.latest_events[0]["message"] == "event 54"
    assert data.latest_events[-1]["message"] == "event 5"


def test_dashboard_does_not_fail_when_database_is_empty(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    store.initialize()
    store.close()

    data = _load_dashboard_data(_config(db_path), filters=DashboardFilters(domain="none"))

    assert data.database_exists is True
    assert data.summary["total_events"] == 0
    assert data.latest_events == ()
    assert "no events match" in data.message


def test_dashboard_builds_chart_data_from_sqlite_events(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    _seed_events(db_path)
    store = SQLiteEventStore(db_path)
    store.save_event(
        event_type=ALERT_SENT,
        timestamp=_ts(2026, 6, 10),
        severity="MEDIA",
        destination_ip="8.8.8.8",
        message="alert sent",
    )
    store.save_event(
        event_type=ALERT_SUPPRESSED,
        timestamp=_ts(2026, 6, 10),
        severity="MEDIA",
        destination_ip="8.8.4.4",
        message="alert suppressed",
    )
    store.close()

    data = _load_dashboard_data(_config(db_path))

    assert _chart_value(data.charts["events_by_type"], DNS_EVENT) == 1
    assert _chart_value(data.charts["events_by_severity"], "INFO") == 2
    assert _chart_value(data.charts["events_by_hour"], "00:00 UTC") == 6
    assert _chart_value(data.charts["top_domains"], "example.com") == 2
    assert _chart_value(data.charts["top_external_ips"], "8.8.8.8") == 2
    assert _chart_value(data.charts["alerts"], ALERT_SENT) == 1
    assert _chart_value(data.charts["alerts"], ALERT_SUPPRESSED) == 1


def test_dashboard_loads_event_detail_by_id(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    event_id = store.save_event(
        event_type=DNS_EVENT,
        timestamp=_ts(2026, 6, 7),
        severity="INFO",
        source_ip="192.168.1.20",
        source_mac="aa:bb:cc:dd:ee:02",
        destination_ip="8.8.8.8",
        protocol="DNS",
        domain="example.com",
        message="dns detail",
        raw={"tipo_consulta": "A"},
    )
    store.close()

    event = _load_event_detail(_config(db_path), event_id)

    assert event is not None
    assert event.id == event_id
    assert event.event_type == DNS_EVENT
    assert event.domain == "example.com"


def test_dashboard_event_detail_returns_none_when_database_is_missing(
    tmp_path: Path,
) -> None:
    event = _load_event_detail(_config(tmp_path / "missing.db"), 1)

    assert event is None


def test_dashboard_event_row_links_to_detail() -> None:
    row = _render_event_row(
        {
            "id": 42,
            "event_type": DNS_EVENT,
            "severity": "INFO",
            "source_ip": "192.168.1.20",
            "source_mac": "aa:bb:cc:dd:ee:02",
            "destination_ip": "8.8.8.8",
            "protocol": "DNS",
            "domain": "example.com",
            "message": "dns",
        }
    )

    assert 'href="/events/42"' in row
    assert ">42</a>" in row


def test_dashboard_event_detail_renders_required_fields_and_redacts_raw_json() -> None:
    event = StoredEvent(
        id=7,
        timestamp=_ts(2026, 6, 7),
        event_type=UNAUTHORIZED_DEVICE,
        severity="ALTA",
        source_ip="192.168.1.30",
        source_mac="aa:bb:cc:dd:ee:03",
        destination_ip="8.8.8.8",
        destination_mac="ff:ee:dd:cc:bb:aa",
        protocol="TCP",
        domain="example.com",
        message="unauthorized detail",
        raw_json='{"api_key": "real-key", "nested": {"token": "real-token"}, "safe": "ok"}',
    )

    rendered = _render_event_detail_html(event)

    assert "Detalle de evento IDS" in rendered
    assert "UNAUTHORIZED_DEVICE" in rendered
    assert "192.168.1.30" in rendered
    assert "ff:ee:dd:cc:bb:aa" in rendered
    assert "unauthorized detail" in rendered
    assert "[REDACTED]" in rendered
    assert "real-key" not in rendered
    assert "real-token" not in rendered
    assert "ok" in rendered


def test_dashboard_event_not_found_page_is_friendly() -> None:
    rendered = _render_event_not_found_html(404)

    assert "Evento no encontrado" in rendered
    assert "ID 404" in rendered
    assert "Volver al dashboard" in rendered


def _seed_events(db_path: Path) -> None:
    store = SQLiteEventStore(db_path)
    store.save_event(
        event_type=AUTHORIZED_DEVICE,
        timestamp=_ts(2026, 5, 31),
        severity="BAJA",
        source_ip="192.168.1.10",
        source_mac="aa:bb:cc:dd:ee:01",
        destination_ip="1.1.1.1",
        protocol="TCP",
        message="authorized",
    )
    store.save_event(
        event_type=DNS_EVENT,
        timestamp=_ts(2026, 6, 3),
        severity="INFO",
        source_ip="192.168.1.20",
        source_mac="aa:bb:cc:dd:ee:02",
        destination_ip="8.8.8.8",
        protocol="DNS",
        domain="example.com",
        message="dns",
    )
    store.save_event(
        event_type=HTTP_EVENT,
        timestamp=_ts(2026, 6, 7),
        severity="INFO",
        source_ip="192.168.1.20",
        source_mac="aa:bb:cc:dd:ee:02",
        destination_ip="93.184.216.34",
        protocol="HTTP",
        domain="example.com",
        message="http",
    )
    store.save_event(
        event_type=UNAUTHORIZED_DEVICE,
        timestamp=_ts(2026, 6, 9),
        severity="ALTA",
        source_ip="192.168.1.30",
        source_mac="aa:bb:cc:dd:ee:03",
        destination_ip="8.8.4.4",
        protocol="TCP",
        message="unauthorized",
    )
    store.close()


def _ts(year: int, month: int, day: int) -> float:
    return datetime(year, month, day, tzinfo=timezone.utc).timestamp()


def _config(db_path: Path) -> SimpleNamespace:
    return SimpleNamespace(ids_db_path=db_path)


def _chart_value(rows, label: str) -> int:
    for row in rows:
        if row["label"] == label:
            return int(row["value"])
    return 0
