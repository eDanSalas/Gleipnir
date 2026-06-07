"""Unit tests for the Gleipnir Flask dashboard."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("flask")

from src.dashboard.app import ADMIN_LIST_ACTION, DashboardError, create_app
from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.storage import ALERT_SENT, DNS_EVENT, HTTP_EVENT, SQLiteEventStore
from src.whitelist import load_whitelist
from src.blacklist import list_blacklist_entries


def test_create_dashboard_app(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "events.db"))

    assert app.name == "src.dashboard.app"


def test_dashboard_index_handles_missing_sqlite(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b"SQLite database not found yet" in response.data
    assert b"Total de eventos" in response.data


def test_dashboard_health_handles_missing_sqlite(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/health")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["database_exists"] is False
    assert payload["total_events"] == 0


def test_dashboard_events_handles_missing_sqlite(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/events")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["database_exists"] is False
    assert payload["summary"]["total_events"] == 0
    assert payload["events"] == []


def test_dashboard_handles_existing_empty_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    store.initialize()
    store.close()
    app = create_app(config=_config(db_path))

    response = app.test_client().get("/events")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["database_exists"] is True
    assert payload["summary"]["total_events"] == 0
    assert payload["events"] == []
    assert "no IDS events" in payload["message"]


def test_dashboard_summarizes_existing_events(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    store.save_event(event_type=AUTHORIZED_DEVICE, timestamp=1, message="authorized")
    store.save_event(event_type=UNAUTHORIZED_DEVICE, timestamp=2, message="unauthorized")
    store.save_event(event_type=DNS_EVENT, timestamp=3, domain="example.org")
    store.save_event(event_type=HTTP_EVENT, timestamp=4, domain="example.org")
    store.save_event(event_type=BLACKLISTED_EXTERNAL_IP, timestamp=5, destination_ip="8.8.8.8")
    store.save_event(event_type=ALERT_SENT, timestamp=6, message="alert sent")
    store.close()
    app = create_app(config=_config(db_path))

    response = app.test_client().get("/events")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["summary"]["total_events"] == 6
    assert payload["summary"]["authorized_devices"] == 1
    assert payload["summary"]["unauthorized_devices"] == 1
    assert payload["summary"]["dns_events"] == 1
    assert payload["summary"]["http_events"] == 1
    assert payload["summary"]["blacklisted_external_ips"] == 1
    assert payload["summary"]["alerts_sent"] == 1
    assert len(payload["events"]) == 6
    assert payload["events"][0]["event_type"] == ALERT_SENT


def test_dashboard_event_detail_route(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    event_id = store.save_event(
        event_type=DNS_EVENT,
        timestamp=3,
        severity="INFO",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        protocol="DNS",
        domain="example.org",
        message="dns detail",
    )
    store.close()
    app = create_app(config=_config(db_path))

    response = app.test_client().get(f"/events/{event_id}")

    assert response.status_code == 200
    assert b"Detalle de evento IDS" in response.data
    assert b"DNS_EVENT" in response.data
    assert b"example.org" in response.data


def test_dashboard_event_detail_route_returns_friendly_404(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path)
    store.initialize()
    store.close()
    app = create_app(config=_config(db_path))

    response = app.test_client().get("/events/999")

    assert response.status_code == 404
    assert b"Evento no encontrado" in response.data


def test_dashboard_auth_disabled_allows_access_without_credentials(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=False,
        )
    )

    response = app.test_client().get("/health")

    assert response.status_code == 200


def test_dashboard_auth_enabled_requires_credentials(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
        )
    )

    response = app.test_client().get("/")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Gleipnir Dashboard"'
    assert b"secret-password" not in response.data


def test_dashboard_auth_enabled_accepts_valid_credentials(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
        )
    )

    response = app.test_client().get(
        "/events",
        headers={"Authorization": _basic_auth("admin", "secret-password")},
    )

    assert response.status_code == 200
    assert response.get_json()["database_exists"] is False


def test_dashboard_auth_enabled_rejects_invalid_credentials(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
        )
    )

    response = app.test_client().get(
        "/events",
        headers={"Authorization": _basic_auth("admin", "wrong-password")},
    )

    assert response.status_code == 401
    assert b"wrong-password" not in response.data
    assert b"secret-password" not in response.data


def test_dashboard_auth_enabled_requires_configured_credentials(tmp_path: Path) -> None:
    with pytest.raises(DashboardError, match="DASHBOARD_USERNAME"):
        create_app(
            config=_config(
                tmp_path / "missing.db",
                dashboard_auth_enabled=True,
                dashboard_username="",
                dashboard_password="",
            )
        )


def test_dashboard_admin_lists_unavailable_when_auth_is_disabled(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=False,
        )
    )

    response = app.test_client().get("/admin/lists")

    assert response.status_code == 404
    assert b"Administracion no disponible" in response.data


def test_dashboard_admin_lists_requires_authentication(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
        )
    )

    response = app.test_client().get("/admin/lists")

    assert response.status_code == 401


def test_dashboard_admin_lists_adds_whitelist_entry_and_audits(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
    )
    app = create_app(config=config)

    response = app.test_client().post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "description": "Laptop laboratorio",
        },
        headers={"Authorization": _basic_auth("admin", "secret-password")},
    )

    entries = load_whitelist(config.whitelist_file)
    audit_events = _fetch_admin_audit_events(config.ids_db_path)

    assert response.status_code == 200
    assert b"Whitelist entry added" in response.data
    assert entries[0].ip == "192.168.1.20"
    assert entries[0].mac == "aa:bb:cc:dd:ee:20"
    assert audit_events[-1].event_type == ADMIN_LIST_ACTION
    assert audit_events[-1].raw["action"] == "whitelist_add"


def test_dashboard_admin_lists_rejects_duplicate_whitelist_entry(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
    )
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}

    app.test_client().post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "description": "Laptop laboratorio",
        },
        headers=auth_header,
    )
    response = app.test_client().post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:21",
            "description": "Duplicado",
        },
        headers=auth_header,
    )

    entries = load_whitelist(config.whitelist_file)

    assert response.status_code == 200
    assert b"already contains IP address" in response.data
    assert len(entries) == 1


def test_dashboard_admin_lists_manages_blacklist_entries(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
    )
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}

    add_response = app.test_client().post(
        "/admin/lists",
        data={
            "action": "blacklist_add",
            "ip": "8.8.8.8",
            "reason": "IP externa reportada",
        },
        headers=auth_header,
    )
    validate_response = app.test_client().post(
        "/admin/lists",
        data={"action": "blacklist_validate"},
        headers=auth_header,
    )
    remove_response = app.test_client().post(
        "/admin/lists",
        data={"action": "blacklist_remove", "ip": "8.8.8.8"},
        headers=auth_header,
    )

    entries = list_blacklist_entries(config.blacklist_file)
    audit_events = _fetch_admin_audit_events(config.ids_db_path)

    assert add_response.status_code == 200
    assert b"Blacklist entry added" in add_response.data
    assert validate_response.status_code == 200
    assert b"Blacklist valid" in validate_response.data
    assert remove_response.status_code == 200
    assert b"Blacklist entry removed" in remove_response.data
    assert entries == ()
    assert {event.raw["action"] for event in audit_events} >= {
        "blacklist_add",
        "blacklist_validate",
        "blacklist_remove",
    }


def _config(
    db_path: Path,
    *,
    dashboard_auth_enabled: bool = False,
    dashboard_username: str | None = None,
    dashboard_password: str | None = None,
) -> SimpleNamespace:
    root = db_path.parent
    return SimpleNamespace(
        ids_db_path=db_path,
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
        log_dir=root / "logs",
        dashboard_auth_enabled=dashboard_auth_enabled,
        dashboard_username=dashboard_username,
        dashboard_password=dashboard_password,
    )


def _basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _fetch_admin_audit_events(db_path: Path):
    store = SQLiteEventStore(db_path)
    try:
        return store.fetch_events(ADMIN_LIST_ACTION)
    finally:
        store.close()
