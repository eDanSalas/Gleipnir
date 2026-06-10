"""Unit tests for the Gleipnir Flask dashboard."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

pytest.importorskip("flask")

from src.dashboard.app import (
    ADMIN_LIST_ACTION,
    DASHBOARD_CONTENT_SECURITY_POLICY,
    SESSION_LOGIN_AT_KEY,
    DashboardError,
    create_app,
)
from src.dashboard.auth import LoginAttemptTracker, hash_dashboard_password
from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.storage import ALERT_SENT, DNS_EVENT, HTTP_EVENT, SQLiteEventStore
from src.storage import (
    ADMIN_BLACKLIST_ADD,
    ADMIN_BLACKLIST_REMOVE,
    ADMIN_LOGIN_FAILED,
    ADMIN_LOGIN_SUCCESS,
    ADMIN_LOGOUT,
    ADMIN_WHITELIST_ADD,
    ADMIN_WHITELIST_REMOVE,
    LOGIN_LOCKED,
)
from src.whitelist import load_whitelist
from src.blacklist import list_blacklist_entries


def test_create_dashboard_app(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "events.db"))

    assert app.name == "src.dashboard.app"


def test_dashboard_index_includes_security_headers(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/")

    _assert_common_security_headers(response)


def test_dashboard_health_includes_security_headers(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/health")

    _assert_common_security_headers(response)


def test_dashboard_events_includes_security_headers(tmp_path: Path) -> None:
    app = create_app(config=_config(tmp_path / "missing.db"))

    response = app.test_client().get("/events")

    _assert_common_security_headers(response)


def test_dashboard_authenticated_routes_use_no_store(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
            dashboard_role="admin",
        )
    )

    response = app.test_client().get(
        "/health",
        headers={"Authorization": _basic_auth("admin", "secret-password")},
    )

    _assert_no_store_headers(response)


def test_dashboard_admin_routes_use_no_store(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
            dashboard_role="admin",
        )
    )

    response = app.test_client().get(
        "/admin/lists",
        headers={"Authorization": _basic_auth("admin", "secret-password")},
    )

    assert response.status_code == 200
    _assert_common_security_headers(response)
    _assert_no_store_headers(response)


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


def test_dashboard_login_accepts_valid_credentials(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    app = create_app(
        config=config
    )
    client = app.test_client()

    login_response = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.50"},
    )
    events_response = client.get("/events")
    audit_events = _fetch_events(config.ids_db_path, ADMIN_LOGIN_SUCCESS)

    assert login_response.status_code == 302
    assert login_response.headers["Location"] == "/"
    assert events_response.status_code == 200
    assert audit_events[-1].raw["user"] == "viewer"
    assert audit_events[-1].raw["action"] == "login"
    assert audit_events[-1].raw["remote_ip"] == "192.168.10.50"
    assert audit_events[-1].raw["result"] == "success"
    _assert_audit_event_has_no_secrets(audit_events[-1])


def test_dashboard_login_accepts_admin_from_users_file(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_users=[
            _dashboard_user("admin", "admin-password", role="admin"),
        ],
    )
    app = create_app(config=config)

    response = app.test_client().post(
        "/login",
        data={"username": "admin", "password": "admin-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_dashboard_login_accepts_viewer_from_users_file(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_users=[
            _dashboard_user("viewer", "viewer-password", role="viewer"),
        ],
    )
    app = create_app(config=config)

    response = app.test_client().post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_dashboard_login_rejects_disabled_user(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_users=[
            _dashboard_user("admin", "admin-password", role="admin"),
            _dashboard_user("viewer", "viewer-password", role="viewer", enabled=False),
        ],
    )
    app = create_app(config=config)

    response = app.test_client().post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
    )

    assert response.status_code == 401
    assert b"viewer-password" not in response.data


def test_dashboard_does_not_render_password_hash(tmp_path: Path) -> None:
    password_hash = hash_dashboard_password("viewer-password")
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_users=[
            _dashboard_user_from_hash("viewer", password_hash, role="viewer"),
        ],
    )
    app = create_app(config=config)

    response = app.test_client().get(
        "/",
        headers={"Authorization": _basic_auth("viewer", "viewer-password")},
    )

    assert response.status_code == 200
    assert password_hash.encode("utf-8") not in response.data


def test_dashboard_login_rejects_invalid_credentials_without_echoing_secret(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    app = create_app(
        config=config
    )

    response = app.test_client().post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.60"},
    )
    audit_events = _fetch_events(config.ids_db_path, ADMIN_LOGIN_FAILED)

    assert response.status_code == 401
    assert b"Credenciales invalidas" in response.data
    assert b"wrong-password" not in response.data
    assert b"viewer-password" not in response.data
    assert "wrong-password" not in caplog.text
    assert "viewer-password" not in caplog.text
    assert audit_events[-1].raw["user"] == "viewer"
    assert audit_events[-1].raw["action"] == "login"
    assert audit_events[-1].raw["result"] == "failed"
    assert audit_events[-1].raw["remote_ip"] == "192.168.10.60"
    _assert_audit_event_has_no_secrets(audit_events[-1])


def test_dashboard_login_lockout_blocks_after_failed_attempts(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
        dashboard_login_max_attempts=2,
        dashboard_login_lockout_seconds=300,
    )
    app = create_app(config=config)
    client = app.test_client()

    first_response = client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.90"},
    )
    second_response = client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.90"},
    )
    locked_response = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.90"},
    )
    failed_events = _fetch_events(config.ids_db_path, ADMIN_LOGIN_FAILED)
    locked_events = _fetch_events(config.ids_db_path, LOGIN_LOCKED)

    assert first_response.status_code == 401
    assert second_response.status_code == 401
    assert locked_response.status_code == 401
    assert b"Credenciales invalidas" in locked_response.data
    assert b"viewer-password" not in locked_response.data
    assert len(failed_events) == 2
    assert locked_events[-1].raw["user"] == "viewer"
    assert locked_events[-1].raw["remote_ip"] == "192.168.10.90"
    assert locked_events[-1].raw["result"] == "locked"
    _assert_audit_event_has_no_secrets(locked_events[-1])


def test_dashboard_login_lockout_expires_after_window(tmp_path: Path) -> None:
    current_time = {"value": 1000.0}
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
        dashboard_login_max_attempts=2,
        dashboard_login_lockout_seconds=10,
    )
    app = create_app(config=config)
    app.config["GLEIPNIR_LOGIN_ATTEMPTS"] = LoginAttemptTracker(
        max_attempts=2,
        lockout_seconds=10,
        time_provider=lambda: current_time["value"],
    )
    client = app.test_client()

    client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.91"},
    )
    client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.91"},
    )
    current_time["value"] = 1011.0
    response = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.91"},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_dashboard_login_success_resets_failed_attempts(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
        dashboard_login_max_attempts=2,
        dashboard_login_lockout_seconds=300,
    )
    app = create_app(config=config)
    client = app.test_client()

    client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.92"},
    )
    success_response = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.92"},
    )
    client.get("/logout")
    second_failure = client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.92"},
    )
    second_success = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.92"},
    )

    assert success_response.status_code == 302
    assert second_failure.status_code == 401
    assert second_success.status_code == 302
    assert _fetch_events(config.ids_db_path, LOGIN_LOCKED) == ()


def test_dashboard_login_lockout_message_does_not_reveal_user_existence(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
        dashboard_login_max_attempts=1,
        dashboard_login_lockout_seconds=300,
    )
    app = create_app(config=config)
    client = app.test_client()

    unknown_response = client.post(
        "/login",
        data={"username": "unknown", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.93"},
    )
    known_response = client.post(
        "/login",
        data={"username": "viewer", "password": "wrong-password"},
        environ_overrides={"REMOTE_ADDR": "192.168.10.94"},
    )

    assert unknown_response.status_code == 401
    assert known_response.status_code == 401
    assert b"Credenciales invalidas" in unknown_response.data
    assert b"Credenciales invalidas" in known_response.data
    assert b"unknown" not in unknown_response.data
    assert b"viewer" not in known_response.data


def test_dashboard_audit_falls_back_to_logger_without_sqlite(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    config.ids_db_path = None
    logger = Mock()
    app = create_app(config=config)

    with patch("src.logger.setup_logging") as setup_logging:
        with patch("src.logger.get_logger", return_value=logger) as get_logger:
            response = app.test_client().post(
                "/login",
                data={"username": "viewer", "password": "wrong-password"},
            )

    assert response.status_code == 401
    setup_logging.assert_called()
    get_logger.assert_called_with("dashboard_admin")
    logger.info.assert_called()
    logged_message = str(logger.info.call_args.args[0])
    assert "Dashboard login failed" in logged_message
    assert "wrong-password" not in logged_message
    assert "viewer-password" not in logged_message
    assert "token" not in logged_message.lower()


def test_dashboard_logout_clears_session(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "missing.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    app = create_app(
        config=config
    )
    client = app.test_client()
    client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
    )

    assert client.get("/events").status_code == 200
    logout_response = client.get("/logout")
    blocked_response = client.get("/events")

    assert logout_response.status_code == 302
    assert logout_response.headers["Location"] == "/login"
    assert blocked_response.status_code == 401
    logout_events = _fetch_events(config.ids_db_path, ADMIN_LOGOUT)
    assert logout_events[-1].raw["user"] == "viewer"
    assert logout_events[-1].raw["action"] == "logout"
    assert logout_events[-1].raw["result"] == "success"
    _assert_audit_event_has_no_secrets(logout_events[-1])


def test_dashboard_session_expiration_blocks_access(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="viewer",
            dashboard_password="viewer-password",
            dashboard_role="viewer",
            dashboard_session_timeout_minutes=1,
        )
    )
    client = app.test_client()
    client.post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
    )
    with client.session_transaction() as active_session:
        active_session[SESSION_LOGIN_AT_KEY] = 0.0

    response = client.get("/events")

    assert response.status_code == 401
    assert b"Acceso al dashboard local" in response.data


def test_dashboard_session_cookie_settings(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="viewer",
            dashboard_password="viewer-password",
            dashboard_role="viewer",
            dashboard_session_cookie_secure=True,
        )
    )

    response = app.test_client().post(
        "/login",
        data={"username": "viewer", "password": "viewer-password"},
    )
    cookie_header = response.headers["Set-Cookie"]

    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header
    assert "Secure" in cookie_header


def test_dashboard_viewer_can_access_read_only_dashboard(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="viewer",
            dashboard_password="viewer-password",
            dashboard_role="viewer",
        )
    )

    response = app.test_client().get(
        "/",
        headers={"Authorization": _basic_auth("viewer", "viewer-password")},
    )

    assert response.status_code == 200
    assert b"Administrar listas" not in response.data


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


def test_dashboard_unauthenticated_access_is_blocked(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "missing.db",
            dashboard_auth_enabled=True,
            dashboard_username="viewer",
            dashboard_password="viewer-password",
        )
    )

    response = app.test_client().get("/events")

    assert response.status_code == 401
    assert b"Acceso al dashboard local" in response.data


def test_dashboard_auth_enabled_requires_configured_users_file(tmp_path: Path) -> None:
    with pytest.raises(DashboardError, match="DASHBOARD_USERS_FILE"):
        create_app(
            config=_config(
                tmp_path / "missing.db",
                dashboard_auth_enabled=True,
                dashboard_users_file=tmp_path / "missing_users.json",
            )
        )


def test_dashboard_auth_enabled_requires_secret_key(tmp_path: Path) -> None:
    with pytest.raises(DashboardError, match="DASHBOARD_SECRET_KEY"):
        create_app(
            config=_config(
                tmp_path / "missing.db",
                dashboard_auth_enabled=True,
                dashboard_username="admin",
                dashboard_password="secret-password",
                dashboard_secret_key="",
            )
        )


def test_dashboard_warns_when_deprecated_credentials_are_present(tmp_path: Path) -> None:
    with pytest.warns(RuntimeWarning, match="deprecated"):
        create_app(
            config=_config(
                tmp_path / "missing.db",
                dashboard_auth_enabled=True,
                dashboard_username="viewer",
                dashboard_password="viewer-password",
                deprecated_dashboard_env_vars=(
                    "DASHBOARD_USERNAME",
                    "DASHBOARD_PASSWORD",
                    "DASHBOARD_ROLE",
                ),
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


def test_dashboard_viewer_receives_403_on_admin_lists(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="viewer",
            dashboard_password="viewer-password",
            dashboard_role="viewer",
        )
    )
    auth_header = {"Authorization": _basic_auth("viewer", "viewer-password")}

    get_response = app.test_client().get("/admin/lists", headers=auth_header)
    post_response = app.test_client().post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "description": "Viewer blocked",
        },
        headers=auth_header,
    )

    assert get_response.status_code == 403
    assert b"Acceso denegado" in get_response.data
    assert post_response.status_code == 403


def test_dashboard_admin_lists_adds_whitelist_entry_and_audits(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    csrf_token = _csrf_token(client, auth_header)

    response = client.post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "csrf_token": csrf_token,
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "description": "Laptop laboratorio",
        },
        headers=auth_header,
        environ_overrides={"REMOTE_ADDR": "192.168.10.70"},
    )

    entries = load_whitelist(config.whitelist_file)
    audit_events = _fetch_admin_audit_events(config.ids_db_path)
    specific_events = _fetch_events(config.ids_db_path, ADMIN_WHITELIST_ADD)

    assert response.status_code == 200
    assert b"Whitelist entry added" in response.data
    assert entries[0].ip == "192.168.1.20"
    assert entries[0].mac == "aa:bb:cc:dd:ee:20"
    assert audit_events[-1].event_type == ADMIN_LIST_ACTION
    assert audit_events[-1].raw["action"] == "whitelist_add"
    assert specific_events[-1].raw["user"] == "admin"
    assert specific_events[-1].raw["action"] == "whitelist_add"
    assert specific_events[-1].raw["remote_ip"] == "192.168.10.70"
    assert specific_events[-1].raw["result"] == "success"
    _assert_audit_event_has_no_secrets(specific_events[-1])


def test_dashboard_admin_lists_rejects_duplicate_whitelist_entry(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    csrf_token = _csrf_token(client, auth_header)

    client.post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "csrf_token": csrf_token,
            "ip": "192.168.1.20",
            "mac": "AA:BB:CC:DD:EE:20",
            "description": "Laptop laboratorio",
        },
        headers=auth_header,
    )
    response = client.post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "csrf_token": csrf_token,
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
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    csrf_token = _csrf_token(client, auth_header)

    add_response = client.post(
        "/admin/lists",
        data={
            "action": "blacklist_add",
            "csrf_token": csrf_token,
            "ip": "8.8.8.8",
            "reason": "IP externa reportada",
        },
        headers=auth_header,
    )
    validate_response = client.post(
        "/admin/lists",
        data={"action": "blacklist_validate", "csrf_token": csrf_token},
        headers=auth_header,
    )
    remove_response = client.post(
        "/admin/lists",
        data={
            "action": "blacklist_remove",
            "csrf_token": csrf_token,
            "ip": "8.8.8.8",
        },
        headers=auth_header,
    )

    entries = list_blacklist_entries(config.blacklist_file)
    audit_events = _fetch_admin_audit_events(config.ids_db_path)
    blacklist_add_events = _fetch_events(config.ids_db_path, ADMIN_BLACKLIST_ADD)
    blacklist_remove_events = _fetch_events(config.ids_db_path, ADMIN_BLACKLIST_REMOVE)

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
    assert blacklist_add_events[-1].raw["user"] == "admin"
    assert blacklist_add_events[-1].raw["action"] == "blacklist_add"
    assert blacklist_add_events[-1].raw["result"] == "success"
    assert blacklist_remove_events[-1].raw["user"] == "admin"
    assert blacklist_remove_events[-1].raw["action"] == "blacklist_remove"
    assert blacklist_remove_events[-1].raw["result"] == "success"
    _assert_audit_event_has_no_secrets(blacklist_add_events[-1])
    _assert_audit_event_has_no_secrets(blacklist_remove_events[-1])


def test_dashboard_admin_lists_records_whitelist_remove_audit(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    csrf_token = _csrf_token(client, auth_header)
    client.post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "csrf_token": csrf_token,
            "ip": "192.168.1.25",
            "mac": "AA:BB:CC:DD:EE:25",
            "description": "Temporal",
        },
        headers=auth_header,
    )

    response = client.post(
        "/admin/lists",
        data={
            "action": "whitelist_remove",
            "csrf_token": csrf_token,
            "ip": "192.168.1.25",
        },
        headers=auth_header,
        environ_overrides={"REMOTE_ADDR": "192.168.10.80"},
    )
    remove_events = _fetch_events(config.ids_db_path, ADMIN_WHITELIST_REMOVE)

    assert response.status_code == 200
    assert remove_events[-1].raw["user"] == "admin"
    assert remove_events[-1].raw["action"] == "whitelist_remove"
    assert remove_events[-1].raw["remote_ip"] == "192.168.10.80"
    assert remove_events[-1].raw["result"] == "success"
    _assert_audit_event_has_no_secrets(remove_events[-1])


def test_dashboard_admin_lists_rejects_missing_csrf_token(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
            dashboard_role="admin",
        )
    )
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    client.get("/admin/lists", headers=auth_header)

    response = client.post(
        "/admin/lists",
        data={
            "action": "whitelist_add",
            "ip": "192.168.1.30",
            "mac": "AA:BB:CC:DD:EE:30",
            "description": "Sin token",
        },
        headers=auth_header,
    )

    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_dashboard_admin_lists_rejects_invalid_csrf_token(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
            dashboard_role="admin",
        )
    )
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    _csrf_token(client, auth_header)

    response = client.post(
        "/admin/lists",
        data={
            "action": "blacklist_add",
            "csrf_token": "invalid-token",
            "ip": "8.8.8.8",
            "reason": "Token invalido",
        },
        headers=auth_header,
    )

    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_dashboard_read_only_routes_do_not_require_csrf(tmp_path: Path) -> None:
    app = create_app(
        config=_config(
            tmp_path / "events.db",
            dashboard_auth_enabled=True,
            dashboard_username="admin",
            dashboard_password="secret-password",
            dashboard_role="admin",
        )
    )
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}

    assert client.get("/", headers=auth_header).status_code == 200
    assert client.get("/health", headers=auth_header).status_code == 200
    assert client.get("/events", headers=auth_header).status_code == 200


def test_dashboard_optional_admin_credentials_can_manage_lists(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
        dashboard_admin_username="admin",
        dashboard_admin_password="admin-password",
    )
    app = create_app(config=config)
    client = app.test_client()
    viewer_header = {"Authorization": _basic_auth("viewer", "viewer-password")}
    admin_header = {"Authorization": _basic_auth("admin", "admin-password")}

    assert client.get("/admin/lists", headers=viewer_header).status_code == 403
    csrf_token = _csrf_token(client, admin_header)
    response = client.post(
        "/admin/lists",
        data={
            "action": "blacklist_add",
            "csrf_token": csrf_token,
            "ip": "8.8.4.4",
            "reason": "Admin separado",
        },
        headers=admin_header,
    )

    assert response.status_code == 200
    assert list_blacklist_entries(config.blacklist_file)[0].ip == "8.8.4.4"


def test_dashboard_viewer_cannot_access_admin_ips(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("viewer", "viewer-password")}

    response = app.test_client().get("/admin/ips", headers=auth_header)
    assert response.status_code == 403


def test_dashboard_admin_can_view_ips_page(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="admin-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("admin", "admin-password")}

    response = app.test_client().get("/admin/ips", headers=auth_header)
    assert response.status_code == 200
    assert "IPS/Firewall".encode("utf-8") in response.data
    assert b"ips_enabled" in response.data


def test_dashboard_admin_ips_post_without_csrf_fails(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="admin-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("admin", "admin-password")}

    response = app.test_client().post(
        "/admin/ips",
        data={"action": "ips_update", "ips_enabled": "true"},
        headers=auth_header,
    )
    assert response.status_code == 400


def test_dashboard_admin_ips_update_saves_config(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="admin-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "admin-password")}
    csrf_token = _csrf_token(client, auth_header)

    response = client.post(
        "/admin/ips",
        data={
            "action": "ips_update",
            "csrf_token": csrf_token,
            "ips_enabled": "true",
            "dry_run": "true",
            "allowlist_policy": "block_unregistered",
            "blacklist_policy": "block",
            "block_direction": "outbound",
            "blacklist_check_private": "false",
            "auto_apply": "false",
        },
        headers=auth_header,
        environ_overrides={"REMOTE_ADDR": "192.168.10.90"},
    )

    from src.ips_config import load_ips_config

    assert response.status_code == 200
    assert "Configuracion IPS actualizada".encode("utf-8") in response.data
    saved = load_ips_config(config)
    assert saved["ips_enabled"] is True
    assert saved["allowlist_policy"] == "block_unregistered"
    assert saved["block_direction"] == "outbound"

    assert len(_fetch_events(config.ids_db_path, "ADMIN_IPS_CONFIG_CHANGED")) >= 1
    assert len(_fetch_events(config.ids_db_path, "ADMIN_IPS_ENABLED")) >= 1


def test_dashboard_admin_ips_apply_without_permissions_shows_clear_error(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="admin-password",
        dashboard_role="admin",
    )
    # Make IPS effectively active with auto_apply so we reach the permission gate.
    from src.ips_config import save_ips_config

    save_ips_config(
        {"ips_enabled": True, "dry_run": False, "auto_apply": True},
        config,
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "admin-password")}
    csrf_token = _csrf_token(client, auth_header)

    with patch("src.firewall.is_nft_available", return_value=False):
        response = client.post(
            "/admin/ips",
            data={"action": "ips_apply", "csrf_token": csrf_token},
            headers=auth_header,
        )

    assert response.status_code == 200
    assert b"no tiene permisos" in response.data
    assert b"sudo .venv/bin/gleipnir ips apply" in response.data


def test_dashboard_admin_ips_apply_blocked_when_auto_apply_false(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="admin-password",
        dashboard_role="admin",
    )
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "admin-password")}
    csrf_token = _csrf_token(client, auth_header)

    response = client.post(
        "/admin/ips",
        data={"action": "ips_apply", "csrf_token": csrf_token},
        headers=auth_header,
    )

    assert response.status_code == 200
    assert b"auto_apply=true" in response.data


def test_dashboard_admin_can_change_admin_email(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password="secret-password",
        dashboard_role="admin",
    )
    config.admin_email = "old@example.org"
    app = create_app(config=config)
    client = app.test_client()
    auth_header = {"Authorization": _basic_auth("admin", "secret-password")}
    csrf_token = _csrf_token(client, auth_header)

    get_response = client.get("/admin/lists", headers=auth_header)
    assert b"Correo del administrador" in get_response.data
    assert b"old@example.org" in get_response.data

    with patch("src.config.set_admin_email", return_value="new@example.org") as setter:
        response = client.post(
            "/admin/lists",
            data={
                "action": "admin_email_set",
                "csrf_token": csrf_token,
                "admin_email": "new@example.org",
            },
            headers=auth_header,
            environ_overrides={"REMOTE_ADDR": "192.168.10.70"},
        )

    setter.assert_called_once_with("new@example.org")
    assert response.status_code == 200
    assert "Correo del administrador actualizado".encode("utf-8") in response.data
    audit_events = _fetch_admin_audit_events(config.ids_db_path)
    assert audit_events[-1].raw["action"] == "admin_email_set"
    assert audit_events[-1].raw["user"] == "admin"
    assert audit_events[-1].raw["result"] == "success"


def test_dashboard_viewer_cannot_change_admin_email(tmp_path: Path) -> None:
    config = _config(
        tmp_path / "events.db",
        dashboard_auth_enabled=True,
        dashboard_username="viewer",
        dashboard_password="viewer-password",
        dashboard_role="viewer",
    )
    config.admin_email = "old@example.org"
    app = create_app(config=config)
    auth_header = {"Authorization": _basic_auth("viewer", "viewer-password")}

    with patch("src.config.set_admin_email") as setter:
        response = app.test_client().post(
            "/admin/lists",
            data={"action": "admin_email_set", "admin_email": "new@example.org"},
            headers=auth_header,
        )

    assert response.status_code == 403
    setter.assert_not_called()


def _config(
    db_path: Path,
    *,
    dashboard_auth_enabled: bool = False,
    dashboard_username: str | None = None,
    dashboard_password: str | None = None,
    dashboard_role: str = "viewer",
    dashboard_admin_username: str | None = None,
    dashboard_admin_password: str | None = None,
    dashboard_secret_key: str | None = "test-dashboard-secret-key",
    dashboard_users_file: Path | None = None,
    dashboard_users: list[dict[str, object]] | None = None,
    deprecated_dashboard_env_vars: tuple[str, ...] = (),
    dashboard_session_cookie_secure: bool = False,
    dashboard_session_timeout_minutes: int = 30,
    dashboard_login_max_attempts: int = 5,
    dashboard_login_lockout_seconds: int = 300,
) -> SimpleNamespace:
    root = db_path.parent
    users_file = dashboard_users_file or root / "dashboard_users.json"
    if dashboard_users is not None:
        _write_dashboard_users(users_file, dashboard_users)
    elif dashboard_auth_enabled:
        generated_users = []
        if dashboard_username and dashboard_password:
            generated_users.append(
                _dashboard_user(
                    dashboard_username,
                    dashboard_password,
                    role=dashboard_role,
                )
            )
        if dashboard_admin_username and dashboard_admin_password:
            generated_users.append(
                _dashboard_user(
                    dashboard_admin_username,
                    dashboard_admin_password,
                    role="admin",
                )
            )
        if generated_users:
            _write_dashboard_users(users_file, generated_users)

    return SimpleNamespace(
        ids_db_path=db_path,
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
        log_dir=root / "logs",
        ips_backend="nftables",
        ips_table="gleipnir",
        ips_chain="gleipnir_filter",
        ips_config_file=root / "ips_config.json",
        dashboard_auth_enabled=dashboard_auth_enabled,
        dashboard_users_file=users_file,
        dashboard_username=dashboard_username,
        dashboard_password=dashboard_password,
        dashboard_role=dashboard_role,
        dashboard_admin_username=dashboard_admin_username,
        dashboard_admin_password=dashboard_admin_password,
        dashboard_secret_key=dashboard_secret_key,
        dashboard_session_cookie_secure=dashboard_session_cookie_secure,
        dashboard_session_timeout_minutes=dashboard_session_timeout_minutes,
        dashboard_login_max_attempts=dashboard_login_max_attempts,
        dashboard_login_lockout_seconds=dashboard_login_lockout_seconds,
        deprecated_dashboard_env_vars=deprecated_dashboard_env_vars,
    )


def _dashboard_user(
    username: str,
    password: str,
    *,
    role: str = "viewer",
    enabled: bool = True,
) -> dict[str, object]:
    return _dashboard_user_from_hash(
        username,
        hash_dashboard_password(password),
        role=role,
        enabled=enabled,
    )


def _dashboard_user_from_hash(
    username: str,
    password_hash: str,
    *,
    role: str = "viewer",
    enabled: bool = True,
) -> dict[str, object]:
    return {
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "enabled": enabled,
        "created_at": "2026-06-07T00:00:00Z",
    }


def _write_dashboard_users(
    users_file: Path,
    users: list[dict[str, object]],
) -> None:
    users_file.parent.mkdir(parents=True, exist_ok=True)
    users_file.write_text(json.dumps(users), encoding="utf-8")


def _basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _csrf_token(client, auth_header: dict[str, str]) -> str:
    response = client.get("/admin/lists", headers=auth_header)
    assert response.status_code == 200
    match = re.search(
        rb'name="csrf_token" value="([^"]+)"',
        response.data,
    )
    assert match is not None
    return match.group(1).decode("utf-8")


def _assert_common_security_headers(response) -> None:
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert (
        response.headers["Content-Security-Policy"]
        == DASHBOARD_CONTENT_SECURITY_POLICY
    )


def _assert_no_store_headers(response) -> None:
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Expires"] == "0"


def _assert_audit_event_has_no_secrets(event) -> None:
    raw_text = event.raw_json
    assert "secret-password" not in raw_text
    assert "viewer-password" not in raw_text
    assert "wrong-password" not in raw_text
    assert "csrf_token" not in raw_text
    assert "gleipnir_csrf_token" not in raw_text
    assert "password_hash" not in raw_text
    assert "password" not in raw_text.lower()
    assert "token" not in raw_text.lower()


def _fetch_events(db_path: Path, event_type: str):
    store = SQLiteEventStore(db_path)
    try:
        return store.fetch_events(event_type)
    finally:
        store.close()


def _fetch_admin_audit_events(db_path: Path):
    store = SQLiteEventStore(db_path)
    try:
        return store.fetch_events(ADMIN_LIST_ACTION)
    finally:
        store.close()
