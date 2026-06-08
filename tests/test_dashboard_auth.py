"""Tests for dashboard users backed by password hashes."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import src.dashboard.auth as dashboard_auth
from src.dashboard.auth import (
    DashboardAuthError,
    LoginAttemptTracker,
    authenticate_dashboard_user,
    change_dashboard_user_password,
    check_users_file_permissions,
    create_dashboard_user,
    disable_dashboard_user,
    enable_dashboard_user,
    hash_dashboard_password,
    list_dashboard_users,
    load_dashboard_users,
    migrate_legacy_dashboard_user,
)


def test_load_dashboard_users_validates_role_and_enabled_flag(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    users_file.write_text(
        json.dumps(
            [
                {
                    "username": "viewer",
                    "password_hash": hash_dashboard_password("viewer-password"),
                    "role": "viewer",
                    "enabled": True,
                    "created_at": "2026-06-07T00:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )

    users = load_dashboard_users(users_file)

    assert users[0].username == "viewer"
    assert users[0].role == "viewer"
    assert users[0].enabled is True
    assert "password_hash" not in users[0].safe_payload()
    assert users[0].password_hash not in repr(users[0])


def test_authenticate_dashboard_user_accepts_valid_hash(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    _write_users(
        users_file,
        [
            _user("admin", "admin-password", role="admin"),
            _user("viewer", "viewer-password", role="viewer"),
        ],
    )

    user = authenticate_dashboard_user(users_file, "admin", "admin-password")

    assert user is not None
    assert user.username == "admin"
    assert user.role == "admin"


def test_authenticate_dashboard_user_rejects_wrong_password(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    _write_users(users_file, [_user("viewer", "viewer-password")])

    user = authenticate_dashboard_user(users_file, "viewer", "wrong-password")

    assert user is None


def test_authenticate_dashboard_user_rejects_disabled_user(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    _write_users(
        users_file,
        [
            _user("admin", "admin-password", role="admin"),
            _user("viewer", "viewer-password", enabled=False),
        ],
    )

    user = authenticate_dashboard_user(users_file, "viewer", "viewer-password")

    assert user is None


def test_load_dashboard_users_rejects_invalid_role(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    _write_users(users_file, [_user("owner", "owner-password", role="owner")])

    with pytest.raises(DashboardAuthError, match="invalid role"):
        load_dashboard_users(users_file)


def test_create_dashboard_user_creates_file_with_hash_only(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    user = create_dashboard_user(
        users_file,
        username="admin",
        password="StrongPassword123!",
        role="admin",
    )
    raw_text = users_file.read_text(encoding="utf-8")

    assert user.username == "admin"
    assert user.role == "admin"
    assert "StrongPassword123!" not in raw_text
    assert "password_hash" in raw_text
    assert authenticate_dashboard_user(users_file, "admin", "StrongPassword123!")


@pytest.mark.skipif(os.name != "posix", reason="POSIX chmod assertion")
def test_create_dashboard_user_sets_private_permissions_on_posix(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    create_dashboard_user(
        users_file,
        username="admin",
        password="StrongPassword123!",
        role="admin",
    )

    assert users_file.stat().st_mode & 0o777 == 0o600


def test_check_users_file_permissions_warns_on_insecure_posix_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    users_file = tmp_path / "dashboard_users.json"
    users_file.write_text("[]", encoding="utf-8")
    users_file.chmod(0o644)
    monkeypatch.setattr(dashboard_auth.os, "name", "posix")

    result = check_users_file_permissions(users_file)

    assert result.status == "WARNING"
    assert "600" in result.message
    assert "password_hash" not in result.message


def test_login_attempt_tracker_counts_by_user_and_ip() -> None:
    now = {"value": 100.0}
    tracker = LoginAttemptTracker(
        max_attempts=2,
        lockout_seconds=10,
        time_provider=lambda: now["value"],
    )

    assert tracker.record_failure("viewer", "192.168.1.10") is False
    assert tracker.is_locked("viewer", "192.168.1.10") is False
    assert tracker.record_failure("viewer", "192.168.1.10") is True
    assert tracker.is_locked("viewer", "192.168.1.10") is True
    assert tracker.is_locked("another-user", "192.168.1.10") is True
    assert tracker.is_locked("viewer", "192.168.1.11") is True

    now["value"] = 111.0

    assert tracker.is_locked("viewer", "192.168.1.10") is False


def test_create_dashboard_user_rejects_duplicate_username(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    create_dashboard_user(
        users_file,
        username="viewer",
        password="StrongPassword123!",
        role="viewer",
    )

    with pytest.raises(DashboardAuthError, match="already exists"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="AnotherStrongPassword123!",
            role="viewer",
        )


def test_create_dashboard_user_rejects_short_password(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    with pytest.raises(DashboardAuthError, match="at least"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="short",
            role="viewer",
        )


def test_create_dashboard_user_rejects_password_without_uppercase(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    with pytest.raises(DashboardAuthError, match="uppercase"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="lowercase123!",
            role="viewer",
        )


def test_create_dashboard_user_rejects_password_without_number(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    with pytest.raises(DashboardAuthError, match="number"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="NoNumberHere!",
            role="viewer",
        )


def test_create_dashboard_user_rejects_password_without_symbol(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    with pytest.raises(DashboardAuthError, match="symbol"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="NoSymbol1234",
            role="viewer",
        )


def test_create_dashboard_user_rejects_common_password(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    with pytest.raises(DashboardAuthError, match="too common"):
        create_dashboard_user(
            users_file,
            username="viewer",
            password="gleipnir",
            role="viewer",
            min_password_length=1,
        )


def test_create_dashboard_user_accepts_strong_password(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    user = create_dashboard_user(
        users_file,
        username="viewer",
        password="StrongPassword123!",
        role="viewer",
    )

    assert user.username == "viewer"
    assert authenticate_dashboard_user(users_file, "viewer", "StrongPassword123!")


def test_migrate_legacy_dashboard_user_creates_hash_only(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"

    result = migrate_legacy_dashboard_user(
        users_file,
        username="admin",
        password="LegacyPassword123!",
        role="admin",
    )
    raw_text = users_file.read_text(encoding="utf-8")
    payload = json.loads(raw_text)

    assert result.created is True
    assert result.username == "admin"
    assert result.role == "admin"
    assert payload[0]["username"] == "admin"
    assert payload[0]["role"] == "admin"
    assert payload[0]["enabled"] is True
    assert "password_hash" in payload[0]
    assert payload[0]["password_hash"] != "LegacyPassword123!"
    assert "LegacyPassword123!" not in raw_text
    assert authenticate_dashboard_user(users_file, "admin", "LegacyPassword123!")


def test_migrate_legacy_dashboard_user_does_not_duplicate_existing_user(
    tmp_path: Path,
) -> None:
    users_file = tmp_path / "dashboard_users.json"
    create_dashboard_user(
        users_file,
        username="viewer",
        password="StrongPassword123!",
        role="viewer",
    )

    result = migrate_legacy_dashboard_user(
        users_file,
        username="viewer",
        password="LegacyPassword123!",
        role="admin",
    )
    users = list_dashboard_users(users_file)

    assert result.created is False
    assert result.username == "viewer"
    assert result.role == "viewer"
    assert len(users) == 1
    assert authenticate_dashboard_user(users_file, "viewer", "StrongPassword123!")
    assert authenticate_dashboard_user(users_file, "viewer", "LegacyPassword123!") is None


def test_enable_disable_and_change_dashboard_password(tmp_path: Path) -> None:
    users_file = tmp_path / "dashboard_users.json"
    create_dashboard_user(
        users_file,
        username="viewer",
        password="StrongPassword123!",
        role="viewer",
    )

    disabled_user = disable_dashboard_user(users_file, username="viewer")
    enabled_user = enable_dashboard_user(users_file, username="viewer")
    changed_user = change_dashboard_user_password(
        users_file,
        username="viewer",
        password="NewStrongPassword123!",
    )

    users = list_dashboard_users(users_file)

    assert disabled_user.enabled is False
    assert enabled_user.enabled is True
    assert changed_user.username == "viewer"
    assert users[0].enabled is True
    assert authenticate_dashboard_user(users_file, "viewer", "StrongPassword123!") is None
    assert authenticate_dashboard_user(users_file, "viewer", "NewStrongPassword123!")


def _user(
    username: str,
    password: str,
    *,
    role: str = "viewer",
    enabled: bool = True,
) -> dict[str, object]:
    return {
        "username": username,
        "password_hash": hash_dashboard_password(password),
        "role": role,
        "enabled": enabled,
        "created_at": "2026-06-07T00:00:00Z",
    }


def _write_users(users_file: Path, users: list[dict[str, object]]) -> None:
    users_file.write_text(json.dumps(users), encoding="utf-8")
