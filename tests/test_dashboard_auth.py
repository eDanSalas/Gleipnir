"""Tests for dashboard users backed by password hashes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.dashboard.auth import (
    DashboardAuthError,
    authenticate_dashboard_user,
    hash_dashboard_password,
    load_dashboard_users,
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
