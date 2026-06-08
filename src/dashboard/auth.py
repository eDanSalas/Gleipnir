"""Dashboard user authentication backed by non-reversible password hashes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash


VALID_DASHBOARD_ROLES = {"viewer", "admin"}


class DashboardAuthError(ValueError):
    """Raised when dashboard users cannot be loaded or validated."""


@dataclass(frozen=True)
class DashboardUser:
    """Dashboard user loaded from the local users file."""

    username: str
    password_hash: str = field(repr=False)
    role: str
    enabled: bool
    created_at: str

    def safe_payload(self) -> dict[str, str | bool]:
        """Return user metadata without password hash material."""
        return {
            "username": self.username,
            "role": self.role,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }


def hash_dashboard_password(password: str) -> str:
    """Return a secure, non-reversible password hash for dashboard users."""
    cleaned = str(password or "")
    if not cleaned:
        raise DashboardAuthError("Dashboard password must not be empty")

    return generate_password_hash(cleaned)


def load_dashboard_users(users_file: str | Path) -> tuple[DashboardUser, ...]:
    """Load and validate dashboard users from a JSON file."""
    path = Path(users_file).expanduser()
    if not path.exists():
        raise DashboardAuthError(f"Dashboard users file not found: {path}")

    try:
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DashboardAuthError("Dashboard users file must contain valid JSON") from exc
    except OSError as exc:
        raise DashboardAuthError(f"Cannot read dashboard users file: {path}") from exc

    if not isinstance(raw_payload, list):
        raise DashboardAuthError("Dashboard users file must contain a JSON list")

    users = tuple(_parse_dashboard_user(item, index) for index, item in enumerate(raw_payload))
    _validate_unique_usernames(users)
    if not any(user.enabled for user in users):
        raise DashboardAuthError("Dashboard users file must contain at least one enabled user")

    return users


def authenticate_dashboard_user(
    users_file: str | Path,
    username: str,
    password: str,
) -> DashboardUser | None:
    """Return an enabled matching user when credentials are valid."""
    provided_username = str(username or "").strip()
    provided_password = str(password or "")
    if not provided_username or not provided_password:
        return None

    for user in load_dashboard_users(users_file):
        if not user.enabled or user.username != provided_username:
            continue
        if check_password_hash(user.password_hash, provided_password):
            return user

    return None


def _parse_dashboard_user(item: Any, index: int) -> DashboardUser:
    if not isinstance(item, dict):
        raise DashboardAuthError(f"Dashboard user entry #{index + 1} must be an object")

    username = _required_string(item, "username", index)
    password_hash = _required_string(item, "password_hash", index)
    role = _required_string(item, "role", index).lower()
    created_at = _required_string(item, "created_at", index)
    enabled = item.get("enabled", True)

    if role not in VALID_DASHBOARD_ROLES:
        allowed = ", ".join(sorted(VALID_DASHBOARD_ROLES))
        raise DashboardAuthError(
            f"Dashboard user '{username}' has invalid role. Allowed roles: {allowed}"
        )
    if not isinstance(enabled, bool):
        raise DashboardAuthError(f"Dashboard user '{username}' enabled must be true or false")

    return DashboardUser(
        username=username,
        password_hash=password_hash,
        role=role,
        enabled=enabled,
        created_at=created_at,
    )


def _required_string(item: dict[str, Any], key: str, index: int) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DashboardAuthError(
            f"Dashboard user entry #{index + 1} requires a non-empty '{key}' value"
        )

    return value.strip()


def _validate_unique_usernames(users: tuple[DashboardUser, ...]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for user in users:
        if user.username in seen:
            duplicates.add(user.username)
        seen.add(user.username)

    if duplicates:
        names = ", ".join(sorted(duplicates))
        raise DashboardAuthError(f"Dashboard users file contains duplicate users: {names}")
