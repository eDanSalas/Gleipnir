"""Dashboard user authentication backed by non-reversible password hashes."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash


VALID_DASHBOARD_ROLES = {"viewer", "admin"}
MIN_DASHBOARD_PASSWORD_LENGTH = 12
DEFAULT_LOGIN_MAX_ATTEMPTS = 5
DEFAULT_LOGIN_LOCKOUT_SECONDS = 300
COMMON_DASHBOARD_PASSWORDS = {
    "admin",
    "password",
    "password123",
    "12345678",
    "gleipnir",
    "qwerty",
}


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


@dataclass(frozen=True)
class UsersFilePermissionCheck:
    """Permission status for the dashboard users file."""

    status: str
    path: Path
    message: str

    @property
    def is_warning(self) -> bool:
        """Return whether the permission check produced a warning."""
        return self.status == "WARNING"


@dataclass(frozen=True)
class DashboardUserMigrationResult:
    """Result of migrating one legacy dashboard user."""

    username: str
    role: str
    created: bool


@dataclass
class _LoginBucket:
    failures: int = 0
    locked_until: float = 0.0


class LoginAttemptTracker:
    """In-memory login failure tracker by username and remote IP."""

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS,
        lockout_seconds: int = DEFAULT_LOGIN_LOCKOUT_SECONDS,
        time_provider=time.time,
    ) -> None:
        self.max_attempts = max(1, int(max_attempts or DEFAULT_LOGIN_MAX_ATTEMPTS))
        self.lockout_seconds = max(
            1,
            int(lockout_seconds or DEFAULT_LOGIN_LOCKOUT_SECONDS),
        )
        self._time_provider = time_provider
        self._buckets: dict[str, _LoginBucket] = {}

    def is_locked(self, username: str | None, remote_ip: str | None) -> bool:
        """Return whether the username or remote IP is currently locked."""
        return any(self._bucket_locked(key) for key in self._keys(username, remote_ip))

    def record_failure(self, username: str | None, remote_ip: str | None) -> bool:
        """Record a failed login and return whether it triggered lockout."""
        now = self._now()
        locked = False
        for key in self._keys(username, remote_ip):
            bucket = self._buckets.setdefault(key, _LoginBucket())
            if bucket.locked_until <= now:
                bucket.locked_until = 0.0
            bucket.failures += 1
            if bucket.failures >= self.max_attempts:
                bucket.locked_until = now + self.lockout_seconds
                locked = True
        return locked

    def record_success(self, username: str | None, remote_ip: str | None) -> None:
        """Clear login failure counters for a successful login."""
        for key in self._keys(username, remote_ip):
            self._buckets.pop(key, None)

    def _bucket_locked(self, key: str) -> bool:
        bucket = self._buckets.get(key)
        if bucket is None:
            return False

        if bucket.locked_until > self._now():
            return True

        if bucket.locked_until:
            self._buckets.pop(key, None)
        return False

    def _keys(self, username: str | None, remote_ip: str | None) -> tuple[str, ...]:
        keys = [f"user:{_normalize_login_identifier(username)}"]
        cleaned_ip = _normalize_login_identifier(remote_ip)
        if cleaned_ip:
            keys.append(f"ip:{cleaned_ip}")
        return tuple(keys)

    def _now(self) -> float:
        return float(self._time_provider())


def hash_dashboard_password(password: str) -> str:
    """Return a secure, non-reversible password hash for dashboard users."""
    cleaned = str(password or "")
    if not cleaned:
        raise DashboardAuthError("Dashboard password must not be empty")

    return generate_password_hash(cleaned)


def password_strength_recommendation(
    min_length: int = MIN_DASHBOARD_PASSWORD_LENGTH,
) -> str:
    """Return a short operator-facing recommendation for dashboard passwords."""
    effective_min_length = _effective_min_password_length(min_length)
    return (
        "Use a unique password or passphrase with at least "
        f"{effective_min_length} characters, including lowercase, uppercase, "
        "number and symbol characters."
    )


def load_dashboard_users(users_file: str | Path) -> tuple[DashboardUser, ...]:
    """Load and validate dashboard users from a JSON file."""
    return _load_dashboard_users(users_file, require_enabled=True)


def list_dashboard_users(users_file: str | Path) -> tuple[DashboardUser, ...]:
    """Return dashboard users, or an empty tuple when the file does not exist."""
    path = Path(users_file).expanduser()
    if not path.exists():
        return ()

    return _load_dashboard_users(path, require_enabled=False)


def check_users_file_permissions(users_file: str | Path) -> UsersFilePermissionCheck:
    """Check whether dashboard users file permissions are safe for Ubuntu."""
    path = Path(users_file).expanduser()
    if not path.exists():
        return UsersFilePermissionCheck(
            "WARNING",
            path,
            f"Dashboard users file does not exist yet: {path}",
        )
    if not path.is_file():
        return UsersFilePermissionCheck(
            "WARNING",
            path,
            f"Dashboard users path is not a regular file: {path}",
        )
    if os.name != "posix":
        return UsersFilePermissionCheck(
            "OK",
            path,
            (
                "Dashboard users file exists. POSIX mode check is skipped on this "
                f"platform; use Ubuntu permissions 600 in deployment: {path}"
            ),
        )

    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        return UsersFilePermissionCheck(
            "WARNING",
            path,
            (
                "Dashboard users file has insecure permissions "
                f"{mode:03o}; recommended mode is 600 on Ubuntu: {path}"
            ),
        )

    return UsersFilePermissionCheck(
        "OK",
        path,
        f"Dashboard users file permissions are restricted: {mode:03o} ({path})",
    )


def create_dashboard_user(
    users_file: str | Path,
    *,
    username: str,
    password: str,
    role: str,
    min_password_length: int = MIN_DASHBOARD_PASSWORD_LENGTH,
) -> DashboardUser:
    """Create a new dashboard user and persist only its password hash."""
    path = Path(users_file).expanduser()
    users = list(list_dashboard_users(path))
    cleaned_username = _validate_username(username)
    cleaned_role = _validate_role(role)
    validate_dashboard_password_policy(password, min_length=min_password_length)

    if any(user.username == cleaned_username for user in users):
        raise DashboardAuthError(f"Dashboard user already exists: {cleaned_username}")

    user = DashboardUser(
        username=cleaned_username,
        password_hash=hash_dashboard_password(password),
        role=cleaned_role,
        enabled=True,
        created_at=_utc_timestamp(),
    )
    users.append(user)
    _write_dashboard_users(path, tuple(users))
    return user


def migrate_legacy_dashboard_user(
    users_file: str | Path,
    *,
    username: str,
    password: str,
    role: str = "viewer",
) -> DashboardUserMigrationResult:
    """Migrate legacy .env dashboard credentials into the users JSON file."""
    path = Path(users_file).expanduser()
    users = list(list_dashboard_users(path))
    cleaned_username = _validate_username(username)
    cleaned_role = _validate_role(role)
    if not str(password or ""):
        raise DashboardAuthError("Legacy dashboard password is missing")

    existing_user = next(
        (user for user in users if user.username == cleaned_username),
        None,
    )
    if existing_user is not None:
        return DashboardUserMigrationResult(
            username=existing_user.username,
            role=existing_user.role,
            created=False,
        )

    user = DashboardUser(
        username=cleaned_username,
        password_hash=hash_dashboard_password(password),
        role=cleaned_role,
        enabled=True,
        created_at=_utc_timestamp(),
    )
    users.append(user)
    _write_dashboard_users(path, tuple(users))
    return DashboardUserMigrationResult(
        username=user.username,
        role=user.role,
        created=True,
    )


def enable_dashboard_user(users_file: str | Path, *, username: str) -> DashboardUser:
    """Enable an existing dashboard user."""
    return _set_dashboard_user_enabled(users_file, username=username, enabled=True)


def disable_dashboard_user(users_file: str | Path, *, username: str) -> DashboardUser:
    """Disable an existing dashboard user."""
    return _set_dashboard_user_enabled(users_file, username=username, enabled=False)


def change_dashboard_user_password(
    users_file: str | Path,
    *,
    username: str,
    password: str,
    min_password_length: int = MIN_DASHBOARD_PASSWORD_LENGTH,
) -> DashboardUser:
    """Change a dashboard user's password by replacing its password hash."""
    path = Path(users_file).expanduser()
    users = list(_load_dashboard_users(path, require_enabled=False))
    cleaned_username = _validate_username(username)
    validate_dashboard_password_policy(password, min_length=min_password_length)

    for index, user in enumerate(users):
        if user.username != cleaned_username:
            continue
        updated_user = DashboardUser(
            username=user.username,
            password_hash=hash_dashboard_password(password),
            role=user.role,
            enabled=user.enabled,
            created_at=user.created_at,
        )
        users[index] = updated_user
        _write_dashboard_users(path, tuple(users))
        return updated_user

    raise DashboardAuthError(f"Dashboard user not found: {cleaned_username}")


def _load_dashboard_users(
    users_file: str | Path,
    *,
    require_enabled: bool,
) -> tuple[DashboardUser, ...]:
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
    if require_enabled and not any(user.enabled for user in users):
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


def _set_dashboard_user_enabled(
    users_file: str | Path,
    *,
    username: str,
    enabled: bool,
) -> DashboardUser:
    path = Path(users_file).expanduser()
    users = list(_load_dashboard_users(path, require_enabled=False))
    cleaned_username = _validate_username(username)

    for index, user in enumerate(users):
        if user.username != cleaned_username:
            continue
        updated_user = DashboardUser(
            username=user.username,
            password_hash=user.password_hash,
            role=user.role,
            enabled=enabled,
            created_at=user.created_at,
        )
        users[index] = updated_user
        _write_dashboard_users(path, tuple(users))
        return updated_user

    raise DashboardAuthError(f"Dashboard user not found: {cleaned_username}")


def _write_dashboard_users(users_file: Path, users: tuple[DashboardUser, ...]) -> None:
    users_file.parent.mkdir(parents=True, exist_ok=True)
    payload = [_dashboard_user_record(user) for user in users]
    temporary_file = users_file.with_name(f"{users_file.name}.tmp")
    try:
        temporary_file.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        _set_private_file_permissions(temporary_file)
        temporary_file.replace(users_file)
        _set_private_file_permissions(users_file)
    except OSError as exc:
        raise DashboardAuthError(f"Cannot write dashboard users file: {users_file}") from exc


def _dashboard_user_record(user: DashboardUser) -> dict[str, str | bool]:
    return {
        "username": user.username,
        "password_hash": user.password_hash,
        "role": user.role,
        "enabled": user.enabled,
        "created_at": user.created_at,
    }


def _set_private_file_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        return


def _validate_username(username: str) -> str:
    cleaned = str(username or "").strip()
    if not cleaned:
        raise DashboardAuthError("Dashboard username must not be empty")
    if any(character.isspace() for character in cleaned):
        raise DashboardAuthError("Dashboard username must not contain whitespace")

    return cleaned


def _validate_role(role: str) -> str:
    cleaned = str(role or "").strip().lower()
    if cleaned not in VALID_DASHBOARD_ROLES:
        allowed = ", ".join(sorted(VALID_DASHBOARD_ROLES))
        raise DashboardAuthError(f"Dashboard role must be one of: {allowed}")

    return cleaned


def validate_dashboard_password_policy(
    password: str,
    *,
    min_length: int = MIN_DASHBOARD_PASSWORD_LENGTH,
) -> None:
    """Validate password policy for user creation and password changes."""
    cleaned = str(password or "")
    effective_min_length = _effective_min_password_length(min_length)
    if len(cleaned) < effective_min_length:
        raise DashboardAuthError(
            "Dashboard password must be at least "
            f"{effective_min_length} characters long. "
            f"{password_strength_recommendation(effective_min_length)}"
        )
    if cleaned.lower() in COMMON_DASHBOARD_PASSWORDS:
        raise DashboardAuthError(
            "Dashboard password is too common. "
            f"{password_strength_recommendation(effective_min_length)}"
        )
    if not any(character.islower() for character in cleaned):
        raise DashboardAuthError(
            "Dashboard password must include at least one lowercase letter. "
            f"{password_strength_recommendation(effective_min_length)}"
        )
    if not any(character.isupper() for character in cleaned):
        raise DashboardAuthError(
            "Dashboard password must include at least one uppercase letter. "
            f"{password_strength_recommendation(effective_min_length)}"
        )
    if not any(character.isdigit() for character in cleaned):
        raise DashboardAuthError(
            "Dashboard password must include at least one number. "
            f"{password_strength_recommendation(effective_min_length)}"
        )
    if not any(not character.isalnum() for character in cleaned):
        raise DashboardAuthError(
            "Dashboard password must include at least one symbol. "
            f"{password_strength_recommendation(effective_min_length)}"
        )


def _effective_min_password_length(min_length: int) -> int:
    try:
        parsed = int(min_length)
    except (TypeError, ValueError):
        return MIN_DASHBOARD_PASSWORD_LENGTH

    return max(1, parsed)


def _normalize_login_identifier(value: str | None) -> str:
    return str(value or "").strip().lower()


def _utc_timestamp() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


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
