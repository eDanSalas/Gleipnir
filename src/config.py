"""Secure configuration loading for Gleipnir IDS."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from dotenv import dotenv_values


REQUIRED_ENV_VARS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "ADMIN_EMAIL",
    "WHITELIST_FILE",
    "BLACKLIST_FILE",
    "LOG_DIR",
)


class ConfigError(ValueError):
    """Raised when the project configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration loaded from environment variables."""

    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str = field(repr=False)
    admin_email: str
    whitelist_file: Path
    blacklist_file: Path
    log_dir: Path
    report_dir: Path
    ids_db_path: Path = field(
        default_factory=lambda: Path("data/gleipnir_events.db")
    )
    abuseipdb_api_key: str | None = field(default=None, repr=False)
    virustotal_api_key: str | None = field(default=None, repr=False)
    threat_intel_timeout_seconds: float = 10.0
    threat_intel_cache_ttl_seconds: int = 86_400
    alert_cooldown_seconds: int = 300
    alert_max_per_minute: int = 5
    gleipnir_interface: str | None = None
    gleipnir_mode: str = "live"
    gleipnir_scapy_use_pcap: bool = False
    health_log_interval_seconds: int = 300
    event_retention_days: int = 30
    max_log_size_mb: int = 50
    max_reports_to_keep: int = 20
    dashboard_auth_enabled: bool = False
    dashboard_users_file: Path = field(
        default_factory=lambda: Path("data/dashboard_users.json")
    )
    dashboard_username: str | None = None
    dashboard_password: str | None = field(default=None, repr=False)
    dashboard_role: str = "viewer"
    dashboard_admin_username: str | None = None
    dashboard_admin_password: str | None = field(default=None, repr=False)
    dashboard_secret_key: str | None = field(default=None, repr=False)
    dashboard_session_cookie_secure: bool = False
    dashboard_session_timeout_minutes: int = 30
    dashboard_password_min_length: int = 12
    dashboard_login_max_attempts: int = 5
    dashboard_login_lockout_seconds: int = 300
    deprecated_dashboard_env_vars: tuple[str, ...] = ()

    def as_redacted_dict(self) -> dict[str, str | int | float | None]:
        """Return a safe representation for diagnostics without secrets."""
        return {
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "smtp_password": "***",
            "admin_email": self.admin_email,
            "whitelist_file": str(self.whitelist_file),
            "blacklist_file": str(self.blacklist_file),
            "log_dir": str(self.log_dir),
            "report_dir": str(self.report_dir),
            "ids_db_path": str(self.ids_db_path),
            "abuseipdb_api_key": "***" if self.abuseipdb_api_key else None,
            "virustotal_api_key": "***" if self.virustotal_api_key else None,
            "threat_intel_timeout_seconds": self.threat_intel_timeout_seconds,
            "threat_intel_cache_ttl_seconds": self.threat_intel_cache_ttl_seconds,
            "alert_cooldown_seconds": self.alert_cooldown_seconds,
            "alert_max_per_minute": self.alert_max_per_minute,
            "gleipnir_interface": self.gleipnir_interface,
            "gleipnir_mode": self.gleipnir_mode,
            "gleipnir_scapy_use_pcap": self.gleipnir_scapy_use_pcap,
            "health_log_interval_seconds": self.health_log_interval_seconds,
            "event_retention_days": self.event_retention_days,
            "max_log_size_mb": self.max_log_size_mb,
            "max_reports_to_keep": self.max_reports_to_keep,
            "dashboard_auth_enabled": self.dashboard_auth_enabled,
            "dashboard_users_file": str(self.dashboard_users_file),
            "dashboard_username": self.dashboard_username,
            "dashboard_password": "***" if self.dashboard_password else None,
            "dashboard_role": self.dashboard_role,
            "dashboard_admin_username": self.dashboard_admin_username,
            "dashboard_admin_password": (
                "***" if self.dashboard_admin_password else None
            ),
            "dashboard_secret_key": "***" if self.dashboard_secret_key else None,
            "dashboard_session_cookie_secure": self.dashboard_session_cookie_secure,
            "dashboard_session_timeout_minutes": (
                self.dashboard_session_timeout_minutes
            ),
            "dashboard_password_min_length": self.dashboard_password_min_length,
            "dashboard_login_max_attempts": self.dashboard_login_max_attempts,
            "dashboard_login_lockout_seconds": self.dashboard_login_lockout_seconds,
            "deprecated_dashboard_env_vars": self.deprecated_dashboard_env_vars,
        }


def load_config(
    env_file: str | Path = ".env",
    environ: Mapping[str, str] | None = None,
) -> Config:
    """Load and validate configuration from a .env file and environment.

    Values from the process environment override values read from the .env file.
    The optional ``environ`` parameter is intended for tests.
    """
    env_values = _read_env_file(Path(env_file))
    runtime_env = os.environ if environ is None else environ
    values = {**env_values, **runtime_env}

    _validate_required(values)

    log_dir = Path(_required(values, "LOG_DIR")).expanduser()

    return Config(
        smtp_host=_required(values, "SMTP_HOST"),
        smtp_port=_parse_smtp_port(_required(values, "SMTP_PORT")),
        smtp_user=_required(values, "SMTP_USER"),
        smtp_password=_required(values, "SMTP_PASSWORD"),
        admin_email=_required(values, "ADMIN_EMAIL"),
        whitelist_file=Path(_required(values, "WHITELIST_FILE")).expanduser(),
        blacklist_file=Path(_required(values, "BLACKLIST_FILE")).expanduser(),
        log_dir=log_dir,
        report_dir=Path(_optional(values, "REPORT_DIR") or str(log_dir)).expanduser(),
        ids_db_path=Path(
            _optional(values, "IDS_DB_PATH") or "data/gleipnir_events.db"
        ).expanduser(),
        abuseipdb_api_key=_optional(values, "ABUSEIPDB_API_KEY"),
        virustotal_api_key=_optional(values, "VIRUSTOTAL_API_KEY"),
        threat_intel_timeout_seconds=_optional_float(
            values,
            "THREAT_INTEL_TIMEOUT_SECONDS",
            default=10.0,
            minimum=0.1,
        ),
        threat_intel_cache_ttl_seconds=_optional_int(
            values,
            "THREAT_INTEL_CACHE_TTL_SECONDS",
            default=86_400,
            minimum=0,
        ),
        alert_cooldown_seconds=_optional_int(
            values,
            "ALERT_COOLDOWN_SECONDS",
            default=300,
            minimum=0,
        ),
        alert_max_per_minute=_optional_int(
            values,
            "ALERT_MAX_PER_MINUTE",
            default=5,
            minimum=1,
        ),
        gleipnir_interface=_optional(values, "GLEIPNIR_INTERFACE"),
        gleipnir_mode=_optional_choice(
            values,
            "GLEIPNIR_MODE",
            default="live",
            choices=("offline", "replay", "live"),
        ),
        gleipnir_scapy_use_pcap=_optional_bool(
            values,
            "GLEIPNIR_SCAPY_USE_PCAP",
            default=False,
        ),
        health_log_interval_seconds=_optional_int(
            values,
            "HEALTH_LOG_INTERVAL_SECONDS",
            default=300,
            minimum=1,
        ),
        event_retention_days=_optional_int(
            values,
            "EVENT_RETENTION_DAYS",
            default=30,
            minimum=1,
        ),
        max_log_size_mb=_optional_int(
            values,
            "MAX_LOG_SIZE_MB",
            default=50,
            minimum=1,
        ),
        max_reports_to_keep=_optional_int(
            values,
            "MAX_REPORTS_TO_KEEP",
            default=20,
            minimum=1,
        ),
        dashboard_auth_enabled=_optional_bool(
            values,
            "DASHBOARD_AUTH_ENABLED",
            default=False,
        ),
        dashboard_users_file=Path(
            _optional(values, "DASHBOARD_USERS_FILE") or "data/dashboard_users.json"
        ).expanduser(),
        dashboard_username=_optional(values, "DASHBOARD_USERNAME"),
        dashboard_password=_optional(values, "DASHBOARD_PASSWORD"),
        dashboard_role=_optional(values, "DASHBOARD_ROLE") or "viewer",
        dashboard_admin_username=_optional(values, "DASHBOARD_ADMIN_USERNAME"),
        dashboard_admin_password=_optional(values, "DASHBOARD_ADMIN_PASSWORD"),
        dashboard_secret_key=_optional(values, "DASHBOARD_SECRET_KEY"),
        dashboard_session_cookie_secure=_optional_bool(
            values,
            "DASHBOARD_SESSION_COOKIE_SECURE",
            default=False,
        ),
        dashboard_session_timeout_minutes=_optional_int(
            values,
            "DASHBOARD_SESSION_TIMEOUT_MINUTES",
            default=30,
            minimum=1,
        ),
        dashboard_password_min_length=_optional_int(
            values,
            "DASHBOARD_PASSWORD_MIN_LENGTH",
            default=12,
            minimum=8,
        ),
        dashboard_login_max_attempts=_optional_int(
            values,
            "DASHBOARD_LOGIN_MAX_ATTEMPTS",
            default=5,
            minimum=1,
        ),
        dashboard_login_lockout_seconds=_optional_int(
            values,
            "DASHBOARD_LOGIN_LOCKOUT_SECONDS",
            default=300,
            minimum=1,
        ),
        deprecated_dashboard_env_vars=_deprecated_dashboard_env_vars(values),
    )


def _read_env_file(env_file: Path) -> dict[str, str]:
    if not env_file.exists():
        return {}

    raw_values = dotenv_values(env_file)
    return {key: value for key, value in raw_values.items() if value is not None}


def _validate_required(values: Mapping[str, str]) -> None:
    missing = [name for name in REQUIRED_ENV_VARS if not _optional(values, name)]

    if missing:
        names = ", ".join(missing)
        raise ConfigError(f"Missing required environment variables: {names}")


def _required(values: Mapping[str, str], name: str) -> str:
    value = _optional(values, name)
    if value is None:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def _optional(values: Mapping[str, str], name: str) -> str | None:
    value = values.get(name)
    if value is None:
        return None

    cleaned = value.strip()
    return cleaned or None


def _parse_smtp_port(raw_port: str) -> int:
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ConfigError("SMTP_PORT must be an integer between 1 and 65535") from exc

    if not 1 <= port <= 65535:
        raise ConfigError("SMTP_PORT must be an integer between 1 and 65535")

    return port


def _optional_int(
    values: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
) -> int:
    value = _optional(values, name)
    if value is None:
        return default

    try:
        parsed_value = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc

    if parsed_value < minimum:
        raise ConfigError(f"{name} must be greater than or equal to {minimum}")

    return parsed_value


def _optional_float(
    values: Mapping[str, str],
    name: str,
    *,
    default: float,
    minimum: float,
) -> float:
    value = _optional(values, name)
    if value is None:
        return default

    try:
        parsed_value = float(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc

    if parsed_value < minimum:
        raise ConfigError(f"{name} must be greater than or equal to {minimum}")

    return parsed_value


def _optional_bool(
    values: Mapping[str, str],
    name: str,
    *,
    default: bool,
) -> bool:
    value = _optional(values, name)
    if value is None:
        return default

    normalized = value.lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    raise ConfigError(f"{name} must be true or false")


def _optional_choice(
    values: Mapping[str, str],
    name: str,
    *,
    default: str,
    choices: tuple[str, ...],
) -> str:
    value = _optional(values, name)
    if value is None:
        return default

    normalized = value.lower()
    if normalized not in choices:
        allowed = ", ".join(choices)
        raise ConfigError(f"{name} must be one of: {allowed}")

    return normalized


def _deprecated_dashboard_env_vars(values: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        name
        for name in (
            "DASHBOARD_USERNAME",
            "DASHBOARD_PASSWORD",
            "DASHBOARD_ROLE",
            "DASHBOARD_ADMIN_USERNAME",
            "DASHBOARD_ADMIN_PASSWORD",
        )
        if _optional(values, name)
    )
