"""Tests for secure project configuration loading."""

from pathlib import Path

import pytest

from src.config import ConfigError, load_config


VALID_ENV = """\
SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_USER=alerts@example.org
SMTP_PASSWORD=super-secret-password
ADMIN_EMAIL=admin@example.org
WHITELIST_FILE=data/whitelist.csv
BLACKLIST_FILE=data/blacklist.txt
LOG_DIR=logs
IDS_DB_PATH=data/gleipnir_events.db
ABUSEIPDB_API_KEY=abuse-secret
VIRUSTOTAL_API_KEY=vt-secret
ALERT_COOLDOWN_SECONDS=120
ALERT_MAX_PER_MINUTE=3
GLEIPNIR_INTERFACE=eth0
GLEIPNIR_MODE=live
HEALTH_LOG_INTERVAL_SECONDS=60
EVENT_RETENTION_DAYS=14
MAX_LOG_SIZE_MB=25
MAX_REPORTS_TO_KEEP=7
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=dashboard-admin
DASHBOARD_PASSWORD=dashboard-secret-password
DASHBOARD_ROLE=admin
DASHBOARD_ADMIN_USERNAME=dashboard-superadmin
DASHBOARD_ADMIN_PASSWORD=dashboard-admin-password
DASHBOARD_SECRET_KEY=dashboard-secret-key
DASHBOARD_SESSION_COOKIE_SECURE=true
DASHBOARD_SESSION_TIMEOUT_MINUTES=45
"""


def test_env_example_exists() -> None:
    """The project should provide a safe environment template."""
    project_root = Path(__file__).resolve().parents[1]

    assert (project_root / ".env.example").is_file()


def test_load_config_reads_required_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    config = load_config(env_file=env_file, environ={})

    assert config.smtp_host == "smtp.example.org"
    assert config.smtp_port == 587
    assert config.smtp_user == "alerts@example.org"
    assert config.admin_email == "admin@example.org"
    assert config.whitelist_file == Path("data/whitelist.csv")
    assert config.blacklist_file == Path("data/blacklist.txt")
    assert config.log_dir == Path("logs")
    assert config.ids_db_path == Path("data/gleipnir_events.db")
    assert config.alert_cooldown_seconds == 120
    assert config.alert_max_per_minute == 3
    assert config.gleipnir_interface == "eth0"
    assert config.gleipnir_mode == "live"
    assert config.health_log_interval_seconds == 60
    assert config.event_retention_days == 14
    assert config.max_log_size_mb == 25
    assert config.max_reports_to_keep == 7
    assert config.dashboard_auth_enabled is True
    assert config.dashboard_username == "dashboard-admin"
    assert config.dashboard_password == "dashboard-secret-password"
    assert config.dashboard_role == "admin"
    assert config.dashboard_admin_username == "dashboard-superadmin"
    assert config.dashboard_admin_password == "dashboard-admin-password"
    assert config.dashboard_secret_key == "dashboard-secret-key"
    assert config.dashboard_session_cookie_secure is True
    assert config.dashboard_session_timeout_minutes == 45


def test_config_repr_does_not_expose_secrets(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    config = load_config(env_file=env_file, environ={})
    visible_text = f"{config!r} {config.as_redacted_dict()}"

    assert "super-secret-password" not in visible_text
    assert "abuse-secret" not in visible_text
    assert "vt-secret" not in visible_text
    assert "dashboard-secret-password" not in visible_text
    assert "dashboard-admin-password" not in visible_text
    assert "dashboard-secret-key" not in visible_text


def test_load_config_reports_missing_required_values(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("SMTP_PASSWORD=super-secret-password\n", ""),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="SMTP_PASSWORD"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_smtp_port(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("SMTP_PORT=587", "SMTP_PORT=not-a-port"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="SMTP_PORT"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_gleipnir_mode(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("GLEIPNIR_MODE=live", "GLEIPNIR_MODE=attack"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="GLEIPNIR_MODE"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_dashboard_auth_flag(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("DASHBOARD_AUTH_ENABLED=true", "DASHBOARD_AUTH_ENABLED=maybe"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_AUTH_ENABLED"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_dashboard_role(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("DASHBOARD_ROLE=admin", "DASHBOARD_ROLE=owner"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_ROLE"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_dashboard_session_timeout(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace(
            "DASHBOARD_SESSION_TIMEOUT_MINUTES=45",
            "DASHBOARD_SESSION_TIMEOUT_MINUTES=0",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_SESSION_TIMEOUT_MINUTES"):
        load_config(env_file=env_file, environ={})
