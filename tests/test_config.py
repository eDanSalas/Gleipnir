"""Tests for secure project configuration loading."""

from pathlib import Path

import pytest

from src.config import (
    ConfigError,
    load_config,
    set_admin_email,
    set_env_value,
    validate_email,
)


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
WHITELIST_AUTH_POLICY=ip_fallback
GLEIPNIR_INTERFACE=eth0
GLEIPNIR_MODE=live
GLEIPNIR_SCAPY_USE_PCAP=true
HEALTH_LOG_INTERVAL_SECONDS=60
EVENT_RETENTION_DAYS=14
MAX_LOG_SIZE_MB=25
MAX_REPORTS_TO_KEEP=7
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_SECRET_KEY=dashboard-secret-key
DASHBOARD_USERS_FILE=data/dashboard_users.json
DASHBOARD_SESSION_COOKIE_SECURE=true
DASHBOARD_SESSION_TIMEOUT_MINUTES=45
DASHBOARD_PASSWORD_MIN_LENGTH=16
DASHBOARD_LOGIN_MAX_ATTEMPTS=4
DASHBOARD_LOGIN_LOCKOUT_SECONDS=120
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
    assert config.whitelist_auth_policy == "ip_fallback"
    assert config.gleipnir_interface == "eth0"
    assert config.gleipnir_mode == "live"
    assert config.gleipnir_scapy_use_pcap is True
    assert config.health_log_interval_seconds == 60
    assert config.event_retention_days == 14
    assert config.max_log_size_mb == 25
    assert config.max_reports_to_keep == 7
    assert config.dashboard_auth_enabled is True
    assert config.dashboard_secret_key == "dashboard-secret-key"
    assert config.dashboard_users_file == Path("data/dashboard_users.json")
    assert config.dashboard_session_cookie_secure is True
    assert config.dashboard_session_timeout_minutes == 45
    assert config.dashboard_password_min_length == 16
    assert config.dashboard_login_max_attempts == 4
    assert config.dashboard_login_lockout_seconds == 120
    assert config.deprecated_dashboard_env_vars == ()


def test_config_repr_does_not_expose_secrets(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    config = load_config(env_file=env_file, environ={})
    visible_text = f"{config!r} {config.as_redacted_dict()}"

    assert "super-secret-password" not in visible_text
    assert "abuse-secret" not in visible_text
    assert "vt-secret" not in visible_text
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


def test_load_config_rejects_invalid_whitelist_auth_policy(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("WHITELIST_AUTH_POLICY=ip_fallback", "WHITELIST_AUTH_POLICY=loose"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="WHITELIST_AUTH_POLICY"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_dashboard_auth_flag(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("DASHBOARD_AUTH_ENABLED=true", "DASHBOARD_AUTH_ENABLED=maybe"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_AUTH_ENABLED"):
        load_config(env_file=env_file, environ={})


def test_load_config_tracks_deprecated_dashboard_credentials(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV
        + "DASHBOARD_USERNAME=legacy\n"
        + "DASHBOARD_PASSWORD=legacy-password\n"
        + "DASHBOARD_ROLE=owner\n",
        encoding="utf-8",
    )

    config = load_config(env_file=env_file, environ={})

    assert config.deprecated_dashboard_env_vars == (
        "DASHBOARD_USERNAME",
        "DASHBOARD_PASSWORD",
        "DASHBOARD_ROLE",
    )


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


def test_load_config_rejects_invalid_dashboard_password_min_length(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace(
            "DASHBOARD_PASSWORD_MIN_LENGTH=16",
            "DASHBOARD_PASSWORD_MIN_LENGTH=7",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_PASSWORD_MIN_LENGTH"):
        load_config(env_file=env_file, environ={})


def test_load_config_rejects_invalid_dashboard_login_lockout_values(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV.replace("DASHBOARD_LOGIN_MAX_ATTEMPTS=4", "DASHBOARD_LOGIN_MAX_ATTEMPTS=0"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="DASHBOARD_LOGIN_MAX_ATTEMPTS"):
        load_config(env_file=env_file, environ={})


def test_validate_email_accepts_valid_address() -> None:
    assert validate_email("  admin@example.org  ") == "admin@example.org"


def test_validate_email_rejects_invalid_address() -> None:
    with pytest.raises(ConfigError, match="Invalid email address"):
        validate_email("not-an-email")


def test_set_env_value_updates_existing_key_and_preserves_others(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    set_env_value(env_file, "ADMIN_EMAIL", "new-admin@example.org")

    config = load_config(env_file=env_file, environ={})
    assert config.admin_email == "new-admin@example.org"
    # Unrelated values stay intact.
    assert config.smtp_host == "smtp.example.org"
    assert config.smtp_user == "alerts@example.org"


def test_set_env_value_appends_missing_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SMTP_HOST=smtp.example.org\n", encoding="utf-8")

    set_env_value(env_file, "ADMIN_EMAIL", "admin@example.org")

    contents = env_file.read_text(encoding="utf-8")
    assert "SMTP_HOST=smtp.example.org" in contents
    assert "ADMIN_EMAIL=admin@example.org" in contents


def test_set_admin_email_validates_and_persists(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    result = set_admin_email("changed@example.org", env_file=env_file)

    assert result == "changed@example.org"
    config = load_config(env_file=env_file, environ={})
    assert config.admin_email == "changed@example.org"


def test_set_admin_email_rejects_invalid_address(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    with pytest.raises(ConfigError, match="Invalid email address"):
        set_admin_email("bad", env_file=env_file)


def test_load_config_reads_ips_and_blacklist_private_settings(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        VALID_ENV
        + "BLACKLIST_CHECK_PRIVATE=true\n"
        + "IPS_ENABLED=true\n"
        + "IPS_DRY_RUN=false\n"
        + "IPS_ALLOWLIST_POLICY=block_unregistered\n"
        + "IPS_BLACKLIST_POLICY=block\n"
        + "IPS_BLOCK_DIRECTION=outbound\n",
        encoding="utf-8",
    )

    config = load_config(env_file=env_file, environ={})

    assert config.blacklist_check_private is True
    assert config.ips_enabled is True
    assert config.ips_dry_run is False
    assert config.ips_allowlist_policy == "block_unregistered"
    assert config.ips_blacklist_policy == "block"
    assert config.ips_block_direction == "outbound"


def test_load_config_defaults_ips_to_passive_ids(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV, encoding="utf-8")

    config = load_config(env_file=env_file, environ={})

    assert config.ips_enabled is False
    assert config.ips_dry_run is True
    assert config.blacklist_check_private is False


def test_load_config_rejects_invalid_ips_allowlist_policy(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(VALID_ENV + "IPS_ALLOWLIST_POLICY=nuke\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="IPS_ALLOWLIST_POLICY"):
        load_config(env_file=env_file, environ={})
