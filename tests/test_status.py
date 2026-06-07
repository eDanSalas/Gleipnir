"""Unit tests for the Gleipnir healthcheck command."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

from src.status import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_WARNING,
    format_health_report,
    run_healthcheck,
)


def test_healthcheck_reports_all_core_components_ok(tmp_path: Path) -> None:
    config = _make_config(tmp_path, interface="eth0")
    _create_runtime_files(config)
    sqlite3.connect(config.ids_db_path).close()

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=_smtp_ok,
        interface_provider=lambda: [(1, "lo"), (2, "eth0")],
    )

    statuses = {item.component: item.status for item in report.items}

    assert report.exit_code == 0
    assert statuses["configuration"] == STATUS_OK
    assert statuses["whitelist"] == STATUS_OK
    assert statuses["blacklist"] == STATUS_OK
    assert statuses["log_dir"] == STATUS_OK
    assert statuses["report_dir"] == STATUS_OK
    assert statuses["sqlite"] == STATUS_OK
    assert statuses["smtp"] == STATUS_OK
    assert statuses["interface"] == STATUS_OK


def test_healthcheck_returns_error_when_required_file_is_missing(
    tmp_path: Path,
) -> None:
    config = _make_config(tmp_path, interface="eth0")
    _create_runtime_files(config)
    config.whitelist_file.unlink()

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=_smtp_ok,
        interface_provider=lambda: [(1, "eth0")],
    )

    whitelist_item = _item(report, "whitelist")

    assert report.exit_code == 1
    assert whitelist_item.status == STATUS_ERROR
    assert "File not found" in whitelist_item.message


def test_healthcheck_does_not_send_email_and_reports_smtp_failure(
    tmp_path: Path,
) -> None:
    config = _make_config(tmp_path, interface="eth0")
    _create_runtime_files(config)

    def smtp_failure(_host: str, _port: int, _timeout: int) -> None:
        raise OSError("connection refused")

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=smtp_failure,
        interface_provider=lambda: [(1, "eth0")],
    )

    smtp_item = _item(report, "smtp")

    assert report.exit_code == 1
    assert smtp_item.status == STATUS_ERROR
    assert "connection refused" in smtp_item.message
    assert "smtp-secret" not in format_health_report(report)


def test_healthcheck_warns_when_live_interface_is_not_configured(
    tmp_path: Path,
) -> None:
    config = _make_config(tmp_path, interface=None)
    _create_runtime_files(config)

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=_smtp_ok,
        interface_provider=lambda: [(1, "eth0")],
    )

    interface_item = _item(report, "interface")

    assert report.exit_code == 0
    assert interface_item.status == STATUS_WARNING
    assert "GLEIPNIR_INTERFACE" in interface_item.message


def test_healthcheck_errors_when_configured_interface_is_missing(
    tmp_path: Path,
) -> None:
    config = _make_config(tmp_path, interface="wlan0")
    _create_runtime_files(config)

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=_smtp_ok,
        interface_provider=lambda: [(1, "lo"), (2, "eth0")],
    )

    interface_item = _item(report, "interface")

    assert report.exit_code == 1
    assert interface_item.status == STATUS_ERROR
    assert "wlan0" in interface_item.message


def test_healthcheck_warns_when_sqlite_database_does_not_exist(
    tmp_path: Path,
) -> None:
    config = _make_config(tmp_path, interface="eth0")
    _create_runtime_files(config)

    report = run_healthcheck(
        config_loader=lambda: config,
        smtp_checker=_smtp_ok,
        interface_provider=lambda: [(1, "eth0")],
    )

    sqlite_item = _item(report, "sqlite")

    assert report.exit_code == 0
    assert sqlite_item.status == STATUS_WARNING
    assert "does not exist yet" in sqlite_item.message


def _make_config(tmp_path: Path, *, interface: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        smtp_host="smtp.example.org",
        smtp_port=587,
        smtp_password="smtp-secret",
        whitelist_file=tmp_path / "data" / "whitelist.csv",
        blacklist_file=tmp_path / "data" / "blacklist.txt",
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        ids_db_path=tmp_path / "data" / "gleipnir_events.db",
        gleipnir_interface=interface,
        gleipnir_mode="live",
    )


def _create_runtime_files(config: SimpleNamespace) -> None:
    config.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
    config.whitelist_file.write_text(
        "ip,mac,description\n192.168.1.10,aa:bb:cc:dd:ee:ff,Laptop\n",
        encoding="utf-8",
    )
    config.blacklist_file.write_text("8.8.8.8 # test\n", encoding="utf-8")
    config.log_dir.mkdir(parents=True, exist_ok=True)
    config.report_dir.mkdir(parents=True, exist_ok=True)


def _smtp_ok(_host: str, _port: int, _timeout: int) -> None:
    return None


def _item(report, component: str):
    return next(item for item in report.items if item.component == component)
