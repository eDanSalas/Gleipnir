"""Unit tests for Gleipnir retention maintenance."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from src.maintenance import (
    cleanup_old_reports,
    format_maintenance_result,
    run_maintenance,
    validate_log_rotation,
)
from src.storage import DNS_EVENT, SQLiteEventStore


def test_run_maintenance_deletes_only_events_older_than_retention(
    tmp_path: Path,
) -> None:
    now = 1_800_000_000.0
    config = _config(tmp_path, event_retention_days=30)
    store = SQLiteEventStore(config.ids_db_path)
    old_timestamp = now - (31 * 86_400)
    recent_timestamp = now - (29 * 86_400)
    store.save_event(
        event_type=DNS_EVENT,
        timestamp=old_timestamp,
        message="old event",
        raw={"age": "old"},
    )
    store.save_event(
        event_type=DNS_EVENT,
        timestamp=recent_timestamp,
        message="recent event",
        raw={"age": "recent"},
    )
    store.close()

    result = run_maintenance(config, now=now, logger=Mock())

    remaining_store = SQLiteEventStore(config.ids_db_path)
    remaining_events = remaining_store.fetch_events()
    remaining_store.close()

    assert result.events_deleted == 1
    assert len(remaining_events) == 1
    assert remaining_events[0].message == "recent event"


def test_run_maintenance_skips_sqlite_when_database_does_not_exist(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)

    result = run_maintenance(config, now=1_800_000_000.0, logger=Mock())

    assert result.exit_code == 0
    assert result.sqlite_checked is False
    assert result.events_deleted == 0
    assert not config.ids_db_path.exists()


def test_cleanup_old_reports_keeps_newest_report_files(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report_files = []
    for index in range(5):
        report_path = report_dir / f"gleipnir_report_2026060{index}T000000Z.json"
        report_path.write_text("{}", encoding="utf-8")
        timestamp = time.time() + index
        os.utime(report_path, (timestamp, timestamp))
        report_files.append(report_path)

    unrelated_file = report_dir / "manual_notes.json"
    unrelated_file.write_text("{}", encoding="utf-8")

    deleted, kept = cleanup_old_reports(report_dir, max_reports_to_keep=2)

    remaining_reports = sorted(path.name for path in report_dir.glob("gleipnir_report_*.json"))

    assert deleted == 3
    assert kept == 2
    assert remaining_reports == [
        report_files[3].name,
        report_files[4].name,
    ]
    assert unrelated_file.exists()


def test_validate_log_rotation_reports_size_based_rotation(tmp_path: Path) -> None:
    config = _config(tmp_path, max_log_size_mb=25)

    enabled, message, error = validate_log_rotation(config)

    assert enabled is True
    assert error is None
    assert "max_size=25MB" in message


def test_format_maintenance_result_includes_counts(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.ids_db_path.parent.mkdir(parents=True, exist_ok=True)
    sqlite3.connect(config.ids_db_path).close()

    result = run_maintenance(config, now=1_800_000_000.0, logger=Mock())
    output = format_maintenance_result(result)

    assert "Gleipnir maintenance" in output
    assert "events_deleted=" in output
    assert "reports_deleted=" in output
    assert "log_rotation=max_size" in output


def _config(
    tmp_path: Path,
    *,
    event_retention_days: int = 30,
    max_log_size_mb: int = 50,
    max_reports_to_keep: int = 20,
) -> SimpleNamespace:
    return SimpleNamespace(
        ids_db_path=tmp_path / "data" / "gleipnir_events.db",
        report_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
        event_retention_days=event_retention_days,
        max_log_size_mb=max_log_size_mb,
        max_reports_to_keep=max_reports_to_keep,
    )
