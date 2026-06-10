
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.logger import DEFAULT_BACKUP_COUNT, LOG_FILE_NAME
from src.reports import DEFAULT_REPORT_PREFIX
from src.storage import SQLiteEventStore


SECONDS_PER_DAY = 86_400
REPORT_SUFFIXES = (".json", ".csv")


@dataclass(frozen=True)
class MaintenanceResult:

    events_deleted: int = 0
    event_retention_days: int = 30
    sqlite_checked: bool = False
    sqlite_path: Path | None = None
    reports_deleted: int = 0
    reports_kept: int = 0
    max_reports_to_keep: int = 20
    report_dir: Path | None = None
    log_rotation_enabled: bool = True
    max_log_size_mb: int = 50
    log_backup_count: int = DEFAULT_BACKUP_COUNT
    messages: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    # FUN-084
    @property
    def exit_code(self) -> int:
        return 1 if self.errors else 0


# FUN-085
def run_maintenance(
    config: Any,
    *,
    now: float | None = None,
    logger: Any | None = None,
) -> MaintenanceResult:
    current_time = time.time() if now is None else float(now)
    messages: list[str] = []
    errors: list[str] = []
    event_retention_days = int(getattr(config, "event_retention_days", 30))
    max_reports_to_keep = int(getattr(config, "max_reports_to_keep", 20))
    max_log_size_mb = int(getattr(config, "max_log_size_mb", 50))
    db_path = Path(getattr(config, "ids_db_path", "data/gleipnir_events.db"))
    report_dir = Path(getattr(config, "report_dir", getattr(config, "log_dir", "logs")))

    events_deleted = 0
    sqlite_checked = db_path.exists()
    if sqlite_checked:
        cutoff_timestamp = current_time - (event_retention_days * SECONDS_PER_DAY)
        try:
            store = SQLiteEventStore(db_path)
            try:
                events_deleted = store.delete_events_older_than(cutoff_timestamp)
            finally:
                store.close()
            messages.append(
                f"SQLite retention removed {events_deleted} old event(s)."
            )
            _log_info(
                logger,
                "MAINTENANCE | sqlite_events_deleted=%s retention_days=%s db=%s",
                events_deleted,
                event_retention_days,
                db_path,
            )
        except Exception as exc:
            error = f"SQLite retention failed: {exc}"
            errors.append(error)
            _log_error(logger, "MAINTENANCE | %s", error)
    else:
        messages.append(f"SQLite database not found, skipping event retention: {db_path}")

    try:
        reports_deleted, reports_kept = cleanup_old_reports(
            report_dir,
            max_reports_to_keep=max_reports_to_keep,
        )
        messages.append(
            f"Report retention kept {reports_kept} file(s) and removed {reports_deleted}."
        )
        _log_info(
            logger,
            "MAINTENANCE | reports_deleted=%s reports_kept=%s report_dir=%s",
            reports_deleted,
            reports_kept,
            report_dir,
        )
    except Exception as exc:
        reports_deleted = 0
        reports_kept = 0
        error = f"Report retention failed: {exc}"
        errors.append(error)
        _log_error(logger, "MAINTENANCE | %s", error)

    log_rotation_enabled, log_message, log_error = validate_log_rotation(config)
    messages.append(log_message)
    if log_error is not None:
        errors.append(log_error)
        _log_error(logger, "MAINTENANCE | %s", log_error)
    else:
        _log_info(logger, "MAINTENANCE | %s", log_message)

    return MaintenanceResult(
        events_deleted=events_deleted,
        event_retention_days=event_retention_days,
        sqlite_checked=sqlite_checked,
        sqlite_path=db_path,
        reports_deleted=reports_deleted,
        reports_kept=reports_kept,
        max_reports_to_keep=max_reports_to_keep,
        report_dir=report_dir,
        log_rotation_enabled=log_rotation_enabled,
        max_log_size_mb=max_log_size_mb,
        messages=tuple(messages),
        errors=tuple(errors),
    )


# FUN-086
def cleanup_old_reports(
    report_dir: str | Path,
    *,
    max_reports_to_keep: int,
) -> tuple[int, int]:
    keep_count = _validate_positive_int(max_reports_to_keep, "max_reports_to_keep")
    directory = Path(report_dir)
    if not directory.exists():
        return 0, 0
    if not directory.is_dir():
        raise ValueError(f"Report path is not a directory: {directory}")

    report_files = sorted(
        _iter_report_files(directory),
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    files_to_delete = report_files[keep_count:]

    deleted = 0
    for path in files_to_delete:
        path.unlink()
        deleted += 1

    return deleted, len(report_files) - deleted


# FUN-087
def validate_log_rotation(config: Any) -> tuple[bool, str, str | None]:
    max_log_size_mb = int(getattr(config, "max_log_size_mb", 50))
    log_dir = Path(getattr(config, "log_dir", "logs"))
    if max_log_size_mb < 1:
        return False, "Log rotation size is invalid.", "MAX_LOG_SIZE_MB must be >= 1"

    message = (
        f"Log rotation is size-based: {LOG_FILE_NAME}, "
        f"max_size={max_log_size_mb}MB, backups={DEFAULT_BACKUP_COUNT}, "
        f"log_dir={log_dir}."
    )
    return True, message, None


# FUN-088
def format_maintenance_result(result: MaintenanceResult) -> str:
    lines = [
        "Gleipnir maintenance",
        f"OK | events_deleted={result.events_deleted} retention_days={result.event_retention_days}",
        f"OK | reports_deleted={result.reports_deleted} reports_kept={result.reports_kept} max_reports_to_keep={result.max_reports_to_keep}",
    ]
    if result.log_rotation_enabled:
        lines.append(
            f"OK | log_rotation=max_size max_log_size_mb={result.max_log_size_mb} backups={result.log_backup_count}"
        )
    else:
        lines.append("ERROR | log_rotation=invalid")

    for message in result.messages:
        lines.append(f"INFO | {message}")
    for error in result.errors:
        lines.append(f"ERROR | {error}")

    return "\n".join(lines) + "\n"


def _iter_report_files(directory: Path):
    for path in directory.iterdir():
        if not path.is_file():
            continue
        if path.suffix.lower() not in REPORT_SUFFIXES:
            continue
        if not path.name.startswith(f"{DEFAULT_REPORT_PREFIX}_"):
            continue
        yield path


def _validate_positive_int(value: int, name: str) -> int:
    try:
        parsed_value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc

    if parsed_value < 1:
        raise ValueError(f"{name} must be a positive integer")

    return parsed_value


def _log_info(logger: Any | None, message: str, *args: Any) -> None:
    if logger is not None:
        logger.info(message, *args)


def _log_error(logger: Any | None, message: str, *args: Any) -> None:
    if logger is not None:
        logger.error(message, *args)
