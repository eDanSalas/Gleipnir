
from __future__ import annotations

import socket
import sqlite3
import smtplib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO


STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_ERROR = "ERROR"
DEFAULT_SMTP_HEALTH_TIMEOUT = 5


@dataclass(frozen=True)
class HealthCheckItem:

    status: str
    component: str
    message: str


@dataclass(frozen=True)
class HealthReport:

    items: tuple[HealthCheckItem, ...]

    # FUN-108
    @property
    def exit_code(self) -> int:
        return 1 if any(item.status == STATUS_ERROR for item in self.items) else 0


ConfigLoader = Callable[[], Any]
SmtpChecker = Callable[[str, int, int], None]
InterfaceProvider = Callable[[], Iterable[tuple[int, str]]]


# FUN-109
def run_healthcheck(
    *,
    config_loader: ConfigLoader | None = None,
    smtp_checker: SmtpChecker | None = None,
    interface_provider: InterfaceProvider | None = None,
) -> HealthReport:
    loader = config_loader or _load_runtime_config
    smtp_probe = smtp_checker or _check_smtp_availability
    interfaces = interface_provider or socket.if_nameindex
    items: list[HealthCheckItem] = []

    try:
        config = loader()
    except Exception as exc:
        return HealthReport(
            (
                HealthCheckItem(
                    STATUS_ERROR,
                    "configuration",
                    f"Configuration could not be loaded: {exc}",
                ),
            )
        )

    items.append(
        HealthCheckItem(
            STATUS_OK,
            "configuration",
            "Configuration loaded successfully.",
        )
    )

    items.append(_check_file("whitelist", Path(config.whitelist_file)))
    items.append(_check_file("blacklist", Path(config.blacklist_file)))
    items.append(_check_directory("log_dir", Path(config.log_dir), required=True))
    items.append(_check_directory("report_dir", Path(config.report_dir), required=False))
    items.append(_check_sqlite(Path(config.ids_db_path)))
    items.append(_check_dashboard_users_file(config))
    items.append(_check_smtp(config, smtp_probe))
    items.append(_check_interface(config, interfaces))

    return HealthReport(tuple(items))


# FUN-110
def format_health_report(report: HealthReport) -> str:
    lines = ["Gleipnir status"]
    for item in report.items:
        lines.append(f"{item.status:<7} | {item.component:<13} | {item.message}")
    return "\n".join(lines) + "\n"


# FUN-111
def print_health_report(report: HealthReport, stdout: TextIO) -> None:
    print(format_health_report(report), end="", file=stdout)


def _check_file(component: str, path: Path) -> HealthCheckItem:
    if path.is_file():
        return HealthCheckItem(STATUS_OK, component, f"File exists: {path}")

    if path.exists():
        return HealthCheckItem(
            STATUS_ERROR,
            component,
            f"Path exists but is not a regular file: {path}",
        )

    return HealthCheckItem(STATUS_ERROR, component, f"File not found: {path}")


def _check_directory(component: str, path: Path, *, required: bool) -> HealthCheckItem:
    if not path.exists():
        status = STATUS_ERROR if required else STATUS_WARNING
        message = f"Directory not found: {path}"
        if not required:
            message = f"{message}; it can be created before generating reports."
        return HealthCheckItem(status, component, message)

    if not path.is_dir():
        return HealthCheckItem(
            STATUS_ERROR,
            component,
            f"Path exists but is not a directory: {path}",
        )

    try:
        with tempfile.NamedTemporaryFile(
            prefix=".gleipnir-status-",
            dir=path,
            delete=True,
        ):
            pass
    except OSError as exc:
        return HealthCheckItem(
            STATUS_ERROR,
            component,
            f"Directory is not writable: {path} ({exc})",
        )

    return HealthCheckItem(STATUS_OK, component, f"Directory is writable: {path}")


def _check_sqlite(db_path: Path) -> HealthCheckItem:
    if not db_path.exists():
        return HealthCheckItem(
            STATUS_WARNING,
            "sqlite",
            f"Database does not exist yet: {db_path}",
        )

    if not db_path.is_file():
        return HealthCheckItem(
            STATUS_ERROR,
            "sqlite",
            f"Database path exists but is not a file: {db_path}",
        )

    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=2)
        try:
            connection.execute("SELECT 1")
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return HealthCheckItem(
            STATUS_ERROR,
            "sqlite",
            f"Database is not accessible: {db_path} ({exc})",
        )

    return HealthCheckItem(STATUS_OK, "sqlite", f"Database is accessible: {db_path}")


def _check_dashboard_users_file(config: Any) -> HealthCheckItem:
    from src.dashboard.auth import check_users_file_permissions

    users_file = Path(getattr(config, "dashboard_users_file", "data/dashboard_users.json"))
    result = check_users_file_permissions(users_file)
    status = STATUS_WARNING if result.is_warning else STATUS_OK
    return HealthCheckItem(status, "dashboard_users", result.message)


def _check_smtp(config: Any, smtp_checker: SmtpChecker) -> HealthCheckItem:
    try:
        smtp_checker(
            str(config.smtp_host),
            int(config.smtp_port),
            DEFAULT_SMTP_HEALTH_TIMEOUT,
        )
    except Exception as exc:
        safe_error = _redact_known_secrets(str(exc), config)
        return HealthCheckItem(
            STATUS_ERROR,
            "smtp",
            f"SMTP endpoint is not available: {config.smtp_host}:{config.smtp_port} ({safe_error})",
        )

    return HealthCheckItem(
        STATUS_OK,
        "smtp",
        f"SMTP endpoint is reachable: {config.smtp_host}:{config.smtp_port}",
    )


def _check_smtp_availability(host: str, port: int, timeout: int) -> None:
    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        smtp.noop()


def _check_interface(
    config: Any,
    interface_provider: InterfaceProvider,
) -> HealthCheckItem:
    interface = getattr(config, "gleipnir_interface", None)
    mode = getattr(config, "gleipnir_mode", "live")

    if not interface:
        status = STATUS_WARNING if mode == "live" else STATUS_OK
        return HealthCheckItem(
            status,
            "interface",
            "GLEIPNIR_INTERFACE is not configured; pass --interface explicitly for live mode.",
        )

    try:
        available_interfaces = {name for _index, name in interface_provider()}
    except OSError as exc:
        return HealthCheckItem(
            STATUS_WARNING,
            "interface",
            f"Could not enumerate network interfaces to verify {interface}: {exc}",
        )

    if interface in available_interfaces:
        return HealthCheckItem(
            STATUS_OK,
            "interface",
            f"Configured interface is available: {interface}",
        )

    return HealthCheckItem(
        STATUS_ERROR,
        "interface",
        f"Configured interface was not found: {interface}",
    )


def _load_runtime_config() -> Any:
    from src.config import load_config

    return load_config()


def _redact_known_secrets(text: str, config: Any) -> str:
    redacted = text
    secret_values = (
        getattr(config, "smtp_password", None),
        getattr(config, "abuseipdb_api_key", None),
        getattr(config, "virustotal_api_key", None),
    )

    for secret in secret_values:
        if secret:
            redacted = redacted.replace(str(secret), "[REDACTED]")

    return redacted
