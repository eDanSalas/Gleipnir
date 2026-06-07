"""Logging setup for Gleipnir IDS.

The logger writes to console and to a rotating log file while redacting
sensitive values before they are emitted.
"""

from __future__ import annotations

import copy
import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable, TextIO


LOG_FILE_NAME = "gleipnir.log"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(module)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_MAX_BYTES = 1_048_576
DEFAULT_BACKUP_COUNT = 5
REDACTED_VALUE = "[REDACTED]"


class SecretRedactor:
    """Redact known secret values and sensitive key assignments."""

    _sensitive_assignment = re.compile(
        r"(?i)(\b[\w.-]*(?:password|passwd|pwd|api[_-]?key|token|secret)"
        r"[\w.-]*\b\s*[:=]\s*)(['\"]?)[^'\"\s,;]+(['\"]?)"
    )

    def __init__(self, secrets: Iterable[str | None] = ()) -> None:
        self._secrets = tuple(
            secret for secret in {item for item in secrets if item} if secret.strip()
        )

    def redact(self, text: str) -> str:
        """Return text without known secret values or secret assignments."""
        redacted = text

        for secret in self._secrets:
            redacted = redacted.replace(secret, REDACTED_VALUE)

        return self._sensitive_assignment.sub(
            rf"\1\2{REDACTED_VALUE}\3",
            redacted,
        )


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts secrets from the final log line."""

    def __init__(
        self,
        fmt: str,
        datefmt: str,
        redactor: SecretRedactor,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        safe_record = copy.copy(record)
        formatted = super().format(safe_record)
        return self._redactor.redact(formatted)


def setup_logging(
    config: Any,
    *,
    logger_name: str = "gleipnir",
    level: int = logging.INFO,
    log_file_name: str = LOG_FILE_NAME,
    max_bytes: int | None = None,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    console_stream: TextIO | None = None,
) -> logging.Logger:
    """Configure console and rotating file logging from project config."""
    log_dir = Path(config.log_dir).expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False
    _reset_handlers(logger)

    formatter = RedactingFormatter(
        fmt=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        redactor=_redactor_from_config(config),
    )

    console_handler = logging.StreamHandler(console_stream)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        filename=log_dir / log_file_name,
        maxBytes=max_bytes if max_bytes is not None else _max_bytes_from_config(config),
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


def get_logger(module_name: str) -> logging.Logger:
    """Return a module logger under the Gleipnir namespace."""
    return logging.getLogger(f"gleipnir.{module_name}")


def _reset_handlers(logger: logging.Logger) -> None:
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def _redactor_from_config(config: Any) -> SecretRedactor:
    return SecretRedactor(
        (
            getattr(config, "smtp_password", None),
            getattr(config, "abuseipdb_api_key", None),
            getattr(config, "virustotal_api_key", None),
            getattr(config, "dashboard_password", None),
        )
    )


def _max_bytes_from_config(config: Any) -> int:
    max_log_size_mb = getattr(config, "max_log_size_mb", None)
    if max_log_size_mb is None:
        return DEFAULT_MAX_BYTES

    try:
        parsed_mb = int(max_log_size_mb)
    except (TypeError, ValueError):
        return DEFAULT_MAX_BYTES

    if parsed_mb < 1:
        return DEFAULT_MAX_BYTES

    return parsed_mb * 1_048_576
