"""Unit tests for the Gleipnir logging setup."""

from __future__ import annotations

import io
import logging
import unittest
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from src.logger import LOG_FILE_NAME, REDACTED_VALUE, setup_logging


@dataclass(frozen=True)
class DummyConfig:
    log_dir: Path
    smtp_password: str = "smtp-secret"
    abuseipdb_api_key: str = "abuse-secret"
    virustotal_api_key: str = "vt-secret"
    dashboard_password: str = "dashboard-secret"
    dashboard_admin_password: str = "dashboard-admin-secret"
    dashboard_secret_key: str = "dashboard-secret-key"
    max_log_size_mb: int = 50


class LoggerTests(unittest.TestCase):
    def test_setup_logging_writes_to_file_and_console(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stream = io.StringIO()
            config = DummyConfig(log_dir=Path(temp_dir))

            logger = setup_logging(
                config,
                logger_name="gleipnir.test.basic",
                console_stream=stream,
            )

            try:
                logger.info("logging ready")
                self._flush(logger)

                log_text = (Path(temp_dir) / LOG_FILE_NAME).read_text(
                    encoding="utf-8"
                )
                console_text = stream.getvalue()

                self.assertIn(" | INFO | ", log_text)
                self.assertIn(" | test_logger | logging ready", log_text)
                self.assertIn("logging ready", console_text)
            finally:
                self._close(logger)

    def test_setup_logging_redacts_secrets(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stream = io.StringIO()
            config = DummyConfig(log_dir=Path(temp_dir))

            logger = setup_logging(
                config,
                logger_name="gleipnir.test.redaction",
                console_stream=stream,
            )

            try:
                logger.warning(
                    "smtp password=%s api_key=%s token=%s",
                    config.smtp_password,
                    config.abuseipdb_api_key,
                    "runtime-token",
                )
                logger.warning("dashboard password=%s", config.dashboard_password)
                logger.warning(
                    "dashboard admin password=%s",
                    config.dashboard_admin_password,
                )
                logger.warning("dashboard secret=%s", config.dashboard_secret_key)
                self._flush(logger)

                emitted_text = (
                    (Path(temp_dir) / LOG_FILE_NAME).read_text(encoding="utf-8")
                    + stream.getvalue()
                )

                self.assertNotIn(config.smtp_password, emitted_text)
                self.assertNotIn(config.abuseipdb_api_key, emitted_text)
                self.assertNotIn(config.dashboard_password, emitted_text)
                self.assertNotIn(config.dashboard_admin_password, emitted_text)
                self.assertNotIn(config.dashboard_secret_key, emitted_text)
                self.assertNotIn("runtime-token", emitted_text)
                self.assertIn(REDACTED_VALUE, emitted_text)
            finally:
                self._close(logger)

    def test_setup_logging_rotates_log_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir))

            logger = setup_logging(
                config,
                logger_name="gleipnir.test.rotation",
                max_bytes=160,
                backup_count=2,
                console_stream=io.StringIO(),
            )

            try:
                for index in range(20):
                    logger.info("rotation line %02d with enough text", index)
                self._flush(logger)

                log_files = list(Path(temp_dir).glob(f"{LOG_FILE_NAME}*"))

                self.assertGreater(len(log_files), 1)
                self.assertLessEqual(len(log_files), 3)
            finally:
                self._close(logger)

    def test_setup_logging_uses_configured_log_size(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = DummyConfig(log_dir=Path(temp_dir), max_log_size_mb=1)

            logger = setup_logging(
                config,
                logger_name="gleipnir.test.configured_size",
                console_stream=io.StringIO(),
            )

            try:
                file_handler = next(
                    handler
                    for handler in logger.handlers
                    if hasattr(handler, "maxBytes")
                )

                self.assertEqual(file_handler.maxBytes, 1_048_576)
            finally:
                self._close(logger)

    @staticmethod
    def _flush(logger: logging.Logger) -> None:
        for handler in logger.handlers:
            handler.flush()

    @staticmethod
    def _close(logger: logging.Logger) -> None:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()


if __name__ == "__main__":
    unittest.main()
