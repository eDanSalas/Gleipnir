"""Unit tests for the Gleipnir CLI."""

from __future__ import annotations

import json
import io
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src import cli
from src.maintenance import MaintenanceResult
from src.reports import ReportData
from src.status import HealthCheckItem, HealthReport
from src.storage import DNS_EVENT, SQLiteEventStore


class CliTests(unittest.TestCase):
    def test_offline_command_calls_parse_pcap(self) -> None:
        stdout = io.StringIO()
        parse_pcap = Mock(return_value=[object(), object()])

        with patch("src.cli.parse_pcap", parse_pcap):
            exit_code = cli.main(
                ["offline", "--pcap", "sample.pcap"],
                stdout=stdout,
                stderr=io.StringIO(),
            )

        self.assertEqual(exit_code, 0)
        parse_pcap.assert_called_once_with("sample.pcap")
        self.assertIn("2 packet event", stdout.getvalue())

    def test_replay_command_calls_replay_pcap(self) -> None:
        stdout = io.StringIO()
        replay_pcap = Mock(
            return_value=SimpleNamespace(
                packet_count=3,
                detection_events=[object()],
                traffic_events=[object(), object()],
                errors=0,
            )
        )
        engine = Mock()

        with patch("src.cli._create_engine", return_value=engine):
            with patch("src.cli.replay_pcap", replay_pcap):
                exit_code = cli.main(
                    ["replay", "--pcap", "sample.pcap", "--delay", "1"],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        replay_pcap.assert_called_once()
        self.assertEqual(replay_pcap.call_args.args, ("sample.pcap",))
        self.assertEqual(replay_pcap.call_args.kwargs["delay_seconds"], 1.0)
        self.assertIn("packet_processor", replay_pcap.call_args.kwargs)
        engine.shutdown.assert_called_once()
        self.assertIn("packets=3", stdout.getvalue())
        self.assertIn("dns_http_events=2", stdout.getvalue())
        self.assertIn("errors=0", stdout.getvalue())

    def test_live_command_calls_start_live_capture(self) -> None:
        stdout = io.StringIO()
        start_live_capture = Mock(
            return_value=SimpleNamespace(
                packets_received=4,
                packet_events_processed=4,
                detection_events_processed=3,
                traffic_events_processed=2,
                errors=1,
            )
        )
        engine = Mock()

        with patch("src.cli._create_engine", return_value=engine):
            with patch("src.cli.start_live_capture", start_live_capture):
                exit_code = cli.main(
                    [
                        "live",
                        "--interface",
                        "wlan0",
                        "--packet-count",
                        "4",
                        "--timeout",
                        "10",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        start_live_capture.assert_called_once()
        self.assertEqual(start_live_capture.call_args.args, ("wlan0",))
        self.assertEqual(start_live_capture.call_args.kwargs["packet_count"], 4)
        self.assertEqual(start_live_capture.call_args.kwargs["timeout"], 10.0)
        self.assertIn("packet_processor", start_live_capture.call_args.kwargs)
        engine.shutdown.assert_called_once()
        self.assertIn("received=4", stdout.getvalue())
        self.assertIn("errors=1", stdout.getvalue())

    def test_live_forever_command_calls_supervised_capture(self) -> None:
        stdout = io.StringIO()
        start_live_capture_forever = Mock(
            return_value=SimpleNamespace(
                capture_cycles=2,
                packets_received=5,
                packet_events_processed=5,
                detection_events_processed=4,
                traffic_events_processed=3,
                errors=1,
            )
        )
        engine = Mock()
        engine.config.health_log_interval_seconds = 120

        with patch("src.cli._create_engine", return_value=engine):
            with patch(
                "src.cli.start_live_capture_forever",
                start_live_capture_forever,
            ):
                exit_code = cli.main(
                    [
                        "live",
                        "--interface",
                        "wlan0",
                        "--forever",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        start_live_capture_forever.assert_called_once()
        self.assertEqual(start_live_capture_forever.call_args.args, ("wlan0",))
        self.assertEqual(
            start_live_capture_forever.call_args.kwargs[
                "health_log_interval_seconds"
            ],
            120,
        )
        self.assertIn("packet_processor", start_live_capture_forever.call_args.kwargs)
        engine.shutdown.assert_called_once()
        self.assertIn("Live capture forever stopped", stdout.getvalue())
        self.assertIn("cycles=2", stdout.getvalue())

    def test_engine_packet_processor_calls_engine_with_dns_http_source(self) -> None:
        engine = Mock()
        packet_event = object()
        source = object()

        processor = cli._engine_packet_processor(engine)
        processor(packet_event, source)

        engine.process_packet_event.assert_called_once_with(
            packet_event,
            dns_http_source=source,
        )

    def test_test_config_prints_redacted_config(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(
            as_redacted_dict=lambda: {
                "smtp_user": "alerts@example.org",
                "smtp_password": "***",
                "abuseipdb_api_key": "***",
            }
        )

        with patch("src.cli._load_config", return_value=config):
            exit_code = cli.main(
                ["test-config"],
                stdout=stdout,
                stderr=io.StringIO(),
            )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Configuration OK", output)
        self.assertIn('"smtp_password": "***"', output)
        self.assertNotIn("real-password", output)

    def test_status_command_prints_health_report(self) -> None:
        stdout = io.StringIO()
        report = HealthReport(
            (
                HealthCheckItem("OK", "configuration", "Configuration loaded."),
                HealthCheckItem("WARNING", "sqlite", "Database does not exist yet."),
            )
        )

        with patch("src.cli.run_healthcheck", return_value=report):
            exit_code = cli.main(
                ["status"],
                stdout=stdout,
                stderr=io.StringIO(),
            )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Gleipnir status", output)
        self.assertIn("OK", output)
        self.assertIn("WARNING", output)

    def test_status_command_returns_one_when_healthcheck_has_error(self) -> None:
        report = HealthReport(
            (
                HealthCheckItem("OK", "configuration", "Configuration loaded."),
                HealthCheckItem("ERROR", "smtp", "SMTP endpoint is not available."),
            )
        )

        with patch("src.cli.run_healthcheck", return_value=report):
            exit_code = cli.main(
                ["status"],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )

        self.assertEqual(exit_code, 1)

    def test_maintenance_command_runs_retention(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(log_dir=Path("logs"))
        result = MaintenanceResult(
            events_deleted=2,
            reports_deleted=1,
            reports_kept=3,
            event_retention_days=30,
            max_reports_to_keep=20,
            max_log_size_mb=50,
        )

        with patch("src.cli._load_config", return_value=config):
            with patch("src.logger.setup_logging") as setup_logging:
                with patch("src.cli.run_maintenance", return_value=result) as maintenance:
                    exit_code = cli.main(
                        ["maintenance"],
                        stdout=stdout,
                        stderr=io.StringIO(),
                    )

        self.assertEqual(exit_code, 0)
        setup_logging.assert_called_once_with(config)
        maintenance.assert_called_once()
        self.assertIn("Gleipnir maintenance", stdout.getvalue())
        self.assertIn("events_deleted=2", stdout.getvalue())

    def test_dashboard_command_starts_read_only_web_server(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(
            ids_db_path=Path("data/events.db"),
            dashboard_auth_enabled=True,
        )
        app = Mock()

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app", return_value=app) as factory:
                exit_code = cli.main(
                    [
                        "dashboard",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8080",
                        "--allow-lan",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        factory.assert_called_once_with(config=config)
        app.run.assert_called_once_with(host="0.0.0.0", port=8080)
        self.assertIn("ADVERTENCIA", stdout.getvalue())
        self.assertIn("no lo expongas a internet", stdout.getvalue())
        self.assertIn("read-only", stdout.getvalue())

    def test_dashboard_localhost_starts_without_extra_flags(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(ids_db_path=Path("data/events.db"))
        app = Mock()

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app", return_value=app) as factory:
                exit_code = cli.main(
                    ["dashboard", "--host", "127.0.0.1", "--port", "8080"],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        factory.assert_called_once_with(config=config)
        app.run.assert_called_once_with(host="127.0.0.1", port=8080)
        self.assertNotIn("ADVERTENCIA", stdout.getvalue())

    def test_dashboard_rejects_all_interfaces_without_allow_lan(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        config = SimpleNamespace(
            ids_db_path=Path("data/events.db"),
            dashboard_auth_enabled=True,
        )

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app") as factory:
                exit_code = cli.main(
                    ["dashboard", "--host", "0.0.0.0", "--port", "8080"],
                    stdout=stdout,
                    stderr=stderr,
                )

        self.assertEqual(exit_code, 1)
        factory.assert_not_called()
        self.assertIn("--allow-lan", stderr.getvalue())
        self.assertIn("internet", stderr.getvalue())

    def test_dashboard_rejects_unauthenticated_lan_without_explicit_flag(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        config = SimpleNamespace(
            ids_db_path=Path("data/events.db"),
            dashboard_auth_enabled=False,
        )

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app") as factory:
                exit_code = cli.main(
                    [
                        "dashboard",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8080",
                        "--allow-lan",
                    ],
                    stdout=stdout,
                    stderr=stderr,
                )

        self.assertEqual(exit_code, 1)
        factory.assert_not_called()
        self.assertIn("DASHBOARD_AUTH_ENABLED=false", stderr.getvalue())
        self.assertIn("--allow-unauthenticated-lan", stderr.getvalue())

    def test_dashboard_allows_unauthenticated_lan_only_with_explicit_flags(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(
            ids_db_path=Path("data/events.db"),
            dashboard_auth_enabled=False,
        )
        app = Mock()

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app", return_value=app) as factory:
                exit_code = cli.main(
                    [
                        "dashboard",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8080",
                        "--allow-lan",
                        "--allow-unauthenticated-lan",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        factory.assert_called_once_with(config=config)
        app.run.assert_called_once_with(host="0.0.0.0", port=8080)
        self.assertIn("ADVERTENCIA", stdout.getvalue())

    def test_report_generates_json_and_csv(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(report_dir=Path("reports"), log_dir=Path("logs"))
        report_paths = SimpleNamespace(
            json_path=Path("reports/gleipnir_report.json"),
            csv_path=Path("reports/gleipnir_report.csv"),
        )

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli._load_report_data", return_value=ReportData()) as loader:
                with patch("src.cli.generate_reports", return_value=report_paths) as reporter:
                    exit_code = cli.main(
                        ["report"],
                        stdout=stdout,
                        stderr=io.StringIO(),
                    )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        loader.assert_called_once()
        self.assertEqual(loader.call_args.args[0], config)
        self.assertIsNone(loader.call_args.args[1].event_type)
        reporter.assert_called_once()
        self.assertEqual(reporter.call_args.kwargs["output_format"], "both")
        self.assertIn("Reports generated:", output)
        self.assertIn("gleipnir_report.json", output)
        self.assertIn("gleipnir_report.csv", output)
        self.assertIn("Summary: total_events=0", output)

    def test_report_filters_sqlite_events_and_writes_json_only(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = SimpleNamespace(
                report_dir=root / "reports",
                log_dir=root / "logs",
                ids_db_path=root / "events.db",
            )
            store = SQLiteEventStore(config.ids_db_path)
            store.save_event(
                event_type=DNS_EVENT,
                timestamp=datetime(2026, 6, 3, tzinfo=timezone.utc).timestamp(),
                severity="INFO",
                source_ip="192.168.1.10",
                destination_ip="8.8.8.8",
                protocol="DNS",
                domain="ejemplo.com",
                message="DNS query observed: ejemplo.com",
                raw={"tipo_consulta": "A"},
            )
            store.save_event(
                event_type=DNS_EVENT,
                timestamp=datetime(2026, 6, 8, tzinfo=timezone.utc).timestamp(),
                severity="INFO",
                source_ip="192.168.1.20",
                destination_ip="1.1.1.1",
                protocol="DNS",
                domain="otro.com",
                message="DNS query observed: otro.com",
                raw={"tipo_consulta": "AAAA"},
            )
            store.close()

            stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    [
                        "report",
                        "--format",
                        "json",
                        "--type",
                        "DNS_EVENT",
                        "--since",
                        "2026-06-01",
                        "--until",
                        "2026-06-07",
                        "--source-ip",
                        "192.168.1.10",
                        "--domain",
                        "ejemplo.com",
                        "--severity",
                        "info",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

            json_reports = list((root / "reports").glob("*.json"))
            csv_reports = list((root / "reports").glob("*.csv"))
            payload = json.loads(json_reports[0].read_text(encoding="utf-8"))

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(json_reports), 1)
        self.assertEqual(csv_reports, [])
        self.assertEqual(payload["summary"]["dns_events"], 1)
        self.assertEqual(payload["filters"]["type"], "DNS_EVENT")
        self.assertEqual(payload["filters"]["severity"], "INFO")
        self.assertIn("Summary: total_events=1", output)
        self.assertIn("- dns_events: 1", output)

    def test_command_errors_are_clear(self) -> None:
        stderr = io.StringIO()

        with patch("src.cli.parse_pcap", side_effect=ValueError("bad pcap")):
            exit_code = cli.main(
                ["offline", "--pcap", "bad.pcap"],
                stdout=io.StringIO(),
                stderr=stderr,
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("Error: bad pcap", stderr.getvalue())

    def test_whitelist_admin_commands_use_configured_file(self) -> None:
        with self._temp_config() as config:
            add_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                add_exit = cli.main(
                    [
                        "whitelist",
                        "add",
                        "--ip",
                        "192.168.1.10",
                        "--mac",
                        "AA-BB-CC-DD-EE-FF",
                        "--description",
                        "Laptop laboratorio",
                    ],
                    stdout=add_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(add_exit, 0)
            self.assertIn("Whitelist entry added", add_stdout.getvalue())

            list_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                list_exit = cli.main(
                    ["whitelist", "list"],
                    stdout=list_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(list_exit, 0)
            self.assertIn("192.168.1.10", list_stdout.getvalue())
            self.assertIn("aa:bb:cc:dd:ee:ff", list_stdout.getvalue())

            validate_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                validate_exit = cli.main(
                    ["whitelist", "validate"],
                    stdout=validate_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(validate_exit, 0)
            self.assertIn("Whitelist valid: 1", validate_stdout.getvalue())

            remove_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                remove_exit = cli.main(
                    ["whitelist", "remove", "--ip", "192.168.1.10"],
                    stdout=remove_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(remove_exit, 0)
            self.assertIn("Whitelist entry removed", remove_stdout.getvalue())

    def test_blacklist_admin_commands_use_configured_file(self) -> None:
        with self._temp_config() as config:
            add_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                add_exit = cli.main(
                    [
                        "blacklist",
                        "add",
                        "--ip",
                        "8.8.8.8",
                        "--reason",
                        "Malware",
                    ],
                    stdout=add_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(add_exit, 0)
            self.assertIn("Blacklist entry added", add_stdout.getvalue())

            list_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                list_exit = cli.main(
                    ["blacklist", "list"],
                    stdout=list_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(list_exit, 0)
            self.assertIn("8.8.8.8", list_stdout.getvalue())
            self.assertIn("Malware", list_stdout.getvalue())

            validate_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                validate_exit = cli.main(
                    ["blacklist", "validate"],
                    stdout=validate_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(validate_exit, 0)
            self.assertIn("Blacklist valid: 1", validate_stdout.getvalue())

            remove_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                remove_exit = cli.main(
                    ["blacklist", "remove", "--ip", "8.8.8.8"],
                    stdout=remove_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(remove_exit, 0)
            self.assertIn("Blacklist entry removed", remove_stdout.getvalue())

    def test_admin_commands_report_duplicate_entries_clearly(self) -> None:
        with self._temp_config() as config:
            with patch("src.cli._load_config", return_value=config):
                cli.main(
                    [
                        "whitelist",
                        "add",
                        "--ip",
                        "10.0.0.5",
                        "--mac",
                        "00:11:22:33:44:55",
                        "--description",
                        "Equipo",
                    ],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            stderr = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    [
                        "whitelist",
                        "add",
                        "--ip",
                        "10.0.0.5",
                        "--mac",
                        "00:11:22:33:44:56",
                        "--description",
                        "Duplicado",
                    ],
                    stdout=io.StringIO(),
                    stderr=stderr,
                )

            self.assertEqual(exit_code, 1)
            self.assertIn("already contains", stderr.getvalue())

    @staticmethod
    def _temp_config():
        from tempfile import TemporaryDirectory

        class TempConfigContext:
            def __enter__(self):
                self._temp_dir = TemporaryDirectory()
                root = Path(self._temp_dir.name)
                return SimpleNamespace(
                    whitelist_file=root / "whitelist.csv",
                    blacklist_file=root / "blacklist.txt",
                    report_dir=root / "reports",
                    log_dir=root / "logs",
                )

            def __exit__(self, exc_type, exc, traceback):
                self._temp_dir.cleanup()

        return TempConfigContext()


if __name__ == "__main__":
    unittest.main()
