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
from src.firewall import FirewallResult
from src.dashboard.auth import (
    authenticate_dashboard_user,
    create_dashboard_user,
    list_dashboard_users,
)
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
                raw_packets=1,
                decoded_from_raw=1,
                ignored_packets=0,
                unsupported_packets=0,
                parse_errors=0,
                packet_events_processed=4,
                engine_errors=1,
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
        self.assertFalse(start_live_capture.call_args.kwargs["debug_packets"])
        self.assertFalse(start_live_capture.call_args.kwargs["use_pcap"])
        engine.shutdown.assert_called_once()
        self.assertIn("received=4", stdout.getvalue())
        self.assertIn("raw_packets=1", stdout.getvalue())
        self.assertIn("decoded_from_raw=1", stdout.getvalue())
        self.assertIn("ignored_packets=0", stdout.getvalue())
        self.assertIn("unsupported_packets=0", stdout.getvalue())
        self.assertIn("parse_errors=0", stdout.getvalue())
        self.assertIn("engine_errors=1", stdout.getvalue())
        self.assertIn("errors=1", stdout.getvalue())

    def test_live_command_enables_debug_packet_output(self) -> None:
        stdout = io.StringIO()

        def start_live_capture(*_args, **kwargs):
            kwargs["debug_output"](
                "DEBUG_PACKET | status=packet_event | summary=IP / TCP"
            )
            return SimpleNamespace(
                packets_received=1,
                raw_packets=0,
                decoded_from_raw=0,
                ignored_packets=0,
                unsupported_packets=0,
                parse_errors=0,
                packet_events_processed=1,
                engine_errors=0,
                detection_events_processed=1,
                traffic_events_processed=0,
                errors=0,
            )

        engine = Mock()

        with patch("src.cli._create_engine", return_value=engine):
            with patch("src.cli.start_live_capture", start_live_capture):
                exit_code = cli.main(
                    [
                        "live",
                        "--interface",
                        "wlan0",
                        "--debug-packets",
                        "--packet-count",
                        "1",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        self.assertIn("DEBUG_PACKET", stdout.getvalue())
        self.assertIn("packet_events=1", stdout.getvalue())

    def test_live_command_enables_libpcap_backend_flag(self) -> None:
        stdout = io.StringIO()
        start_live_capture = Mock(
            return_value=SimpleNamespace(
                packets_received=1,
                raw_packets=0,
                decoded_from_raw=0,
                ignored_packets=0,
                unsupported_packets=0,
                parse_errors=0,
                packet_events_processed=1,
                engine_errors=0,
                detection_events_processed=1,
                traffic_events_processed=0,
                errors=0,
            )
        )
        engine = Mock()

        with patch("src.cli._create_engine", return_value=engine):
            with patch("src.cli.start_live_capture", start_live_capture):
                exit_code = cli.main(
                    [
                        "live",
                        "--interface",
                        "ens33",
                        "--packet-count",
                        "1",
                        "--use-pcap",
                    ],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

        self.assertEqual(exit_code, 0)
        self.assertTrue(start_live_capture.call_args.kwargs["use_pcap"])
        self.assertIn("packet_events=1", stdout.getvalue())

    def test_live_forever_command_calls_supervised_capture(self) -> None:
        stdout = io.StringIO()
        start_live_capture_forever = Mock(
            return_value=SimpleNamespace(
                capture_cycles=2,
                packets_received=5,
                raw_packets=2,
                decoded_from_raw=1,
                ignored_packets=1,
                unsupported_packets=0,
                parse_errors=0,
                packet_events_processed=5,
                engine_errors=1,
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
        self.assertFalse(start_live_capture_forever.call_args.kwargs["debug_packets"])
        engine.shutdown.assert_called_once()
        self.assertIn("Live capture forever stopped", stdout.getvalue())
        self.assertIn("cycles=2", stdout.getvalue())
        self.assertIn("raw_packets=2", stdout.getvalue())
        self.assertIn("decoded_from_raw=1", stdout.getvalue())
        self.assertIn("ignored_packets=1", stdout.getvalue())
        self.assertIn("engine_errors=1", stdout.getvalue())

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

    def test_dashboard_command_prints_users_file_permission_warning(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(
            ids_db_path=Path("data/events.db"),
            dashboard_users_file=Path("data/dashboard_users.json"),
        )
        app = Mock()
        permission_check = SimpleNamespace(
            is_warning=True,
            message="Dashboard users file has insecure permissions 644; recommended mode is 600",
        )

        with patch("src.cli._load_config", return_value=config):
            with patch("src.cli.create_dashboard_app", return_value=app):
                with patch(
                    "src.cli.check_users_file_permissions",
                    return_value=permission_check,
                ):
                    exit_code = cli.main(
                        ["dashboard", "--host", "127.0.0.1", "--port", "8080"],
                        stdout=stdout,
                        stderr=io.StringIO(),
                    )

        self.assertEqual(exit_code, 0)
        self.assertIn("WARNING", stdout.getvalue())
        self.assertIn("600", stdout.getvalue())
        self.assertNotIn("password_hash", stdout.getvalue())

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

    def test_dashboard_user_commands_manage_hashed_users(self) -> None:
        with self._temp_config() as config:
            create_stdout = io.StringIO()
            create_stderr = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.cli.getpass.getpass",
                    side_effect=["StrongPassword123!", "StrongPassword123!"],
                ):
                    create_exit = cli.main(
                        ["user", "create", "--username", "admin", "--role", "admin"],
                        stdout=create_stdout,
                        stderr=create_stderr,
                    )

            raw_users = config.dashboard_users_file.read_text(encoding="utf-8")
            self.assertEqual(create_exit, 0)
            self.assertIn("Dashboard user created: admin", create_stdout.getvalue())
            self.assertNotIn("StrongPassword123!", create_stdout.getvalue())
            self.assertNotIn("StrongPassword123!", create_stderr.getvalue())
            self.assertNotIn("StrongPassword123!", raw_users)
            self.assertIn("password_hash", raw_users)

            list_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                list_exit = cli.main(
                    ["user", "list"],
                    stdout=list_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(list_exit, 0)
            self.assertIn("admin", list_stdout.getvalue())
            self.assertIn("role=admin", list_stdout.getvalue())
            self.assertNotIn("password_hash", list_stdout.getvalue())

            with patch("src.cli._load_config", return_value=config):
                disable_exit = cli.main(
                    ["user", "disable", "--username", "admin"],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            disabled_list_stdout = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                cli.main(
                    ["user", "list"],
                    stdout=disabled_list_stdout,
                    stderr=io.StringIO(),
                )

            self.assertEqual(disable_exit, 0)
            self.assertIn("status=disabled", disabled_list_stdout.getvalue())

            with patch("src.cli._load_config", return_value=config):
                enable_exit = cli.main(
                    ["user", "enable", "--username", "admin"],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            self.assertEqual(enable_exit, 0)

            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.cli.getpass.getpass",
                    side_effect=["NewStrongPassword123!", "NewStrongPassword123!"],
                ):
                    change_exit = cli.main(
                        ["user", "change-password", "--username", "admin"],
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                    )

            self.assertEqual(change_exit, 0)
            self.assertIsNone(
                authenticate_dashboard_user(
                    config.dashboard_users_file,
                    "admin",
                    "StrongPassword123!",
                )
            )
            self.assertIsNotNone(
                authenticate_dashboard_user(
                    config.dashboard_users_file,
                    "admin",
                    "NewStrongPassword123!",
                )
            )

    def test_dashboard_user_migrate_env_creates_hashed_user(self) -> None:
        with self._temp_config() as config:
            config.dashboard_username = "legacy-admin"
            config.dashboard_password = "LegacyPassword123!"
            config.dashboard_role = "admin"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    ["user", "migrate-env"],
                    stdout=stdout,
                    stderr=stderr,
                )

            raw_users = config.dashboard_users_file.read_text(encoding="utf-8")
            output = stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Dashboard user migrated: legacy-admin", output)
            self.assertIn(
                "El usuario fue migrado. Elimina DASHBOARD_USERNAME y DASHBOARD_PASSWORD de tu .env.",
                output,
            )
            self.assertNotIn("LegacyPassword123!", output)
            self.assertNotIn("LegacyPassword123!", stderr.getvalue())
            self.assertNotIn("password_hash", output)
            self.assertNotIn("LegacyPassword123!", raw_users)
            self.assertIn("password_hash", raw_users)
            self.assertIsNotNone(
                authenticate_dashboard_user(
                    config.dashboard_users_file,
                    "legacy-admin",
                    "LegacyPassword123!",
                )
            )

    def test_dashboard_user_migrate_env_skips_existing_user(self) -> None:
        with self._temp_config() as config:
            create_dashboard_user(
                config.dashboard_users_file,
                username="admin",
                password="StrongPassword123!",
                role="admin",
            )
            config.dashboard_username = "admin"
            config.dashboard_password = "LegacyPassword123!"
            config.dashboard_role = "viewer"
            stdout = io.StringIO()

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    ["user", "migrate-env"],
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

            users = list_dashboard_users(config.dashboard_users_file)
            output = stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(users), 1)
            self.assertIn("already exists", output)
            self.assertIn(
                "El usuario fue migrado. Elimina DASHBOARD_USERNAME y DASHBOARD_PASSWORD de tu .env.",
                output,
            )
            self.assertNotIn("LegacyPassword123!", output)
            self.assertNotIn("password_hash", output)
            self.assertIsNotNone(
                authenticate_dashboard_user(
                    config.dashboard_users_file,
                    "admin",
                    "StrongPassword123!",
                )
            )
            self.assertIsNone(
                authenticate_dashboard_user(
                    config.dashboard_users_file,
                    "admin",
                    "LegacyPassword123!",
                )
            )

    def test_dashboard_user_migrate_env_reports_missing_legacy_variables(self) -> None:
        with self._temp_config() as config:
            stdout = io.StringIO()
            stderr = io.StringIO()

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    ["user", "migrate-env"],
                    stdout=stdout,
                    stderr=stderr,
                )

            self.assertEqual(exit_code, 0)
            self.assertIn("No legacy dashboard credentials found", stdout.getvalue())
            self.assertEqual("", stderr.getvalue())
            self.assertFalse(config.dashboard_users_file.exists())

    def test_dashboard_user_create_rejects_password_mismatch(self) -> None:
        with self._temp_config() as config:
            stderr = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.cli.getpass.getpass",
                    side_effect=["StrongPassword123!", "DifferentPassword123!"],
                ):
                    exit_code = cli.main(
                        ["user", "create", "--username", "viewer", "--role", "viewer"],
                        stdout=io.StringIO(),
                        stderr=stderr,
                    )

            self.assertEqual(exit_code, 1)
            self.assertIn("passwords do not match", stderr.getvalue())

    def test_dashboard_user_create_rejects_weak_password(self) -> None:
        with self._temp_config() as config:
            stderr = io.StringIO()
            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.cli.getpass.getpass",
                    side_effect=["weakpassword1!", "weakpassword1!"],
                ):
                    exit_code = cli.main(
                        ["user", "create", "--username", "viewer", "--role", "viewer"],
                        stdout=io.StringIO(),
                        stderr=stderr,
                    )

            self.assertEqual(exit_code, 1)
            self.assertIn("uppercase", stderr.getvalue())
            self.assertNotIn("weakpassword1!", stderr.getvalue())

    def test_dashboard_user_list_prints_permission_warning_without_hashes(self) -> None:
        with self._temp_config() as config:
            config.dashboard_users_file.write_text("[]", encoding="utf-8")
            permission_check = SimpleNamespace(
                is_warning=True,
                message="Dashboard users file has insecure permissions 644; recommended mode is 600",
            )
            stdout = io.StringIO()

            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.cli.check_users_file_permissions",
                    return_value=permission_check,
                ):
                    with patch("src.logger.setup_logging"):
                        with patch("src.logger.get_logger", return_value=Mock()):
                            exit_code = cli.main(
                                ["user", "list"],
                                stdout=stdout,
                                stderr=io.StringIO(),
                            )

            self.assertEqual(exit_code, 0)
            self.assertIn("WARNING", stdout.getvalue())
            self.assertIn("600", stdout.getvalue())
            self.assertNotIn("password_hash", stdout.getvalue())

    def test_admin_email_show_prints_configured_email(self) -> None:
        stdout = io.StringIO()
        config = SimpleNamespace(admin_email="admin@example.org")

        with patch("src.cli._load_config", return_value=config):
            exit_code = cli.main(
                ["admin-email", "show"],
                stdout=stdout,
                stderr=io.StringIO(),
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("admin@example.org", stdout.getvalue())

    def test_admin_email_set_updates_env(self) -> None:
        with TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "SMTP_HOST=smtp.example.org\nADMIN_EMAIL=old@example.org\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with patch("src.config.set_admin_email") as set_admin_email:
                set_admin_email.return_value = "new@example.org"
                with patch.dict("os.environ", {}, clear=True):
                    exit_code = cli.main(
                        ["admin-email", "set", "--email", "new@example.org"],
                        stdout=stdout,
                        stderr=io.StringIO(),
                    )

        self.assertEqual(exit_code, 0)
        set_admin_email.assert_called_once_with("new@example.org")
        self.assertIn("new@example.org", stdout.getvalue())

    def test_admin_email_set_rejects_invalid_email(self) -> None:
        stderr = io.StringIO()

        exit_code = cli.main(
            ["admin-email", "set", "--email", "not-an-email"],
            stdout=io.StringIO(),
            stderr=stderr,
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Invalid email address", stderr.getvalue())

    def test_ips_status_reports_configuration(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=False, dry_run=True)

            with patch("src.cli._load_config", return_value=config):
                with patch("src.firewall.is_nft_available", return_value=False):
                    exit_code = cli.main(["ips", "status"], stdout=stdout, stderr=io.StringIO())

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("enabled: False", output)
        self.assertIn("backend: nftables", output)
        self.assertIn("dry_run: True", output)
        self.assertIn("auto_apply: False", output)
        self.assertIn("nft_available: False", output)
        self.assertIn("Modo IDS pasivo", output)

    def test_ips_dry_run_prints_rules_without_applying(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=True, dry_run=True)

            with patch("src.cli._load_config", return_value=config):
                with patch("src.firewall.apply_rules") as apply_rules:
                    exit_code = cli.main(["ips", "dry-run"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 0)
        self.assertIn("table inet gleipnir", stdout.getvalue())
        apply_rules.assert_not_called()

    def test_ips_apply_rejected_when_disabled(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=False, dry_run=False)

            with patch("src.cli._load_config", return_value=config):
                with patch("src.firewall.sync_firewall_rules") as sync:
                    exit_code = cli.main(["ips", "apply"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 1)
        self.assertIn("IPS deshabilitado", stdout.getvalue())
        sync.assert_not_called()

    def test_ips_apply_rejected_when_dry_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=True, dry_run=True)

            with patch("src.cli._load_config", return_value=config):
                with patch("src.firewall.sync_firewall_rules") as sync:
                    exit_code = cli.main(["ips", "apply"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 1)
        self.assertIn("dry_run=true", stdout.getvalue())
        sync.assert_not_called()

    def test_ips_apply_invokes_backend_when_active(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=True, dry_run=False)

            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.firewall.sync_firewall_rules",
                    return_value=FirewallResult(applied=True, dry_run=False),
                ) as sync:
                    exit_code = cli.main(["ips", "apply"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 0)
        self.assertIn("Reglas IPS aplicadas", stdout.getvalue())
        sync.assert_called_once()

    def test_ips_remove_only_targets_gleipnir_table(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=True, dry_run=False)

            with patch("src.cli._load_config", return_value=config):
                with patch(
                    "src.firewall.remove_gleipnir_rules",
                    return_value=FirewallResult(applied=True, dry_run=False),
                ) as remove:
                    exit_code = cli.main(["ips", "remove"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 0)
        self.assertIn("eliminada", stdout.getvalue())
        remove.assert_called_once()
        settings = remove.call_args.args[0]
        self.assertEqual(settings.table, "gleipnir")

    def test_ips_config_show_lists_operational_keys(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir))

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(["ips", "config", "show"], stdout=stdout, stderr=io.StringIO())

        self.assertEqual(exit_code, 0)
        self.assertIn("ips_enabled: False", stdout.getvalue())
        self.assertIn("dry_run: True", stdout.getvalue())

    def test_ips_enable_sets_flag_true(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=False)

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(["ips", "enable"], stdout=stdout, stderr=io.StringIO())

            from src.ips_config import load_ips_config

            self.assertEqual(exit_code, 0)
            self.assertIn("IPS habilitado", stdout.getvalue())
            self.assertIn("sudo .venv/bin/gleipnir ips apply", stdout.getvalue())
            self.assertTrue(load_ips_config(config)["ips_enabled"])

    def test_ips_disable_sets_flag_false(self) -> None:
        with TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            config = _ips_config(Path(temp_dir), ips_enabled=True)

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(["ips", "disable"], stdout=stdout, stderr=io.StringIO())

            from src.ips_config import load_ips_config

            self.assertEqual(exit_code, 0)
            self.assertIn("ips remove", stdout.getvalue())
            self.assertFalse(load_ips_config(config)["ips_enabled"])

    def test_ips_dry_run_enable_and_disable(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = _ips_config(Path(temp_dir), dry_run=False)
            from src.ips_config import load_ips_config

            with patch("src.cli._load_config", return_value=config):
                cli.main(["ips", "dry-run-enable"], stdout=io.StringIO(), stderr=io.StringIO())
                self.assertTrue(load_ips_config(config)["dry_run"])
                stdout = io.StringIO()
                cli.main(["ips", "dry-run-disable"], stdout=stdout, stderr=io.StringIO())
                self.assertFalse(load_ips_config(config)["dry_run"])
                self.assertIn("reglas reales", stdout.getvalue())

    def test_ips_policy_allowlist_saved(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = _ips_config(Path(temp_dir))
            from src.ips_config import load_ips_config

            with patch("src.cli._load_config", return_value=config):
                exit_code = cli.main(
                    ["ips", "policy", "allowlist", "--mode", "block_unregistered"],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(load_ips_config(config)["allowlist_policy"], "block_unregistered")

    def test_ips_policy_blacklist_rejects_invalid_mode(self) -> None:
        # argparse choices reject the invalid value with SystemExit(2).
        with self.assertRaises(SystemExit) as ctx:
            cli.main(
                ["ips", "policy", "blacklist", "--mode", "nuke"],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_ips_direction_saved(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config = _ips_config(Path(temp_dir))
            from src.ips_config import load_ips_config

            with patch("src.cli._load_config", return_value=config):
                cli.main(
                    ["ips", "direction", "--mode", "inbound"],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            self.assertEqual(load_ips_config(config)["block_direction"], "inbound")

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
                    dashboard_users_file=root / "dashboard_users.json",
                    report_dir=root / "reports",
                    log_dir=root / "logs",
                )

            def __exit__(self, exc_type, exc, traceback):
                self._temp_dir.cleanup()

        return TempConfigContext()


def _ips_config(root: Path, **operational) -> SimpleNamespace:
    """Write an operational ips_config.json and return a matching config namespace."""
    from src.ips_config import get_default_ips_config

    config = get_default_ips_config()
    config.update(operational)
    config_path = root / "ips_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return SimpleNamespace(
        ips_backend="nftables",
        ips_table="gleipnir",
        ips_chain="gleipnir_filter",
        ips_config_file=config_path,
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
    )


if __name__ == "__main__":
    unittest.main()
