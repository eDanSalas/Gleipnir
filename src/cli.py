"""Command line interface for Gleipnir IDS."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import sys
from datetime import datetime, time, timezone
from typing import Any, Sequence, TextIO

from src import blacklist, firewall, ips_config, whitelist
from src.dashboard import create_app as create_dashboard_app
from src.dashboard.auth import (
    change_dashboard_user_password,
    check_users_file_permissions,
    create_dashboard_user,
    disable_dashboard_user,
    enable_dashboard_user,
    list_dashboard_users,
    migrate_legacy_dashboard_user,
    password_strength_recommendation,
)
from src.maintenance import format_maintenance_result, run_maintenance
from src.reports import (
    REPORT_FORMATS,
    ReportData,
    ReportFilters,
    generate_reports,
    summarize_report_data,
)
from src.replay import replay_pcap
from src.runtime import IDSEngine
from src.sniffer import parse_pcap, start_live_capture, start_live_capture_forever
from src.status import print_health_report, run_healthcheck


LAN_DASHBOARD_WARNING = (
    "ADVERTENCIA: el dashboard está escuchando en todas las interfaces. "
    "Úsalo solo en red local/laboratorio y no lo expongas a internet."
)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the Gleipnir command line interface."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()

    try:
        args = parser.parse_args(argv)
        return args.handler(args, out, err)
    except Exception as exc:
        print(f"Error: {exc}", file=err)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="gleipnir",
        description="Gleipnir IDS institutional defensive CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    offline = subparsers.add_parser(
        "offline",
        help="Parse an offline PCAP file without replay delay.",
    )
    offline.add_argument("--pcap", required=True, help="Path to the PCAP file.")
    offline.set_defaults(handler=_handle_offline)

    replay = subparsers.add_parser(
        "replay",
        help="Replay an offline PCAP as simulated traffic.",
    )
    replay.add_argument("--pcap", required=True, help="Path to the PCAP file.")
    replay.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between packets.",
    )
    replay.set_defaults(handler=_handle_replay)

    live = subparsers.add_parser(
        "live",
        help="Capture live traffic from a selected interface.",
    )
    live.add_argument("--interface", required=True, help="Network interface name.")
    live.add_argument(
        "--packet-count",
        type=int,
        default=None,
        help="Optional maximum number of packets to process.",
    )
    live.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Optional capture timeout in seconds.",
    )
    live.add_argument(
        "--forever",
        action="store_true",
        help="Run supervised live capture continuously for systemd/24-7 execution.",
    )
    live.add_argument(
        "--debug-packets",
        action="store_true",
        help="Print one safe diagnostic summary per captured packet.",
    )
    live.add_argument(
        "--use-pcap",
        action="store_true",
        help="Use Scapy's libpcap backend when available.",
    )
    live.set_defaults(handler=_handle_live)

    report = subparsers.add_parser(
        "report",
        help="Generate JSON and CSV IDS reports.",
    )
    report.add_argument(
        "--format",
        choices=REPORT_FORMATS,
        default="both",
        help="Output format: both, json, or csv.",
    )
    report.add_argument(
        "--type",
        dest="event_type",
        default=None,
        help="Filter by event type, for example UNAUTHORIZED_DEVICE.",
    )
    report.add_argument(
        "--since",
        default=None,
        help="Filter events since YYYY-MM-DD or an ISO datetime.",
    )
    report.add_argument(
        "--until",
        default=None,
        help="Filter events until YYYY-MM-DD or an ISO datetime.",
    )
    report.add_argument(
        "--source-ip",
        default=None,
        help="Filter by source IP address.",
    )
    report.add_argument(
        "--domain",
        default=None,
        help="Filter DNS/HTTP events by observed domain or host.",
    )
    report.add_argument(
        "--severity",
        default=None,
        help="Filter by severity: high/alta, medium/media, low/baja, or info.",
    )
    report.set_defaults(handler=_handle_report)

    test_config = subparsers.add_parser(
        "test-config",
        help="Validate .env configuration without printing secrets.",
    )
    test_config.set_defaults(handler=_handle_test_config)

    status = subparsers.add_parser(
        "status",
        help="Run a local Gleipnir healthcheck.",
    )
    status.set_defaults(handler=_handle_status)

    maintenance = subparsers.add_parser(
        "maintenance",
        help="Apply retention policies for events, reports, and logs.",
    )
    maintenance.set_defaults(handler=_handle_maintenance)

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Start the read-only local web dashboard.",
    )
    dashboard.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address. Use 0.0.0.0 only in controlled local networks.",
    )
    dashboard.add_argument(
        "--port",
        type=int,
        default=8080,
        help="HTTP port for the dashboard.",
    )
    dashboard.add_argument(
        "--allow-lan",
        action="store_true",
        help="Explicitly allow binding the dashboard to 0.0.0.0 on a trusted LAN.",
    )
    dashboard.add_argument(
        "--allow-unauthenticated-lan",
        action="store_true",
        help=(
            "Allow 0.0.0.0 with DASHBOARD_AUTH_ENABLED=false. Not recommended."
        ),
    )
    dashboard.set_defaults(handler=_handle_dashboard)

    user_parser = subparsers.add_parser(
        "user",
        help="Manage local dashboard users stored with password hashes.",
    )
    user_subparsers = user_parser.add_subparsers(
        dest="user_command",
        required=True,
    )

    user_list = user_subparsers.add_parser(
        "list",
        help="List dashboard users without password hashes.",
    )
    user_list.set_defaults(handler=_handle_user_list)

    user_create = user_subparsers.add_parser(
        "create",
        help="Create one dashboard user and store only its password hash.",
    )
    user_create.add_argument("--username", required=True, help="Dashboard username.")
    user_create.add_argument(
        "--role",
        required=True,
        choices=("viewer", "admin"),
        help="Dashboard role: viewer or admin.",
    )
    user_create.set_defaults(handler=_handle_user_create)

    user_disable = user_subparsers.add_parser(
        "disable",
        help="Disable one dashboard user.",
    )
    user_disable.add_argument("--username", required=True, help="Dashboard username.")
    user_disable.set_defaults(handler=_handle_user_disable)

    user_enable = user_subparsers.add_parser(
        "enable",
        help="Enable one dashboard user.",
    )
    user_enable.add_argument("--username", required=True, help="Dashboard username.")
    user_enable.set_defaults(handler=_handle_user_enable)

    user_change_password = user_subparsers.add_parser(
        "change-password",
        help="Change one dashboard user's password using a secure prompt.",
    )
    user_change_password.add_argument(
        "--username",
        required=True,
        help="Dashboard username.",
    )
    user_change_password.set_defaults(handler=_handle_user_change_password)

    user_migrate_env = user_subparsers.add_parser(
        "migrate-env",
        help="Migrate legacy DASHBOARD_USERNAME/PASSWORD from .env into password hashes.",
    )
    user_migrate_env.set_defaults(handler=_handle_user_migrate_env)

    whitelist_parser = subparsers.add_parser(
        "whitelist",
        help="Manage the authorized IP/MAC whitelist.",
    )
    whitelist_subparsers = whitelist_parser.add_subparsers(
        dest="whitelist_command",
        required=True,
    )

    whitelist_list = whitelist_subparsers.add_parser(
        "list",
        help="List authorized whitelist entries.",
    )
    whitelist_list.set_defaults(handler=_handle_whitelist_list)

    whitelist_add = whitelist_subparsers.add_parser(
        "add",
        help="Add one authorized IP/MAC entry.",
    )
    whitelist_add.add_argument("--ip", required=True, help="Authorized IP address.")
    whitelist_add.add_argument("--mac", required=True, help="Authorized MAC address.")
    whitelist_add.add_argument(
        "--description",
        required=True,
        help="Human-readable device description.",
    )
    whitelist_add.set_defaults(handler=_handle_whitelist_add)

    whitelist_remove = whitelist_subparsers.add_parser(
        "remove",
        help="Remove one whitelist entry by IP address.",
    )
    whitelist_remove.add_argument("--ip", required=True, help="IP address to remove.")
    whitelist_remove.set_defaults(handler=_handle_whitelist_remove)

    whitelist_validate = whitelist_subparsers.add_parser(
        "validate",
        help="Validate whitelist file format.",
    )
    whitelist_validate.set_defaults(handler=_handle_whitelist_validate)

    blacklist_parser = subparsers.add_parser(
        "blacklist",
        help="Manage the external IP blacklist.",
    )
    blacklist_subparsers = blacklist_parser.add_subparsers(
        dest="blacklist_command",
        required=True,
    )

    blacklist_list = blacklist_subparsers.add_parser(
        "list",
        help="List blacklisted IP entries.",
    )
    blacklist_list.set_defaults(handler=_handle_blacklist_list)

    blacklist_add = blacklist_subparsers.add_parser(
        "add",
        help="Add one blacklisted IP address.",
    )
    blacklist_add.add_argument("--ip", required=True, help="IP address to blacklist.")
    blacklist_add.add_argument(
        "--reason",
        required=True,
        help=(
            "Risk type for the blacklist entry: Virus, Malware, Botnet, "
            "Phishing, or Unknown."
        ),
    )
    blacklist_add.set_defaults(handler=_handle_blacklist_add)

    blacklist_remove = blacklist_subparsers.add_parser(
        "remove",
        help="Remove one blacklist entry by IP address.",
    )
    blacklist_remove.add_argument("--ip", required=True, help="IP address to remove.")
    blacklist_remove.set_defaults(handler=_handle_blacklist_remove)

    blacklist_validate = blacklist_subparsers.add_parser(
        "validate",
        help="Validate blacklist file format.",
    )
    blacklist_validate.set_defaults(handler=_handle_blacklist_validate)

    admin_email_parser = subparsers.add_parser(
        "admin-email",
        help="Show or change the administrator alert email (ADMIN_EMAIL in .env).",
    )
    admin_email_subparsers = admin_email_parser.add_subparsers(
        dest="admin_email_command",
        required=True,
    )

    admin_email_show = admin_email_subparsers.add_parser(
        "show",
        help="Show the administrator email currently configured.",
    )
    admin_email_show.set_defaults(handler=_handle_admin_email_show)

    admin_email_set = admin_email_subparsers.add_parser(
        "set",
        help="Change the administrator email stored in .env.",
    )
    admin_email_set.add_argument(
        "--email",
        required=True,
        help="New administrator email address.",
    )
    admin_email_set.set_defaults(handler=_handle_admin_email_set)

    ips_parser = subparsers.add_parser(
        "ips",
        help="Optional defensive IPS/firewall layer (nftables). IDS stays passive by default.",
    )
    ips_subparsers = ips_parser.add_subparsers(dest="ips_command", required=True)

    ips_status = ips_subparsers.add_parser(
        "status",
        help="Show IPS configuration and nft availability without applying rules.",
    )
    ips_status.set_defaults(handler=_handle_ips_status)

    ips_dry_run = ips_subparsers.add_parser(
        "dry-run",
        help="Show the nftables rules that would be applied. Does not modify the system.",
    )
    ips_dry_run.set_defaults(handler=_handle_ips_dry_run)

    ips_apply = ips_subparsers.add_parser(
        "apply",
        help="Apply rules (requires IPS_ENABLED=true, IPS_DRY_RUN=false, and sudo/root).",
    )
    ips_apply.set_defaults(handler=_handle_ips_apply)

    ips_remove = ips_subparsers.add_parser(
        "remove",
        help="Remove only Gleipnir's own nftables table/chain. Never touches external rules.",
    )
    ips_remove.set_defaults(handler=_handle_ips_remove)

    ips_rules = ips_subparsers.add_parser(
        "rules",
        help="Print the generated nftables ruleset for the current lists.",
    )
    ips_rules.set_defaults(handler=_handle_ips_rules)

    ips_config_parser = ips_subparsers.add_parser(
        "config",
        help="Show or set the operational IPS config (data/ips_config.json).",
    )
    ips_config_subparsers = ips_config_parser.add_subparsers(
        dest="ips_config_command",
        required=True,
    )
    ips_config_show = ips_config_subparsers.add_parser(
        "show",
        help="Show the current operational IPS configuration.",
    )
    ips_config_show.set_defaults(handler=_handle_ips_config_show)
    ips_config_set = ips_config_subparsers.add_parser(
        "set",
        help="Set one operational IPS config key to a value.",
    )
    ips_config_set.add_argument("--key", required=True, help="Config key to change.")
    ips_config_set.add_argument("--value", required=True, help="New value.")
    ips_config_set.set_defaults(handler=_handle_ips_config_set)

    ips_enable = ips_subparsers.add_parser("enable", help="Enable IPS in configuration (does not apply rules).")
    ips_enable.set_defaults(handler=_handle_ips_enable)
    ips_disable = ips_subparsers.add_parser("disable", help="Disable IPS in configuration.")
    ips_disable.set_defaults(handler=_handle_ips_disable)

    ips_dry_run_enable = ips_subparsers.add_parser("dry-run-enable", help="Enable dry-run mode.")
    ips_dry_run_enable.set_defaults(handler=_handle_ips_dry_run_enable)
    ips_dry_run_disable = ips_subparsers.add_parser("dry-run-disable", help="Disable dry-run mode.")
    ips_dry_run_disable.set_defaults(handler=_handle_ips_dry_run_disable)

    ips_policy = ips_subparsers.add_parser("policy", help="Change allowlist/blacklist policy.")
    ips_policy_subparsers = ips_policy.add_subparsers(dest="ips_policy_command", required=True)
    ips_policy_allowlist = ips_policy_subparsers.add_parser("allowlist", help="Set allowlist policy.")
    ips_policy_allowlist.add_argument(
        "--mode",
        required=True,
        choices=("monitor", "allow_registered", "block_unregistered"),
    )
    ips_policy_allowlist.set_defaults(handler=_handle_ips_policy_allowlist)
    ips_policy_blacklist = ips_policy_subparsers.add_parser("blacklist", help="Set blacklist policy.")
    ips_policy_blacklist.add_argument("--mode", required=True, choices=("monitor", "block"))
    ips_policy_blacklist.set_defaults(handler=_handle_ips_policy_blacklist)

    ips_direction = ips_subparsers.add_parser("direction", help="Set the block direction.")
    ips_direction.add_argument("--mode", required=True, choices=("outbound", "inbound", "both"))
    ips_direction.set_defaults(handler=_handle_ips_direction)

    ips_private_check = ips_subparsers.add_parser(
        "private-check",
        help="Enable/disable checking private/local IPs against the blacklist.",
    )
    ips_private_check_subparsers = ips_private_check.add_subparsers(
        dest="ips_private_check_command",
        required=True,
    )
    ips_private_check_subparsers.add_parser("enable").set_defaults(
        handler=_handle_ips_private_check_enable
    )
    ips_private_check_subparsers.add_parser("disable").set_defaults(
        handler=_handle_ips_private_check_disable
    )

    ips_auto_apply = ips_subparsers.add_parser(
        "auto-apply",
        help="Enable/disable auto-apply (off by default for safety).",
    )
    ips_auto_apply_subparsers = ips_auto_apply.add_subparsers(
        dest="ips_auto_apply_command",
        required=True,
    )
    ips_auto_apply_subparsers.add_parser("enable").set_defaults(
        handler=_handle_ips_auto_apply_enable
    )
    ips_auto_apply_subparsers.add_parser("disable").set_defaults(
        handler=_handle_ips_auto_apply_disable
    )

    return parser


def _handle_offline(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    events = parse_pcap(args.pcap)
    print(f"Offline PCAP parsed: {len(events)} packet event(s)", file=stdout)
    return 0


def _handle_replay(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    engine = _create_engine()
    try:
        result = replay_pcap(
            args.pcap,
            delay_seconds=args.delay,
            packet_processor=_engine_packet_processor(engine),
        )
    finally:
        engine.shutdown()

    print(
        "Replay complete: "
        f"packets={result.packet_count} "
        f"detections={len(result.detection_events)} "
        f"dns_http_events={len(result.traffic_events)} "
        f"errors={result.errors}",
        file=stdout,
    )
    return 0


def _handle_live(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    engine = _create_engine()
    use_pcap = _live_use_pcap_enabled(args, getattr(engine, "config", None))
    try:
        if args.forever:
            result = start_live_capture_forever(
                args.interface,
                packet_count=args.packet_count,
                timeout=args.timeout,
                packet_processor=_engine_packet_processor(engine),
                debug_packets=args.debug_packets,
                debug_output=lambda message: print(message, file=stdout),
                use_pcap=use_pcap,
                health_log_interval_seconds=engine.config.health_log_interval_seconds,
            )
        else:
            result = start_live_capture(
                args.interface,
                packet_count=args.packet_count,
                timeout=args.timeout,
                packet_processor=_engine_packet_processor(engine),
                debug_packets=args.debug_packets,
                debug_output=lambda message: print(message, file=stdout),
                use_pcap=use_pcap,
            )
    finally:
        engine.shutdown()

    if args.forever:
        print(
            "Live capture forever stopped: "
            f"cycles={result.capture_cycles} "
            f"received={result.packets_received} "
            f"raw_packets={result.raw_packets} "
            f"decoded_from_raw={result.decoded_from_raw} "
            f"ignored_packets={result.ignored_packets} "
            f"unsupported_packets={result.unsupported_packets} "
            f"parse_errors={result.parse_errors} "
            f"packet_events={result.packet_events_processed} "
            f"engine_errors={result.engine_errors} "
            f"detections={result.detection_events_processed} "
            f"dns_http_events={result.traffic_events_processed} "
            f"errors={result.errors}",
            file=stdout,
        )
        return 0

    print(
        "Live capture complete: "
        f"received={result.packets_received} "
        f"raw_packets={result.raw_packets} "
        f"decoded_from_raw={result.decoded_from_raw} "
        f"ignored_packets={result.ignored_packets} "
        f"unsupported_packets={result.unsupported_packets} "
        f"parse_errors={result.parse_errors} "
        f"packet_events={result.packet_events_processed} "
        f"engine_errors={result.engine_errors} "
        f"detections={result.detection_events_processed} "
        f"dns_http_events={result.traffic_events_processed} "
        f"errors={result.errors}",
        file=stdout,
    )
    return 0


def _live_use_pcap_enabled(args: argparse.Namespace, config: Any) -> bool:
    if bool(getattr(args, "use_pcap", False)):
        return True

    value = getattr(config, "gleipnir_scapy_use_pcap", False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}

    return False


def _handle_report(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    filters = _build_report_filters(args)
    report_data = _load_report_data(config, filters)
    report_paths = generate_reports(
        report_data,
        config=config,
        output_format=args.format,
        filters=filters,
    )
    print("Reports generated:", file=stdout)
    if report_paths.json_path is not None:
        print(f"- JSON: {report_paths.json_path}", file=stdout)
    if report_paths.csv_path is not None:
        print(f"- CSV: {report_paths.csv_path}", file=stdout)
    _print_report_summary(report_data, stdout)

    return 0


def _handle_test_config(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    print("Configuration OK", file=stdout)
    print(
        json.dumps(config.as_redacted_dict(), indent=2, sort_keys=True),
        file=stdout,
    )
    return 0


def _handle_status(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    report = run_healthcheck()
    print_health_report(report, stdout)
    return report.exit_code


def _handle_maintenance(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    from src.logger import get_logger, setup_logging

    setup_logging(config)
    result = run_maintenance(config, logger=get_logger("maintenance"))
    print(format_maintenance_result(result), end="", file=stdout)
    return result.exit_code


def _handle_dashboard(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    port = _validate_dashboard_port(args.port)
    host = str(args.host).strip() or "127.0.0.1"
    _validate_dashboard_exposure(args, host, config)
    _print_users_file_permission_warning(config, stdout)
    app = create_dashboard_app(config=config)

    print(f"Starting Gleipnir dashboard at http://{host}:{port}", file=stdout)
    if host == "0.0.0.0":
        print(LAN_DASHBOARD_WARNING, file=stdout)
        _log_dashboard_exposure_warning(config)
    print(
        "Dashboard event views are read-only. No browser will be opened automatically.",
        file=stdout,
    )
    app.run(host=host, port=port)
    return 0


def _validate_dashboard_exposure(
    args: argparse.Namespace,
    host: str,
    config: Any,
) -> None:
    if host != "0.0.0.0":
        return

    if not bool(getattr(args, "allow_lan", False)):
        raise ValueError(
            "Binding the dashboard to 0.0.0.0 requires --allow-lan. "
            "Use it only in a trusted local network/laboratory and never expose "
            "the dashboard to internet."
        )

    if _dashboard_auth_enabled(config):
        return

    if not bool(getattr(args, "allow_unauthenticated_lan", False)):
        raise ValueError(
            "DASHBOARD_AUTH_ENABLED=false with --host 0.0.0.0 is blocked. "
            "Enable dashboard authentication or add --allow-unauthenticated-lan "
            "only for a controlled local/laboratory network."
        )


def _dashboard_auth_enabled(config: Any) -> bool:
    value = getattr(config, "dashboard_auth_enabled", False)
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _log_dashboard_exposure_warning(config: Any) -> None:
    try:
        from src.logger import get_logger, setup_logging

        setup_logging(config)
        get_logger("dashboard").warning(LAN_DASHBOARD_WARNING)
    except Exception:
        return


def _print_users_file_permission_warning(config: Any, stdout: TextIO) -> None:
    users_file = getattr(config, "dashboard_users_file", "data/dashboard_users.json")
    result = check_users_file_permissions(users_file)
    if not result.is_warning:
        return

    message = f"WARNING: {result.message}"
    print(message, file=stdout)
    try:
        from src.logger import get_logger, setup_logging

        setup_logging(config)
        get_logger("dashboard").warning(message)
    except Exception:
        return


def _handle_user_list(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    _print_users_file_permission_warning(config, stdout)
    users = list_dashboard_users(config.dashboard_users_file)
    if not users:
        print(f"Dashboard users file is empty or missing: {config.dashboard_users_file}", file=stdout)
        return 0

    print(f"Dashboard users ({len(users)}):", file=stdout)
    for user in users:
        status = "enabled" if user.enabled else "disabled"
        print(
            f"- {user.username} | role={user.role} | status={status} | "
            f"created_at={user.created_at}",
            file=stdout,
        )
    return 0


def _handle_user_create(
    args: argparse.Namespace,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    config = _load_config()
    min_password_length = _dashboard_password_min_length(config)
    password = _prompt_dashboard_password(stderr, min_password_length=min_password_length)
    user = create_dashboard_user(
        config.dashboard_users_file,
        username=args.username,
        password=password,
        role=args.role,
        min_password_length=min_password_length,
    )
    print(
        f"Dashboard user created: {user.username} | role={user.role} | status=enabled",
        file=stdout,
    )
    return 0


def _handle_user_disable(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    user = disable_dashboard_user(
        config.dashboard_users_file,
        username=args.username,
    )
    print(f"Dashboard user disabled: {user.username}", file=stdout)
    return 0


def _handle_user_enable(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    user = enable_dashboard_user(
        config.dashboard_users_file,
        username=args.username,
    )
    print(f"Dashboard user enabled: {user.username}", file=stdout)
    return 0


def _handle_user_change_password(
    args: argparse.Namespace,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    config = _load_config()
    min_password_length = _dashboard_password_min_length(config)
    password = _prompt_dashboard_password(stderr, min_password_length=min_password_length)
    user = change_dashboard_user_password(
        config.dashboard_users_file,
        username=args.username,
        password=password,
        min_password_length=min_password_length,
    )
    print(f"Dashboard user password changed: {user.username}", file=stdout)
    return 0


def _handle_user_migrate_env(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    username = _legacy_dashboard_username(config)
    password = _legacy_dashboard_password(config)
    if not username or not password:
        print(
            "No legacy dashboard credentials found. Set DASHBOARD_USERNAME and "
            "DASHBOARD_PASSWORD only long enough to run this migration.",
            file=stdout,
        )
        return 0

    result = migrate_legacy_dashboard_user(
        config.dashboard_users_file,
        username=username,
        password=password,
        role=_legacy_dashboard_role(config),
    )
    if result.created:
        print(
            f"Dashboard user migrated: {result.username} | role={result.role}",
            file=stdout,
        )
    else:
        print(
            f"Dashboard user already exists, no duplicate created: {result.username}",
            file=stdout,
        )
    print(
        "El usuario fue migrado. Elimina DASHBOARD_USERNAME y DASHBOARD_PASSWORD de tu .env.",
        file=stdout,
    )
    return 0


def _prompt_dashboard_password(stderr: TextIO, *, min_password_length: int) -> str:
    print(
        f"Recommendation: {password_strength_recommendation(min_password_length)}",
        file=stderr,
    )
    password = getpass.getpass("Dashboard password: ")
    confirmation = getpass.getpass("Confirm dashboard password: ")
    if password != confirmation:
        raise ValueError("Dashboard passwords do not match")
    return password


def _dashboard_password_min_length(config: Any) -> int:
    try:
        return int(getattr(config, "dashboard_password_min_length", 12))
    except (TypeError, ValueError):
        return 12


def _legacy_dashboard_username(config: Any) -> str | None:
    return _clean_optional_config_value(getattr(config, "dashboard_username", None))


def _legacy_dashboard_password(config: Any) -> str | None:
    return _clean_optional_config_value(getattr(config, "dashboard_password", None))


def _legacy_dashboard_role(config: Any) -> str:
    role = _clean_optional_config_value(getattr(config, "dashboard_role", None))
    if role is not None:
        role = role.lower()
    return role if role in {"viewer", "admin"} else "viewer"


def _clean_optional_config_value(value: Any) -> str | None:
    if value is None:
        return None

    cleaned = str(value).strip()
    return cleaned or None


def _handle_whitelist_list(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entries = whitelist.load_whitelist(config.whitelist_file)
    if not entries:
        print(f"Whitelist is empty: {config.whitelist_file}", file=stdout)
        return 0

    print(f"Whitelist entries ({len(entries)}):", file=stdout)
    for entry in entries:
        print(f"- {entry.ip} | {entry.mac} | {entry.description}", file=stdout)

    return 0


def _handle_whitelist_add(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entry = whitelist.add_whitelist_entry(
        config.whitelist_file,
        ip=args.ip,
        mac=args.mac,
        description=args.description,
    )
    print(f"Whitelist entry added: {entry.ip} | {entry.mac}", file=stdout)
    return 0


def _handle_whitelist_remove(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entry = whitelist.remove_whitelist_entry(config.whitelist_file, ip=args.ip)
    print(f"Whitelist entry removed: {entry.ip} | {entry.mac}", file=stdout)
    return 0


def _handle_whitelist_validate(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entries = whitelist.validate_whitelist_file(config.whitelist_file)
    print(f"Whitelist valid: {len(entries)} entry(s)", file=stdout)
    return 0


def _handle_blacklist_list(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entries = blacklist.list_blacklist_entries(config.blacklist_file)
    if not entries:
        print(f"Blacklist is empty: {config.blacklist_file}", file=stdout)
        return 0

    print(f"Blacklist entries ({len(entries)}):", file=stdout)
    for entry in entries:
        reason = f" | {entry.reason}" if entry.reason else ""
        print(f"- {entry.ip}{reason}", file=stdout)

    return 0


def _handle_blacklist_add(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entry = blacklist.add_blacklist_entry(
        config.blacklist_file,
        ip=args.ip,
        reason=args.reason,
    )
    print(f"Blacklist entry added: {entry.ip}", file=stdout)
    return 0


def _handle_blacklist_remove(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entry = blacklist.remove_blacklist_entry(config.blacklist_file, ip=args.ip)
    print(f"Blacklist entry removed: {entry.ip}", file=stdout)
    return 0


def _handle_blacklist_validate(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    entries = blacklist.validate_blacklist_file(config.blacklist_file)
    print(f"Blacklist valid: {len(entries)} entry(s)", file=stdout)
    return 0


def _handle_admin_email_show(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    print(f"ADMIN_EMAIL: {config.admin_email}", file=stdout)
    return 0


def _handle_admin_email_set(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    import os

    from src.config import set_admin_email

    new_email = set_admin_email(args.email)
    print(f"ADMIN_EMAIL updated in .env: {new_email}", file=stdout)

    if os.environ.get("ADMIN_EMAIL"):
        print(
            "Advertencia: la variable de entorno ADMIN_EMAIL esta definida y tiene "
            "prioridad sobre .env. Quitala o actualizala para que aplique el cambio.",
            file=stdout,
        )

    print(
        "Reinicia los procesos de Gleipnir (live/replay/dashboard) para aplicar el cambio.",
        file=stdout,
    )
    return 0


def _handle_ips_status(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    settings = ips_config.build_ips_settings(config)
    nft_available = firewall.is_nft_available()
    print("Gleipnir IPS/Firewall status:", file=stdout)
    print(f"- enabled: {settings.enabled}", file=stdout)
    print(f"- backend: {settings.backend}", file=stdout)
    print(f"- dry_run: {settings.dry_run}", file=stdout)
    print(f"- allowlist_policy: {settings.allowlist_policy}", file=stdout)
    print(f"- blacklist_policy: {settings.blacklist_policy}", file=stdout)
    print(f"- block_direction: {settings.block_direction}", file=stdout)
    print(f"- blacklist_check_private: {settings.blacklist_check_private}", file=stdout)
    print(f"- auto_apply: {settings.auto_apply}", file=stdout)
    print(f"- table/chain: inet {settings.table} / {settings.chain}", file=stdout)
    print(f"- config_file: {config.ips_config_file}", file=stdout)
    print(f"- nft_available: {nft_available}", file=stdout)
    if not settings.enabled:
        print(
            "Modo IDS pasivo: no se bloquea trafico. Usa 'gleipnir ips enable' para activar IPS.",
            file=stdout,
        )
    return 0


def _handle_ips_dry_run(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    settings = ips_config.build_ips_settings(config)
    whitelist_entries, blacklist_entries = _load_ips_lists(config)
    result = firewall.dry_run_rules(whitelist_entries, blacklist_entries, settings)
    print("IPS dry-run (no se modifica el sistema):", file=stdout)
    for line in result.rules:
        print(line, file=stdout)
    return 0


def _handle_ips_apply(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    settings = ips_config.build_ips_settings(config)
    if not settings.enabled:
        print(
            "IPS deshabilitado. Ejecuta 'gleipnir ips enable' antes de aplicar reglas.",
            file=stdout,
        )
        return 1
    if settings.dry_run:
        print(
            "dry_run=true: no se aplican reglas reales. Ejecuta "
            "'gleipnir ips dry-run-disable' (y corre con sudo/root) para aplicar.",
            file=stdout,
        )
        return 1

    whitelist_entries, blacklist_entries = _load_ips_lists(config)
    result = firewall.sync_firewall_rules(whitelist_entries, blacklist_entries, settings)
    if result.applied:
        print(
            f"Reglas IPS aplicadas en inet {settings.table}/{settings.chain}.",
            file=stdout,
        )
        return 0

    print(
        f"No se aplicaron reglas IPS: reason={result.reason} error={result.error or ''}",
        file=stdout,
    )
    if result.reason in {"nft_unavailable", "nft_rejected", "nft_error"}:
        print(
            "Verifica que nft este instalado y que ejecutes con sudo/root.",
            file=stdout,
        )
    return 1


def _handle_ips_remove(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    settings = ips_config.build_ips_settings(config)
    result = firewall.remove_gleipnir_rules(settings)
    if result.applied:
        print(f"Tabla IPS de Gleipnir eliminada: inet {settings.table}.", file=stdout)
        return 0
    if result.reason == "table_absent":
        print("No habia tabla IPS de Gleipnir que eliminar.", file=stdout)
        return 0

    print(
        f"No se pudo eliminar la tabla IPS: reason={result.reason} error={result.error or ''}",
        file=stdout,
    )
    if result.reason in {"nft_unavailable", "nft_rejected", "nft_error"}:
        print("Verifica que nft este instalado y que ejecutes con sudo/root.", file=stdout)
    return 1


def _handle_ips_rules(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    settings = ips_config.build_ips_settings(config)
    whitelist_entries, blacklist_entries = _load_ips_lists(config)
    script = firewall.build_ruleset(whitelist_entries, blacklist_entries, settings)
    print(script, end="", file=stdout)
    return 0


def _handle_ips_config_show(
    _args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    operational = ips_config.load_ips_config(config)
    print(f"IPS operational config ({config.ips_config_file}):", file=stdout)
    for key in ips_config.CONFIG_KEYS:
        print(f"- {key}: {operational[key]}", file=stdout)
    return 0


def _handle_ips_config_set(
    args: argparse.Namespace,
    stdout: TextIO,
    _stderr: TextIO,
) -> int:
    config = _load_config()
    updated = ips_config.update_ips_config({args.key: args.value}, config)
    print(f"IPS config updated: {args.key}={updated[args.key]}", file=stdout)
    return 0


def _handle_ips_enable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"ips_enabled": True}, config)
    print(
        "IPS habilitado en configuracion. Para aplicar reglas reales ejecuta: "
        "sudo .venv/bin/gleipnir ips apply",
        file=stdout,
    )
    return 0


def _handle_ips_disable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"ips_enabled": False}, config)
    print(
        "IPS deshabilitado en configuracion. Si ya habia reglas aplicadas, ejecuta: "
        "sudo .venv/bin/gleipnir ips remove",
        file=stdout,
    )
    return 0


def _handle_ips_dry_run_enable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"dry_run": True}, config)
    print("dry_run habilitado: el IPS solo simula reglas, no aplica reglas reales.", file=stdout)
    return 0


def _handle_ips_dry_run_disable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"dry_run": False}, config)
    print(
        "dry_run deshabilitado. Esto permite aplicar reglas reales con 'ips apply' "
        "si ips_enabled=true.",
        file=stdout,
    )
    return 0


def _handle_ips_policy_allowlist(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"allowlist_policy": args.mode}, config)
    print(f"allowlist_policy={args.mode}", file=stdout)
    return 0


def _handle_ips_policy_blacklist(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"blacklist_policy": args.mode}, config)
    print(f"blacklist_policy={args.mode}", file=stdout)
    return 0


def _handle_ips_direction(args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"block_direction": args.mode}, config)
    print(f"block_direction={args.mode}", file=stdout)
    return 0


def _handle_ips_private_check_enable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"blacklist_check_private": True}, config)
    print("blacklist_check_private=True", file=stdout)
    return 0


def _handle_ips_private_check_disable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"blacklist_check_private": False}, config)
    print("blacklist_check_private=False", file=stdout)
    return 0


def _handle_ips_auto_apply_enable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"auto_apply": True}, config)
    print(
        "auto_apply=True. Nota: aplicar reglas reales sigue requiriendo permisos "
        "root; se recomienda usar 'sudo .venv/bin/gleipnir ips apply'.",
        file=stdout,
    )
    return 0


def _handle_ips_auto_apply_disable(_args: argparse.Namespace, stdout: TextIO, _stderr: TextIO) -> int:
    config = _load_config()
    ips_config.update_ips_config({"auto_apply": False}, config)
    print("auto_apply=False", file=stdout)
    return 0


def _load_ips_lists(config: Any) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    whitelist_entries: tuple[Any, ...] = ()
    blacklist_entries: tuple[Any, ...] = ()
    try:
        whitelist_entries = whitelist.load_whitelist(config.whitelist_file)
    except (OSError, whitelist.WhitelistError):
        whitelist_entries = ()
    try:
        blacklist_entries = blacklist.list_blacklist_entries(config.blacklist_file)
    except (OSError, blacklist.BlacklistError):
        blacklist_entries = ()
    return whitelist_entries, blacklist_entries


def _load_config() -> Any:
    from src.config import load_config

    return load_config()


def _load_report_data(config: Any, filters: ReportFilters | None = None) -> ReportData:
    from src.storage import SQLiteEventStore

    event_store = SQLiteEventStore.from_config(config)
    try:
        event_store.initialize()
        return event_store.build_report_data(filters=filters)
    finally:
        event_store.close()


def _create_engine() -> IDSEngine:
    return IDSEngine.from_config()


def _engine_packet_processor(engine: IDSEngine):
    def process(packet_event: Any, dns_http_source: Any) -> Any:
        return engine.process_packet_event(
            packet_event,
            dns_http_source=dns_http_source,
        )

    return process


def _build_report_filters(args: argparse.Namespace) -> ReportFilters:
    return ReportFilters(
        event_type=_normalize_optional_text(getattr(args, "event_type", None), uppercase=True),
        since=_parse_report_timestamp(getattr(args, "since", None), end_of_day=False),
        until=_parse_report_timestamp(getattr(args, "until", None), end_of_day=True),
        source_ip=_normalize_report_source_ip(getattr(args, "source_ip", None)),
        domain=_normalize_optional_text(getattr(args, "domain", None), lowercase=True),
        severity=_normalize_report_severity(getattr(args, "severity", None)),
        since_label=_normalize_optional_text(getattr(args, "since", None)),
        until_label=_normalize_optional_text(getattr(args, "until", None)),
    )


def _print_report_summary(report_data: ReportData, stdout: TextIO) -> None:
    summary = summarize_report_data(report_data)
    total_events = sum(summary.values())
    print(f"Summary: total_events={total_events}", file=stdout)
    for key, value in summary.items():
        print(f"- {key}: {value}", file=stdout)


def _parse_report_timestamp(
    raw_value: str | None,
    *,
    end_of_day: bool,
) -> float | None:
    value = _normalize_optional_text(raw_value)
    if value is None:
        return None

    try:
        if _is_date_only(value):
            parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
            parsed_time = time.max if end_of_day else time.min
            parsed_datetime = datetime.combine(
                parsed_date,
                parsed_time,
                tzinfo=timezone.utc,
            )
        else:
            parsed_datetime = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed_datetime.tzinfo is None:
                parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(
            "Report date filters must use YYYY-MM-DD or ISO datetime format"
        ) from exc

    return parsed_datetime.timestamp()


def _normalize_report_source_ip(raw_value: str | None) -> str | None:
    value = _normalize_optional_text(raw_value)
    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid --source-ip value: {value}") from exc


def _normalize_report_severity(raw_value: str | None) -> str | None:
    value = _normalize_optional_text(raw_value, lowercase=True)
    if value is None:
        return None

    aliases = {
        "high": "ALTA",
        "alta": "ALTA",
        "medium": "MEDIA",
        "media": "MEDIA",
        "low": "BAJA",
        "baja": "BAJA",
        "info": "INFO",
        "informativa": "INFO",
    }
    severity = aliases.get(value)
    if severity is None:
        raise ValueError(
            "Invalid --severity value. Use high/alta, medium/media, low/baja, or info"
        )

    return severity


def _validate_dashboard_port(port: int) -> int:
    if not 1 <= int(port) <= 65535:
        raise ValueError("--port must be between 1 and 65535")

    return int(port)


def _normalize_optional_text(
    raw_value: str | None,
    *,
    uppercase: bool = False,
    lowercase: bool = False,
) -> str | None:
    if raw_value is None:
        return None

    value = str(raw_value).strip()
    if not value:
        return None

    if uppercase:
        return value.upper()
    if lowercase:
        return value.lower()

    return value


def _is_date_only(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False

    return True


if __name__ == "__main__":
    raise SystemExit(main())
