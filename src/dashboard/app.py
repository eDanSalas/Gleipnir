"""Flask dashboard for read-only Gleipnir IDS event visualization."""

from __future__ import annotations

import html
import hmac
import ipaddress
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any, Mapping

from src import blacklist, whitelist
from src.detector import AUTHORIZED_DEVICE, BLACKLISTED_EXTERNAL_IP, UNAUTHORIZED_DEVICE
from src.storage import (
    ALERT_SENT,
    ALERT_SUPPRESSED,
    DNS_EVENT,
    HTTP_EVENT,
    SQLiteEventStore,
    StoredEvent,
)

try:
    from flask import Flask, Response, jsonify, request
except ImportError:  # pragma: no cover - exercised only when Flask is missing.
    Flask = None
    Response = None
    jsonify = None
    request = None


LATEST_EVENT_LIMIT = 50
ADMIN_LIST_ACTION = "ADMIN_LIST_ACTION"
REDACTED_VALUE = "[REDACTED]"
SECRET_FIELD_HINTS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "token",
    "secret",
    "smtp_password",
)


class DashboardError(RuntimeError):
    """Raised when the dashboard cannot be created."""


@dataclass(frozen=True)
class DashboardData:
    """Read-only dashboard payload derived from SQLite events."""

    database_exists: bool
    database_path: str
    message: str
    summary: dict[str, int]
    latest_events: tuple[dict[str, Any], ...]
    filters: "DashboardFilters"
    charts: dict[str, tuple[dict[str, Any], ...]]

    @property
    def total_events(self) -> int:
        """Return total event count."""
        return self.summary["total_events"]


@dataclass(frozen=True)
class DashboardFilters:
    """Filters accepted by dashboard query parameters."""

    event_type: str | None = None
    severity: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_mac: str | None = None
    domain: str | None = None
    protocol: str | None = None
    since: float | None = None
    until: float | None = None
    since_label: str | None = None
    until_label: str | None = None

    @property
    def active_count(self) -> int:
        """Return the number of active filters."""
        return sum(1 for value in self.as_payload().values() if value not in (None, ""))

    def as_query_kwargs(self) -> dict[str, Any]:
        """Return keyword arguments accepted by SQLiteEventStore.fetch_events."""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_mac": self.source_mac,
            "domain": self.domain,
            "protocol": self.protocol,
            "since": self.since,
            "until": self.until,
        }

    def as_payload(self) -> dict[str, Any]:
        """Return JSON-safe filter labels."""
        payload = {
            "type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_mac": self.source_mac,
            "domain": self.domain,
            "protocol": self.protocol,
            "since": self.since_label,
            "until": self.until_label,
        }
        return {key: value for key, value in payload.items() if value not in (None, "")}


@dataclass(frozen=True)
class AdminListData:
    """Data required by the administrative list management page."""

    whitelist_entries: tuple[whitelist.WhitelistEntry, ...]
    blacklist_entries: tuple[blacklist.BlacklistEntry, ...]
    whitelist_error: str | None = None
    blacklist_error: str | None = None


def create_app(config: Any | None = None, *, event_store_factory=SQLiteEventStore) -> Any:
    """Create the Flask dashboard application."""
    if Flask is None:
        raise DashboardError("Flask is required. Install dependencies with pip install -e .")

    runtime_config = config or _load_runtime_config()
    _validate_dashboard_auth_settings(runtime_config)
    app = Flask(__name__)
    app.config["GLEIPNIR_CONFIG"] = runtime_config
    app.config["GLEIPNIR_EVENT_STORE_FACTORY"] = event_store_factory

    @app.before_request
    def require_dashboard_auth():
        if _is_dashboard_request_authorized(app.config["GLEIPNIR_CONFIG"]):
            return None

        return _dashboard_auth_challenge()

    @app.get("/")
    def index():
        filters = _filters_from_query(request.args)
        data = _load_dashboard_data(
            app.config["GLEIPNIR_CONFIG"],
            event_store_factory=app.config["GLEIPNIR_EVENT_STORE_FACTORY"],
            filters=filters,
        )
        return _render_dashboard_html(
            data,
            admin_available=_dashboard_auth_enabled(app.config["GLEIPNIR_CONFIG"]),
        )

    @app.get("/health")
    def health():
        data = _load_dashboard_data(
            app.config["GLEIPNIR_CONFIG"],
            event_store_factory=app.config["GLEIPNIR_EVENT_STORE_FACTORY"],
        )
        return jsonify(
            {
                "status": "ok",
                "database_exists": data.database_exists,
                "database_path": data.database_path,
                "total_events": data.total_events,
                "message": data.message,
            }
        )

    @app.get("/events")
    def events():
        filters = _filters_from_query(request.args)
        data = _load_dashboard_data(
            app.config["GLEIPNIR_CONFIG"],
            event_store_factory=app.config["GLEIPNIR_EVENT_STORE_FACTORY"],
            filters=filters,
        )
        return jsonify(
            {
                "database_exists": data.database_exists,
                "message": data.message,
                "summary": data.summary,
                "filters": data.filters.as_payload(),
                "charts": data.charts,
                "events": list(data.latest_events),
            }
        )

    @app.get("/events/<int:event_id>")
    def event_detail(event_id: int):
        event = _load_event_detail(
            app.config["GLEIPNIR_CONFIG"],
            event_id,
            event_store_factory=app.config["GLEIPNIR_EVENT_STORE_FACTORY"],
        )
        if event is None:
            return _render_event_not_found_html(event_id), 404

        return _render_event_detail_html(event)

    @app.route("/admin/lists", methods=["GET", "POST"])
    def admin_lists():
        runtime_config = app.config["GLEIPNIR_CONFIG"]
        if not _dashboard_auth_enabled(runtime_config):
            return _render_admin_unavailable_html(), 404

        notice: dict[str, str] | None = None
        if request.method == "POST":
            notice = _handle_admin_list_post(runtime_config, request.form)

        data = _load_admin_list_data(runtime_config)
        return _render_admin_lists_html(data, notice=notice)

    return app


def _validate_dashboard_auth_settings(config: Any) -> None:
    if not _dashboard_auth_enabled(config):
        return

    if not _dashboard_username(config) or not _dashboard_password(config):
        raise DashboardError(
            "Dashboard authentication is enabled. Set DASHBOARD_USERNAME and "
            "DASHBOARD_PASSWORD in .env."
        )


def _is_dashboard_request_authorized(config: Any) -> bool:
    if not _dashboard_auth_enabled(config):
        return True

    authorization = request.authorization
    if authorization is None:
        return False

    expected_username = _dashboard_username(config) or ""
    expected_password = _dashboard_password(config) or ""
    provided_username = authorization.username or ""
    provided_password = authorization.password or ""

    return _safe_compare(provided_username, expected_username) and _safe_compare(
        provided_password,
        expected_password,
    )


def _dashboard_auth_challenge() -> Any:
    return Response(
        "Dashboard authentication required.",
        401,
        {"WWW-Authenticate": 'Basic realm="Gleipnir Dashboard"'},
    )


def _dashboard_auth_enabled(config: Any) -> bool:
    value = getattr(config, "dashboard_auth_enabled", False)
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _dashboard_username(config: Any) -> str | None:
    username = getattr(config, "dashboard_username", None)
    if username is None:
        return None

    cleaned = str(username).strip()
    return cleaned or None


def _dashboard_password(config: Any) -> str | None:
    password = getattr(config, "dashboard_password", None)
    if password is None:
        return None

    cleaned = str(password).strip()
    return cleaned or None


def _safe_compare(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _load_admin_list_data(config: Any) -> AdminListData:
    whitelist_entries: tuple[whitelist.WhitelistEntry, ...] = ()
    blacklist_entries: tuple[blacklist.BlacklistEntry, ...] = ()
    whitelist_error = None
    blacklist_error = None

    whitelist_path = Path(getattr(config, "whitelist_file", "data/whitelist.csv"))
    if whitelist_path.exists():
        try:
            whitelist_entries = whitelist.load_whitelist(whitelist_path)
        except (OSError, whitelist.WhitelistError) as exc:
            whitelist_error = str(exc)
    else:
        whitelist_error = "Whitelist file does not exist yet."

    blacklist_path = Path(getattr(config, "blacklist_file", "data/blacklist.txt"))
    if blacklist_path.exists():
        try:
            blacklist_entries = blacklist.list_blacklist_entries(blacklist_path)
        except (OSError, blacklist.BlacklistError) as exc:
            blacklist_error = str(exc)
    else:
        blacklist_error = "Blacklist file does not exist yet."

    return AdminListData(
        whitelist_entries=whitelist_entries,
        blacklist_entries=blacklist_entries,
        whitelist_error=whitelist_error,
        blacklist_error=blacklist_error,
    )


def _handle_admin_list_post(config: Any, form: Mapping[str, Any]) -> dict[str, str]:
    action = _form_value(form, "action")
    target = "lists"

    try:
        if action == "whitelist_add":
            target = "whitelist"
            entry = whitelist.add_whitelist_entry(
                getattr(config, "whitelist_file"),
                ip=_form_value(form, "ip"),
                mac=_form_value(form, "mac"),
                description=_form_value(form, "description"),
            )
            details = f"ip={entry.ip} mac={entry.mac}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Whitelist entry added: {entry.ip}")

        if action == "whitelist_remove":
            target = "whitelist"
            entry = whitelist.remove_whitelist_entry(
                getattr(config, "whitelist_file"),
                ip=_form_value(form, "ip"),
            )
            details = f"ip={entry.ip} mac={entry.mac}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Whitelist entry removed: {entry.ip}")

        if action == "whitelist_validate":
            target = "whitelist"
            entries = whitelist.validate_whitelist_file(getattr(config, "whitelist_file"))
            details = f"entries={len(entries)}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Whitelist valid: {len(entries)} entry(s)")

        if action == "blacklist_add":
            target = "blacklist"
            entry = blacklist.add_blacklist_entry(
                getattr(config, "blacklist_file"),
                ip=_form_value(form, "ip"),
                reason=_form_value(form, "reason"),
            )
            details = f"ip={entry.ip}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Blacklist entry added: {entry.ip}")

        if action == "blacklist_remove":
            target = "blacklist"
            entry = blacklist.remove_blacklist_entry(
                getattr(config, "blacklist_file"),
                ip=_form_value(form, "ip"),
            )
            details = f"ip={entry.ip}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Blacklist entry removed: {entry.ip}")

        if action == "blacklist_validate":
            target = "blacklist"
            entries = blacklist.validate_blacklist_file(getattr(config, "blacklist_file"))
            details = f"entries={len(entries)}"
            _record_admin_action(config, action, target, "success", details)
            return _admin_notice("success", f"Blacklist valid: {len(entries)} entry(s)")

        _record_admin_action(config, action or "unknown", target, "error", "unknown action")
        return _admin_notice("error", "Unknown administrative action.")
    except (OSError, AttributeError, blacklist.BlacklistError, whitelist.WhitelistError) as exc:
        _record_admin_action(config, action or "unknown", target, "error", "validation failed")
        return _admin_notice("error", str(exc))


def _record_admin_action(
    config: Any,
    action: str,
    target: str,
    result: str,
    details: str,
) -> None:
    message = (
        f"Dashboard admin list action: action={action} target={target} "
        f"result={result} details={details}"
    )

    _write_admin_action_log(config, message)
    _write_admin_action_storage(config, action, target, result, details, message)


def _write_admin_action_log(config: Any, message: str) -> None:
    if getattr(config, "log_dir", None) is None:
        return

    try:
        from src.logger import get_logger, setup_logging

        setup_logging(config)
        get_logger("dashboard_admin").info(message)
    except Exception:
        return


def _write_admin_action_storage(
    config: Any,
    action: str,
    target: str,
    result: str,
    details: str,
    message: str,
) -> None:
    if getattr(config, "ids_db_path", None) is None:
        return

    store = SQLiteEventStore.from_config(config)
    try:
        store.save_event(
            event_type=ADMIN_LIST_ACTION,
            timestamp=datetime.now(tz=timezone.utc).timestamp(),
            severity="INFO" if result == "success" else "MEDIA",
            message=message,
            raw={
                "component": "dashboard_admin",
                "action": action,
                "target": target,
                "result": result,
                "details": details,
            },
        )
    except Exception:
        return
    finally:
        store.close()


def _admin_notice(level: str, message: str) -> dict[str, str]:
    return {"level": level, "message": message}


def _form_value(form: Mapping[str, Any], name: str) -> str:
    return str(form.get(name) or "").strip()


def _load_dashboard_data(
    config: Any,
    *,
    event_store_factory=SQLiteEventStore,
    filters: DashboardFilters | None = None,
) -> DashboardData:
    active_filters = filters or DashboardFilters()
    db_path = Path(getattr(config, "ids_db_path", "data/gleipnir_events.db")).expanduser()
    if not db_path.exists():
        return DashboardData(
            database_exists=False,
            database_path=str(db_path),
            message="SQLite database not found yet. Run replay/live before opening reports.",
            summary=_empty_summary(),
            latest_events=(),
            filters=active_filters,
            charts=_empty_charts(),
        )

    store = event_store_factory(db_path)
    try:
        events = store.fetch_events(
            **{
                key: value
                for key, value in active_filters.as_query_kwargs().items()
                if value is not None
            }
        )
    finally:
        store.close()

    if not events and active_filters.active_count:
        message = "SQLite database exists, but no events match the selected filters."
    elif not events:
        message = "SQLite database exists, but no IDS events have been stored yet."
    else:
        message = "Dashboard loaded from SQLite events."

    latest_events = tuple(_event_to_dict(event) for event in reversed(events[-LATEST_EVENT_LIMIT:]))
    return DashboardData(
        database_exists=True,
        database_path=str(db_path),
        message=message,
        summary=_build_summary(events),
        latest_events=latest_events,
        filters=active_filters,
        charts=_build_charts(events),
    )


def _load_event_detail(
    config: Any,
    event_id: int,
    *,
    event_store_factory=SQLiteEventStore,
) -> StoredEvent | None:
    """Load one event for the dashboard detail view."""
    db_path = Path(getattr(config, "ids_db_path", "data/gleipnir_events.db")).expanduser()
    if not db_path.exists():
        return None

    store = event_store_factory(db_path)
    try:
        return store.get_event(event_id)
    finally:
        store.close()


def _build_summary(events: tuple[StoredEvent, ...]) -> dict[str, int]:
    counts = _empty_summary()
    counts["total_events"] = len(events)
    for event in events:
        if event.event_type == AUTHORIZED_DEVICE:
            counts["authorized_devices"] += 1
        elif event.event_type == UNAUTHORIZED_DEVICE:
            counts["unauthorized_devices"] += 1
        elif event.event_type == DNS_EVENT:
            counts["dns_events"] += 1
        elif event.event_type == HTTP_EVENT:
            counts["http_events"] += 1
        elif event.event_type == BLACKLISTED_EXTERNAL_IP:
            counts["blacklisted_external_ips"] += 1
        elif event.event_type == ALERT_SENT:
            counts["alerts_sent"] += 1
    return counts


def _build_charts(events: tuple[StoredEvent, ...]) -> dict[str, tuple[dict[str, Any], ...]]:
    return {
        "events_by_type": _counter_chart(
            event.event_type or "UNKNOWN"
            for event in events
        ),
        "events_by_severity": _counter_chart(
            event.severity or "SIN_SEVERIDAD"
            for event in events
        ),
        "events_by_hour": _counter_chart(
            _hour_label(event.timestamp)
            for event in events
            if event.timestamp is not None
        ),
        "top_domains": _counter_chart(
            event.domain
            for event in events
            if event.domain
        )[:10],
        "top_external_ips": _counter_chart(
            event.destination_ip
            for event in events
            if event.destination_ip and _is_external_ip_event(event)
        )[:10],
        "alerts": _counter_chart(
            event.event_type
            for event in events
            if event.event_type in {ALERT_SENT, ALERT_SUPPRESSED}
        ),
    }


def _empty_summary() -> dict[str, int]:
    return {
        "total_events": 0,
        "authorized_devices": 0,
        "unauthorized_devices": 0,
        "dns_events": 0,
        "http_events": 0,
        "blacklisted_external_ips": 0,
        "alerts_sent": 0,
    }


def _empty_charts() -> dict[str, tuple[dict[str, Any], ...]]:
    return {
        "events_by_type": (),
        "events_by_severity": (),
        "events_by_hour": (),
        "top_domains": (),
        "top_external_ips": (),
        "alerts": (),
    }


def _event_to_dict(event: StoredEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "source_mac": event.source_mac,
        "destination_ip": event.destination_ip,
        "destination_mac": event.destination_mac,
        "protocol": event.protocol,
        "domain": event.domain,
        "message": event.message,
    }


def _counter_chart(values) -> tuple[dict[str, Any], ...]:
    counter = Counter(str(value) for value in values if value)
    return tuple(
        {"label": label, "value": value}
        for label, value in sorted(
            counter.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )


def _hour_label(timestamp: float | None) -> str:
    if timestamp is None:
        return ""

    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime("%H:00 UTC")


def _is_external_ip_event(event: StoredEvent) -> bool:
    if event.event_type == BLACKLISTED_EXTERNAL_IP:
        return True

    if not event.destination_ip:
        return False

    try:
        ip_address = ipaddress.ip_address(event.destination_ip)
    except ValueError:
        return False

    return not (
        ip_address.is_private
        or ip_address.is_loopback
        or ip_address.is_link_local
        or ip_address.is_multicast
    )


def _render_dashboard_html(data: DashboardData, *, admin_available: bool = False) -> str:
    filter_form = _render_filter_form(data.filters)
    charts = _render_charts(data.charts)
    admin_link = (
        '<a class="nav-link" href="/admin/lists">Administrar listas</a>'
        if admin_available
        else ""
    )
    cards = "".join(
        _render_card(label, value)
        for label, value in (
            ("Total de eventos", data.summary["total_events"]),
            ("Dispositivos autorizados", data.summary["authorized_devices"]),
            ("Dispositivos no autorizados", data.summary["unauthorized_devices"]),
            ("Eventos DNS", data.summary["dns_events"]),
            ("Eventos HTTP", data.summary["http_events"]),
            ("IPs externas en blacklist", data.summary["blacklisted_external_ips"]),
            ("Alertas enviadas", data.summary["alerts_sent"]),
        )
    )
    rows = "".join(_render_event_row(event) for event in data.latest_events)
    if not rows:
        rows = """
        <tr>
          <td colspan="8" class="empty">No hay eventos para mostrar.</td>
        </tr>
        """

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gleipnir IDS Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1d2433;
      --muted: #687385;
      --border: #d8dee8;
      --accent: #1f6feb;
      --warn: #b54708;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 20px 24px;
      background: #111827;
      color: white;
    }}
    header h1 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: 0;
    }}
    header p {{ margin: 0; color: #cbd5e1; }}
    .top-nav {{
      margin-top: 12px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .nav-link {{
      color: white;
      border: 1px solid #475569;
      border-radius: 5px;
      padding: 6px 10px;
      text-decoration: none;
      font-size: 13px;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    .notice {{
      margin-bottom: 18px;
      padding: 12px 14px;
      border: 1px solid var(--border);
      background: var(--panel);
      border-left: 4px solid var(--accent);
      border-radius: 6px;
    }}
    .notice.missing {{ border-left-color: var(--warn); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .charts {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }}
    .chart {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      min-height: 220px;
    }}
    .chart h2 {{
      margin: 0 0 12px;
      font-size: 17px;
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: minmax(110px, 1fr) minmax(120px, 2fr) 44px;
      gap: 8px;
      align-items: center;
      margin-bottom: 8px;
      font-size: 13px;
    }}
    .bar-label {{
      overflow-wrap: anywhere;
      color: var(--text);
    }}
    .bar-track {{
      height: 12px;
      background: #e5e7eb;
      border-radius: 999px;
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      min-width: 2px;
      background: var(--accent);
    }}
    .bar-value {{
      text-align: right;
      color: var(--muted);
      font-variant-numeric: tabular-nums;
    }}
    .filters {{
      margin-bottom: 18px;
      padding: 16px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
    }}
    .filters h2 {{
      margin: 0 0 12px;
      font-size: 18px;
    }}
    .filter-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 12px;
      align-items: end;
    }}
    label {{
      display: block;
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 5px;
    }}
    input, select {{
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--border);
      border-radius: 5px;
      padding: 7px 9px;
      background: white;
      color: var(--text);
      font: inherit;
    }}
    .filter-actions {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    button, .button-link {{
      min-height: 36px;
      border: 1px solid var(--accent);
      border-radius: 5px;
      padding: 7px 12px;
      background: var(--accent);
      color: white;
      text-decoration: none;
      font: inherit;
      cursor: pointer;
    }}
    .button-link {{
      display: inline-flex;
      align-items: center;
      background: white;
      color: var(--accent);
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      min-height: 88px;
    }}
    .card .label {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.25;
    }}
    .card .value {{
      margin-top: 10px;
      font-size: 28px;
      font-weight: 700;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    section h2 {{
      margin: 0;
      padding: 14px 16px;
      font-size: 18px;
      border-bottom: 1px solid var(--border);
    }}
    .table-wrap {{ overflow-x: auto; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 900px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      color: var(--muted);
      background: #f9fafb;
      font-weight: 600;
    }}
    .empty {{
      color: var(--muted);
      text-align: center;
      padding: 24px;
    }}
    .mono {{ font-family: Consolas, Monaco, monospace; }}
  </style>
</head>
<body>
  <header>
    <h1>Gleipnir IDS Dashboard</h1>
    <p>Panel local de solo lectura para eventos almacenados en SQLite.</p>
    <nav class="top-nav">{admin_link}</nav>
  </header>
  <main>
    <div class="notice {'missing' if not data.database_exists else ''}">
      <strong>Estado:</strong> {html.escape(data.message)}
      <br>
      <span class="mono">SQLite: {html.escape(data.database_path)}</span>
    </div>
    {filter_form}
    <div class="grid">{cards}</div>
    <div class="charts">{charts}</div>
    <section>
      <h2>Ultimos 50 eventos</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Tipo</th>
              <th>Severidad</th>
              <th>Origen</th>
              <th>Destino</th>
              <th>Protocolo</th>
              <th>Dominio</th>
              <th>Mensaje</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"""


def _render_charts(charts: dict[str, tuple[dict[str, Any], ...]]) -> str:
    chart_specs = (
        ("Eventos por tipo", charts["events_by_type"]),
        ("Eventos por severidad", charts["events_by_severity"]),
        ("Eventos por hora", charts["events_by_hour"]),
        ("Top 10 dominios consultados", charts["top_domains"]),
        ("Top 10 IPs externas detectadas", charts["top_external_ips"]),
        ("Alertas enviadas/suprimidas", charts["alerts"]),
    )
    return "".join(_render_bar_chart(title, rows) for title, rows in chart_specs)


def _render_bar_chart(title: str, rows: tuple[dict[str, Any], ...]) -> str:
    if not rows:
        body = '<div class="empty">Sin datos para esta grafica.</div>'
    else:
        max_value = max(int(row["value"]) for row in rows) or 1
        body = "".join(_render_bar_row(row, max_value) for row in rows[:10])

    return f"""
    <div class="chart">
      <h2>{html.escape(title)}</h2>
      {body}
    </div>
    """


def _render_bar_row(row: dict[str, Any], max_value: int) -> str:
    value = int(row["value"])
    width = max(2, round((value / max_value) * 100))
    label = str(row["label"])
    return f"""
    <div class="bar-row">
      <div class="bar-label">{html.escape(label)}</div>
      <div class="bar-track"><div class="bar-fill" style="width: {width}%"></div></div>
      <div class="bar-value">{value}</div>
    </div>
    """


def _render_filter_form(filters: DashboardFilters) -> str:
    values = filters.as_payload()
    event_type = values.get("type", "")
    severity = values.get("severity", "")
    return f"""
    <form class="filters" method="get" action="/">
      <h2>Filtros</h2>
      <div class="filter-grid">
        <div>
          <label for="type">Tipo de evento</label>
          <input id="type" name="type" value="{html.escape(str(event_type))}" placeholder="UNAUTHORIZED_DEVICE">
        </div>
        <div>
          <label for="severity">Severidad</label>
          <input id="severity" name="severity" value="{html.escape(str(severity))}" placeholder="high, medium, low, info">
        </div>
        <div>
          <label for="source_ip">IP origen</label>
          <input id="source_ip" name="source_ip" value="{html.escape(str(values.get('source_ip', '')))}" placeholder="192.168.1.20">
        </div>
        <div>
          <label for="destination_ip">IP destino</label>
          <input id="destination_ip" name="destination_ip" value="{html.escape(str(values.get('destination_ip', '')))}" placeholder="8.8.8.8">
        </div>
        <div>
          <label for="source_mac">MAC origen</label>
          <input id="source_mac" name="source_mac" value="{html.escape(str(values.get('source_mac', '')))}" placeholder="aa:bb:cc:dd:ee:ff">
        </div>
        <div>
          <label for="domain">Dominio</label>
          <input id="domain" name="domain" value="{html.escape(str(values.get('domain', '')))}" placeholder="example.com">
        </div>
        <div>
          <label for="protocol">Protocolo</label>
          <input id="protocol" name="protocol" value="{html.escape(str(values.get('protocol', '')))}" placeholder="DNS, HTTP, TCP">
        </div>
        <div>
          <label for="since">Fecha inicial</label>
          <input id="since" name="since" value="{html.escape(str(values.get('since', '')))}" placeholder="2026-06-01">
        </div>
        <div>
          <label for="until">Fecha final</label>
          <input id="until" name="until" value="{html.escape(str(values.get('until', '')))}" placeholder="2026-06-07">
        </div>
        <div class="filter-actions">
          <button type="submit">Aplicar filtros</button>
          <a class="button-link" href="/">Limpiar</a>
        </div>
      </div>
    </form>
    """


def _render_card(label: str, value: int) -> str:
    return f"""
    <div class="card">
      <div class="label">{html.escape(label)}</div>
      <div class="value">{value}</div>
    </div>
    """


def _render_event_row(event: dict[str, Any]) -> str:
    source = _join_ip_mac(event.get("source_ip"), event.get("source_mac"))
    destination = _join_ip_mac(event.get("destination_ip"), event.get("destination_mac"))
    event_id = str(event.get("id") or "")
    event_id_cell = ""
    if event_id:
        escaped_id = html.escape(event_id)
        event_id_cell = f'<a href="/events/{escaped_id}">{escaped_id}</a>'
    return f"""
    <tr>
      <td>{event_id_cell}</td>
      <td>{html.escape(str(event.get("event_type") or ""))}</td>
      <td>{html.escape(str(event.get("severity") or ""))}</td>
      <td>{html.escape(source)}</td>
      <td>{html.escape(destination)}</td>
      <td>{html.escape(str(event.get("protocol") or ""))}</td>
      <td>{html.escape(str(event.get("domain") or ""))}</td>
      <td>{html.escape(str(event.get("message") or ""))}</td>
    </tr>
    """


def _render_event_detail_html(event: StoredEvent) -> str:
    raw_payload = _redact_dashboard_raw(event.raw)
    formatted_raw = json.dumps(
        raw_payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    rows = "".join(
        _render_detail_row(label, value)
        for label, value in (
            ("ID", event.id),
            ("Timestamp", event.timestamp),
            ("Tipo de evento", event.event_type),
            ("Severidad", event.severity),
            ("IP origen", event.source_ip),
            ("MAC origen", event.source_mac),
            ("IP destino", event.destination_ip),
            ("MAC destino", event.destination_mac),
            ("Protocolo", event.protocol),
            ("Dominio", event.domain),
            ("Mensaje", event.message),
        )
    )

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Detalle de evento {html.escape(str(event.id))} - Gleipnir IDS</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1d2433;
      --muted: #687385;
      --border: #d8dee8;
      --accent: #1f6feb;
      --code: #111827;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 20px 24px;
      background: #111827;
      color: white;
    }}
    header h1 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: 0;
    }}
    header p {{ margin: 0; color: #cbd5e1; }}
    main {{
      max-width: 980px;
      margin: 0 auto;
      padding: 24px;
    }}
    a {{ color: var(--accent); }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 18px;
    }}
    .row {{
      display: grid;
      grid-template-columns: minmax(150px, 220px) 1fr;
      gap: 14px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
    }}
    .row:last-child {{ border-bottom: 0; }}
    .label {{
      color: var(--muted);
      font-weight: 600;
    }}
    .value {{
      overflow-wrap: anywhere;
    }}
    h2 {{
      margin: 22px 0 10px;
      font-size: 18px;
    }}
    pre {{
      margin: 0;
      padding: 16px;
      overflow-x: auto;
      background: var(--code);
      color: #e5e7eb;
      border-radius: 6px;
      font-family: Consolas, Monaco, monospace;
      font-size: 13px;
      line-height: 1.45;
    }}
    .actions {{ margin-bottom: 16px; }}
  </style>
</head>
<body>
  <header>
    <h1>Detalle de evento IDS</h1>
    <p>Vista local de solo lectura para revisar un evento almacenado.</p>
  </header>
  <main>
    <div class="actions"><a href="/">Volver al dashboard</a></div>
    <section class="panel">{rows}</section>
    <h2>raw_json</h2>
    <pre>{html.escape(formatted_raw)}</pre>
  </main>
</body>
</html>"""


def _render_event_not_found_html(event_id: int) -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Evento no encontrado - Gleipnir IDS</title>
  <style>
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: #f6f7f9;
      color: #1d2433;
    }}
    main {{
      max-width: 760px;
      margin: 0 auto;
      padding: 36px 24px;
    }}
    .panel {{
      background: white;
      border: 1px solid #d8dee8;
      border-left: 4px solid #b54708;
      border-radius: 6px;
      padding: 18px;
    }}
    a {{ color: #1f6feb; }}
  </style>
</head>
<body>
  <main>
    <div class="panel">
      <h1>Evento no encontrado</h1>
      <p>No existe un evento con ID {html.escape(str(event_id))} en la base SQLite configurada.</p>
      <p><a href="/">Volver al dashboard</a></p>
    </div>
  </main>
</body>
</html>"""


def _render_admin_lists_html(
    data: AdminListData,
    *,
    notice: dict[str, str] | None = None,
) -> str:
    notice_html = _render_admin_notice(notice)
    whitelist_status = _render_admin_status(data.whitelist_error)
    blacklist_status = _render_admin_status(data.blacklist_error)
    whitelist_rows = _render_whitelist_admin_rows(data.whitelist_entries)
    blacklist_rows = _render_blacklist_admin_rows(data.blacklist_entries)

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Administracion de listas - Gleipnir IDS</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1d2433;
      --muted: #687385;
      --border: #d8dee8;
      --accent: #1f6feb;
      --danger: #b42318;
      --success: #027a48;
      --warning: #b54708;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 20px 24px;
      background: #111827;
      color: white;
    }}
    header h1 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: 0;
    }}
    header p {{ margin: 0; color: #cbd5e1; }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    a {{ color: var(--accent); }}
    .actions {{ margin-bottom: 16px; }}
    .notice {{
      margin-bottom: 18px;
      padding: 12px 14px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--panel);
    }}
    .notice.success {{ border-left: 4px solid var(--success); }}
    .notice.error {{ border-left: 4px solid var(--danger); }}
    .status {{
      margin: 0 0 12px;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-left: 4px solid var(--warning);
      border-radius: 6px;
      background: #fff;
      color: var(--muted);
    }}
    .admin-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
      gap: 18px;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    section h2 {{
      margin: 0;
      padding: 14px 16px;
      font-size: 18px;
      border-bottom: 1px solid var(--border);
    }}
    .section-body {{ padding: 16px; }}
    .table-wrap {{
      overflow-x: auto;
      margin-bottom: 16px;
    }}
    table {{
      width: 100%;
      min-width: 520px;
      border-collapse: collapse;
    }}
    th, td {{
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      color: var(--muted);
      background: #f9fafb;
      font-weight: 600;
    }}
    .empty {{
      color: var(--muted);
      text-align: center;
      padding: 18px;
    }}
    form {{
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 12px;
      background: #fbfcfe;
    }}
    form h3 {{
      margin: 0 0 10px;
      font-size: 15px;
    }}
    .form-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 10px;
      align-items: end;
    }}
    label {{
      display: block;
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 5px;
    }}
    input {{
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--border);
      border-radius: 5px;
      padding: 7px 9px;
      background: white;
      color: var(--text);
      font: inherit;
    }}
    button {{
      min-height: 36px;
      border: 1px solid var(--accent);
      border-radius: 5px;
      padding: 7px 12px;
      background: var(--accent);
      color: white;
      font: inherit;
      cursor: pointer;
    }}
    .danger button {{
      border-color: var(--danger);
      background: var(--danger);
    }}
    .validate-form {{
      background: white;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Administracion de listas</h1>
    <p>Seccion protegida para gestionar whitelist y blacklist.</p>
  </header>
  <main>
    <div class="actions"><a href="/">Volver al dashboard</a></div>
    {notice_html}
    <div class="admin-grid">
      <section>
        <h2>Whitelist</h2>
        <div class="section-body">
          {whitelist_status}
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>MAC</th>
                  <th>Descripcion</th>
                </tr>
              </thead>
              <tbody>{whitelist_rows}</tbody>
            </table>
          </div>
          {_render_whitelist_add_form()}
          {_render_whitelist_remove_form()}
          {_render_validate_form("whitelist_validate", "Validar whitelist")}
        </div>
      </section>
      <section>
        <h2>Blacklist</h2>
        <div class="section-body">
          {blacklist_status}
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Motivo</th>
                </tr>
              </thead>
              <tbody>{blacklist_rows}</tbody>
            </table>
          </div>
          {_render_blacklist_add_form()}
          {_render_blacklist_remove_form()}
          {_render_validate_form("blacklist_validate", "Validar blacklist")}
        </div>
      </section>
    </div>
  </main>
</body>
</html>"""


def _render_admin_unavailable_html() -> str:
    return """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Administracion no disponible - Gleipnir IDS</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: #f6f7f9;
      color: #1d2433;
    }
    main {
      max-width: 760px;
      margin: 0 auto;
      padding: 36px 24px;
    }
    .panel {
      background: white;
      border: 1px solid #d8dee8;
      border-left: 4px solid #b54708;
      border-radius: 6px;
      padding: 18px;
    }
    a { color: #1f6feb; }
  </style>
</head>
<body>
  <main>
    <div class="panel">
      <h1>Administracion no disponible</h1>
      <p>Esta seccion solo se habilita cuando DASHBOARD_AUTH_ENABLED=true.</p>
      <p><a href="/">Volver al dashboard</a></p>
    </div>
  </main>
</body>
</html>"""


def _render_admin_notice(notice: dict[str, str] | None) -> str:
    if notice is None:
        return ""

    level = "success" if notice.get("level") == "success" else "error"
    message = html.escape(notice.get("message") or "")
    return f'<div class="notice {level}">{message}</div>'


def _render_admin_status(error: str | None) -> str:
    if not error:
        return ""

    return f'<div class="status">{html.escape(error)}</div>'


def _render_whitelist_admin_rows(entries: tuple[whitelist.WhitelistEntry, ...]) -> str:
    if not entries:
        return '<tr><td colspan="3" class="empty">No hay entradas en whitelist.</td></tr>'

    return "".join(
        f"""
        <tr>
          <td>{html.escape(entry.ip)}</td>
          <td>{html.escape(entry.mac)}</td>
          <td>{html.escape(entry.description)}</td>
        </tr>
        """
        for entry in entries
    )


def _render_blacklist_admin_rows(entries: tuple[blacklist.BlacklistEntry, ...]) -> str:
    if not entries:
        return '<tr><td colspan="2" class="empty">No hay entradas en blacklist.</td></tr>'

    return "".join(
        f"""
        <tr>
          <td>{html.escape(entry.ip)}</td>
          <td>{html.escape(entry.reason)}</td>
        </tr>
        """
        for entry in entries
    )


def _render_whitelist_add_form() -> str:
    return """
    <form method="post" action="/admin/lists">
      <input type="hidden" name="action" value="whitelist_add">
      <h3>Agregar a whitelist</h3>
      <div class="form-grid">
        <div>
          <label for="whitelist_ip">IP</label>
          <input id="whitelist_ip" name="ip" required placeholder="192.168.1.10">
        </div>
        <div>
          <label for="whitelist_mac">MAC</label>
          <input id="whitelist_mac" name="mac" required placeholder="aa:bb:cc:dd:ee:ff">
        </div>
        <div>
          <label for="whitelist_description">Descripcion</label>
          <input id="whitelist_description" name="description" required placeholder="Laptop laboratorio">
        </div>
        <div>
          <button type="submit">Agregar</button>
        </div>
      </div>
    </form>
    """


def _render_whitelist_remove_form() -> str:
    return """
    <form class="danger" method="post" action="/admin/lists">
      <input type="hidden" name="action" value="whitelist_remove">
      <h3>Eliminar de whitelist</h3>
      <div class="form-grid">
        <div>
          <label for="whitelist_remove_ip">IP</label>
          <input id="whitelist_remove_ip" name="ip" required placeholder="192.168.1.10">
        </div>
        <div>
          <button type="submit">Eliminar</button>
        </div>
      </div>
    </form>
    """


def _render_blacklist_add_form() -> str:
    return """
    <form method="post" action="/admin/lists">
      <input type="hidden" name="action" value="blacklist_add">
      <h3>Agregar a blacklist</h3>
      <div class="form-grid">
        <div>
          <label for="blacklist_ip">IP</label>
          <input id="blacklist_ip" name="ip" required placeholder="8.8.8.8">
        </div>
        <div>
          <label for="blacklist_reason">Motivo</label>
          <input id="blacklist_reason" name="reason" required placeholder="IP externa reportada">
        </div>
        <div>
          <button type="submit">Agregar</button>
        </div>
      </div>
    </form>
    """


def _render_blacklist_remove_form() -> str:
    return """
    <form class="danger" method="post" action="/admin/lists">
      <input type="hidden" name="action" value="blacklist_remove">
      <h3>Eliminar de blacklist</h3>
      <div class="form-grid">
        <div>
          <label for="blacklist_remove_ip">IP</label>
          <input id="blacklist_remove_ip" name="ip" required placeholder="8.8.8.8">
        </div>
        <div>
          <button type="submit">Eliminar</button>
        </div>
      </div>
    </form>
    """


def _render_validate_form(action: str, label: str) -> str:
    return f"""
    <form class="validate-form" method="post" action="/admin/lists">
      <input type="hidden" name="action" value="{html.escape(action)}">
      <button type="submit">{html.escape(label)}</button>
    </form>
    """


def _render_detail_row(label: str, value: Any) -> str:
    display_value = "" if value is None else str(value)
    return f"""
    <div class="row">
      <div class="label">{html.escape(label)}</div>
      <div class="value">{html.escape(display_value)}</div>
    </div>
    """


def _redact_dashboard_raw(value: Any, key_name: str = "") -> Any:
    if _looks_like_secret_key(key_name):
        return REDACTED_VALUE

    if isinstance(value, Mapping):
        return {
            str(key): _redact_dashboard_raw(item, str(key))
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_redact_dashboard_raw(item, key_name) for item in value]

    return value


def _looks_like_secret_key(key_name: str) -> bool:
    normalized = key_name.lower().replace("-", "_")
    return any(secret_hint in normalized for secret_hint in SECRET_FIELD_HINTS)


def _join_ip_mac(ip: Any, mac: Any) -> str:
    values = [str(value) for value in (ip, mac) if value]
    return " / ".join(values)


def _filters_from_query(query: Mapping[str, Any]) -> DashboardFilters:
    since_label = _query_value(query, "since")
    until_label = _query_value(query, "until")
    return DashboardFilters(
        event_type=_query_value(query, "type", uppercase=True),
        severity=_query_value(query, "severity"),
        source_ip=_query_value(query, "source_ip"),
        destination_ip=_query_value(query, "destination_ip"),
        source_mac=_query_value(query, "source_mac"),
        domain=_query_value(query, "domain", lowercase=True),
        protocol=_query_value(query, "protocol", uppercase=True),
        since=_parse_filter_timestamp(since_label, end_of_day=False),
        until=_parse_filter_timestamp(until_label, end_of_day=True),
        since_label=since_label,
        until_label=until_label,
    )


def _query_value(
    query: Mapping[str, Any],
    name: str,
    *,
    uppercase: bool = False,
    lowercase: bool = False,
) -> str | None:
    raw_value = query.get(name)
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


def _parse_filter_timestamp(raw_value: str | None, *, end_of_day: bool) -> float | None:
    if raw_value is None:
        return None

    try:
        if _is_date_only(raw_value):
            parsed_date = datetime.strptime(raw_value, "%Y-%m-%d").date()
            parsed_time = time.max if end_of_day else time.min
            parsed_datetime = datetime.combine(
                parsed_date,
                parsed_time,
                tzinfo=timezone.utc,
            )
        else:
            parsed_datetime = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
            if parsed_datetime.tzinfo is None:
                parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    return parsed_datetime.timestamp()


def _is_date_only(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False

    return True


def _load_runtime_config() -> Any:
    from src.config import load_config

    return load_config()
