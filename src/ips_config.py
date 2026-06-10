"""Operational IPS/Firewall configuration stored in an editable JSON file.

Design split:
- ``.env`` holds only base values, paths and secrets (IPS_CONFIG_FILE,
  IPS_BACKEND, IPS_TABLE, IPS_CHAIN).
- ``data/ips_config.json`` holds the *operational* IPS behaviour that the user
  changes from the CLI or dashboard. This module is the single source of truth
  for that operational config.

Safety:
- Created with safe defaults (passive IDS, dry-run on, auto_apply off).
- No secrets are ever stored here.
- ``.env`` is never modified by this module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

DEFAULT_IPS_CONFIG_FILE = Path("data/ips_config.json")

BOOL_KEYS = ("ips_enabled", "dry_run", "blacklist_check_private", "auto_apply")
ALLOWLIST_POLICIES = ("monitor", "allow_registered", "block_unregistered")
BLACKLIST_POLICIES = ("monitor", "block")
BLOCK_DIRECTIONS = ("outbound", "inbound", "both")

_DEFAULTS: dict[str, Any] = {
    "ips_enabled": False,
    "dry_run": True,
    "allowlist_policy": "monitor",
    "blacklist_policy": "block",
    "block_direction": "both",
    "blacklist_check_private": False,
    "auto_apply": False,
}

_VALID_VALUES: dict[str, tuple[Any, ...]] = {
    "ips_enabled": (True, False),
    "dry_run": (True, False),
    "allowlist_policy": ALLOWLIST_POLICIES,
    "blacklist_policy": BLACKLIST_POLICIES,
    "block_direction": BLOCK_DIRECTIONS,
    "blacklist_check_private": (True, False),
    "auto_apply": (True, False),
}

CONFIG_KEYS = tuple(_DEFAULTS)


class IpsConfigError(ValueError):
    """Raised when IPS operational configuration is invalid or unreadable."""


def get_default_ips_config() -> dict[str, Any]:
    """Return a copy of the safe default operational configuration."""
    return dict(_DEFAULTS)


def coerce_value(key: str, value: Any) -> Any:
    """Coerce a raw (possibly string) value to the proper type for ``key``."""
    if key not in _DEFAULTS:
        raise IpsConfigError(f"Unknown IPS config key: {key}")

    if key in BOOL_KEYS:
        return _coerce_bool(key, value)

    return str(value).strip().lower()


def validate_ips_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a full or partial config and return a complete normalized dict.

    Unknown keys and invalid values are rejected. Missing keys are filled with
    safe defaults so a partial file still loads with predictable behaviour.
    """
    if not isinstance(config, Mapping):
        raise IpsConfigError("IPS config must be a JSON object")

    unknown = [key for key in config if key not in _DEFAULTS]
    if unknown:
        raise IpsConfigError(f"Unknown IPS config keys: {', '.join(sorted(unknown))}")

    result = get_default_ips_config()
    for key, raw_value in config.items():
        value = coerce_value(key, raw_value)
        if value not in _VALID_VALUES[key]:
            allowed = ", ".join(str(item) for item in _VALID_VALUES[key])
            raise IpsConfigError(f"Invalid value for {key}: {raw_value!r}. Allowed: {allowed}")
        result[key] = value

    return result


def load_ips_config(config_or_path: Any) -> dict[str, Any]:
    """Load operational IPS config, creating it with safe defaults if missing."""
    path = _resolve_path(config_or_path)
    if not path.exists():
        defaults = get_default_ips_config()
        _write_config(path, defaults)
        return defaults

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IpsConfigError(f"IPS config file is not valid JSON: {path}") from exc

    if not isinstance(raw, dict):
        raise IpsConfigError(f"IPS config file must contain a JSON object: {path}")

    return validate_ips_config(raw)


def save_ips_config(config: Mapping[str, Any], config_or_path: Any) -> dict[str, Any]:
    """Validate and persist the operational IPS config atomically."""
    validated = validate_ips_config(config)
    _write_config(_resolve_path(config_or_path), validated)
    return validated


def update_ips_config(changes: Mapping[str, Any], config_or_path: Any) -> dict[str, Any]:
    """Apply ``changes`` to the stored config and persist the result."""
    if not isinstance(changes, Mapping) or not changes:
        raise IpsConfigError("No IPS config changes provided")

    unknown = [key for key in changes if key not in _DEFAULTS]
    if unknown:
        raise IpsConfigError(f"Unknown IPS config keys: {', '.join(sorted(unknown))}")

    current = load_ips_config(config_or_path)
    merged = {**current, **{key: coerce_value(key, value) for key, value in changes.items()}}
    return save_ips_config(merged, config_or_path)


def is_ips_effectively_active(config: Mapping[str, Any]) -> bool:
    """Return True only when real rules may be applied (enabled and not dry-run)."""
    return bool(config.get("ips_enabled")) and not bool(config.get("dry_run"))


def build_ips_settings(runtime_config: Any) -> Any:
    """Merge base config (.env) with operational JSON into firewall IPSSettings."""
    from src import firewall

    operational = load_ips_config(runtime_config)
    return firewall.IPSSettings(
        enabled=operational["ips_enabled"],
        backend=str(getattr(runtime_config, "ips_backend", "nftables") or "nftables"),
        dry_run=operational["dry_run"],
        table=str(getattr(runtime_config, "ips_table", "gleipnir") or "gleipnir"),
        chain=str(getattr(runtime_config, "ips_chain", "gleipnir_filter") or "gleipnir_filter"),
        allowlist_policy=operational["allowlist_policy"],
        blacklist_policy=operational["blacklist_policy"],
        block_direction=operational["block_direction"],
        blacklist_check_private=operational["blacklist_check_private"],
        auto_apply=operational["auto_apply"],
    )


def _resolve_path(config_or_path: Any) -> Path:
    if isinstance(config_or_path, (str, Path)):
        return Path(config_or_path).expanduser()

    path = getattr(config_or_path, "ips_config_file", None) or DEFAULT_IPS_CONFIG_FILE
    return Path(path).expanduser()


def _write_config(path: Path, config: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp")
    temp_path.write_text(
        json.dumps(dict(config), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temp_path.replace(path)


def _coerce_bool(key: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "y", "on"}:
        return True
    if normalized in {"false", "0", "no", "n", "off"}:
        return False

    raise IpsConfigError(f"{key} must be true or false, got: {value!r}")
