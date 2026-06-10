"""Optional defensive IPS/Firewall enforcement layer for Gleipnir.

This module is fully optional. Gleipnir's default behaviour is a passive IDS:
it detects, logs, and alerts but never blocks traffic. When the operator
explicitly enables the IPS layer (``IPS_ENABLED=true``) this module can build
and apply nftables rules in a dedicated, self-contained table/chain.

Safety design:
- Nothing is applied unless ``IPS_ENABLED=true`` and ``IPS_DRY_RUN=false``.
- Only Gleipnir's own ``table inet <IPS_TABLE>`` is created or removed; existing
  system rules are never flushed or modified.
- ``nft flush ruleset`` is never used.
- Missing ``nft`` binary, missing permissions, or backend errors are logged and
  returned as structured results; they never stop the IDS.
- No offensive, evasion, or spoofing behaviour. Intended for owned/lab networks.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from src.logger import get_logger

CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]

_LOGGER = get_logger("firewall")
_LOGGER.addHandler(logging.NullHandler())

BACKEND_NFTABLES = "nftables"
NFT_FAMILY = "inet"
DEFAULT_NFT_TIMEOUT_SECONDS = 10

# Allowlist policies.
ALLOWLIST_MONITOR = "monitor"
ALLOWLIST_ALLOW_REGISTERED = "allow_registered"
ALLOWLIST_BLOCK_UNREGISTERED = "block_unregistered"

# Blacklist policies.
BLACKLIST_MONITOR = "monitor"
BLACKLIST_BLOCK = "block"

# Block directions.
DIRECTION_OUTBOUND = "outbound"
DIRECTION_INBOUND = "inbound"
DIRECTION_BOTH = "both"

# Actions recorded on events.
ACTION_DETECTED = "detected"
ACTION_ALERTED = "alerted"
ACTION_BLOCKED = "blocked"
ACTION_DRY_RUN_BLOCK = "dry_run_block"
ACTION_MONITORED = "monitored"

# IPS action event types persisted to SQLite/reports.
IPS_BLOCKED_BLACKLISTED_IP = "IPS_BLOCKED_BLACKLISTED_IP"
IPS_BLOCKED_UNREGISTERED_DEVICE = "IPS_BLOCKED_UNREGISTERED_DEVICE"

# Set names live inside Gleipnir's own table only.
SET_BLACKLIST_V4 = "gleipnir_blacklist_v4"
SET_BLACKLIST_V6 = "gleipnir_blacklist_v6"
SET_ALLOW_V4 = "gleipnir_allow_v4"
SET_ALLOW_V6 = "gleipnir_allow_v6"
SET_ALLOW_MAC = "gleipnir_allow_mac"


class FirewallError(RuntimeError):
    """Raised only for programming errors; runtime failures return results."""


@dataclass(frozen=True)
class IPSSettings:
    """Validated IPS/firewall settings derived from configuration."""

    enabled: bool = False
    backend: str = BACKEND_NFTABLES
    dry_run: bool = True
    table: str = "gleipnir"
    chain: str = "gleipnir_filter"
    allowlist_policy: str = ALLOWLIST_MONITOR
    blacklist_policy: str = BLACKLIST_BLOCK
    block_direction: str = DIRECTION_BOTH
    blacklist_check_private: bool = False
    auto_apply: bool = False

    @classmethod
    def from_config(cls, config: Any) -> "IPSSettings":
        """Build IPS settings from runtime configuration (base-only fallback).

        Prefer ``ips_config.build_ips_settings`` which overlays the operational
        JSON file. This classmethod is kept for direct/base use and tests.
        """
        return cls(
            enabled=bool(getattr(config, "ips_enabled", False)),
            backend=str(getattr(config, "ips_backend", BACKEND_NFTABLES)),
            dry_run=bool(getattr(config, "ips_dry_run", True)),
            table=str(getattr(config, "ips_table", "gleipnir")) or "gleipnir",
            chain=str(getattr(config, "ips_chain", "gleipnir_filter")) or "gleipnir_filter",
            allowlist_policy=str(getattr(config, "ips_allowlist_policy", ALLOWLIST_MONITOR)),
            blacklist_policy=str(getattr(config, "ips_blacklist_policy", BLACKLIST_BLOCK)),
            block_direction=str(getattr(config, "ips_block_direction", DIRECTION_BOTH)),
            blacklist_check_private=bool(getattr(config, "blacklist_check_private", False)),
            auto_apply=bool(getattr(config, "ips_auto_apply", False)),
        )

    @property
    def is_active(self) -> bool:
        """Return True when rules may actually be applied to the system."""
        return self.enabled and not self.dry_run


@dataclass(frozen=True)
class FirewallResult:
    """Structured outcome of a firewall operation; never raises to callers."""

    applied: bool
    dry_run: bool
    reason: str | None = None
    error: str | None = None
    rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class IPSActionEvent:
    """Defensive action taken (or simulated) for one detection."""

    event_type: str
    timestamp: float
    ip_origen: str
    ip_destino: str
    direccion: str
    protocolo: str
    motivo: str
    severidad: str
    accion: str
    dry_run: bool
    applied: bool
    message: str = ""
    backend: str = BACKEND_NFTABLES


# --------------------------------------------------------------------------- #
# Backend availability / permissions
# --------------------------------------------------------------------------- #
def is_nft_available(runner: CommandRunner | None = None) -> bool:
    """Return True when the ``nft`` binary is callable on this system."""
    run = runner or subprocess.run
    try:
        completed = run(
            ["nft", "--version"],
            capture_output=True,
            text=True,
            timeout=DEFAULT_NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return False
    except Exception as exc:  # pragma: no cover - defensive
        _LOGGER.warning("nft availability check failed: %s", exc)
        return False

    return getattr(completed, "returncode", 1) == 0


def has_required_permissions(runner: CommandRunner | None = None) -> bool:
    """Best-effort check that we can read Gleipnir's own table (proxy for root).

    Applying real nftables changes requires root/CAP_NET_ADMIN. We never assume
    privileges; callers should run apply/remove with sudo. A non-zero result
    here usually means the process lacks the necessary capabilities.
    """
    run = runner or subprocess.run
    try:
        completed = run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=DEFAULT_NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return False
    except Exception:  # pragma: no cover - defensive
        return False

    return getattr(completed, "returncode", 1) == 0


# --------------------------------------------------------------------------- #
# Rule generation (pure functions, safe to run without nft)
# --------------------------------------------------------------------------- #
def build_blacklist_rules(
    blacklist_entries: Iterable[Any],
    settings: IPSSettings,
) -> list[str]:
    """Return nftables chain rule lines that drop blacklisted IPs.

    Direction is controlled by ``settings.block_direction``. Returns an empty
    list when the blacklist policy is ``monitor`` or there are no entries.
    """
    if settings.blacklist_policy != BLACKLIST_BLOCK:
        return []

    v4, v6 = _split_ip_versions(_entry_ips(blacklist_entries))
    rules: list[str] = []
    block_out = settings.block_direction in (DIRECTION_OUTBOUND, DIRECTION_BOTH)
    block_in = settings.block_direction in (DIRECTION_INBOUND, DIRECTION_BOTH)

    if v4:
        if block_out:
            rules.append(f"ip daddr @{SET_BLACKLIST_V4} drop")
        if block_in:
            rules.append(f"ip saddr @{SET_BLACKLIST_V4} drop")
    if v6:
        if block_out:
            rules.append(f"ip6 daddr @{SET_BLACKLIST_V6} drop")
        if block_in:
            rules.append(f"ip6 saddr @{SET_BLACKLIST_V6} drop")

    return rules


def build_allowlist_rules(
    whitelist_entries: Iterable[Any],
    settings: IPSSettings,
) -> list[str]:
    """Return nftables chain rule lines for the allowlist policy.

    - ``monitor``: no rules (passive).
    - ``allow_registered``: explicitly accept registered source IPs.
    - ``block_unregistered``: accept registered sources then drop the rest.

    MAC matching (``ether saddr``) is only reliable on the same Ethernet
    segment / bridged path. On routed (L3) traffic the source MAC is the last
    hop, not the original host, so IP rules are preferred and authoritative.
    """
    policy = settings.allowlist_policy
    if policy == ALLOWLIST_MONITOR:
        return []

    entries = tuple(whitelist_entries)
    v4, v6 = _split_ip_versions(_entry_ips(entries))
    macs = _entry_macs(entries)
    rules: list[str] = []

    if policy in (ALLOWLIST_ALLOW_REGISTERED, ALLOWLIST_BLOCK_UNREGISTERED):
        if v4:
            rules.append(f"ip saddr @{SET_ALLOW_V4} accept")
        if v6:
            rules.append(f"ip6 saddr @{SET_ALLOW_V6} accept")
        if macs:
            rules.append(f"ether saddr @{SET_ALLOW_MAC} accept")

    if policy == ALLOWLIST_BLOCK_UNREGISTERED:
        # Guard: never emit a blanket drop when there is nothing to allow,
        # which would otherwise blackhole the whole segment.
        if v4:
            rules.append(f"ip saddr != @{SET_ALLOW_V4} drop")
        if v6:
            rules.append(f"ip6 saddr != @{SET_ALLOW_V6} drop")
        if not v4 and not v6:
            _LOGGER.warning(
                "IPS block_unregistered requested but allowlist has no IPs; "
                "refusing to emit a blanket drop rule."
            )

    return rules


def build_ruleset(
    whitelist_entries: Iterable[Any],
    blacklist_entries: Iterable[Any],
    settings: IPSSettings,
) -> str:
    """Render the full ``nft -f`` script for Gleipnir's own table only."""
    whitelist_entries = tuple(whitelist_entries)
    blacklist_entries = tuple(blacklist_entries)

    bl_v4, bl_v6 = _split_ip_versions(_entry_ips(blacklist_entries))
    al_v4, al_v6 = _split_ip_versions(_entry_ips(whitelist_entries))
    al_macs = _entry_macs(whitelist_entries)

    sets: list[str] = []
    needs_bl = settings.blacklist_policy == BLACKLIST_BLOCK
    needs_al = settings.allowlist_policy in (
        ALLOWLIST_ALLOW_REGISTERED,
        ALLOWLIST_BLOCK_UNREGISTERED,
    )
    if needs_bl and bl_v4:
        sets.append(_render_set(SET_BLACKLIST_V4, "ipv4_addr", bl_v4))
    if needs_bl and bl_v6:
        sets.append(_render_set(SET_BLACKLIST_V6, "ipv6_addr", bl_v6))
    if needs_al and al_v4:
        sets.append(_render_set(SET_ALLOW_V4, "ipv4_addr", al_v4))
    if needs_al and al_v6:
        sets.append(_render_set(SET_ALLOW_V6, "ipv6_addr", al_v6))
    if needs_al and al_macs:
        sets.append(_render_set(SET_ALLOW_MAC, "ether_addr", al_macs))

    chain_rules = build_blacklist_rules(blacklist_entries, settings)
    chain_rules += build_allowlist_rules(whitelist_entries, settings)

    indented_sets = "\n".join(_indent(block, 4) for block in sets)
    indented_rules = "\n".join(f"        {rule}" for rule in chain_rules)

    chain_body = (
        f"    chain {settings.chain} {{\n"
        "        type filter hook forward priority 0; policy accept;\n"
        f"{indented_rules}\n"
        "    }"
    )

    parts = [f"table {NFT_FAMILY} {settings.table} {{"]
    if indented_sets:
        parts.append(indented_sets)
    parts.append(chain_body)
    parts.append("}")
    return "\n".join(parts) + "\n"


def dry_run_rules(
    whitelist_entries: Iterable[Any],
    blacklist_entries: Iterable[Any],
    settings: IPSSettings,
) -> FirewallResult:
    """Return the rules that *would* be applied without touching the system."""
    script = build_ruleset(whitelist_entries, blacklist_entries, settings)
    rule_lines = tuple(line for line in script.splitlines())
    _LOGGER.info(
        "IPS dry-run ruleset rendered: table=%s chain=%s lines=%s",
        settings.table,
        settings.chain,
        len(rule_lines),
    )
    return FirewallResult(applied=False, dry_run=True, reason="dry_run", rules=rule_lines)


# --------------------------------------------------------------------------- #
# Applying / removing rules (only ever touches Gleipnir's own table)
# --------------------------------------------------------------------------- #
def apply_rules(
    script: str,
    settings: IPSSettings,
    *,
    runner: CommandRunner | None = None,
) -> FirewallResult:
    """Apply a Gleipnir nft script, but only when enforcement is truly active."""
    rule_lines = tuple(script.splitlines())
    if not settings.enabled:
        return FirewallResult(
            applied=False,
            dry_run=settings.dry_run,
            reason="ips_disabled",
            rules=rule_lines,
        )
    if settings.dry_run:
        return FirewallResult(
            applied=False,
            dry_run=True,
            reason="dry_run",
            rules=rule_lines,
        )
    if not is_nft_available(runner):
        _LOGGER.warning("IPS apply skipped: nft binary not available.")
        return FirewallResult(
            applied=False,
            dry_run=False,
            reason="nft_unavailable",
            rules=rule_lines,
        )

    run = runner or subprocess.run
    try:
        completed = run(
            ["nft", "-f", "-"],
            input=script,
            capture_output=True,
            text=True,
            timeout=DEFAULT_NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        _LOGGER.error("IPS apply failed to invoke nft: %s", exc)
        return FirewallResult(
            applied=False,
            dry_run=False,
            reason="nft_error",
            error=str(exc),
            rules=rule_lines,
        )

    if getattr(completed, "returncode", 1) != 0:
        stderr = (getattr(completed, "stderr", "") or "").strip()
        _LOGGER.error("IPS apply rejected by nft: %s", stderr or "unknown error")
        return FirewallResult(
            applied=False,
            dry_run=False,
            reason="nft_rejected",
            error=stderr or f"nft exited with code {completed.returncode}",
            rules=rule_lines,
        )

    _LOGGER.info(
        "IPS rules applied: table=%s chain=%s", settings.table, settings.chain
    )
    return FirewallResult(applied=True, dry_run=False, rules=rule_lines)


def remove_gleipnir_rules(
    settings: IPSSettings,
    *,
    runner: CommandRunner | None = None,
) -> FirewallResult:
    """Delete only Gleipnir's own table; never touches external rules."""
    command = ["nft", "delete", "table", NFT_FAMILY, settings.table]
    rule_lines = (" ".join(command),)

    if not is_nft_available(runner):
        return FirewallResult(
            applied=False,
            dry_run=settings.dry_run,
            reason="nft_unavailable",
            rules=rule_lines,
        )

    run = runner or subprocess.run
    try:
        completed = run(
            command,
            capture_output=True,
            text=True,
            timeout=DEFAULT_NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        _LOGGER.error("IPS remove failed to invoke nft: %s", exc)
        return FirewallResult(
            applied=False,
            dry_run=settings.dry_run,
            reason="nft_error",
            error=str(exc),
            rules=rule_lines,
        )

    returncode = getattr(completed, "returncode", 1)
    if returncode != 0:
        stderr = (getattr(completed, "stderr", "") or "").strip().lower()
        # A missing table is a benign no-op, not an error.
        if "no such file" in stderr or "does not exist" in stderr:
            return FirewallResult(
                applied=False,
                dry_run=settings.dry_run,
                reason="table_absent",
                rules=rule_lines,
            )
        return FirewallResult(
            applied=False,
            dry_run=settings.dry_run,
            reason="nft_rejected",
            error=stderr or f"nft exited with code {returncode}",
            rules=rule_lines,
        )

    _LOGGER.info("IPS table removed: %s %s", NFT_FAMILY, settings.table)
    return FirewallResult(applied=True, dry_run=settings.dry_run, rules=rule_lines)


def block_ip(
    ip: str,
    settings: IPSSettings,
    *,
    runner: CommandRunner | None = None,
) -> FirewallResult:
    """Add one IP to Gleipnir's own blacklist set (only when enforcement active).

    Requires that ``sync_firewall_rules`` has already created the table/sets.
    Never raises: backend problems are returned as a structured result.
    """
    if not settings.enabled:
        return FirewallResult(applied=False, dry_run=settings.dry_run, reason="ips_disabled")
    if settings.dry_run:
        return FirewallResult(applied=False, dry_run=True, reason="dry_run")

    try:
        parsed = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return FirewallResult(applied=False, dry_run=False, reason="invalid_ip", error=str(ip))

    set_name = SET_BLACKLIST_V4 if parsed.version == 4 else SET_BLACKLIST_V6
    element = "{ " + str(parsed) + " }"
    command = ["nft", "add", "element", NFT_FAMILY, settings.table, set_name, element]
    rule_lines = (" ".join(command),)

    if not is_nft_available(runner):
        return FirewallResult(applied=False, dry_run=False, reason="nft_unavailable", rules=rule_lines)

    run = runner or subprocess.run
    try:
        completed = run(
            command,
            capture_output=True,
            text=True,
            timeout=DEFAULT_NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        _LOGGER.error("IPS block_ip failed to invoke nft: %s", exc)
        return FirewallResult(applied=False, dry_run=False, reason="nft_error", error=str(exc), rules=rule_lines)

    if getattr(completed, "returncode", 1) != 0:
        stderr = (getattr(completed, "stderr", "") or "").strip()
        return FirewallResult(
            applied=False,
            dry_run=False,
            reason="nft_rejected",
            error=stderr or f"nft exited with code {completed.returncode}",
            rules=rule_lines,
        )

    return FirewallResult(applied=True, dry_run=False, rules=rule_lines)


def sync_firewall_rules(
    whitelist_entries: Iterable[Any],
    blacklist_entries: Iterable[Any],
    settings: IPSSettings,
    *,
    runner: CommandRunner | None = None,
) -> FirewallResult:
    """Build the ruleset and apply it (or report dry-run/disabled)."""
    script = build_ruleset(whitelist_entries, blacklist_entries, settings)
    if not settings.enabled:
        return FirewallResult(
            applied=False,
            dry_run=settings.dry_run,
            reason="ips_disabled",
            rules=tuple(script.splitlines()),
        )
    if settings.dry_run:
        return dry_run_rules(whitelist_entries, blacklist_entries, settings)

    return apply_rules(script, settings, runner=runner)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _entry_ips(entries: Iterable[Any]) -> list[str]:
    ips: list[str] = []
    for entry in entries:
        value = getattr(entry, "ip", entry)
        if value:
            ips.append(str(value))
    return ips


def _entry_macs(entries: Iterable[Any]) -> list[str]:
    macs: list[str] = []
    for entry in entries:
        mac = getattr(entry, "mac", None)
        if mac:
            macs.append(str(mac))
    return sorted(set(macs))


def _split_ip_versions(ips: Sequence[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for raw in ips:
        try:
            parsed = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            _LOGGER.warning("Skipping invalid IP for firewall rules: %s", raw)
            continue
        if parsed.version == 4:
            v4.append(str(parsed))
        else:
            v6.append(str(parsed))
    return sorted(set(v4)), sorted(set(v6))


def _render_set(name: str, set_type: str, elements: Sequence[str]) -> str:
    flags = "\n        flags interval" if set_type in ("ipv4_addr", "ipv6_addr") else ""
    joined = ", ".join(elements)
    return (
        f"set {name} {{\n"
        f"        type {set_type}{flags}\n"
        f"        elements = {{ {joined} }}\n"
        "    }"
    )


def _indent(block: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line else line for line in block.splitlines())
