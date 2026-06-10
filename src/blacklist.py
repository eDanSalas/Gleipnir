"""Blacklist loading and IP checks for dangerous external addresses."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_BLACKLIST_FILE = Path("data/blacklist.txt")
DEFAULT_RISK = "Unknown"
SUPPORTED_RISKS = ("Virus", "Malware", "Botnet", "Phishing", DEFAULT_RISK)
_RISK_PREFIX_PATTERN = re.compile(r"^(reason|risk|riesgo|motivo)\s*:\s*", re.IGNORECASE)

_BLACKLISTED_IPS: set[str] = set()
_BLACKLISTED_ENTRIES: dict[str, "BlacklistEntry"] = {}


class BlacklistError(ValueError):
    """Raised when the blacklist file has invalid content."""


@dataclass(frozen=True)
class BlacklistEntry:
    """Single blacklisted IP with a normalized risk label."""

    ip: str
    reason: str = DEFAULT_RISK


def load_blacklist(file_path: str | Path = DEFAULT_BLACKLIST_FILE) -> tuple[str, ...]:
    """Load blacklisted IPv4/IPv6 addresses from a TXT file."""
    entries = list_blacklist_entries(file_path)
    _replace_blacklisted_entries(entries)
    return tuple(entry.ip for entry in entries)


def list_blacklist_entries(file_path: str | Path = DEFAULT_BLACKLIST_FILE) -> tuple[BlacklistEntry, ...]:
    """List blacklisted IPs and optional reasons from the TXT file."""
    path = Path(file_path)
    entries: list[BlacklistEntry] = []
    pending_reason = ""

    with path.open("r", encoding="utf-8") as blacklist_file:
        for line_number, raw_line in enumerate(blacklist_file, start=1):
            line = raw_line.strip()
            if not line:
                pending_reason = ""
                continue

            if line.startswith("#"):
                pending_reason = _comment_to_reason(line)
                continue

            entries.append(_entry_from_line(line, line_number, pending_reason))
            pending_reason = ""

    return tuple(entries)


def add_blacklist_entry(
    file_path: str | Path,
    *,
    ip: str,
    reason: str,
) -> BlacklistEntry:
    """Add an IP address to the blacklist TXT file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized_ip = validate_ip(ip)
    existing_ips = set(load_blacklist(path)) if path.exists() else set()

    if normalized_ip in existing_ips:
        raise BlacklistError(f"Blacklist already contains IP address: {normalized_ip}")

    entry = BlacklistEntry(ip=normalized_ip, reason=normalize_risk(reason))
    with path.open("a", encoding="utf-8") as blacklist_file:
        if path.stat().st_size > 0:
            blacklist_file.write("\n")
        blacklist_file.write(f"{entry.ip},{entry.reason}\n")

    _replace_blacklisted_entries((*list_blacklist_entries(path),))
    return entry


def remove_blacklist_entry(file_path: str | Path, *, ip: str) -> BlacklistEntry:
    """Remove an IP address from the blacklist TXT file."""
    path = Path(file_path)
    normalized_ip = validate_ip(ip)
    entries = list_blacklist_entries(path)
    removed = next((entry for entry in entries if entry.ip == normalized_ip), None)
    if removed is None:
        raise BlacklistError(f"Blacklist does not contain IP address: {normalized_ip}")

    remaining = [entry for entry in entries if entry.ip != normalized_ip]
    _write_blacklist_entries(path, remaining)
    _replace_blacklisted_entries(remaining)
    return removed


def validate_blacklist_file(file_path: str | Path) -> tuple[BlacklistEntry, ...]:
    """Validate a blacklist file and reject duplicate IP addresses."""
    entries = list_blacklist_entries(file_path)
    seen_ips: set[str] = set()

    for entry in entries:
        if entry.ip in seen_ips:
            raise BlacklistError(f"Duplicate blacklist IP address: {entry.ip}")
        seen_ips.add(entry.ip)

    _replace_blacklisted_entries(entries)
    return entries


def is_blacklisted(ip: str) -> bool:
    """Return whether an IPv4/IPv6 address exists in the loaded blacklist."""
    normalized_ip = validate_ip(ip)

    return normalized_ip in _BLACKLISTED_IPS


def get_blacklist_entry(ip: str) -> BlacklistEntry | None:
    """Return blacklist metadata for an IP already loaded in memory."""
    normalized_ip = validate_ip(ip)
    return _BLACKLISTED_ENTRIES.get(normalized_ip)


def validate_ip(value: str) -> str:
    """Validate IPv4 or IPv6 input and return a canonical string."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise BlacklistError(f"Invalid IP address: {value}") from exc


def normalize_risk(value: str | None) -> str:
    """Return one supported risk label from free-text blacklist metadata."""
    if value is None:
        return DEFAULT_RISK

    cleaned = _RISK_PREFIX_PATTERN.sub("", value.strip())
    if not cleaned:
        return DEFAULT_RISK

    lowered = cleaned.lower()
    for risk in SUPPORTED_RISKS:
        if lowered == risk.lower():
            return risk

    for risk in SUPPORTED_RISKS:
        if risk == DEFAULT_RISK:
            continue
        if re.search(rf"\b{re.escape(risk.lower())}\b", lowered):
            return risk

    return DEFAULT_RISK


def _entry_from_line(
    line: str,
    line_number: int,
    pending_reason: str,
) -> BlacklistEntry:
    if "," in line:
        raw_ip, raw_reason = line.split(",", maxsplit=1)
        return BlacklistEntry(
            ip=_validate_blacklist_ip(raw_ip.strip(), line_number),
            reason=normalize_risk(raw_reason),
        )

    return BlacklistEntry(
        ip=_validate_blacklist_ip(line, line_number),
        reason=normalize_risk(pending_reason),
    )


def _validate_blacklist_ip(value: str, line_number: int) -> str:
    try:
        return validate_ip(value)
    except BlacklistError as exc:
        raise BlacklistError(f"Blacklist line {line_number}: {exc}") from exc


def _replace_blacklisted_ips(entries: Iterable[str]) -> None:
    _replace_blacklisted_entries(BlacklistEntry(ip=entry) for entry in entries)


def _replace_blacklisted_entries(entries: Iterable[BlacklistEntry]) -> None:
    global _BLACKLISTED_IPS
    global _BLACKLISTED_ENTRIES

    entry_map = {entry.ip: entry for entry in entries}
    _BLACKLISTED_ENTRIES = entry_map
    _BLACKLISTED_IPS = set(entry_map)


def _comment_to_reason(line: str) -> str:
    comment = line.lstrip("#").strip()
    return normalize_risk(comment)


def _write_blacklist_entries(path: Path, entries: Iterable[BlacklistEntry]) -> None:
    with path.open("w", encoding="utf-8") as blacklist_file:
        for entry in entries:
            blacklist_file.write(f"{entry.ip},{normalize_risk(entry.reason)}\n")
