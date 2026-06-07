"""Whitelist loading and authorization checks for IP/MAC pairs."""

from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_WHITELIST_FILE = Path("data/whitelist.csv")
REQUIRED_COLUMNS = ("ip", "mac", "description")
MAC_PATTERN = re.compile(
    r"^(?P<a>[0-9a-fA-F]{2})[:-](?P<b>[0-9a-fA-F]{2})[:-]"
    r"(?P<c>[0-9a-fA-F]{2})[:-](?P<d>[0-9a-fA-F]{2})[:-]"
    r"(?P<e>[0-9a-fA-F]{2})[:-](?P<f>[0-9a-fA-F]{2})$"
)

_AUTHORIZED_PAIRS: set[tuple[str, str]] = set()


class WhitelistError(ValueError):
    """Raised when the whitelist file has invalid content."""


@dataclass(frozen=True)
class WhitelistEntry:
    """Single authorized IP/MAC identity."""

    ip: str
    mac: str
    description: str


def load_whitelist(file_path: str | Path = DEFAULT_WHITELIST_FILE) -> tuple[WhitelistEntry, ...]:
    """Load authorized IP/MAC pairs from a CSV whitelist file."""
    path = Path(file_path)
    entries: list[WhitelistEntry] = []

    with path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        _validate_columns(reader.fieldnames)

        for line_number, row in enumerate(reader, start=2):
            entries.append(_entry_from_row(row, line_number))

    _replace_authorized_pairs(entries)
    return tuple(entries)


def add_whitelist_entry(
    file_path: str | Path,
    *,
    ip: str,
    mac: str,
    description: str,
) -> WhitelistEntry:
    """Add an authorized IP/MAC pair to the whitelist CSV file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = list(_read_whitelist_if_exists(path))
    new_entry = WhitelistEntry(
        ip=validate_ip(ip),
        mac=validate_mac(mac),
        description=description.strip(),
    )

    if any(entry.ip == new_entry.ip for entry in entries):
        raise WhitelistError(f"Whitelist already contains IP address: {new_entry.ip}")

    entries.append(new_entry)
    _write_whitelist(path, entries)
    _replace_authorized_pairs(entries)
    return new_entry


def remove_whitelist_entry(file_path: str | Path, *, ip: str) -> WhitelistEntry:
    """Remove an authorized IP/MAC pair by IP address."""
    path = Path(file_path)
    normalized_ip = validate_ip(ip)
    entries = list(load_whitelist(path))
    remaining: list[WhitelistEntry] = []
    removed: WhitelistEntry | None = None

    for entry in entries:
        if entry.ip == normalized_ip:
            removed = entry
        else:
            remaining.append(entry)

    if removed is None:
        raise WhitelistError(f"Whitelist does not contain IP address: {normalized_ip}")

    _write_whitelist(path, remaining)
    _replace_authorized_pairs(remaining)
    return removed


def validate_whitelist_file(file_path: str | Path) -> tuple[WhitelistEntry, ...]:
    """Validate a whitelist file and reject duplicate IP addresses."""
    entries = load_whitelist(file_path)
    seen_ips: set[str] = set()

    for entry in entries:
        if entry.ip in seen_ips:
            raise WhitelistError(f"Duplicate whitelist IP address: {entry.ip}")
        seen_ips.add(entry.ip)

    return entries


def is_authorized(ip: str, mac: str) -> bool:
    """Return whether the IP/MAC pair exists in the loaded whitelist."""
    normalized_ip = validate_ip(ip)
    normalized_mac = validate_mac(mac)

    return (normalized_ip, normalized_mac) in _AUTHORIZED_PAIRS


def validate_ip(value: str) -> str:
    """Validate IPv4 or IPv6 input and return a canonical string."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise WhitelistError(f"Invalid IP address: {value}") from exc


def validate_mac(value: str) -> str:
    """Validate a MAC address and return lowercase colon-separated form."""
    match = MAC_PATTERN.match(value.strip())
    if not match:
        raise WhitelistError(f"Invalid MAC address: {value}")

    return ":".join(part.lower() for part in match.groups())


def _validate_columns(fieldnames: Iterable[str] | None) -> None:
    if fieldnames is None:
        raise WhitelistError("Whitelist CSV must include a header row")

    missing = [name for name in REQUIRED_COLUMNS if name not in fieldnames]
    if missing:
        names = ", ".join(missing)
        raise WhitelistError(f"Whitelist CSV is missing required columns: {names}")


def _entry_from_row(row: dict[str, str | None], line_number: int) -> WhitelistEntry:
    raw_ip = _required_cell(row, "ip", line_number)
    raw_mac = _required_cell(row, "mac", line_number)
    description = (row.get("description") or "").strip()

    try:
        ip = validate_ip(raw_ip)
        mac = validate_mac(raw_mac)
    except WhitelistError as exc:
        raise WhitelistError(f"Whitelist line {line_number}: {exc}") from exc

    return WhitelistEntry(ip=ip, mac=mac, description=description)


def _required_cell(row: dict[str, str | None], field_name: str, line_number: int) -> str:
    value = row.get(field_name)
    if value is None or not value.strip():
        raise WhitelistError(
            f"Whitelist line {line_number}: missing required field '{field_name}'"
        )

    return value.strip()


def _replace_authorized_pairs(entries: Iterable[WhitelistEntry]) -> None:
    global _AUTHORIZED_PAIRS

    _AUTHORIZED_PAIRS = {(entry.ip, entry.mac) for entry in entries}


def _read_whitelist_if_exists(path: Path) -> tuple[WhitelistEntry, ...]:
    if not path.exists():
        return ()

    return load_whitelist(path)


def _write_whitelist(path: Path, entries: Iterable[WhitelistEntry]) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=REQUIRED_COLUMNS)
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "ip": entry.ip,
                    "mac": entry.mac,
                    "description": entry.description,
                }
            )
