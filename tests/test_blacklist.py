"""Unit tests for blacklist loading and IP checks."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.blacklist import (
    BlacklistError,
    DEFAULT_RISK,
    add_blacklist_entry,
    get_blacklist_entry,
    is_blacklisted,
    list_blacklist_entries,
    load_blacklist,
    normalize_risk,
    remove_blacklist_entry,
    validate_blacklist_file,
)


class BlacklistTests(unittest.TestCase):
    def test_load_blacklist_accepts_ipv4_and_ipv6(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text(
                "# IPs externas peligrosas\n"
                "8.8.8.8\n"
                "2001:4860:4860::8888\n",
                encoding="utf-8",
            )

            entries = load_blacklist(blacklist_file)
            loaded_entries = list_blacklist_entries(blacklist_file)

            self.assertEqual(entries, ("8.8.8.8", "2001:4860:4860::8888"))
            self.assertEqual(loaded_entries[0].reason, DEFAULT_RISK)
            self.assertEqual(loaded_entries[1].reason, DEFAULT_RISK)
            self.assertTrue(is_blacklisted("8.8.8.8"))
            self.assertTrue(is_blacklisted("2001:4860:4860:0:0:0:0:8888"))

    def test_is_blacklisted_rejects_unknown_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text("203.0.113.10\n", encoding="utf-8")

            load_blacklist(blacklist_file)

            self.assertFalse(is_blacklisted("203.0.113.11"))

    def test_load_blacklist_rejects_invalid_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text("not-an-ip\n", encoding="utf-8")

            with self.assertRaisesRegex(BlacklistError, "line 1"):
                load_blacklist(blacklist_file)

    def test_load_blacklist_rejects_cidr_ranges(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text("203.0.113.0/24\n", encoding="utf-8")

            with self.assertRaisesRegex(BlacklistError, "Invalid IP"):
                load_blacklist(blacklist_file)

    def test_list_blacklist_entries_reads_reason_comments(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text(
                "# reason: Malware test\n"
                "8.8.8.8\n",
                encoding="utf-8",
            )

            entries = list_blacklist_entries(blacklist_file)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].ip, "8.8.8.8")
            self.assertEqual(entries[0].reason, "Malware")
            load_blacklist(blacklist_file)
            self.assertEqual(get_blacklist_entry("8.8.8.8").reason, "Malware")

    def test_list_blacklist_entries_reads_risk_comments(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text(
                "# Riesgo: Botnet\n"
                "8.8.8.8\n"
                "# Riesgo: Virus\n"
                "1.1.1.1\n",
                encoding="utf-8",
            )

            entries = list_blacklist_entries(blacklist_file)
            load_blacklist(blacklist_file)

            self.assertEqual(entries[0].reason, "Botnet")
            self.assertEqual(entries[1].reason, "Virus")
            self.assertEqual(get_blacklist_entry("8.8.8.8").reason, "Botnet")
            self.assertEqual(get_blacklist_entry("1.1.1.1").reason, "Virus")

    def test_list_blacklist_entries_reads_comma_risk_format(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text(
                "8.8.8.8,Botnet\n"
                "1.1.1.1,Malware\n"
                "9.9.9.9,Virus\n"
                "208.67.222.222,Phishing\n",
                encoding="utf-8",
            )

            entries = list_blacklist_entries(blacklist_file)

            self.assertEqual([entry.reason for entry in entries], [
                "Botnet",
                "Malware",
                "Virus",
                "Phishing",
            ])

    def test_simple_blacklist_line_defaults_to_unknown_risk(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text("8.8.8.8\n", encoding="utf-8")

            entries = list_blacklist_entries(blacklist_file)
            load_blacklist(blacklist_file)

            self.assertEqual(entries[0].reason, "Unknown")
            self.assertEqual(get_blacklist_entry("8.8.8.8").reason, "Unknown")

    def test_add_blacklist_entry_creates_file_with_reason(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"

            entry = add_blacklist_entry(
                blacklist_file,
                ip="8.8.8.8",
                reason="Botnet C2",
            )

            self.assertEqual(entry.ip, "8.8.8.8")
            self.assertEqual(entry.reason, "Botnet")
            self.assertEqual(load_blacklist(blacklist_file), ("8.8.8.8",))
            self.assertIn("8.8.8.8,Botnet", blacklist_file.read_text(encoding="utf-8"))
            self.assertTrue(is_blacklisted("8.8.8.8"))

    def test_add_blacklist_entry_rejects_duplicate_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            add_blacklist_entry(blacklist_file, ip="1.1.1.1", reason="Uno")

            with self.assertRaisesRegex(BlacklistError, "already contains"):
                add_blacklist_entry(blacklist_file, ip="1.1.1.1", reason="Dos")

    def test_remove_blacklist_entry_deletes_matching_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            add_blacklist_entry(blacklist_file, ip="9.9.9.9", reason="Temporal")

            removed = remove_blacklist_entry(blacklist_file, ip="9.9.9.9")

            self.assertEqual(removed.ip, "9.9.9.9")
            self.assertEqual(load_blacklist(blacklist_file), ())

    def test_validate_blacklist_file_rejects_duplicate_ips(self) -> None:
        with TemporaryDirectory() as temp_dir:
            blacklist_file = Path(temp_dir) / "blacklist.txt"
            blacklist_file.write_text("8.8.8.8\n8.8.8.8\n", encoding="utf-8")

            with self.assertRaisesRegex(BlacklistError, "Duplicate"):
                validate_blacklist_file(blacklist_file)

    def test_normalize_risk_accepts_supported_risk_words(self) -> None:
        self.assertEqual(normalize_risk("Riesgo: Botnet"), "Botnet")
        self.assertEqual(normalize_risk("Malware C2"), "Malware")
        self.assertEqual(normalize_risk("virus"), "Virus")
        self.assertEqual(normalize_risk("phishing campaign"), "Phishing")
        self.assertEqual(normalize_risk("custom note"), "Unknown")


if __name__ == "__main__":
    unittest.main()
