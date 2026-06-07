"""Unit tests for whitelist loading and authorization checks."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.whitelist import (
    WhitelistError,
    add_whitelist_entry,
    is_authorized,
    load_whitelist,
    remove_whitelist_entry,
    validate_mac,
    validate_whitelist_file,
)


class WhitelistTests(unittest.TestCase):
    def test_load_whitelist_accepts_ipv4_ipv6_and_normalizes_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "192.168.1.10,AA-BB-CC-DD-EE-FF,Equipo laboratorio\n"
                "2001:db8::1,00:11:22:33:44:55,Servidor IPv6\n",
                encoding="utf-8",
            )

            entries = load_whitelist(whitelist_file)

            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].mac, "aa:bb:cc:dd:ee:ff")
            self.assertTrue(is_authorized("192.168.1.10", "aa:bb:cc:dd:ee:ff"))
            self.assertTrue(is_authorized("2001:db8:0:0:0:0:0:1", "00-11-22-33-44-55"))

    def test_is_authorized_rejects_unknown_pair(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            self.assertFalse(is_authorized("10.0.0.5", "00:11:22:33:44:56"))

    def test_load_whitelist_rejects_invalid_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "999.1.1.1,00:11:22:33:44:55,IP invalida\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(WhitelistError, "line 2"):
                load_whitelist(whitelist_file)

    def test_load_whitelist_rejects_invalid_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44,MAC invalida\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(WhitelistError, "MAC"):
                load_whitelist(whitelist_file)

    def test_load_whitelist_requires_expected_columns(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,description\n10.0.0.5,Sin MAC\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(WhitelistError, "mac"):
                load_whitelist(whitelist_file)

    def test_validate_mac_rejects_non_hexadecimal_values(self) -> None:
        with self.assertRaises(WhitelistError):
            validate_mac("00:11:22:33:44:GG")

    def test_add_whitelist_entry_creates_file_and_normalizes_values(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"

            entry = add_whitelist_entry(
                whitelist_file,
                ip="192.168.1.20",
                mac="AA-BB-CC-DD-EE-FF",
                description="Equipo administrado",
            )

            self.assertEqual(entry.ip, "192.168.1.20")
            self.assertEqual(entry.mac, "aa:bb:cc:dd:ee:ff")
            self.assertTrue(is_authorized("192.168.1.20", "aa:bb:cc:dd:ee:ff"))
            self.assertIn("ip,mac,description", whitelist_file.read_text(encoding="utf-8"))

    def test_add_whitelist_entry_rejects_duplicate_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            add_whitelist_entry(
                whitelist_file,
                ip="192.168.1.20",
                mac="00:11:22:33:44:55",
                description="Equipo",
            )

            with self.assertRaisesRegex(WhitelistError, "already contains"):
                add_whitelist_entry(
                    whitelist_file,
                    ip="192.168.1.20",
                    mac="00:11:22:33:44:56",
                    description="Duplicado",
                )

    def test_remove_whitelist_entry_deletes_matching_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            add_whitelist_entry(
                whitelist_file,
                ip="10.0.0.5",
                mac="00:11:22:33:44:55",
                description="Temporal",
            )

            removed = remove_whitelist_entry(whitelist_file, ip="10.0.0.5")

            self.assertEqual(removed.ip, "10.0.0.5")
            self.assertEqual(load_whitelist(whitelist_file), ())

    def test_validate_whitelist_file_rejects_duplicate_ips(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Uno\n"
                "10.0.0.5,00:11:22:33:44:56,Dos\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(WhitelistError, "Duplicate"):
                validate_whitelist_file(whitelist_file)


if __name__ == "__main__":
    unittest.main()
