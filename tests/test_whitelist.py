
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.whitelist import (
    AUTHORIZED_BY_IP_FALLBACK,
    AUTHORIZED_BY_IP_MAC,
    AUTH_POLICY_IP_FALLBACK,
    AUTH_POLICY_STRICT,
    REASON_IP_MAC_PAIR_MISMATCH,
    REASON_IP_NOT_IN_WHITELIST,
    REASON_MAC_MISSING_STRICT_POLICY,
    REASON_MAC_NOT_IN_WHITELIST,
    WhitelistError,
    add_whitelist_entry,
    check_authorization,
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

    def test_strict_policy_authorizes_matching_ip_mac_pair(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.5",
                "00:11:22:33:44:55",
                policy=AUTH_POLICY_STRICT,
            )

            self.assertTrue(result.authorized)
            self.assertEqual(result.authorized_by, AUTHORIZED_BY_IP_MAC)

    def test_strict_policy_rejects_authorized_ip_with_different_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.5",
                "00:11:22:33:44:56",
                policy=AUTH_POLICY_STRICT,
            )

            self.assertFalse(result.authorized)
            self.assertEqual(result.reason, REASON_MAC_NOT_IN_WHITELIST)
            self.assertFalse(is_authorized("10.0.0.5", "00:11:22:33:44:56"))

    def test_strict_policy_rejects_authorized_mac_with_different_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.6",
                "00:11:22:33:44:55",
                policy=AUTH_POLICY_STRICT,
            )

            self.assertFalse(result.authorized)
            self.assertEqual(result.reason, REASON_IP_NOT_IN_WHITELIST)

    def test_strict_policy_rejects_known_ip_and_known_mac_when_pair_mismatches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo A\n"
                "10.0.0.6,00:11:22:33:44:66,Equipo B\n",
                encoding="utf-8",
            )

            validate_whitelist_file(whitelist_file)

            result = check_authorization(
                "10.0.0.5",
                "00:11:22:33:44:66",
                policy=AUTH_POLICY_STRICT,
            )

            self.assertFalse(result.authorized)
            self.assertEqual(result.reason, REASON_IP_MAC_PAIR_MISMATCH)

    def test_strict_policy_rejects_missing_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.5",
                None,
                policy=AUTH_POLICY_STRICT,
            )

            self.assertFalse(result.authorized)
            self.assertEqual(result.reason, REASON_MAC_MISSING_STRICT_POLICY)

    def test_ip_fallback_policy_authorizes_known_ip_when_mac_is_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.5",
                None,
                policy=AUTH_POLICY_IP_FALLBACK,
            )

            self.assertTrue(result.authorized)
            self.assertEqual(result.authorized_by, AUTHORIZED_BY_IP_FALLBACK)
            self.assertTrue(
                is_authorized("10.0.0.5", None, policy=AUTH_POLICY_IP_FALLBACK)
            )

    def test_ip_fallback_policy_rejects_unknown_ip_when_mac_is_missing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Equipo autorizado\n",
                encoding="utf-8",
            )

            load_whitelist(whitelist_file)

            result = check_authorization(
                "10.0.0.6",
                None,
                policy=AUTH_POLICY_IP_FALLBACK,
            )

            self.assertFalse(result.authorized)
            self.assertEqual(result.reason, REASON_IP_NOT_IN_WHITELIST)

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

    def test_add_whitelist_entry_rejects_duplicate_mac(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            add_whitelist_entry(
                whitelist_file,
                ip="192.168.1.20",
                mac="00:11:22:33:44:55",
                description="Equipo",
            )

            with self.assertRaisesRegex(WhitelistError, "MAC address"):
                add_whitelist_entry(
                    whitelist_file,
                    ip="192.168.1.21",
                    mac="00:11:22:33:44:55",
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

    def test_validate_whitelist_file_rejects_duplicate_mac_on_different_ip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            whitelist_file = Path(temp_dir) / "whitelist.csv"
            whitelist_file.write_text(
                "ip,mac,description\n"
                "10.0.0.5,00:11:22:33:44:55,Uno\n"
                "10.0.0.6,00:11:22:33:44:55,Dos\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(WhitelistError, "Duplicate whitelist MAC"):
                validate_whitelist_file(whitelist_file)


if __name__ == "__main__":
    unittest.main()
