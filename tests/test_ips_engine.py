
from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from src.config import Config
from src.ips_config import get_default_ips_config
from src.detector import UNAUTHORIZED_DEVICE
from src.firewall import (
    ACTION_ALERTED,
    ACTION_BLOCKED,
    ACTION_DRY_RUN_BLOCK,
    IPS_BLOCKED_BLACKLISTED_IP,
    IPS_BLOCKED_UNREGISTERED_DEVICE,
    FirewallResult,
)
from src.runtime.engine import IDSEngine
from src.sniffer import PacketEvent, parse_packet
from src.storage import SQLiteEventStore


DANGEROUS_IP = "8.8.8.8"


class IPSEngineTests(unittest.TestCase):
    def test_ids_mode_default_does_not_block(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root, blacklist=f"{DANGEROUS_IP},Botnet\n")
            firewall_block = Mock()
            engine = _engine(root, ips={}, firewall_block=firewall_block)

            result = engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:01", ip_destino=DANGEROUS_IP)
            )
            engine.shutdown()

            self.assertIsNotNone(result.blacklist_event)
            self.assertEqual(result.ips_events, ())
            firewall_block.assert_not_called()

    def test_ips_dry_run_blacklist_generates_dry_run_block(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root, blacklist=f"{DANGEROUS_IP},Botnet\n")
            firewall_block = Mock()
            engine = _engine(
                root,
                ips={"ips_enabled": True, "ips_dry_run": True, "ips_blacklist_policy": "block"},
                firewall_block=firewall_block,
            )

            result = engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:02", ip_destino=DANGEROUS_IP)
            )
            engine.shutdown()

            self.assertEqual(len(result.ips_events), 1)
            ips_event = result.ips_events[0]
            self.assertEqual(ips_event.event_type, IPS_BLOCKED_BLACKLISTED_IP)
            self.assertEqual(ips_event.accion, ACTION_DRY_RUN_BLOCK)
            self.assertEqual(ips_event.motivo, "Botnet")
            self.assertFalse(ips_event.applied)
            firewall_block.assert_not_called()

    def test_ips_apply_blacklist_calls_firewall_backend(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root, blacklist=f"{DANGEROUS_IP},Malware\n")
            firewall_block = Mock(return_value=FirewallResult(applied=True, dry_run=False))
            engine = _engine(
                root,
                ips={"ips_enabled": True, "ips_dry_run": False, "ips_blacklist_policy": "block"},
                firewall_block=firewall_block,
            )

            result = engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:03", ip_destino=DANGEROUS_IP)
            )
            engine.shutdown()

            firewall_block.assert_called_once()
            self.assertEqual(firewall_block.call_args.args[0], DANGEROUS_IP)
            ips_event = result.ips_events[0]
            self.assertEqual(ips_event.accion, ACTION_BLOCKED)
            self.assertTrue(ips_event.applied)
            self.assertEqual(result.blacklist_event.accion, ACTION_BLOCKED)

    def test_ips_disabled_never_calls_firewall(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root, blacklist=f"{DANGEROUS_IP},Botnet\n")
            firewall_block = Mock()
            engine = _engine(
                root,
                ips={"ips_enabled": False, "ips_dry_run": False, "ips_blacklist_policy": "block"},
                firewall_block=firewall_block,
            )

            engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:04", ip_destino=DANGEROUS_IP)
            )
            engine.shutdown()
            firewall_block.assert_not_called()

    def test_ips_block_unregistered_dry_run(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root)
            firewall_block = Mock()
            engine = _engine(
                root,
                ips={
                    "ips_enabled": True,
                    "ips_dry_run": True,
                    "ips_allowlist_policy": "block_unregistered",
                },
                firewall_block=firewall_block,
            )

            result = engine.process_packet_event(
                _packet("192.168.1.99", "aa:bb:cc:dd:ee:05", ip_destino="192.168.1.1")
            )
            engine.shutdown()

            self.assertEqual(result.detection_event.event_type, UNAUTHORIZED_DEVICE)
            self.assertEqual(len(result.ips_events), 1)
            self.assertEqual(result.ips_events[0].event_type, IPS_BLOCKED_UNREGISTERED_DEVICE)
            self.assertEqual(result.ips_events[0].accion, ACTION_DRY_RUN_BLOCK)
            firewall_block.assert_not_called()

    def test_ips_block_unregistered_without_mac_only_alerts_under_strict(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root)
            firewall_block = Mock()
            engine = _engine(
                root,
                ips={
                    "ips_enabled": True,
                    "ips_dry_run": False,
                    "ips_allowlist_policy": "block_unregistered",
                },
                firewall_block=firewall_block,
            )

            packet = PacketEvent(
                timestamp=1710000000.25,
                mac_origen=None,
                mac_destino=None,
                ip_origen="192.168.1.123",
                ip_destino="192.168.1.1",
                protocolo="tcp",
            )
            result = engine.process_packet_event(packet)
            engine.shutdown()

            self.assertEqual(len(result.ips_events), 1)
            self.assertEqual(result.ips_events[0].accion, ACTION_ALERTED)
            self.assertFalse(result.ips_events[0].applied)
            firewall_block.assert_not_called()

    def test_ips_events_are_persisted(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_lists(root, blacklist=f"{DANGEROUS_IP},Botnet\n")
            engine = _engine(
                root,
                ips={"ips_enabled": True, "ips_dry_run": True, "ips_blacklist_policy": "block"},
                firewall_block=Mock(),
            )
            engine.process_packet_event(
                _packet("192.168.1.20", "aa:bb:cc:dd:ee:06", ip_destino=DANGEROUS_IP)
            )
            engine.shutdown()

            store = SQLiteEventStore(root / "events.db")
            stored = store.fetch_events(IPS_BLOCKED_BLACKLISTED_IP)
            store.close()
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].raw["accion"], ACTION_DRY_RUN_BLOCK)


_IPS_KEY_MAP = {
    "ips_enabled": "ips_enabled",
    "ips_dry_run": "dry_run",
    "ips_blacklist_policy": "blacklist_policy",
    "ips_allowlist_policy": "allowlist_policy",
    "ips_block_direction": "block_direction",
    "blacklist_check_private": "blacklist_check_private",
    "auto_apply": "auto_apply",
}


def _engine(root: Path, *, ips: dict, firewall_block) -> IDSEngine:
    config = _config(root, ips)
    return IDSEngine.from_config(
        config=config,
        send_email=False,
        enable_threat_intel=False,
        console_stream=io.StringIO(),
        firewall_block=firewall_block,
    )


def _config(root: Path, ips: dict) -> Config:
    operational = get_default_ips_config()
    for key, value in ips.items():
        operational[_IPS_KEY_MAP[key]] = value
    config_path = root / "ips_config.json"
    config_path.write_text(json.dumps(operational), encoding="utf-8")
    return Config(
        smtp_host="smtp.example.org",
        smtp_port=587,
        smtp_user="alerts@example.org",
        smtp_password="test-password",
        admin_email="admin@example.org",
        whitelist_file=root / "whitelist.csv",
        blacklist_file=root / "blacklist.txt",
        log_dir=root / "logs",
        report_dir=root / "reports",
        ids_db_path=root / "events.db",
        ips_config_file=config_path,
    )


def _write_lists(root: Path, *, whitelist: str = "", blacklist: str = "") -> None:
    (root / "whitelist.csv").write_text("ip,mac,description\n" + whitelist, encoding="utf-8")
    (root / "blacklist.txt").write_text(blacklist, encoding="utf-8")


def _packet(ip_origen: str, mac_origen: str, *, ip_destino: str = "8.8.8.8") -> PacketEvent:
    return parse_packet(
        {
            "timestamp": 1710000000.25,
            "mac_origen": mac_origen,
            "mac_destino": "66:55:44:33:22:11",
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "protocolo": "tcp",
        }
    )


if __name__ == "__main__":
    unittest.main()
