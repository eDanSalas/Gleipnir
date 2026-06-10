
from __future__ import annotations

from types import SimpleNamespace

from src import firewall
from src.firewall import (
    ALLOWLIST_ALLOW_REGISTERED,
    ALLOWLIST_BLOCK_UNREGISTERED,
    ALLOWLIST_MONITOR,
    BLACKLIST_BLOCK,
    BLACKLIST_MONITOR,
    DIRECTION_BOTH,
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    IPSSettings,
)


def _ok_runner(returncode: int = 0, stderr: str = "", stdout: str = ""):
    def run(args, **kwargs):
        run.calls.append((list(args), kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    run.calls = []
    return run


def _entry(ip: str, mac: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(ip=ip, mac=mac)


def test_is_nft_available_true_when_runner_succeeds() -> None:
    assert firewall.is_nft_available(_ok_runner(0)) is True


def test_is_nft_available_false_when_missing() -> None:
    def run(args, **kwargs):
        raise FileNotFoundError("nft")

    assert firewall.is_nft_available(run) is False


def test_is_nft_available_false_on_nonzero() -> None:
    assert firewall.is_nft_available(_ok_runner(1)) is False


def test_build_blacklist_rules_both_directions() -> None:
    settings = IPSSettings(blacklist_policy=BLACKLIST_BLOCK, block_direction=DIRECTION_BOTH)
    rules = firewall.build_blacklist_rules(["203.0.113.50"], settings)

    assert "ip daddr @gleipnir_blacklist_v4 drop" in rules
    assert "ip saddr @gleipnir_blacklist_v4 drop" in rules


def test_build_blacklist_rules_outbound_only() -> None:
    settings = IPSSettings(blacklist_policy=BLACKLIST_BLOCK, block_direction=DIRECTION_OUTBOUND)
    rules = firewall.build_blacklist_rules(["203.0.113.50"], settings)

    assert rules == ["ip daddr @gleipnir_blacklist_v4 drop"]


def test_build_blacklist_rules_inbound_only_ipv6() -> None:
    settings = IPSSettings(blacklist_policy=BLACKLIST_BLOCK, block_direction=DIRECTION_INBOUND)
    rules = firewall.build_blacklist_rules(["2001:db8::1"], settings)

    assert rules == ["ip6 saddr @gleipnir_blacklist_v6 drop"]


def test_build_blacklist_rules_monitor_is_empty() -> None:
    settings = IPSSettings(blacklist_policy=BLACKLIST_MONITOR)
    assert firewall.build_blacklist_rules(["203.0.113.50"], settings) == []


def test_build_allowlist_rules_allow_registered() -> None:
    settings = IPSSettings(allowlist_policy=ALLOWLIST_ALLOW_REGISTERED)
    rules = firewall.build_allowlist_rules(
        [_entry("192.168.1.10", "aa:bb:cc:dd:ee:ff")], settings
    )

    assert "ip saddr @gleipnir_allow_v4 accept" in rules
    assert "ether saddr @gleipnir_allow_mac accept" in rules
    assert all("drop" not in rule for rule in rules)


def test_build_allowlist_rules_block_unregistered_adds_drop() -> None:
    settings = IPSSettings(allowlist_policy=ALLOWLIST_BLOCK_UNREGISTERED)
    rules = firewall.build_allowlist_rules([_entry("192.168.1.10")], settings)

    assert "ip saddr @gleipnir_allow_v4 accept" in rules
    assert "ip saddr != @gleipnir_allow_v4 drop" in rules


def test_build_allowlist_rules_block_unregistered_without_ips_has_no_blanket_drop() -> None:
    settings = IPSSettings(allowlist_policy=ALLOWLIST_BLOCK_UNREGISTERED)
    rules = firewall.build_allowlist_rules([], settings)

    assert all("drop" not in rule for rule in rules)


def test_build_allowlist_rules_monitor_is_empty() -> None:
    settings = IPSSettings(allowlist_policy=ALLOWLIST_MONITOR)
    assert firewall.build_allowlist_rules([_entry("192.168.1.10")], settings) == []


def test_build_ruleset_creates_own_table_and_chain() -> None:
    settings = IPSSettings(
        blacklist_policy=BLACKLIST_BLOCK,
        allowlist_policy=ALLOWLIST_ALLOW_REGISTERED,
    )
    script = firewall.build_ruleset(
        [_entry("192.168.1.10", "aa:bb:cc:dd:ee:ff")],
        ["203.0.113.50"],
        settings,
    )

    assert "table inet gleipnir {" in script
    assert "chain gleipnir_filter {" in script
    assert "hook forward" in script
    assert "203.0.113.50" in script
    assert "192.168.1.10" in script
    assert "flush ruleset" not in script


def test_apply_rules_disabled_does_not_run() -> None:
    settings = IPSSettings(enabled=False, dry_run=True)
    runner = _ok_runner()
    result = firewall.apply_rules("table inet gleipnir {}", settings, runner=runner)

    assert result.applied is False
    assert result.reason == "ips_disabled"
    assert runner.calls == []


def test_apply_rules_dry_run_does_not_run() -> None:
    settings = IPSSettings(enabled=True, dry_run=True)
    runner = _ok_runner()
    result = firewall.apply_rules("table inet gleipnir {}", settings, runner=runner)

    assert result.applied is False
    assert result.reason == "dry_run"
    assert runner.calls == []


def test_apply_rules_active_calls_backend() -> None:
    settings = IPSSettings(enabled=True, dry_run=False)
    runner = _ok_runner(0)
    result = firewall.apply_rules("table inet gleipnir {}", settings, runner=runner)

    assert result.applied is True
    apply_call = runner.calls[-1]
    assert apply_call[0] == ["nft", "-f", "-"]
    assert apply_call[1].get("input") == "table inet gleipnir {}"


def test_apply_rules_nft_unavailable_is_handled() -> None:
    settings = IPSSettings(enabled=True, dry_run=False)

    def run(args, **kwargs):
        raise FileNotFoundError("nft")

    result = firewall.apply_rules("table inet gleipnir {}", settings, runner=run)
    assert result.applied is False
    assert result.reason == "nft_unavailable"


def test_apply_rules_error_does_not_raise() -> None:
    settings = IPSSettings(enabled=True, dry_run=False)

    calls = {"n": 0}

    def run(args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise RuntimeError("boom")

    result = firewall.apply_rules("table inet gleipnir {}", settings, runner=run)
    assert result.applied is False
    assert result.reason == "nft_error"


def test_remove_gleipnir_rules_only_targets_own_table() -> None:
    settings = IPSSettings(enabled=True, dry_run=False, table="gleipnir")
    runner = _ok_runner(0)
    result = firewall.remove_gleipnir_rules(settings, runner=runner)

    assert result.applied is True
    delete_call = runner.calls[-1][0]
    assert delete_call == ["nft", "delete", "table", "inet", "gleipnir"]
    assert "flush" not in delete_call


def test_remove_gleipnir_rules_absent_table_is_benign() -> None:
    settings = IPSSettings(enabled=True, dry_run=False)

    def run(args, **kwargs):
        if "--version" in args:
            return SimpleNamespace(returncode=0, stdout="nftables", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="No such file or directory")

    result = firewall.remove_gleipnir_rules(settings, runner=run)

    assert result.applied is False
    assert result.reason == "table_absent"


def test_block_ip_dry_run_does_not_run() -> None:
    settings = IPSSettings(enabled=True, dry_run=True)
    runner = _ok_runner()
    result = firewall.block_ip("203.0.113.50", settings, runner=runner)

    assert result.applied is False
    assert result.reason == "dry_run"
    assert runner.calls == []


def test_block_ip_active_adds_element() -> None:
    settings = IPSSettings(enabled=True, dry_run=False, table="gleipnir")
    runner = _ok_runner(0)
    result = firewall.block_ip("203.0.113.50", settings, runner=runner)

    assert result.applied is True
    add_call = runner.calls[-1][0]
    assert add_call[:5] == ["nft", "add", "element", "inet", "gleipnir"]
    assert "gleipnir_blacklist_v4" in add_call


def test_sync_firewall_rules_dry_run_returns_rules_without_applying() -> None:
    settings = IPSSettings(enabled=True, dry_run=True, blacklist_policy=BLACKLIST_BLOCK)
    runner = _ok_runner()
    result = firewall.sync_firewall_rules(["192.168.1.10"], ["203.0.113.50"], settings, runner=runner)

    assert result.applied is False
    assert result.dry_run is True
    assert runner.calls == []
    assert any("table inet gleipnir" in line for line in result.rules)
