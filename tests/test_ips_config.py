
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import ips_config
from src.ips_config import (
    IpsConfigError,
    build_ips_settings,
    get_default_ips_config,
    is_ips_effectively_active,
    load_ips_config,
    save_ips_config,
    update_ips_config,
    validate_ips_config,
)


def test_load_creates_file_with_safe_defaults_when_missing(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    config = load_ips_config(path)

    assert path.exists()
    assert config == get_default_ips_config()
    assert config["ips_enabled"] is False
    assert config["dry_run"] is True
    assert config["auto_apply"] is False


def test_validate_fills_defaults_for_partial_config() -> None:
    result = validate_ips_config({"ips_enabled": True})
    assert result["ips_enabled"] is True
    assert result["dry_run"] is True


def test_validate_rejects_unknown_keys() -> None:
    with pytest.raises(IpsConfigError, match="Unknown IPS config keys"):
        validate_ips_config({"bogus_key": True})


def test_validate_rejects_invalid_value() -> None:
    with pytest.raises(IpsConfigError, match="Invalid value for allowlist_policy"):
        validate_ips_config({"allowlist_policy": "nuke"})


def test_load_rejects_corrupt_json(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    path.write_text("{ this is not valid json", encoding="utf-8")

    with pytest.raises(IpsConfigError, match="not valid JSON"):
        load_ips_config(path)


def test_update_applies_changes_and_persists(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    load_ips_config(path)

    updated = update_ips_config({"ips_enabled": "true", "allowlist_policy": "block_unregistered"}, path)

    assert updated["ips_enabled"] is True
    assert updated["allowlist_policy"] == "block_unregistered"
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["ips_enabled"] is True


def test_update_rejects_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    load_ips_config(path)
    with pytest.raises(IpsConfigError):
        update_ips_config({"unknown": "x"}, path)


def test_save_validates_before_writing(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    with pytest.raises(IpsConfigError):
        save_ips_config({"blacklist_policy": "explode"}, path)
    assert not path.exists()


def test_is_ips_effectively_active() -> None:
    assert is_ips_effectively_active({"ips_enabled": True, "dry_run": False}) is True
    assert is_ips_effectively_active({"ips_enabled": True, "dry_run": True}) is False
    assert is_ips_effectively_active({"ips_enabled": False, "dry_run": False}) is False


def test_build_ips_settings_merges_base_and_operational(tmp_path: Path) -> None:
    path = tmp_path / "ips_config.json"
    save_ips_config(
        {"ips_enabled": True, "dry_run": False, "blacklist_check_private": True, "auto_apply": True},
        path,
    )
    config = SimpleNamespace(
        ips_backend="nftables",
        ips_table="gleipnir",
        ips_chain="gleipnir_filter",
        ips_config_file=path,
    )

    settings = build_ips_settings(config)

    assert settings.enabled is True
    assert settings.dry_run is False
    assert settings.table == "gleipnir"
    assert settings.blacklist_check_private is True
    assert settings.auto_apply is True


def test_no_secrets_in_default_config() -> None:
    serialized = json.dumps(get_default_ips_config()).lower()
    for secret_hint in ("password", "secret", "token", "api_key"):
        assert secret_hint not in serialized
