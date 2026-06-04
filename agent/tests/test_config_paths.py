import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# Server tests also have a top-level ``config`` package. When pytest collects
# both trees in one process, drop any already-cached non-agent config package
# before importing the agent config modules below.
cached_config = sys.modules.get("config")
cached_path = getattr(cached_config, "__file__", "") if cached_config else ""
if cached_config and not os.path.abspath(cached_path).startswith(AGENT_DIR):
    for module_name in list(sys.modules):
        if module_name == "config" or module_name.startswith("config."):
            sys.modules.pop(module_name, None)

from config.paths import get_config_read_paths, get_config_write_path
from config.validator import validate_config
from firewall.manager import (
    DEFAULT_SNAPSHOT_FILENAME,
    _resolve_snapshot_path,
    _resolve_snapshot_read_path,
)


def test_config_write_path_uses_local_appdata(monkeypatch, tmp_path):
    local_appdata = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.delenv("FIREWALL_CONTROLLER_CONFIG", raising=False)

    assert get_config_write_path() == local_appdata / "SAINT" / "agent_config.json"


def test_config_env_override_wins(monkeypatch, tmp_path):
    env_path = tmp_path / "custom" / "agent_config.json"
    monkeypatch.setenv("FIREWALL_CONTROLLER_CONFIG", str(env_path))

    assert get_config_write_path() == env_path
    assert get_config_read_paths() == [env_path]


def test_config_read_paths_start_with_write_path(monkeypatch, tmp_path):
    local_appdata = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.delenv("FIREWALL_CONTROLLER_CONFIG", raising=False)

    paths = get_config_read_paths()

    assert paths[0] == local_appdata / "SAINT" / "agent_config.json"
    assert len(paths) == len({str(path) for path in paths})


def test_default_offline_config_without_server_url_is_valid():
    config = {
        "server": {"url": "", "urls": []},
        "firewall": {"mode": "whitelist_only"},
        "logging": {"level": "INFO"},
        "whitelist": {"update_interval": 60},
        "heartbeat": {"interval": 20},
    }

    is_valid, errors, warnings = validate_config(config)

    assert is_valid is True
    assert errors == []
    assert any("offline mode" in warning for warning in warnings)


def test_snapshot_write_path_uses_local_appdata(monkeypatch, tmp_path):
    local_appdata = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))

    assert (
        _resolve_snapshot_path(DEFAULT_SNAPSHOT_FILENAME)
        == local_appdata / "SAINT" / "profiles" / "backup.saint-snapshot.json"
    )


def test_snapshot_read_path_falls_back_to_legacy_install_dir(
    monkeypatch, tmp_path
):
    local_appdata = tmp_path / "LocalAppData"
    install_root = tmp_path / "install"
    legacy_snapshot = (
        install_root / "profiles" / "backup.saint-snapshot.json"
    )
    legacy_snapshot.parent.mkdir(parents=True)
    legacy_snapshot.write_text("{}", encoding="utf-8")

    import firewall.manager as firewall_manager

    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.setattr(
        firewall_manager,
        "__file__",
        str(install_root / "agent" / "firewall" / "manager.py"),
    )

    assert _resolve_snapshot_read_path(DEFAULT_SNAPSHOT_FILENAME) == legacy_snapshot
