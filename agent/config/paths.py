"""Config path helpers shared by runtime and GUI.

The agent should not write mutable configuration next to the executable. In a
PyInstaller onefile run that location can be read-only, ACL-restricted, or
locked by the running EXE. Use a stable per-user app-data location for writes
and keep legacy locations as read-only fallbacks.
"""

import os
from pathlib import Path
from typing import List


DEFAULT_CONFIG_FILE = "agent_config.json"


def _agent_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def _user_config_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if base:
        return Path(base) / "SAINT"
    return Path.home() / ".saint"


def get_user_data_dir() -> Path:
    """Return SAINT's per-user writable data directory."""
    return _user_config_dir()


def get_config_write_path() -> Path:
    """Return the path Settings/runtime should write to."""
    env_path = os.environ.get("FIREWALL_CONTROLLER_CONFIG")
    if env_path:
        return Path(env_path)
    return _user_config_dir() / DEFAULT_CONFIG_FILE


def get_config_read_paths() -> List[Path]:
    """Return read candidates, preferring the stable writable path.

    Legacy paths are kept so existing configs can still be loaded/migrated, but
    new saves should go to :func:`get_config_write_path`.
    """
    env_path = os.environ.get("FIREWALL_CONTROLLER_CONFIG")
    if env_path:
        return [Path(env_path)]

    candidates = [
        get_config_write_path(),
        _agent_dir() / DEFAULT_CONFIG_FILE,
        Path(DEFAULT_CONFIG_FILE),
        Path.home() / ".firewall-controller" / DEFAULT_CONFIG_FILE,
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        / "FirewallController"
        / DEFAULT_CONFIG_FILE,
    ]

    seen = set()
    out: List[Path] = []
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out
