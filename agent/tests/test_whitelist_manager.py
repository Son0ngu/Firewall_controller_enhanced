import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from whitelist.manager import WhitelistManager


def test_whitelist_manager_uses_update_interval_from_config():
    manager = WhitelistManager({"server": {}, "whitelist": {"update_interval": 123}})
    try:
        assert manager._sync_interval == 123
    finally:
        manager.cleanup()


def test_whitelist_manager_keeps_legacy_sync_interval_fallback():
    manager = WhitelistManager({"server": {}, "whitelist": {"sync_interval": 45}})
    try:
        assert manager._sync_interval == 45
    finally:
        manager.cleanup()
