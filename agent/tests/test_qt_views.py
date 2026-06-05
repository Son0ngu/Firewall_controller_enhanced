import os
import sys

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from gui_qt.views.whitelist import WhitelistView


class _FakeWhitelistController:
    def __init__(self):
        self._whitelist_manager = object()
        self._callbacks = []

    def on_data_changed(self, callback):
        self._callbacks.append(callback)

    def on_error(self, _callback):
        pass

    def on_success(self, _callback):
        pass

    def get_all_ips(self):
        return []

    def get_stats(self):
        return {
            "total_ips": 3,
            "manager_domains": 1,
            "manager_ips": 2,
            "active": 3,
        }

    def refresh(self):
        pass


def _app():
    return QApplication.instance() or QApplication([])


def test_whitelist_view_default_table_shows_domain_pattern_and_ip():
    app = _app()
    view = WhitelistView(lambda: _FakeWhitelistController())
    try:
        app.processEvents()
        rows = [
            {"ip": "login.example.com", "type": "Domain", "status": "Active", "source": "Server"},
            {"ip": "*.example.com", "type": "Pattern", "status": "Active", "source": "Server"},
            {"ip": "192.168.1.10", "type": "IP", "status": "Active", "source": "Server"},
        ]

        view._update_table(rows)

        rendered = view._table.get_data()
        assert [row["type"] for row in rendered] == ["Domain", "Pattern", "IP"]
        assert [row["ip"] for row in rendered] == [
            "login.example.com",
            "*.example.com",
            "192.168.1.10",
        ]
    finally:
        view.close()
        view.deleteLater()
