import logging
import os
import sys

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from gui_qt.views.logs import LogsView


def _process_events(app):
    for _ in range(5):
        app.processEvents()


def test_logs_view_does_not_duplicate_propagated_records():
    app = QApplication.instance() or QApplication([])
    view = LogsView()
    try:
        _process_events(app)
        marker = "dedupe-marker-for-gui-log-handler"

        logging.getLogger("core.lifecycle").info(marker)
        _process_events(app)

        matches = [
            entry
            for entry in view._log_console.get_history()
            if entry.get("message") == marker
        ]
        assert len(matches) == 1
    finally:
        view.cleanup()
        view.deleteLater()
