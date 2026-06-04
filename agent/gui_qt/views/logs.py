"""Logs view for the Qt GUI.

Hooks `logging.Handler` into the agent's loggers so anything emitted by the
runtime (core, firewall, whitelist, capture, heartbeat, GUI) appears in the
console. Supports filter-by-level, search, clear, and CSV export.
"""

import csv
import logging
from typing import Optional

from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget,
)

from ..components.log_console import GUILogHandler, LogConsole
from ..styles import ACCENT_RED, FG_PRIMARY, FG_SECONDARY


# Loggers we explicitly hook so messages reach the GUI even if root level
# is INFO and they are emitted at DEBUG.
_CAPTURED_LOGGERS = [
    "agent",
    "core.agent",
    "core.lifecycle",
    "firewall",
    "whitelist",
    "capture",
    "heartbeat",
    "controllers",
    "controllers.agent_controller",
    "controllers.whitelist_controller",
    "gui_qt",
]


class LogsView(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._log_handler: Optional[GUILogHandler] = None

        self._build_ui()
        self._setup_logging()
        self._add_welcome_logs()

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        # Title
        title = QLabel("Activity Logs")
        title.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )
        root.addWidget(title)

        root.addLayout(self._build_controls())

        # Console (already has its own toolbar - filter combo & pause/line count)
        self._log_console = LogConsole(
            max_lines=2000,
            font_family="Consolas",
            font_size=11,
            show_toolbar=True,
        )
        root.addWidget(self._log_console, stretch=1)

        # Status bar
        self._status_label = QLabel("Log console ready")
        self._status_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        root.addWidget(self._status_label)

    def _build_controls(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("Level:"))
        self._level_combo = QComboBox()
        self._level_combo.addItems(["ALL", "DEBUG", "INFO", "WARNING", "ERROR"])
        self._level_combo.setFixedWidth(120)
        self._level_combo.currentTextChanged.connect(self._on_filter_change)
        bar.addWidget(self._level_combo)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search logs...")
        # Search is purely visual in the CTk port - we honour it the same way:
        # filter on substring match against the rendered line.
        self._search_input.textChanged.connect(self._on_search)
        bar.addWidget(self._search_input)

        bar.addStretch(1)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self._on_clear)
        bar.addWidget(clear_btn)

        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self._on_export)
        bar.addWidget(export_btn)

        return bar

    # =======================================================================
    # Logging integration
    # =======================================================================

    def _setup_logging(self) -> None:
        """Attach our `GUILogHandler` to root + selected named loggers so
        runtime messages reach the console."""
        self._log_handler = GUILogHandler(self._log_console)
        self._log_handler.setLevel(logging.INFO)

        root_logger = logging.getLogger()
        if root_logger.level > logging.INFO:
            root_logger.setLevel(logging.INFO)
        if self._log_handler not in root_logger.handlers:
            root_logger.addHandler(self._log_handler)

        for name in _CAPTURED_LOGGERS:
            named = logging.getLogger(name)
            if named.level > logging.INFO:
                named.setLevel(logging.INFO)
            # Keep delivery through the root handler only. Attaching the same
            # handler to both a child logger and root renders each propagated
            # record twice in the GUI console.
            named.propagate = True

    def _add_welcome_logs(self) -> None:
        self._log_console.append_log("=" * 60, "INFO")
        self._log_console.append_log("  SECURITY AGENT Log Console", "INFO")
        self._log_console.append_log("  - Education Security", "INFO")
        self._log_console.append_log("=" * 60, "INFO")
        self._log_console.append_log("", "INFO")
        self._log_console.append_log("Log console initialized and ready", "INFO")
        self._log_console.append_log("Capturing logs from all agent modules", "DEBUG")

    # =======================================================================
    # Handlers
    # =======================================================================

    def _on_filter_change(self, value: str) -> None:
        self._status_label.setText(f"Filter: {value}")
        self._log_console.set_filter_level(value)
        # Keep the search filter applied on top of the level filter.
        self._apply_search_filter()

    def _on_search(self, _text: str) -> None:
        self._apply_search_filter()

    def _apply_search_filter(self) -> None:
        """Re-render history honouring both the level filter (in `LogConsole`)
        and the local substring search."""
        query = self._search_input.text().lower().strip()
        if not query:
            self._log_console.set_filter_level(self._level_combo.currentText())
            return
        # When a query is present, build the console contents ourselves so we
        # can apply substring filtering. (Slow path - only runs while user is
        # typing in the search box, which already has typing-rate limiting
        # naturally because QPlainTextEdit handles char input cheaply.)
        history = self._log_console.get_history()
        level_filter = self._level_combo.currentText().upper()
        lines = []
        order = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for entry in history:
            lvl = entry.get("level", "INFO")
            if level_filter != "ALL":
                if lvl in order and level_filter in order:
                    if order.index(lvl) < order.index(level_filter):
                        continue
            line = LogConsole._format_line(entry)
            if query in line.lower():
                lines.append(line)
        self._log_console._console.setPlainText("\n".join(lines))
        cursor = self._log_console._console.textCursor()
        self._log_console._console.moveCursor(cursor.MoveOperation.End)

    def _on_clear(self) -> None:
        self._log_console.clear()
        self._status_label.setText("Cleared")

    def _on_export(self) -> None:
        """Save the full retained history (independent of filter) to CSV."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save logs as CSV",
            "logs.csv",
            "CSV Files (*.csv);;All Files (*.*)",
        )
        if not path:
            self._status_label.setText("Export canceled")
            return

        rows = self._log_console.get_history()
        if not rows:
            self._status_label.setText("No logs to export")
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "level", "message"])
                for entry in rows:
                    writer.writerow([
                        entry.get("timestamp", ""),
                        entry.get("level", ""),
                        entry.get("message", ""),
                    ])
            self._log_console.append_log(
                f"Exported {len(rows)} log lines to {path}", "INFO"
            )
            self._status_label.setText(f"Exported {len(rows)} lines")
        except Exception as e:
            self._log_console.append_log(f"Export failed: {e}", "ERROR")
            self._status_label.setText("Export failed")
            self._status_label.setStyleSheet(f"color: {ACCENT_RED};")

    # =======================================================================
    # Cleanup
    # =======================================================================

    def cleanup(self) -> None:
        if self._log_handler is None:
            return
        root_logger = logging.getLogger()
        if self._log_handler in root_logger.handlers:
            root_logger.removeHandler(self._log_handler)
        for name in _CAPTURED_LOGGERS:
            named = logging.getLogger(name)
            if self._log_handler in named.handlers:
                named.removeHandler(self._log_handler)
        self._log_handler = None
