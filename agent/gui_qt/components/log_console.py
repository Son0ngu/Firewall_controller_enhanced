"""Qt log console - `QPlainTextEdit` wrapper with toolbar + filter + history.

Replaces the CTk `LogConsole` (which used `CTkTextbox` and a Python queue
drained by `self.after(200, …)`). Three things change in the Qt port:

1. **Thread-safety** - Python logging emits from arbitrary threads. The CTk
   port used a `queue.Queue` and a periodic drain. Here we use a Qt signal
   carried by `_LogSignals` - Qt signals are thread-safe and auto-marshall
   to the receiver's (GUI) thread, so the queue + timer go away.

2. **Auto-trim** - `QPlainTextEdit.setMaximumBlockCount(N)` does the trim
   natively in O(1) per insert. No need to manually `delete("1.0", "2.0")`.

3. **Filter / history** - same model as CTk: keep a full history list for
   export, redraw the visible textbox from history when the filter level
   changes.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
    QVBoxLayout, QWidget,
)

from ..styles import (
    ACCENT_ORANGE, BG_INPUT, BORDER_LIGHT, FG_PRIMARY, FG_SECONDARY,
)


_LEVEL_ORDER = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class _LogSignals(QObject):
    """Carrier so `GUILogHandler.emit` (any thread) hands records to the
    LogConsole on the GUI thread via a queued connection."""
    entry_received = Signal(dict)


class LogConsole(QFrame):
    """A read-only log viewer with toolbar (pause, level filter, line count)."""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        max_lines: int = 2000,
        font_family: str = "Consolas",
        font_size: int = 11,
        show_toolbar: bool = True,
    ):
        super().__init__(parent)
        self.setObjectName("card")

        self._max_lines = max_lines
        self._paused = False
        self._filter_level = "ALL"
        # Full history retained for export - independent of the visible filter.
        self._history: List[Dict[str, str]] = []

        # Signal bridge so handlers from worker threads can deliver records
        # safely. `Qt.QueuedConnection` forces the slot to run on this
        # widget's owning (GUI) thread.
        self._signals = _LogSignals()
        self._signals.entry_received.connect(
            self._append_entry, type=Qt.ConnectionType.QueuedConnection
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        if show_toolbar:
            layout.addLayout(self._build_toolbar())

        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        # The big win vs CTk: Qt trims the oldest block automatically when
        # the buffer exceeds N lines. Insert stays O(1).
        self._console.setMaximumBlockCount(max_lines)
        self._console.setFont(QFont(font_family, font_size))
        self._console.setStyleSheet(
            "QPlainTextEdit { "
            f"background: {BG_INPUT}; color: {FG_PRIMARY}; "
            f"border: 1px solid {BORDER_LIGHT}; border-radius: 8px; "
            "padding: 8px; }"
        )
        layout.addWidget(self._console, stretch=1)

    # =======================================================================
    # Toolbar
    # =======================================================================

    def _build_toolbar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(10)

        title = QLabel("Console")
        title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {FG_PRIMARY};")
        bar.addWidget(title)

        self._line_count_label = QLabel("0 lines")
        self._line_count_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        bar.addWidget(self._line_count_label)
        bar.addStretch(1)

        self._level_combo = QComboBox()
        self._level_combo.addItems(["ALL"] + _LEVEL_ORDER[:-1])  # drop CRITICAL from user filter (rare)
        self._level_combo.setFixedHeight(28)
        self._level_combo.currentTextChanged.connect(self.set_filter_level)
        bar.addWidget(self._level_combo)

        self._pause_btn = QPushButton("Pause")
        self._pause_btn.setFixedHeight(28)
        self._pause_btn.clicked.connect(self._toggle_pause)
        bar.addWidget(self._pause_btn)

        return bar

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        if self._paused:
            self._pause_btn.setText("Resume")
            self._pause_btn.setStyleSheet(
                f"background-color: {ACCENT_ORANGE}; color: white;"
            )
        else:
            self._pause_btn.setText("Pause")
            self._pause_btn.setStyleSheet("")

    # =======================================================================
    # Filtering
    # =======================================================================

    def set_filter_level(self, level: str) -> None:
        self._filter_level = (level or "ALL").upper()
        self._rebuild_from_history()

    def _passes_filter(self, level: str) -> bool:
        if self._filter_level == "ALL":
            return True
        if level in _LEVEL_ORDER and self._filter_level in _LEVEL_ORDER:
            return _LEVEL_ORDER.index(level) >= _LEVEL_ORDER.index(self._filter_level)
        return True

    def _rebuild_from_history(self) -> None:
        """Re-render the textbox from `_history` under the current filter."""
        self._console.clear()
        # Build the whole block of text in Python first, then `setPlainText`
        # once - much cheaper than N appendPlainText calls.
        lines = []
        for entry in self._history:
            if self._passes_filter(entry.get("level", "INFO")):
                lines.append(self._format_line(entry))
        self._console.setPlainText("\n".join(lines))
        # Move cursor to end so future appends scroll into view.
        self._console.moveCursor(self._console.textCursor().MoveOperation.End)
        self._line_count_label.setText(
            f"{self._console.blockCount() if lines else 0} lines"
        )

    # =======================================================================
    # Public API - log delivery
    # =======================================================================

    def append_log(
        self,
        message: str,
        level: str = "INFO",
        timestamp: Optional[str] = None,
    ) -> None:
        """Thread-safe entry point. May be called from worker threads -
        the signal connection above ensures the actual widget update runs
        on the GUI thread."""
        if timestamp is None:
            timestamp = datetime.now().strftime("%H:%M:%S")
        self._signals.entry_received.emit({
            "timestamp": timestamp,
            "level": level.upper(),
            "message": message,
        })

    def _append_entry(self, entry: Dict[str, str]) -> None:
        """Slot - runs on the GUI thread. Updates history + textbox."""
        # Always retain history for export, even while paused.
        self._history.append(entry)
        if len(self._history) > self._max_lines:
            self._history.pop(0)

        if self._paused or not self._passes_filter(entry.get("level", "INFO")):
            return

        self._console.appendPlainText(self._format_line(entry))
        self._line_count_label.setText(f"{self._console.blockCount()} lines")

    @staticmethod
    def _format_line(entry: Dict[str, str]) -> str:
        timestamp = entry.get("timestamp", "")
        level = entry.get("level", "INFO")
        message = entry.get("message", "")
        return f"[{timestamp}] [{level:8}] {message}"

    # =======================================================================
    # House-keeping
    # =======================================================================

    def clear(self) -> None:
        self._console.clear()
        self._history.clear()
        self._line_count_label.setText("0 lines")
        self.append_log("Console cleared", "INFO")

    def get_history(self) -> List[Dict[str, str]]:
        return list(self._history)


class GUILogHandler(logging.Handler):
    """`logging.Handler` that forwards records to a `LogConsole`.

    Same role as the CTk `GUILogHandler`. Thread-safe because `LogConsole.
    append_log` posts to a Qt signal with `QueuedConnection` - the actual
    widget update is hopped onto the GUI thread by Qt.
    """

    def __init__(self, console: LogConsole):
        super().__init__()
        self._console = console
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            self._console.append_log(msg, record.levelname, timestamp)
        except Exception:
            self.handleError(record)
