"""Dashboard status card widget for the Qt GUI.

Mirrors the public API used by dashboard code (`set_value`, `set_color`,
`set_icon`, etc.).
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout

from ..styles import FG_PRIMARY, FG_SECONDARY, FG_MUTED


class StatusCard(QFrame):
    """A single dashboard tile with SaaS-style status dot and metric text."""

    def __init__(
        self,
        parent=None,
        title: str = "Title",
        value: str = "0",
        icon: str = "",
        color: str = "#0077cc",
        subtitle: str = "",
    ):
        super().__init__(parent)
        self.setObjectName("card")
        # Fixed height keeps the row neat regardless of subtitle length.
        self.setMinimumHeight(110)
        self.setMaximumHeight(130)

        self._color = color
        self._icon_name = icon

        # --- layout ---------------------------------------------------------
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(6)

        # Top row: status dot + title
        top = QHBoxLayout()
        top.setSpacing(8)
        self._dot = QFrame()
        self._dot.setFixedSize(8, 8)
        self._dot.setStyleSheet(self._dot_style(color))
        top.addWidget(self._dot)

        self._title_label = QLabel(title)
        self._title_label.setObjectName("card_title")
        self._title_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 12px;")
        top.addWidget(self._title_label)
        top.addStretch(1)
        root.addLayout(top)

        # Middle: value (large, accent colour)
        self._value_label = QLabel(value)
        self._value_label.setObjectName("card_value")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._value_label.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )
        # Allow long text (e.g. "Connecting...") to wrap rather than truncate.
        self._value_label.setWordWrap(True)
        root.addWidget(self._value_label, stretch=1)

        # Bottom: subtitle
        self._subtitle_label = QLabel(subtitle)
        self._subtitle_label.setObjectName("card_subtitle")
        self._subtitle_label.setStyleSheet(f"color: {FG_MUTED}; font-size: 11px;")
        root.addWidget(self._subtitle_label)

    # -----------------------------------------------------------------------
    # Public API used by the Dashboard view's diff-skip cache.
    # -----------------------------------------------------------------------

    def set_value(self, value: str) -> None:
        self._value_label.setText(str(value))

    def set_title(self, title: str) -> None:
        self._title_label.setText(title)

    def set_icon(self, icon: str) -> None:
        self._icon_name = icon

    def set_color(self, color: str) -> None:
        self._color = color
        self._dot.setStyleSheet(self._dot_style(color))
        self._value_label.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )

    def set_subtitle(self, subtitle: str) -> None:
        self._subtitle_label.setText(subtitle)

    def get_value(self) -> str:
        return self._value_label.text()

    @staticmethod
    def _dot_style(color: str) -> str:
        return f"background-color: {color}; border: 0; border-radius: 4px;"
