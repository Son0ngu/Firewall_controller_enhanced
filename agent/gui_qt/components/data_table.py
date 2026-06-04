"""Reusable Qt table = model + view.

Replaces the CTk `DataTable` (which manually created `CTkFrame`+`CTkLabel` per
cell and choked on hundreds of rows). `QTableView` is virtualized natively -
only the rows currently scrolled into view are painted, so a 10,000-row table
renders in tens of milliseconds.

Public API mirrors the CTk component (`set_data`, `get_data`, `clear`, etc.)
so view code stays portable.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QHeaderView, QTableView, QVBoxLayout, QWidget,
)

from ..styles import (
    ACCENT_GREEN, ACCENT_ORANGE, ACCENT_RED, BG_ACTIVE, BG_TABLE_HEADER,
    BORDER_LIGHT, FG_PRIMARY, FG_SECONDARY,
)


# Foreground colours keyed on lowercased status text. Matches the CTk
# DataTable colour rules so the two ports look the same at a glance.
_STATUS_COLOURS = {
    "active": ACCENT_GREEN,
    "allowed": ACCENT_GREEN,
    "online": ACCENT_GREEN,
    "blocked": ACCENT_RED,
    "denied": ACCENT_RED,
    "offline": ACCENT_RED,
    "pending": ACCENT_ORANGE,
    "syncing": ACCENT_ORANGE,
}


class DictTableModel(QAbstractTableModel):
    """Qt model that wraps a list-of-dicts data source.

    Column definitions accept the same shape as the CTk DataTable:
        [{"key": "ip", "title": "IP Address", "width": 200, "type": "datetime"?}]
    """

    def __init__(self, columns: Sequence[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self._columns: List[Dict[str, Any]] = list(columns)
        self._rows: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # QAbstractTableModel interface
    # -----------------------------------------------------------------------

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        # `parent.isValid()` filters out child rows (we don't have any -
        # this is a flat table, not a tree).
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._columns)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = self._rows[index.row()]
        col = self._columns[index.column()]
        key = col.get("key", "")
        value = row.get(key)

        if role == Qt.ItemDataRole.DisplayRole:
            return self._format_value(value, col.get("type"))

        if role == Qt.ItemDataRole.ForegroundRole and key == "status":
            colour = _STATUS_COLOURS.get(str(value).lower())
            if colour:
                return QColor(colour)
            return QColor(FG_PRIMARY)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self._columns):
                col = self._columns[section]
                return col.get("title", col.get("key", ""))
        return None

    # -----------------------------------------------------------------------
    # CTk-compatible API
    # -----------------------------------------------------------------------

    def set_rows(self, rows: List[Dict[str, Any]]) -> None:
        """Replace the entire row set. Uses begin/endResetModel because we
        usually replace many rows at once (sync from server, search filter),
        and signalling a full reset is faster than emitting `dataChanged`
        for thousands of individual cells."""
        self.beginResetModel()
        self._rows = list(rows) if rows else []
        self.endResetModel()

    def rows(self) -> List[Dict[str, Any]]:
        return list(self._rows)

    def row_count(self) -> int:
        return len(self._rows)

    @staticmethod
    def _format_value(value: Any, value_type: Optional[str]) -> str:
        if value is None:
            return "-"
        if value_type == "datetime" and isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")
        if value_type == "date" and isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d")
        return str(value)


class DataTable(QWidget):
    """QTableView wrapped in a card-styled frame.

    Convenience wrapper that owns the model and applies sensible defaults
    (alternating row colours, no row numbers, columns sized by `width`).
    """

    def __init__(
        self,
        columns: Sequence[Dict[str, Any]],
        parent: Optional[QWidget] = None,
        row_height: int = 32,
    ):
        super().__init__(parent)

        self._model = DictTableModel(columns, self)

        self._view = QTableView(self)
        self._view.setModel(self._model)
        self._view.setAlternatingRowColors(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setShowGrid(False)
        self._view.setSortingEnabled(False)  # set_data preserves source order
        self._view.verticalHeader().setVisible(False)
        self._view.verticalHeader().setDefaultSectionSize(row_height)
        self._view.setMouseTracking(True)

        # ----- Header alignment -------------------------------------------
        # Qt's Fusion style centers header text by default, while our cells
        # are left-aligned (via model's TextAlignmentRole). The mismatch
        # made data look "shifted" from the headers above it. Match them.
        header = self._view.horizontalHeader()
        header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

        # ----- Column sizing ----------------------------------------------
        # Layout rule: every column gets its configured `width`; the LAST
        # column auto-stretches to fill remaining table width. That keeps
        # narrow-content columns (IP, type, status) at a sensible size and
        # lets the wide-content tail column (rule name, source) absorb the
        # extra space - matches typical data-table conventions and avoids
        # the bug where setting one column to Stretch made it eat the entire
        # available width regardless of how short its content was.
        header.setStretchLastSection(True)
        for col_idx, col_cfg in enumerate(columns):
            if col_idx == len(columns) - 1:
                # Last column auto-stretches; don't fight Qt with an explicit mode.
                continue
            header.setSectionResizeMode(col_idx, QHeaderView.ResizeMode.Interactive)
            self._view.setColumnWidth(col_idx, col_cfg.get("width", 100))

        # Card-styled wrap so the table feels like a dashboard panel.
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._view)
        # `QTableView::item` padding matches the QSS header padding (`8px 10px`)
        # so the left edge of header text and the left edge of cell text line
        # up to the pixel.
        self.setStyleSheet(
            f"""
            QTableView {{
                background: white;
                alternate-background-color: #FBFDFF;
                border: 1px solid {BORDER_LIGHT};
                border-radius: 8px;
                selection-background-color: {BG_ACTIVE};
                selection-color: {FG_PRIMARY};
            }}
            QTableView::item {{
                padding: 7px 10px;
            }}
            QHeaderView::section {{
                background-color: {BG_TABLE_HEADER};
                color: {FG_SECONDARY};
                border: 0;
                border-bottom: 1px solid {BORDER_LIGHT};
                padding: 9px 10px;
                font-weight: 600;
            }}
            """
        )

    # -----------------------------------------------------------------------
    # Public API (mirrors CTk `DataTable`)
    # -----------------------------------------------------------------------

    def set_data(self, rows: List[Dict[str, Any]]) -> None:
        self._model.set_rows(rows)

    def get_data(self) -> List[Dict[str, Any]]:
        return self._model.rows()

    def clear(self) -> None:
        self._model.set_rows([])

    def row_count(self) -> int:
        return self._model.row_count()

    def view(self) -> QTableView:
        """Expose the underlying view for advanced customisation."""
        return self._view
