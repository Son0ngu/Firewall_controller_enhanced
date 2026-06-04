"""Qt main window - sidebar nav + stacked view area.

Only Dashboard is wired up in Phase 1. The other tabs render a placeholder
panel so the layout looks complete; they're filled in by later phases.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from .signal_bridge import QtSignalBridge
from .views.dashboard import DashboardView
from .views.firewall import FirewallView
from .views.logs import LogsView
from .views.settings import SettingsView
from .views.whitelist import WhitelistView
from .styles import ACCENT_BLUE, FG_SECONDARY


_NAV_ITEMS = [
    ("dashboard", "Dashboard"),
    ("firewall", "Firewall Rules"),
    ("whitelist", "IP Whitelist"),
    ("logs", "Logs"),
    ("settings", "Settings"),
]


class MainWindow(QMainWindow):
    def __init__(self, controller, bridge: QtSignalBridge):
        super().__init__()
        self._controller = controller
        self._bridge = bridge

        self.setWindowTitle("SAINT - Security Agent Integrated Network Tool")
        self.resize(1200, 800)
        self.setMinimumSize(900, 600)

        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- sidebar --------------------------------------------------------
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(232)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(18, 24, 18, 20)
        sidebar_layout.setSpacing(8)

        brand = QLabel("SAINT")
        brand.setStyleSheet(
            f"font-size: 24px; font-weight: 800; color: {ACCENT_BLUE};"
        )
        sidebar_layout.addWidget(brand)

        tagline = QLabel("Security Agent")
        tagline.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 12px;")
        sidebar_layout.addWidget(tagline)
        sidebar_layout.addSpacing(24)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._nav_buttons = {}
        for view_id, label in _NAV_ITEMS:
            btn = QPushButton(label)
            btn.setObjectName("sidebar_item")
            btn.setCheckable(True)
            btn.setMinimumHeight(42)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _checked, vid=view_id: self._show_view(vid))
            sidebar_layout.addWidget(btn)
            self._nav_group.addButton(btn)
            self._nav_buttons[view_id] = btn
        sidebar_layout.addStretch(1)

        root.addWidget(sidebar)

        # --- content area ---------------------------------------------------
        self._stack = QStackedWidget()
        root.addWidget(self._stack, stretch=1)

        # All five views now have Qt ports (Phase 1: dashboard, Phase 2:
        # whitelist + firewall, Phase 3: logs + settings).
        from controllers.whitelist_controller import get_whitelist_controller
        self._views = {
            "dashboard": DashboardView(self._controller, self._bridge),
            "whitelist": WhitelistView(get_whitelist_controller),
            "firewall": FirewallView(),
            "logs": LogsView(),
            "settings": SettingsView(),
        }
        # Defensive fallback - if a future nav item gets added but the view
        # isn't built yet, the sidebar button still navigates to a placeholder
        # instead of crashing.
        for view_id, label in _NAV_ITEMS:
            if view_id not in self._views:
                self._views[view_id] = self._build_placeholder(label)

        for view_id, _label in _NAV_ITEMS:
            self._stack.addWidget(self._views[view_id])

        # Cross-view wiring driven by agent lifecycle:
        #  - When agent transitions to running/degraded, hand the live
        #    FirewallManager to the Firewall view so it stops using the
        #    netsh fallback and pulls rules directly from memory.
        #  - When the controller fires `whitelist_synced { agent_ready: True }`,
        #    flip the Whitelist view into auto-sync mode.
        self._bridge.status_changed.connect(self._on_status_changed)
        self._bridge.whitelist_synced.connect(self._on_whitelist_synced)

        # Start on Dashboard
        self._show_view("dashboard")

    def _on_status_changed(self, data: dict) -> None:
        status = data.get("status", "")
        if status not in ("running", "degraded"):
            return
        # The controller may not have built its `_agent.firewall` yet on the
        # first emit (e.g. for "starting"); guard against AttributeError.
        try:
            agent = getattr(self._controller, "_agent", None)
            fw_manager = getattr(agent, "firewall", None) if agent else None
            if fw_manager is not None:
                self._views["firewall"].set_firewall_manager(fw_manager)
        except Exception:
            pass

    def _on_whitelist_synced(self, data: dict) -> None:
        if data.get("agent_ready"):
            view = self._views.get("whitelist")
            if view is not None and hasattr(view, "set_agent_ready"):
                view.set_agent_ready(True)

    def _build_placeholder(self, label: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel(f"{label.strip()}")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note = QLabel("This view is not implemented yet.")
        note.setStyleSheet(f"color: {FG_SECONDARY};")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(note)
        return widget

    def _show_view(self, view_id: str) -> None:
        btn = self._nav_buttons.get(view_id)
        if btn:
            btn.setChecked(True)
        widget = self._views.get(view_id)
        if widget:
            self._stack.setCurrentWidget(widget)

    # -----------------------------------------------------------------------
    # Window close - confirm if the agent is running so we don't yank the
    # firewall out from under the user mid-session.
    # -----------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._controller and self._controller.is_running:
            reply = QMessageBox.warning(
                self,
                "SAINT - Confirm Exit",
                "Agent is currently running.\n\n"
                "Exiting will stop the agent and restore the firewall to its "
                "original state.\n\nAre you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            try:
                self._controller.stop_agent()
            except Exception:
                pass

        # Detach the LogsView logging handler so the global logging system
        # doesn't keep a dangling reference to a deleted widget after the
        # window closes (otherwise the next emit crashes inside Qt cleanup).
        try:
            logs_view = self._views.get("logs")
            if logs_view is not None and hasattr(logs_view, "cleanup"):
                logs_view.cleanup()
        except Exception:
            pass

        # Stop the signal-bridge drain timer cleanly.
        try:
            self._bridge.stop()
        except Exception:
            pass
        event.accept()
