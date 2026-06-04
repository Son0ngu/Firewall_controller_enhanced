"""Redesigned Qt Dashboard.

Layout (top → bottom):

    Header:    title + subtitle | StatusPill | [Sync Now] [Start/Stop]
    Cards:     8 small StatusCards in one row
    Middle:    [ Activity Log (60%) ][ Server Overview + Firewall Status (40%) ]

Data sources (signal-driven, no polling):
- `status_changed`  → updates Agent Status / Mode cards, header pill, buttons
- `stats_updated`   → updates Whitelist / Uptime / Packets / Server cards
- `packet_captured` → appends to activity log (rate-limited)
- `whitelist_synced`→ updates Last Sync card + Server Overview last-sync row
"""

import time
from datetime import datetime
from typing import Dict, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
    QSizePolicy, QVBoxLayout, QWidget,
)

from ..components.status_card import StatusCard
from ..signal_bridge import QtSignalBridge
from ..styles import (
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_PURPLE, ACCENT_RED,
    BG_INPUT, BORDER_LIGHT, FG_PRIMARY, FG_SECONDARY,
)


# =======================================================================
# Constants
# =======================================================================

_LOG_MAX_LINES = 500
_PACKET_LOG_WINDOW_MS = 1000
_PACKET_LOG_MAX_PER_WINDOW = 20


# =======================================================================
# Inline helper widgets
# =======================================================================

class StatusPill(QFrame):
    """Pill-shaped badge with a leading dot and short text.
    Used in the header to indicate agent run state."""

    def __init__(self, text: str = "Stopped", color: str = "#888888", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 5, 14, 5)
        layout.setSpacing(6)
        self._dot = QFrame()
        self._dot.setFixedSize(8, 8)
        self._dot.setStyleSheet(self._dot_style(color))
        self._label = QLabel(text)
        self._label.setStyleSheet(f"font-size: 13px; color: {FG_PRIMARY};")
        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        self._apply_bg(color)

    def _apply_bg(self, color: str) -> None:
        # Light tint of the accent colour as background so the pill reads
        # as a state indicator rather than a generic chip.
        self.setStyleSheet(
            f"background: {_tint(color, 0.12)}; "
            f"border: 1px solid {_tint(color, 0.30)}; "
            "border-radius: 14px;"
        )

    def setStatus(self, text: str, color: str) -> None:
        self._dot.setStyleSheet(self._dot_style(color))
        self._label.setText(text)
        self._apply_bg(color)

    @staticmethod
    def _dot_style(color: str) -> str:
        return f"background-color: {color}; border: 0; border-radius: 4px;"


def _tint(color_hex: str, alpha: float) -> str:
    """Return an `rgba(r, g, b, a)` string for a hex colour.
    Used so the pill background gets a soft tint of its accent colour
    instead of a flat white."""
    c = color_hex.lstrip("#")
    if len(c) != 6:
        return color_hex
    r = int(c[0:2], 16)
    g = int(c[2:4], 16)
    b = int(c[4:6], 16)
    a = max(0.0, min(1.0, alpha))
    return f"rgba({r}, {g}, {b}, {int(round(a * 255))})"


class _StackedField(QVBoxLayout):
    """Label-on-top / value-below pair for the Server Overview panel.

    Old horizontal `label : value` layout meant the value column ended up
    half the panel width - fine for short strings like "42ms" but the
    server URL (30+ chars) collapsed to an unreadable ellipsis. Stacking
    the label above the value gives the value the full available width.
    """

    def __init__(self, label: str, wrap: bool = False):
        super().__init__()
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(2)
        self._label = QLabel(label)
        self._label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        self.value_label = QLabel("-")
        self.value_label.setStyleSheet(
            f"color: {FG_PRIMARY}; font-size: 13px; font-weight: 500;"
        )
        self.value_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        # For long values (URL) allow wrapping to a second line rather than
        # clipping; for short values (latency / ago strings) keep it on a
        # single line.
        self.value_label.setWordWrap(wrap)
        self.addWidget(self._label)
        self.addWidget(self.value_label)

    def set_value(self, text: str, color: Optional[str] = None) -> None:
        self.value_label.setText(text)
        if color:
            self.value_label.setStyleSheet(
                f"color: {color}; font-size: 13px; font-weight: 500;"
            )


class _MetricCell(QVBoxLayout):
    """Compact (label / value) pair for Firewall Status & Traffic Overview
    bottom-row metrics. Centered, slightly larger value."""

    def __init__(self, label: str):
        super().__init__()
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(2)
        self._label = QLabel(label)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        self._value = QLabel("-")
        self._value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._value.setStyleSheet(
            f"color: {FG_PRIMARY}; font-size: 16px; font-weight: bold;"
        )
        self.addWidget(self._label)
        self.addWidget(self._value)

    def set_value(self, text: str, color: Optional[str] = None) -> None:
        self._value.setText(text)
        if color:
            self._value.setStyleSheet(
                f"color: {color}; font-size: 16px; font-weight: bold;"
            )


# =======================================================================
# DashboardView
# =======================================================================

class DashboardView(QWidget):

    def __init__(
        self,
        controller,
        bridge: QtSignalBridge,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._controller = controller
        self._bridge = bridge

        # ----- state caches ------------------------------------------------
        self._cards: Dict[str, StatusCard] = {}
        self._last_card_values: Dict[str, str] = {}

        # Packet-log rate-limit state
        self._packet_log_window_start_ms: float = 0.0
        self._packet_log_count_in_window: int = 0
        self._packet_log_dropped_in_window: int = 0

        # Heartbeat / last sync timestamps (epoch seconds). We display them
        # as relative "Ns ago" via a 1s tick timer.
        self._last_sync_ts: Optional[float] = None

        self._build_ui()
        self._connect_signals()
        self._render_initial_stats()

        # 1s tick to refresh relative-time strings ("10s ago"). Doesn't fetch
        # any data - just re-formats from cached timestamps.
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._refresh_relative_times)
        self._tick_timer.start()

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        root.addLayout(self._build_header())
        root.addLayout(self._build_cards_grid())
        root.addLayout(self._build_middle_row(), stretch=1)

    # ----- Header ------------------------------------------------------

    def _build_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setSpacing(10)

        # Title block (title + subtitle stacked)
        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(2)
        title = QLabel("Dashboard")
        title.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )
        subtitle = QLabel("Security system overview")
        subtitle.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 12px;")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        layout.addLayout(title_block)
        layout.addStretch(1)

        # Status pill - replaces the old plain-text indicator
        self._status_pill = StatusPill("Stopped", "#888888")
        layout.addWidget(self._status_pill)

        # Sync Now button - calls whitelist controller refresh
        self._sync_btn = QPushButton("Sync Now")
        self._sync_btn.setMinimumHeight(38)
        self._sync_btn.setMinimumWidth(120)
        self._sync_btn.clicked.connect(self._on_sync_now)
        layout.addWidget(self._sync_btn)

        # Start/Stop button
        self._start_stop_btn = QPushButton("Start Agent")
        self._start_stop_btn.setObjectName("success")
        self._start_stop_btn.setMinimumHeight(38)
        self._start_stop_btn.setMinimumWidth(150)
        self._start_stop_btn.clicked.connect(self._toggle_agent)
        layout.addWidget(self._start_stop_btn)

        return layout

    # ----- 8 status cards in a 4 × 2 grid ------------------------------
    # Single-row of 8 cards looked great in the mockup but only at very wide
    # window sizes; at 1200-1400px each card collapsed to ~120px and titles
    # like "Agent Status" / "Allowed IPs" got clipped mid-word. A 4-up grid
    # gives every card ~250px even at narrow widths.

    def _build_cards_grid(self) -> QGridLayout:
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        # (key, title, value, icon, color, subtitle)
        specs = [
            ("status",  "Agent Status", "Stopped", "", ACCENT_RED,    "Agent state"),
            ("mode",    "Mode",         "-",       "", ACCENT_BLUE,   "Current mode"),
            ("domains", "Whitelist",    "0",       "", ACCENT_BLUE,   "Domains"),
            ("ips",     "Allowed IPs",  "0",       "", ACCENT_GREEN,  "In whitelist"),
            ("packets", "Packets",      "0",       "", ACCENT_PURPLE, "Processed"),
            ("server",  "Server",       "Offline", "", ACCENT_RED,    "Connection state"),
            ("sync",    "Last Sync",    "Never",   "", ACCENT_BLUE,   "Whitelist sync"),
            ("uptime",  "Uptime",       "0s",      "", ACCENT_ORANGE, "Agent runtime"),
        ]
        for i, (key, title_, value, icon, color, subtitle) in enumerate(specs):
            card = StatusCard(
                title=title_, value=value, icon=icon, color=color, subtitle=subtitle
            )
            self._cards[key] = card
            row, col = divmod(i, 4)
            grid.addWidget(card, row, col)
        for c in range(4):
            grid.setColumnStretch(c, 1)
        return grid

    # ----- Middle row: log (left) + 3 panels (right) -------------------

    def _build_middle_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(14)
        row.addWidget(self._build_activity_log(), stretch=6)
        row.addLayout(self._build_side_panels(), stretch=4)
        return row

    def _build_activity_log(self) -> QWidget:
        wrap = QFrame()
        wrap.setObjectName("card")
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("Activity Log")
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {FG_PRIMARY};")
        header.addWidget(title)
        header.addStretch(1)
        clear = QPushButton("Clear Log")
        clear.setFixedHeight(28)
        clear.clicked.connect(self._clear_log)
        header.addWidget(clear)
        layout.addLayout(header)

        self._log_widget = QPlainTextEdit()
        self._log_widget.setReadOnly(True)
        self._log_widget.setMaximumBlockCount(_LOG_MAX_LINES)
        self._log_widget.setStyleSheet(
            f"""
            QPlainTextEdit {{
                background: {BG_INPUT};
                border: 1px solid {BORDER_LIGHT};
                border-radius: 6px;
                padding: 6px;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }}
            """
        )
        layout.addWidget(self._log_widget, stretch=1)

        self._append_log("Dashboard initialized. Click 'Start Agent' to begin.", "INFO")
        return wrap

    def _build_side_panels(self) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(12)
        col.addWidget(self._build_server_overview_panel())
        col.addWidget(self._build_firewall_status_panel())
        # `addStretch` pushes the two panels to the top of the side column
        # so they don't get vertically stretched to fill the row height.
        col.addStretch(1)
        return col

    # ----- Server Overview panel ---------------------------------------

    def _build_server_overview_panel(self) -> QWidget:
        wrap = QFrame()
        wrap.setObjectName("card")
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(12)

        header = QLabel("Server Overview")
        header.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {FG_PRIMARY};")
        layout.addWidget(header)

        # URL gets the full panel width - a typical server URL like
        # "firewall-controller.onrender.com" is 30+ chars and was getting
        # clipped to "firewall-co..." when it shared a row with another
        # field. WordWrap=True lets it spill onto a second line if needed
        # rather than truncate.
        self._server_url = _StackedField("URL", wrap=True)
        layout.addLayout(self._server_url)

        # Latency / Heartbeat / Last sync are all short - fit 3-up under
        # the URL row to keep the panel compact.
        row = QHBoxLayout()
        row.setSpacing(16)
        self._server_latency = _StackedField("Latency")
        self._server_heartbeat = _StackedField("Heartbeat")
        self._server_last_sync = _StackedField("Last sync")
        row.addLayout(self._server_latency, stretch=1)
        row.addLayout(self._server_heartbeat, stretch=1)
        row.addLayout(self._server_last_sync, stretch=1)
        layout.addLayout(row)
        return wrap

    # ----- Firewall Status panel ---------------------------------------

    def _build_firewall_status_panel(self) -> QWidget:
        wrap = QFrame()
        wrap.setObjectName("card")
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        header = QLabel("Firewall Status")
        header.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {FG_PRIMARY};")
        layout.addWidget(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        self._fw_policy = _MetricCell("Policy")
        self._fw_rules = _MetricCell("Rules")
        self._fw_mode = _MetricCell("Mode")
        self._fw_allowed = _MetricCell("Allowed IPs")
        grid.addLayout(self._fw_policy, 0, 0)
        grid.addLayout(self._fw_rules, 0, 1)
        grid.addLayout(self._fw_mode, 0, 2)
        grid.addLayout(self._fw_allowed, 0, 3)
        layout.addLayout(grid)
        return wrap

    # =======================================================================
    # Signal wiring
    # =======================================================================

    def _connect_signals(self) -> None:
        self._bridge.status_changed.connect(self._on_status_changed)
        self._bridge.stats_updated.connect(self._on_stats_updated)
        self._bridge.packet_captured.connect(self._on_packet_captured)
        self._bridge.error_occurred.connect(self._on_error)
        self._bridge.whitelist_synced.connect(self._on_whitelist_synced)

    # =======================================================================
    # Diff-skip card helpers (unchanged from previous version)
    # =======================================================================

    def _render_initial_stats(self) -> None:
        if not self._controller:
            return
        try:
            info = self._controller.get_agent_info()
            stats = dict(info.get("stats", {}))
            stats["is_registered"] = info.get("is_registered", False)
            stats["firewall_enabled"] = info.get("firewall_enabled", False)
            self._apply_stats_to_cards(stats)
            self._update_server_overview(initial=True)
            self._update_firewall_status_panel()
        except Exception:
            pass

    def _set_card_value_if_changed(self, key: str, value: str) -> bool:
        cache_key = f"{key}:value"
        if self._last_card_values.get(cache_key) == value:
            return False
        self._last_card_values[cache_key] = value
        self._cards[key].set_value(value)
        return True

    def _set_card_color_if_changed(self, key: str, color: str) -> bool:
        cache_key = f"{key}:color"
        if self._last_card_values.get(cache_key) == color:
            return False
        self._last_card_values[cache_key] = color
        self._cards[key].set_color(color)
        return True

    def _apply_stats_to_cards(self, stats: Dict) -> None:
        self._set_card_value_if_changed(
            "uptime", self._format_uptime(stats.get("uptime_seconds", 0))
        )
        domains = stats.get("domains_count", 0)
        if self._set_card_value_if_changed("domains", str(domains)):
            self._cards["domains"].set_subtitle(f"{domains} Domains")

        self._set_card_value_if_changed("ips", str(stats.get("ips_count", 0)))
        self._set_card_value_if_changed(
            "packets", str(stats.get("packets_captured", 0))
        )

        if stats.get("is_registered"):
            self._set_card_value_if_changed("server", "Online")
            self._set_card_color_if_changed("server", ACCENT_GREEN)
        elif self._controller and self._controller.is_running:
            self._set_card_value_if_changed("server", "Connecting...")
            self._set_card_color_if_changed("server", ACCENT_ORANGE)
        else:
            self._set_card_value_if_changed("server", "Offline")
            self._set_card_color_if_changed("server", ACCENT_RED)

    # =======================================================================
    # Side panels - Server Overview + Firewall Status
    # =======================================================================

    def _update_server_overview(self, initial: bool = False) -> None:
        """Pull URL + heartbeat info from controller / config and render."""
        try:
            cfg = getattr(self._controller, "_config", None) or {}
        except Exception:
            cfg = {}
        url = (cfg.get("server", {}) or {}).get("url") or "-"
        self._server_url.set_value(url)
        # Latency is left as "-" until the agent measures it. Heartbeat age
        # is recomputed by the 1s tick from a timestamp we'll capture when
        # `whitelist_synced` fires (proxy for "agent talked to server").
        if initial:
            self._server_latency.set_value("-")
            self._server_heartbeat.set_value("-")
            self._server_last_sync.set_value("Never")

    def _update_firewall_status_panel(self) -> None:
        agent = getattr(self._controller, "_agent", None)
        fw = getattr(agent, "firewall", None) if agent else None
        if fw is None:
            self._fw_policy.set_value("-", color=FG_SECONDARY)
            self._fw_rules.set_value("0")
            self._fw_mode.set_value("-")
            self._fw_allowed.set_value("0")
            return
        pm = getattr(fw, "policy_manager", None)
        if pm and getattr(pm, "default_deny_enabled", False):
            self._fw_policy.set_value("Default Deny", color=ACCENT_GREEN)
        else:
            self._fw_policy.set_value("Default Allow", color=ACCENT_ORANGE)

        allowed = getattr(fw, "allowed_ips", []) or []
        self._fw_rules.set_value(str(len(allowed)))
        self._fw_allowed.set_value(str(len(allowed)), color=ACCENT_GREEN)
        if getattr(fw, "whitelist_mode_active", False):
            self._fw_mode.set_value("Whitelist Only", color=ACCENT_GREEN)
        else:
            self._fw_mode.set_value("Idle", color=FG_SECONDARY)

    def _refresh_relative_times(self) -> None:
        """Tick handler - re-formats `Ns ago` strings without re-pulling
        backend state."""
        if self._last_sync_ts is not None:
            age = int(time.time() - self._last_sync_ts)
            txt = "Just now" if age < 5 else (
                f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            )
            self._server_last_sync.set_value(txt, color=ACCENT_GREEN if age < 60 else None)
            self._server_heartbeat.set_value(txt)
            self._set_card_value_if_changed("sync", "Just now" if age < 10 else txt)

    # =======================================================================
    # Signal handlers
    # =======================================================================

    def _on_status_changed(self, data: Dict) -> None:
        status = data.get("status", "unknown")
        message = data.get("message", "")

        if status == "running":
            self._set_card_value_if_changed("status", "Running")
            self._cards["status"].set_icon("")
            self._set_card_color_if_changed("status", ACCENT_GREEN)
            self._cards["status"].set_subtitle("Agent is active")
            self._status_pill.setStatus("Running", ACCENT_GREEN)
            self._update_button_state("running")
            self._update_mode_card(running=True, degraded=False)
            self._update_firewall_status_panel()

        elif status == "degraded":
            self._set_card_value_if_changed("status", "Degraded")
            self._cards["status"].set_icon("")
            self._set_card_color_if_changed("status", ACCENT_ORANGE)
            issues = data.get("issues", []) or []
            self._cards["status"].set_subtitle(
                f"{len(issues)} issue(s)" if issues else "Degraded"
            )
            self._status_pill.setStatus("Degraded", ACCENT_ORANGE)
            self._update_button_state("running")
            self._update_mode_card(running=True, degraded=True)
            self._update_firewall_status_panel()
            self._append_log("Agent running in DEGRADED mode", "WARN")
            for issue in issues:
                self._append_log(
                    f"{issue.get('name', '?')}: {issue.get('detail', '') or issue.get('status', '')}",
                    "WARN",
                )

        elif status == "stopped":
            self._set_card_value_if_changed("status", "Stopped")
            self._cards["status"].set_icon("")
            self._set_card_color_if_changed("status", ACCENT_RED)
            self._cards["status"].set_subtitle("Not running")
            self._status_pill.setStatus("Stopped", "#888888")
            self._update_button_state("stopped")
            self._update_mode_card(running=False, degraded=False)
            self._update_firewall_status_panel()
            self._set_card_value_if_changed("server", "Offline")
            self._set_card_color_if_changed("server", ACCENT_RED)

        elif status == "starting":
            self._set_card_value_if_changed("status", "Starting...")
            self._cards["status"].set_icon("")
            self._set_card_color_if_changed("status", ACCENT_ORANGE)
            self._status_pill.setStatus("Starting...", ACCENT_ORANGE)
            self._update_button_state("starting")

        elif status == "stopping":
            self._set_card_value_if_changed("status", "Stopping...")
            self._cards["status"].set_icon("")
            self._set_card_color_if_changed("status", ACCENT_ORANGE)
            self._status_pill.setStatus("Stopping...", ACCENT_ORANGE)
            self._update_button_state("stopping")

        if message:
            self._append_log(message, "STATUS")

    def _on_stats_updated(self, data: Dict) -> None:
        self._apply_stats_to_cards(data)
        # Whenever stats update we also refresh the firewall side-panel -
        # rule counts may change as the whitelist syncs.
        self._update_firewall_status_panel()
        # And the server URL row (config could have just been saved).
        self._update_server_overview()

    def _on_error(self, data: Dict) -> None:
        error = data.get("error", "Unknown error")
        message = data.get("message", "")
        self._set_card_value_if_changed("status", "Error")
        self._set_card_color_if_changed("status", ACCENT_RED)
        self._cards["status"].set_subtitle("Error occurred")
        self._status_pill.setStatus("Error", ACCENT_RED)
        self._update_button_state("error")
        self._append_log(error, "ERROR")
        if message:
            self._append_log(message, "ERROR")

    def _on_whitelist_synced(self, data: Dict) -> None:
        if data.get("agent_ready"):
            self._append_log("Agent ready - whitelist sync enabled", "INFO")
            return
        if data.get("success"):
            self._last_sync_ts = time.time()
            self._set_card_value_if_changed("sync", "Just now")
            self._set_card_color_if_changed("sync", ACCENT_GREEN)
            self._server_last_sync.set_value("Just now", color=ACCENT_GREEN)
            self._append_log("Whitelist synchronized successfully", "SYNC")
        else:
            self._set_card_value_if_changed("sync", "Failed")
            self._set_card_color_if_changed("sync", ACCENT_RED)
            self._append_log("Whitelist sync failed", "ERROR")

    def _on_packet_captured(self, data: Dict) -> None:
        domain = data.get("domain", "")
        dest_ip = data.get("dest_ip", "")
        action = (data.get("action", "detected") or "").lower()
        protocol = data.get("protocol", "")
        port = data.get("port", "")

        if not domain and not dest_ip:
            return

        # Increment packet card immediately (the stats_updated tick would
        # only catch up 1s later).
        try:
            current = int(self._cards["packets"].get_value() or 0)
            self._cards["packets"].set_value(str(current + 1))
        except (TypeError, ValueError):
            pass

        target = domain if domain and domain != "unknown" else dest_ip
        if not target or target == "unknown":
            return

        if not self._should_log_packet(action):
            return

        proto_info = ""
        if protocol and protocol != "unknown":
            proto_info = f" ({protocol}"
            if port and port != "unknown":
                proto_info += f":{port}"
            proto_info += ")"

        if action == "blocked":
            self._append_log(f"{target}{proto_info}", "BLOCK")
        elif action == "allowed_by_ip":
            self._append_log(f"{target}{proto_info}  (CDN/IP-only match)", "ALLOW")
        elif action == "allowed":
            self._append_log(f"{target}{proto_info}", "ALLOW")
        else:
            self._append_log(f"{target}{proto_info}", "INFO")

    # =======================================================================
    # Agent control
    # =======================================================================

    def _toggle_agent(self) -> None:
        if not self._controller:
            return
        if self._controller.is_running:
            self._append_log("Stopping agent...", "INFO")
            self._controller.stop_agent()
        else:
            self._append_log("Starting agent...", "INFO")
            self._controller.start_agent()

    def _update_button_state(self, state: str) -> None:
        if state == "running":
            self._start_stop_btn.setText("Stop Agent")
            self._start_stop_btn.setObjectName("danger")
            self._start_stop_btn.setEnabled(True)
        elif state == "starting":
            self._start_stop_btn.setText("Starting...")
            self._start_stop_btn.setObjectName("")
            self._start_stop_btn.setEnabled(False)
        elif state == "stopping":
            self._start_stop_btn.setText("Stopping...")
            self._start_stop_btn.setObjectName("")
            self._start_stop_btn.setEnabled(False)
        elif state == "error":
            self._start_stop_btn.setText("Error")
            self._start_stop_btn.setObjectName("danger")
            self._start_stop_btn.setEnabled(True)
        else:  # stopped
            self._start_stop_btn.setText("Start Agent")
            self._start_stop_btn.setObjectName("success")
            self._start_stop_btn.setEnabled(True)
        self._start_stop_btn.style().unpolish(self._start_stop_btn)
        self._start_stop_btn.style().polish(self._start_stop_btn)

    def _update_mode_card(self, running: bool, degraded: bool) -> None:
        if not running:
            self._cards["mode"].set_value("-")
            self._cards["mode"].set_icon("")
            self._cards["mode"].set_color("#888888")
            self._cards["mode"].set_subtitle("Mode not set")
            return

        firewall_enabled = False
        try:
            info = self._controller.get_agent_info()
            firewall_enabled = info.get("firewall_enabled", False)
        except Exception:
            pass

        if firewall_enabled:
            self._cards["mode"].set_value("Whitelist")
            self._cards["mode"].set_icon("")
            self._cards["mode"].set_color(ACCENT_ORANGE if degraded else ACCENT_GREEN)
            self._cards["mode"].set_subtitle(
                "Whitelist active (degraded)" if degraded else "Only whitelist allowed"
            )
        else:
            self._cards["mode"].set_value("Disabled")
            self._cards["mode"].set_icon("")
            self._cards["mode"].set_color("#888888")
            self._cards["mode"].set_subtitle("Firewall disabled (no admin)")

    def _on_sync_now(self) -> None:
        """Quick Action: force whitelist refresh now."""
        if not self._controller or not self._controller.is_running:
            self._append_log("Sync ignored - agent isn't running", "WARN")
            return
        try:
            self._controller.force_whitelist_sync()
            self._append_log("Sync requested...", "SYNC")
        except Exception as e:
            self._append_log(f"Sync failed: {e}", "ERROR")

    # =======================================================================
    # Activity log
    # =======================================================================

    # Tag → (foreground colour, light background)
    _TAG_COLORS = {
        "INFO":   (ACCENT_BLUE,   "#dceaf7"),
        "STATUS": (ACCENT_ORANGE, "#fde8cf"),
        "SYNC":   (ACCENT_PURPLE, "#e8e1f7"),
        "WARN":   (ACCENT_ORANGE, "#fde8cf"),
        "ERROR":  (ACCENT_RED,    "#fadcdc"),
        "BLOCK":  (ACCENT_RED,    "#fadcdc"),
        "ALLOW":  (ACCENT_GREEN,  "#d4f1e1"),
    }

    def _append_log(self, message: str, tag: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        tag = tag.upper()
        fg, bg = self._TAG_COLORS.get(tag, (ACCENT_BLUE, "#dceaf7"))
        # HTML so the tag renders as a coloured badge. Plain timestamp +
        # message stays monospace (the textbox font), but the inline span
        # for the tag uses the badge colours.
        html = (
            f'<span style="color:#666;">{timestamp}</span>&nbsp;&nbsp;'
            f'<span style="background:{bg}; color:{fg}; padding:1px 6px; '
            f'border-radius:6px; font-weight:bold;">{tag}</span>'
            f'&nbsp;&nbsp;<span style="color:{FG_PRIMARY};">'
            f'{_html_escape(message)}</span>'
        )
        self._log_widget.appendHtml(html)

    def _clear_log(self) -> None:
        self._log_widget.clear()
        self._append_log("Log cleared.", "INFO")

    def _should_log_packet(self, action_lc: str) -> bool:
        if action_lc == "blocked":
            return True
        now_ms = time.monotonic() * 1000.0
        if now_ms - self._packet_log_window_start_ms >= _PACKET_LOG_WINDOW_MS:
            if self._packet_log_dropped_in_window > 0:
                self._append_log(
                    f"... {self._packet_log_dropped_in_window} more packet event(s) "
                    "suppressed (rate limit)",
                    "INFO",
                )
            self._packet_log_window_start_ms = now_ms
            self._packet_log_count_in_window = 0
            self._packet_log_dropped_in_window = 0
        if self._packet_log_count_in_window >= _PACKET_LOG_MAX_PER_WINDOW:
            self._packet_log_dropped_in_window += 1
            return False
        self._packet_log_count_in_window += 1
        return True

    # =======================================================================
    # Helpers
    # =======================================================================

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        seconds = int(seconds or 0)
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
