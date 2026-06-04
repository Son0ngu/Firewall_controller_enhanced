"""Whitelist view for the Qt GUI.

Same controller (`WhitelistController` singleton), same behaviours:
- Local data cache + 200ms debounced search (in-memory filter, no controller hit)
- "Resolved IPs" toggle (background DNS resolution worker)
- 30s auto-sync after the agent reports ready
- Status bar feedback

The big win over the CTk port: the table is `QTableView`-backed and only
paints visible rows, so even a few thousand domains render in <100ms.
"""

import logging
import threading
from typing import Dict, List, Optional, Set

from PySide6.QtCore import QObject, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QVBoxLayout, QWidget,
)

from ..components.data_table import DataTable
from ..styles import (
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_RED, FG_PRIMARY,
    FG_SECONDARY,
)

logger = logging.getLogger("gui_qt.whitelist")


# Auto-sync cadence after the agent reports ready. Matches the CTk port.
_AUTO_SYNC_INTERVAL_MS = 30_000
_SEARCH_DEBOUNCE_MS = 200


class _ResolveSignals(QObject):
    """Helper QObject so a background worker thread can hand resolved domain
    pairs back to the GUI thread. Qt signals are thread-safe and auto-marshall."""
    finished = Signal(list)  # List[Tuple[str, str]] of (ip, domain)


class WhitelistView(QWidget):
    def __init__(self, controller_get, parent: Optional[QWidget] = None):
        """`controller_get` is the same `get_whitelist_controller` callable used
        by the CTk port - we accept it as a parameter so this view doesn't
        directly import controller modules (cleaner separation, easier to mock
        in tests)."""
        super().__init__(parent)
        self._controller = controller_get()
        self._dns_resolver = None  # Lazy - only built when "Resolved IPs" is toggled on

        # ----- data caches -------------------------------------------------
        self._last_loaded_data: List[Dict] = []
        # Resolution state (mirrors the CTk impl)
        self._resolved_data: Optional[List[tuple]] = None
        self._last_resolved_domains: Set[str] = set()
        self._resolving_thread: Optional[threading.Thread] = None
        self._resolve_lock = threading.Lock()
        self._resolve_queued_domains: Optional[List[str]] = None

        # ----- timers ------------------------------------------------------
        # 200ms debounce on the search input (Qt-native, no after_cancel dance).
        self._search_debounce = QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.setInterval(_SEARCH_DEBOUNCE_MS)
        self._search_debounce.timeout.connect(self._apply_search)

        self._auto_sync_timer = QTimer(self)
        self._auto_sync_timer.setInterval(_AUTO_SYNC_INTERVAL_MS)
        self._auto_sync_timer.timeout.connect(self._do_auto_sync)
        self._agent_ready = False

        # Signal carrier for the DNS background thread.
        self._resolve_signals = _ResolveSignals()
        self._resolve_signals.finished.connect(self._on_resolve_finished)

        self._build_ui()
        self._register_controller_callbacks()

        # Initial load (local cache only - server sync starts when agent is ready).
        QTimer.singleShot(0, self._load_data)

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        root.addWidget(self._build_stats_row())
        root.addWidget(self._build_table(), stretch=1)
        root.addWidget(self._build_status_bar())

    def _build_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        title = QLabel("IP Whitelist Manager")
        title.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )
        layout.addWidget(title)
        layout.addStretch(1)

        sync_btn = QPushButton("Sync Server")
        sync_btn.setObjectName("primary")
        sync_btn.setMinimumHeight(36)
        sync_btn.clicked.connect(self._on_sync)
        layout.addWidget(sync_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setMinimumHeight(36)
        refresh_btn.clicked.connect(self._on_refresh)
        layout.addWidget(refresh_btn)

        return layout

    def _build_stats_row(self) -> QWidget:
        wrap = QFrame()
        layout = QHBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self._stats_label = QLabel("Loading statistics...")
        self._stats_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 13px;")
        layout.addWidget(self._stats_label, stretch=1)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter...")
        self._search_input.setFixedWidth(180)
        self._search_input.textChanged.connect(self._on_search_text_changed)
        layout.addWidget(self._search_input)

        self._resolved_toggle = QCheckBox("Resolved IPs")
        self._resolved_toggle.toggled.connect(self._on_toggle_resolved)
        layout.addWidget(self._resolved_toggle)
        return wrap

    def _build_table(self) -> QWidget:
        # Widths chosen for typical content:
        #   ip:     "firewall-controller.onrender.com" fits in ~280-300px
        #   type:   "Domain" / "Pattern" / "IP" → 80px is plenty
        #   status: "Active" / "Resolved" / "Pending" → ~100px
        #   source: "Resolved from gstatic.com" can run long - make this the
        #           stretching column so it absorbs any extra width.
        columns = [
            {"key": "ip", "title": "Domain / IP Address", "width": 320},
            {"key": "type", "title": "Type", "width": 90},
            {"key": "status", "title": "Status", "width": 110},
            {"key": "source", "title": "Source", "width": 220},  # auto-stretches
        ]
        self._table = DataTable(columns, parent=self)
        return self._table

    def _build_status_bar(self) -> QWidget:
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"color: {ACCENT_GREEN}; font-size: 12px;")
        return self._status_label

    # =======================================================================
    # Controller wiring
    # =======================================================================

    def _register_controller_callbacks(self) -> None:
        # Controller callbacks fire from background threads - wrap each one in
        # a `QTimer.singleShot(0, …)` so the UI work happens on the GUI thread.
        # (Qt would also accept a queued signal connection; singleShot is the
        # simplest way to bounce a plain callable onto the event loop.)
        def on_thread_safe(fn):
            return lambda *args: QTimer.singleShot(0, lambda: fn(*args))

        self._controller.on_data_changed(on_thread_safe(self._on_data_changed))
        self._controller.on_error(on_thread_safe(self._show_error))
        self._controller.on_success(on_thread_safe(self._show_success))

    # =======================================================================
    # Data binding
    # =======================================================================

    def _load_data(self) -> None:
        self._last_loaded_data = self._controller.get_all_ips()
        self._update_table(self._last_loaded_data)
        self._update_stats()

    def _on_data_changed(self, data: List[Dict]) -> None:
        self._last_loaded_data = list(data)
        self._update_table(self._last_loaded_data)
        self._update_stats()

    def _update_table(self, data: List[Dict]) -> None:
        """Apply current search + resolved-toggle to `data` and push to the
        table. Resolved mode kicks off a background DNS resolve and bails;
        results arrive via `_on_resolve_finished`."""
        filter_text = self._search_input.text().lower().strip()
        show_resolved = self._resolved_toggle.isChecked()

        if show_resolved:
            domains = [
                item.get("ip", "") for item in data
                if item.get("type", "").lower() == "domain"
            ]
            if set(domains) != self._last_resolved_domains or self._resolved_data is None:
                self._last_resolved_domains = set(domains)
                self._resolved_data = None
                self._start_resolve_domains(domains)
                return  # Keep stale rows until resolution completes

            resolved_ips = self._resolved_data or []
            filtered: List[Dict] = []
            for ip, domain in resolved_ips:
                if filter_text and filter_text not in ip.lower():
                    continue
                filtered.append({
                    "ip": ip,
                    "type": "IP",
                    "status": "Resolved",
                    "source": f"Resolved from {domain}",
                })
            self._table.set_data(filtered)
        else:
            # Reset resolution cache when leaving resolved view.
            self._resolved_data = None
            self._last_resolved_domains = set()
            filtered = []
            for item in data:
                if item.get("type", "").lower() != "domain":
                    continue
                ip = item.get("ip", "")
                if filter_text and filter_text not in ip.lower():
                    continue
                filtered.append(item)
            self._table.set_data(filtered)

        self._update_stats()

    def _update_stats(self) -> None:
        stats = self._controller.get_stats()
        domains = stats.get("manager_domains", 0)
        ips = stats.get("manager_ips", 0)
        total = stats.get("total_ips", 0)
        active = stats.get("active", 0)
        sync_count = stats.get("sync_count", 0)

        text = (
            f"Total: {total}  |  Domains: {domains}  |  "
            f"IPs: {ips}  |  Active: {active}"
        )
        if sync_count:
            text += f"  |  Syncs: {sync_count}"
        self._stats_label.setText(text)

    # =======================================================================
    # Search / toggle handlers
    # =======================================================================

    def _on_search_text_changed(self, _text: str) -> None:
        # Restart the debounce timer on every keystroke. After 200ms of
        # quiet, `_apply_search` runs once.
        self._search_debounce.start()

    def _apply_search(self) -> None:
        if self._last_loaded_data:
            self._update_table(self._last_loaded_data)
        else:
            self._load_data()

    def _on_toggle_resolved(self, checked: bool) -> None:
        if checked:
            self._status_label.setText("Resolving domains...")
            self._status_label.setStyleSheet(f"color: {ACCENT_ORANGE};")
        else:
            self._status_label.setText("Showing domains")
            self._status_label.setStyleSheet(f"color: {ACCENT_GREEN};")
        self._load_data()

    # =======================================================================
    # Buttons
    # =======================================================================

    def _on_refresh(self) -> None:
        self._status_label.setText("Refreshing...")
        self._status_label.setStyleSheet(f"color: {ACCENT_ORANGE};")
        self._controller.refresh()

    def _on_sync(self) -> None:
        if self._controller._whitelist_manager is None:
            QMessageBox.warning(
                self, "Whitelist Sync",
                "Agent not started - please Start Agent before sync.",
            )
            return
        self._status_label.setText("Syncing with server...")
        self._status_label.setStyleSheet(f"color: {ACCENT_BLUE};")
        self._controller.refresh()

    # =======================================================================
    # DNS resolution (background thread → Qt signal)
    # =======================================================================

    def _start_resolve_domains(self, domains: List[str]) -> None:
        """Off-thread resolve of `domains`. Results arrive on the GUI thread
        via `_resolve_signals.finished` so we never touch widgets from a
        worker."""
        if self._resolving_thread and self._resolving_thread.is_alive():
            # Coalesce: just keep the latest request, drop intermediates.
            self._resolve_queued_domains = domains
            return
        self._resolve_queued_domains = None

        def worker():
            try:
                with self._resolve_lock:
                    pairs = self._resolve_domains_to_ips(domains)
            except Exception as e:
                logger.error(f"DNS resolve failed: {e}")
                pairs = []
            self._resolve_signals.finished.emit(pairs)

        self._resolving_thread = threading.Thread(
            target=worker, daemon=True, name="QtResolveDomains",
        )
        self._resolving_thread.start()

    def _on_resolve_finished(self, pairs: list) -> None:
        self._resolved_data = pairs
        if self._resolved_toggle.isChecked():
            self._status_label.setText(f"Resolved {len(pairs)} IPs")
            self._status_label.setStyleSheet(f"color: {ACCENT_GREEN};")
            self._update_table(self._last_loaded_data)
        else:
            # User toggled off mid-resolve; drop the data.
            self._resolved_data = None

        # If another resolve was queued while we were busy, run it now.
        if self._resolve_queued_domains is not None:
            next_domains = self._resolve_queued_domains
            self._resolve_queued_domains = None
            QTimer.singleShot(50, lambda: self._start_resolve_domains(next_domains))

    def _resolve_domains_to_ips(self, domains: List[str]) -> List[tuple]:
        """Resolve `domains` via the shared `OptimizedDNSResolver`, deduping
        IPs across domains so the table doesn't show the same IP twice."""
        if not domains:
            return []
        if self._dns_resolver is None:
            # Lazy import - keeps Qt startup snappy when the user never
            # toggles resolution.
            from network.dns_resolver import OptimizedDNSResolver
            self._dns_resolver = OptimizedDNSResolver()

        unique_domains = [d for d in dict.fromkeys(domains) if d]
        seen_ips: Set[str] = set()
        resolved: List[tuple] = []

        try:
            results = self._dns_resolver.resolve_multiple_parallel(unique_domains)
        except Exception as e:
            logger.error(f"Parallel resolve failed: {e}")
            return []

        for domain in unique_domains:
            record = results.get(domain)
            if not record or not getattr(record, "ipv4", None):
                continue
            for ip in record.ipv4:
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                resolved.append((ip, domain))
        return resolved

    # =======================================================================
    # Auto-sync (wired from MainWindow when agent reports ready)
    # =======================================================================

    def set_agent_ready(self, ready: bool = True) -> None:
        self._agent_ready = ready
        if ready and not self._auto_sync_timer.isActive():
            self._do_auto_sync()
            self._auto_sync_timer.start()

    def _do_auto_sync(self) -> None:
        try:
            self._controller._sync_from_manager()
            self._last_loaded_data = self._controller.get_all_ips()
            self._update_table(self._last_loaded_data)
            self._update_stats()
        except Exception as e:
            logger.debug(f"Auto-sync error (ignored): {e}")

    # =======================================================================
    # Status helpers
    # =======================================================================

    def _show_error(self, message: str) -> None:
        self._status_label.setText(message)
        self._status_label.setStyleSheet(f"color: {ACCENT_RED};")
        # Reset back to "Ready" after 3s, like the CTk port.
        QTimer.singleShot(3000, self._reset_status_label)

    def _show_success(self, message: str) -> None:
        self._status_label.setText(message)
        self._status_label.setStyleSheet(f"color: {ACCENT_GREEN};")
        self._update_stats()

    def _reset_status_label(self) -> None:
        self._status_label.setText("Ready")
        self._status_label.setStyleSheet(f"color: {ACCENT_GREEN};")

    # =======================================================================
    # Cleanup
    # =======================================================================

    def closeEvent(self, event) -> None:
        self._auto_sync_timer.stop()
        self._search_debounce.stop()
        # If "Resolved IPs" was ever toggled on we built a private resolver
        # for this view. Shut its thread pool down here so the view can be
        # destroyed without leaving DNS worker threads behind.
        if self._dns_resolver is not None:
            try:
                self._dns_resolver.shutdown()
            except Exception as e:
                logger.debug(f"DNS resolver shutdown failed: {e}")
            self._dns_resolver = None
        super().closeEvent(event)
