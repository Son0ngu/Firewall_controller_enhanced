"""Settings view for the Qt GUI.

Reuses the same config crypto and firewall application service as the agent.
The view owns UI confirmation/status only; firewall writes stay in
``agent.firewall``.
"""

import json
import logging
import socket
from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from ..styles import (
    ACCENT_GREEN, ACCENT_RED, FG_PRIMARY, FG_SECONDARY,
)

logger = logging.getLogger("gui_qt.settings")


class SettingsView(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._config_path = self._find_config_path()
        self._config: Dict = self._load_config()

        # Form widgets - populated by `_build_ui` so save/restore can read them.
        self._api_key_input: Optional[QLineEdit] = None
        self._server_url_input: Optional[QLineEdit] = None
        self._heartbeat_input: Optional[QLineEdit] = None
        self._sync_input: Optional[QLineEdit] = None
        self._log_level_combo: Optional[QComboBox] = None
        self._api_key_toggle_btn: Optional[QPushButton] = None

        self._build_ui()

    # =======================================================================
    # Config IO (mirrors CTk impl so users editing in either GUI see the
    # same encrypted file)
    # =======================================================================

    @staticmethod
    def _find_config_path() -> Path:
        from config.paths import get_config_write_path

        return get_config_write_path()

    def _load_config(self) -> Dict:
        try:
            from config.crypto import decrypt_config, ENCRYPTED_EXT
            from config.loader import load_config

            enc_path = self._config_path.with_suffix(
                self._config_path.suffix + ENCRYPTED_EXT
            )
            if enc_path.exists():
                decrypted = decrypt_config(self._config_path)
                if decrypted is not None:
                    return decrypted
            if self._config_path.exists():
                with open(self._config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            return load_config()
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
        return {}

    # =======================================================================
    # UI construction
    # =======================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("Settings")
        title.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {FG_PRIMARY};"
        )
        root.addWidget(title)

        # Scrollable form so the window doesn't get unmanageably tall.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        root.addWidget(scroll, stretch=1)

        content = QWidget()
        scroll.setWidget(content)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 10, 0)  # 10px gutter for scrollbar
        content_layout.setSpacing(16)

        content_layout.addWidget(self._build_auth_section())
        content_layout.addWidget(self._build_server_section())
        content_layout.addWidget(self._build_agent_section())
        content_layout.addWidget(self._build_firewall_section())
        content_layout.addWidget(self._build_save_section())

        # Config file path footer
        footer = QLabel(f"Config file: {self._config_path.absolute()}")
        footer.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(footer)
        content_layout.addStretch(1)

    # ----- Section helper --------------------------------------------------

    def _section_card(self, title: str) -> tuple[QFrame, QFormLayout]:
        """Return (outer card frame, form layout to add rows into)."""
        wrap = QFrame()
        wrap_layout = QVBoxLayout(wrap)
        wrap_layout.setContentsMargins(0, 0, 0, 0)
        wrap_layout.setSpacing(8)

        section_title = QLabel(title)
        section_title.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {FG_PRIMARY};"
        )
        wrap_layout.addWidget(section_title)

        card = QFrame()
        card.setObjectName("card")
        form = QFormLayout(card)
        form.setContentsMargins(20, 16, 20, 16)
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        wrap_layout.addWidget(card)
        return wrap, form

    # ----- Sections --------------------------------------------------------

    def _build_auth_section(self) -> QWidget:
        wrap, form = self._section_card("Authentication")

        self._api_key_input = QLineEdit(
            self._config.get("auth", {}).get("api_key", "")
        )
        self._api_key_input.setPlaceholderText("Paste your API key here (fwc_...)")
        # Hide chars by default if there's an existing key (looks like a password)
        if self._api_key_input.text():
            self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setMinimumWidth(360)

        self._api_key_toggle_btn = QPushButton("Show")
        self._api_key_toggle_btn.setFixedWidth(64)
        self._api_key_toggle_btn.setCheckable(True)
        self._api_key_toggle_btn.clicked.connect(self._toggle_api_key_visibility)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self._api_key_input, stretch=1)
        row.addWidget(self._api_key_toggle_btn)
        row_container = QWidget()
        row_container.setLayout(row)
        form.addRow("API Key:", row_container)

        help_label = QLabel("Get your API key from the server Web UI: /api-keys")
        help_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")
        form.addRow("", help_label)
        return wrap

    def _build_server_section(self) -> QWidget:
        wrap, form = self._section_card("Server Connection")

        self._server_url_input = QLineEdit(
            self._config.get("server", {}).get("url", "http://localhost:5000")
        )
        self._server_url_input.setPlaceholderText("http://localhost:5000")
        form.addRow("Server URL:", self._server_url_input)

        self._heartbeat_input = QLineEdit(
            str(self._config.get("heartbeat", {}).get("interval", 30))
        )
        self._heartbeat_input.setValidator(QIntValidator(1, 86400, self))
        form.addRow("Heartbeat Interval (s):", self._heartbeat_input)

        self._sync_input = QLineEdit(
            str(self._config.get("whitelist", {}).get("update_interval", 60))
        )
        self._sync_input.setValidator(QIntValidator(1, 86400, self))
        form.addRow("Sync Interval (s):", self._sync_input)
        return wrap

    def _build_agent_section(self) -> QWidget:
        wrap, form = self._section_card("Agent Configuration")

        hostname_field = QLineEdit(socket.gethostname())
        hostname_field.setReadOnly(True)
        form.addRow("Hostname:", hostname_field)

        self._log_level_combo = QComboBox()
        self._log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        current = self._config.get("logging", {}).get("level", "INFO")
        idx = self._log_level_combo.findText(current)
        if idx >= 0:
            self._log_level_combo.setCurrentIndex(idx)
        form.addRow("Log Level:", self._log_level_combo)
        return wrap

    def _build_firewall_section(self) -> QWidget:
        wrap, form = self._section_card("Firewall Backup & Restore")

        description = QLabel(
            "A snapshot of your firewall state is captured the first time SAINT "
            "runs.\nUse Restore to revert all SAINT-applied changes back to that "
            "pre-SAINT state."
        )
        description.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 12px;")
        description.setWordWrap(True)
        form.addRow("", description)

        backup_path = self._config.get(
            "firewall", {}
        ).get("backup", {}).get("path", "profiles/backup.saint-snapshot.json")
        try:
            from firewall.manager import _resolve_snapshot_path
            resolved_path = str(_resolve_snapshot_path(backup_path))
        except Exception:
            resolved_path = backup_path

        path_field = QLineEdit(resolved_path)
        path_field.setReadOnly(True)
        form.addRow("Snapshot File:", path_field)

        restore_btn = QPushButton("Restore Firewall")
        restore_btn.setObjectName("primary")
        restore_btn.setMinimumHeight(34)
        restore_btn.clicked.connect(self._manual_restore)

        help_label = QLabel("Restore firewall to the state before SAINT started")
        help_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 11px;")

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.addWidget(restore_btn)
        btn_row.addWidget(help_label)
        btn_row.addStretch(1)
        btn_container = QWidget()
        btn_container.setLayout(btn_row)
        form.addRow("", btn_container)
        return wrap

    def _build_save_section(self) -> QWidget:
        wrap = QFrame()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("primary")
        save_btn.setMinimumHeight(42)
        save_btn.setMinimumWidth(220)
        save_btn.clicked.connect(self._save_config)
        layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color: {FG_SECONDARY}; font-size: 13px;")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)
        return wrap

    # =======================================================================
    # Actions
    # =======================================================================

    def _toggle_api_key_visibility(self, checked: bool) -> None:
        if not self._api_key_input:
            return
        self._api_key_input.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        if self._api_key_toggle_btn:
            self._api_key_toggle_btn.setText("Hide" if checked else "Show")

    def _save_config(self) -> None:
        try:
            # Validate server URL - required by lifecycle.initialize_components.
            url_value = (self._server_url_input.text() or "").strip() if self._server_url_input else ""
            if not url_value:
                self._show_error(
                    "Server URL is required. Enter the controller URL "
                    "(e.g. http://localhost:5000) before saving."
                )
                return
            from shared.server_urls import normalize_server_url

            normalized_url = normalize_server_url(url_value)
            if not (
                normalized_url.startswith("http://")
                or normalized_url.startswith("https://")
            ):
                self._show_error("Server URL must start with http:// or https://")
                return
            if self._server_url_input:
                self._server_url_input.setText(normalized_url)

            # Mutate config from form values.
            self._config.setdefault("auth", {})
            self._config["auth"]["api_key"] = (
                self._api_key_input.text() if self._api_key_input else ""
            )

            self._config.setdefault("server", {})
            self._config["server"]["url"] = normalized_url
            # Keep `server.urls` list in sync so the runtime sees the new endpoint.
            self._config["server"]["urls"] = [normalized_url]

            if self._heartbeat_input:
                try:
                    self._config.setdefault("heartbeat", {})
                    self._config["heartbeat"]["interval"] = int(
                        self._heartbeat_input.text()
                    )
                except ValueError:
                    pass

            if self._sync_input:
                try:
                    self._config.setdefault("whitelist", {})
                    self._config["whitelist"]["update_interval"] = int(
                        self._sync_input.text()
                    )
                except ValueError:
                    pass

            if self._log_level_combo:
                self._config.setdefault("logging", {})
                self._config["logging"]["level"] = self._log_level_combo.currentText()

            # Encrypt + write.
            from config.crypto import encrypt_config
            encrypt_config(self._config, self._config_path)
            if normalized_url != url_value:
                self._show_success(f"Settings saved. Server URL normalized to {normalized_url}")
            else:
                self._show_success("Settings saved successfully!")
        except Exception as e:
            self._show_error(str(e))

    def _manual_restore(self) -> None:
        """Restore firewall to pre-SAINT state from snapshot."""
        try:
            from firewall.manager import _resolve_snapshot_read_path
            from firewall.utils import FirewallUtils
            from firewall.application_service import FirewallApplicationService

            backup_path = self._config.get(
                "firewall", {}
            ).get("backup", {}).get("path", "profiles/backup.saint-snapshot.json")
            file_path = _resolve_snapshot_read_path(backup_path)

            if not file_path.exists():
                self._show_error(
                    f"No snapshot found: {file_path}\n"
                    "Agent must have run at least once to create one."
                )
                return

            # Without admin, firewall writes can fail silently and we'd lie to
            # the user.
            if not FirewallUtils.has_admin_privileges():
                self._show_error(
                    "Restore requires administrator privileges. "
                    "Please relaunch SAINT as administrator."
                )
                return

            with open(file_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
            timestamp = snapshot.get("timestamp", "unknown")

            reply = QMessageBox.question(
                self,
                "Restore Firewall",
                f"Restore firewall to the state saved at:\n{timestamp}\n\n"
                "This will revert all changes made by SAINT.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

            rule_prefix = (
                self._config.get("firewall", {}).get("rule_prefix", "FirewallController")
            )

            # Fast path: if the agent is running, delegate to its FirewallManager
            # so its in-memory state stays consistent with disk.
            from controllers.agent_controller import AgentController
            ctrl = AgentController()
            manager = None
            if ctrl.is_running and getattr(ctrl, "_agent", None) and getattr(ctrl._agent, "firewall", None):
                manager = ctrl._agent.firewall

            service = FirewallApplicationService(
                rule_prefix=rule_prefix,
                manager=manager,
            )
            if service.restore_firewall_snapshot(backup_path):
                self._show_success("Firewall restored to pre-SAINT state")
            else:
                self._show_error(
                    "Restore failed. See agent.log for details and verify firewall state in wf.msc."
                )

        except Exception as e:
            self._show_error(f"Restore failed: {e}")

    # =======================================================================
    # Status helpers
    # =======================================================================

    def _show_success(self, message: str) -> None:
        self._status_label.setText(message)
        self._status_label.setStyleSheet(f"color: {ACCENT_GREEN}; font-size: 13px;")
        QTimer.singleShot(5000, lambda: self._status_label.setText(""))

    def _show_error(self, message: str) -> None:
        self._status_label.setText(f"Error: {message}")
        self._status_label.setStyleSheet(f"color: {ACCENT_RED}; font-size: 13px;")
