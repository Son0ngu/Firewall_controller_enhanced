# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# PyInstaller provides SPECPATH as the directory containing this spec file.
AGENT_ROOT = Path(SPECPATH)
REPO_ROOT = AGENT_ROOT.parent
ICON_FILE = AGENT_ROOT / "miku.ico"


# ---------------------------------------------------------------------------
# Hidden imports
# ---------------------------------------------------------------------------

hiddenimports = [
    # Core modules
    "core",
    "core.agent",
    "core.handlers",
    "core.lifecycle",
    "core.registry",
    "core.token_manager",

    # Config
    "config",
    "config.loader",
    "config.defaults",
    "config.validator",
    "config.crypto",

    # Capture
    "capture",
    "capture.sniffer",
    "capture.extractors",
    "capture.scapy_config",
    "capture.winpcap_installer",

    # Firewall
    "firewall",
    "firewall.application_service",
    "firewall.manager",
    "firewall.netsecurity_provider",
    "firewall.netsh_provider",
    "firewall.policy",
    "firewall.provider",
    "firewall.rules",
    "firewall.utils",

    # Whitelist
    "whitelist",
    "whitelist.manager",
    "whitelist.state",
    "whitelist.sync",
    "whitelist.monitor",

    # Services
    "services",
    "services.heartbeat",

    # Logging
    "logging_module",
    "logging_module.sender",

    # Network
    "network",
    "network.dns_resolver",

    # Cache
    "cache",
    "cache.lru_cache",

    # Shared
    "shared",
    "shared.os_info",
    "shared.server_urls",
    "shared.time_utils",

    # Utils
    "utils",
    "utils.ip_detector",
    "utils.error_handler",
    "utils.validators",

    # GUI controllers
    "controllers",
    "controllers.agent_controller",
    "controllers.whitelist_controller",

    # Qt GUI
    "gui_qt",
    "gui_qt.app",
    "gui_qt.main_window",
    "gui_qt.signal_bridge",
    "gui_qt.styles",
    "gui_qt.components",
    "gui_qt.components.status_card",
    "gui_qt.components.data_table",
    "gui_qt.components.log_console",
    "gui_qt.components.sparkline",
    "gui_qt.views",
    "gui_qt.views.dashboard",
    "gui_qt.views.firewall",
    "gui_qt.views.whitelist",
    "gui_qt.views.logs",
    "gui_qt.views.settings",

    # Package-style imports used by some GUI/runtime fallbacks.
    "agent",
    "agent.cache",
    "agent.cache.lru_cache",
    "agent.capture",
    "agent.capture.extractors",
    "agent.capture.scapy_config",
    "agent.capture.sniffer",
    "agent.capture.winpcap_installer",
    "agent.config",
    "agent.config.crypto",
    "agent.config.defaults",
    "agent.config.loader",
    "agent.config.validator",
    "agent.controllers",
    "agent.controllers.agent_controller",
    "agent.controllers.whitelist_controller",
    "agent.core",
    "agent.core.agent",
    "agent.core.handlers",
    "agent.core.lifecycle",
    "agent.core.registry",
    "agent.core.token_manager",
    "agent.firewall",
    "agent.firewall.application_service",
    "agent.firewall.manager",
    "agent.firewall.netsecurity_provider",
    "agent.firewall.netsh_provider",
    "agent.firewall.policy",
    "agent.firewall.provider",
    "agent.firewall.rules",
    "agent.firewall.utils",
    "agent.gui_qt",
    "agent.gui_qt.app",
    "agent.gui_qt.main_window",
    "agent.gui_qt.signal_bridge",
    "agent.gui_qt.styles",
    "agent.gui_qt.components",
    "agent.gui_qt.components.data_table",
    "agent.gui_qt.components.log_console",
    "agent.gui_qt.components.sparkline",
    "agent.gui_qt.components.status_card",
    "agent.gui_qt.views",
    "agent.gui_qt.views.dashboard",
    "agent.gui_qt.views.firewall",
    "agent.gui_qt.views.logs",
    "agent.gui_qt.views.settings",
    "agent.gui_qt.views.whitelist",
    "agent.logging_module",
    "agent.logging_module.sender",
    "agent.network",
    "agent.network.dns_resolver",
    "agent.services",
    "agent.services.heartbeat",
    "agent.shared",
    "agent.shared.os_info",
    "agent.shared.server_urls",
    "agent.shared.time_utils",
    "agent.utils",
    "agent.utils.error_handler",
    "agent.utils.ip_detector",
    "agent.utils.validators",
    "agent.whitelist",
    "agent.whitelist.manager",
    "agent.whitelist.monitor",
    "agent.whitelist.state",
    "agent.whitelist.sync",

    # Third party
    "dns",
    "dns.resolver",
    "requests",
    "psutil",
    "zoneinfo",
    "aiodns",
    "netifaces",
    "pydivert",

    # pywin32
    "win32api",
    "win32con",
    "win32event",
    "win32process",
    "win32security",
    "win32service",
    "win32serviceutil",
    "pywintypes",
    "winerror",

    # cryptography
    "cryptography",
    "cryptography.fernet",
    "cryptography.hazmat.backends",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.primitives.ciphers.aead",
]

# Scapy lazy-loads protocol layers such as DNS, HTTP, and TLS.
hiddenimports += collect_submodules("scapy")


# ---------------------------------------------------------------------------
# Data files
# ---------------------------------------------------------------------------

datas = []

if ICON_FILE.exists():
    datas.append((str(ICON_FILE), "."))

# PySide6 plugins needed for a portable windowed app.
datas += collect_data_files("PySide6", subdir="plugins/platforms")
datas += collect_data_files("PySide6", subdir="plugins/imageformats")
datas += collect_data_files("PySide6", subdir="plugins/styles")

# Runtime data loaded lazily by Scapy and pydivert.
datas += collect_data_files("scapy", include_py_files=False)
datas += collect_data_files("pydivert", include_py_files=False)


# ---------------------------------------------------------------------------
# Excludes
# ---------------------------------------------------------------------------

excludes = [
    "customtkinter",
    "darkdetect",
    "tkinter",
    "_tkinter",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "matplotlib",
    "pandas",
    "numpy",
    "scipy",
    "PIL",
    "Pillow",
]


# ========================================
# GUI Application
# ========================================

a_gui = Analysis(
    [str(AGENT_ROOT / "agent_gui.py")],
    pathex=[str(REPO_ROOT), str(AGENT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz_gui = PYZ(a_gui.pure)

exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    a_gui.binaries,
    a_gui.zipfiles,
    a_gui.datas,
    [],
    exclude_binaries=False,
    name="SAINT",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # Windowed mode - no console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_FILE) if ICON_FILE.exists() else None,
    uac_admin=True,  # Require admin to run
)
