# SAINT Agent

Windows client application for lab workstations. The current agent entry point is `agent_gui.py`, which starts the PySide6 GUI in `gui_qt` and drives the background `core.Agent` through controllers in `controllers`.

## Main Packages

| Package | Purpose |
| --- | --- |
| `core` | Agent lifecycle, registration state, token handling, and domain callbacks. |
| `controllers` | GUI-safe orchestration for starting/stopping the agent and managing whitelist actions. |
| `gui_qt` | PySide6 desktop application, main window, views, reusable components, and Qt signal bridge. |
| `firewall` | Windows Firewall policy/rule management through `netsh`, including snapshot/restore helpers. |
| `whitelist` | Whitelist state, sync, DNS expansion, monitoring, and firewall integration. |
| `capture` | Scapy-based passive packet capture and domain extraction. |
| `services` | Heartbeat sender and server synchronization callbacks. |
| `logging_module` | Batched log delivery to the server. |
| `config` | Defaults, validation, encrypted local config, and environment overrides. |

## Run Locally

```powershell
cd agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python agent_gui.py
```

Run the agent as Administrator when testing firewall enforcement or restore flows.

## Build

```powershell
cd agent
pyinstaller saint_agent.spec --clean --noconfirm
```

The expected one-file bundle path is `dist/SAINT.exe`.
