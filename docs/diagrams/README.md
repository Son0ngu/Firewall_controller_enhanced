# SAINT Diagram Index

Central manifest of all architecture/flow diagrams. Last updated: 2026-06-09.

- **PlantUML** (`.puml`) lives here in `docs/diagrams/`; render to SVG with
  `java -jar docs/diagrams/plantuml.jar -tsvg <file>.puml` (offline; Java 21) or
  `python docs/diagrams/render_plantuml.py <file>.puml` (auto-uses the local
  `plantuml.jar` if present, else the public server).
  NOTE: PlantUML names the output SVG after the `@startuml <NAME>` directive, not
  the `.puml` filename — hence the `SAINT_*.svg` files below.
- **Mermaid** (`.mmd`) lives in `report/diagrams/`; view directly in VS Code
  (PlantUML/Mermaid extension) or paste into https://mermaid.live. No build step.

## Use case
| Diagram | Source | Render (SVG) |
| --- | --- | --- |
| Use cases (Admin / Teacher / Agent) | `usecase_diagram.puml` | `SAINT_UseCase_Diagram.svg` |

## Class diagrams
| Level | Scope | Source | Render (SVG) |
| --- | --- | --- | --- |
| Overview | Agent packages + ownership graph | `class_overview_agent.puml` | `SAINT_Agent_Class_Overview.svg` |
| Overview | Server MVC + DI container | `class_overview_server.puml` | `SAINT_Server_Class_Overview.svg` |
| Detail | Agent (full members) | `class_diagram_agent.puml` | `SAINT_Agent_Class_Diagram.svg` |
| Detail | Server (full members) | `class_diagram_server.puml` | `SAINT_Server_Class_Diagram.svg` |

> Legacy lowercase renders (`usecase_diagram.svg`, `class_diagram_agent.svg`,
> `class_diagram_server.svg`) are stale outputs from an older render path and can
> be deleted; the current renders are the `SAINT_*.svg` files above.

## Class diagrams — per part (general, focused)
Readable per-package class diagrams (key classes + main members + intra-part
relationships). Sit between the broad overview and the dense detail diagrams.

| Part | Source | Render (SVG) |
| --- | --- | --- |
| agent.core (runtime, lifecycle, token, registry) | `class_part_agent_core.puml` | `SAINT_Class_Agent_Core.svg` |
| agent.whitelist (manager, state, syncer) | `class_part_agent_whitelist.puml` | `SAINT_Class_Agent_Whitelist.svg` |
| agent.firewall (manager, policy, rules, providers) | `class_part_agent_firewall.puml` | `SAINT_Class_Agent_Firewall.svg` |
| agent.capture / network / cache | `class_part_agent_capture_network.puml` | `SAINT_Class_Agent_Capture_Network.svg` |
| agent.services / logging_module | `class_part_agent_services.puml` | `SAINT_Class_Agent_Services.svg` |
| agent.config / shared / utils | `class_part_agent_config.puml` | `SAINT_Class_Agent_Config.svg` |
| agent.controllers / gui_qt | `class_part_agent_controllers_gui.puml` | `SAINT_Class_Agent_Controllers_GUI.svg` |
| server.controllers (10) | `class_part_server_controllers.puml` | `SAINT_Class_Server_Controllers.svg` |
| server.services (12) | `class_part_server_services.puml` | `SAINT_Class_Server_Services.svg` |
| server.models (11) + collections | `class_part_server_models.puml` | `SAINT_Class_Server_Models.svg` |
| server.middleware / bootstrap | `class_part_server_middleware.puml` | `SAINT_Class_Server_Middleware.svg` |

## Architecture flows (Mermaid — `report/diagrams/`)
| Diagram | File |
| --- | --- |
| System architecture (agents + server + Mongo) | `system_architecture.mmd` |
| Agent MVP layers | `agent_mvp_architecture.mmd` |
| Server MVC architecture | `server_mvc_architecture.mmd` |

## Agent per-part flows (Mermaid — `report/diagrams/`)
| Part | File |
| --- | --- |
| Startup / lifecycle | `agent_startup_sequence.mmd` |
| Registration + JWT + token refresh | `agent_registration_jwt.mmd` |
| Whitelist sync (server-triggered) | `whitelist_sync_sequence.mmd` |
| DNS resolution + LRU cache | `dns_resolution_cache.mmd` |
| Firewall default-deny (fail-closed) | `firewall_default_deny.mmd` |
| Packet capture -> detect -> log | `network_enforcement_flow.mmd` |
| Heartbeat loop + backoff | `heartbeat_flow.mmd` |
| Config encrypt/decrypt + migration | `config_crypto_flow.mmd` |
| GUI signal/event flow | `gui_signal_flow.mmd` |

## Server per-part flows (Mermaid — `report/diagrams/`)
| Part | File |
| --- | --- |
| Web login + JWT + RBAC | `rbac_auth_flow.mmd` |
| Agent register + API key validate | `server_agent_register_apikey.mmd` |
| Agent heartbeat processing | `server_agent_heartbeat.mmd` |
| Agent-sync merge + policy override | `server_agent_sync_merge_policy.mmd` |
| Whitelist CRUD (global/group) | `server_whitelist_crud.mmd` |
| Whitelist profile (teacher) | `server_whitelist_profile.mmd` |
| Per-agent policy (isolate/custom) | `server_agent_policy.mmd` |
| Logs ingest + realtime | `server_logs_ingest_realtime.mmd` |
| Group management + teacher scope | `server_group_management.mmd` |
| User management + audit | `server_user_management.mmd` |
| API key lifecycle | `server_apikey_lifecycle.mmd` |
| SocketIO event map | `server_socketio_events.mmd` |

## Validation status (2026-06-09)
- All 24 Mermaid flow `.mmd` validated with `@mermaid-js/mermaid-cli` (mmdc) — 24/24 parse OK.
- All PlantUML diagrams (use-case, 2 overview, 2 detail, 11 per-part) render to SVG via local `plantuml.jar` (no Graphviz needed; Smetana layout).
- To render Mermaid to images locally: `npx -y @mermaid-js/mermaid-cli -i <file>.mmd -o <file>.svg` (needs a Chrome/headless-shell for puppeteer).

## Related text references
- `docs/reference/current-flows.md` — narrative flow reference with embedded Mermaid.
- `docs/reference/agent/*.md`, `docs/reference/server/*.md` — per-module API reference.
