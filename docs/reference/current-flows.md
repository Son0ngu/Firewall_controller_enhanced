# SAINT Current Runtime Flows

Last checked against source: 2026-06-05.

This page is the current source-readable flow reference for the recent Agent,
Server, whitelist, packaging, and config changes. It intentionally uses
Mermaid diagrams so the flow can be reviewed without opening DrawIO.

## Source Anchors

| Area | Current source of truth |
| --- | --- |
| Web whitelist routes | `server/controllers/whitelist_controller.py` |
| Unified whitelist service | `server/services/whitelist_service.py` |
| Group/profile whitelist | `server/services/whitelist_profile_service.py`, `server/models/group_model.py` |
| Agent whitelist sync | `agent/whitelist/manager.py`, `agent/whitelist/state.py` |
| Firewall allow rules | `agent/firewall/manager.py`, `agent/firewall/utils.py` |
| Server URL/config paths | `agent/shared/server_urls.py`, `agent/config/paths.py` |
| Build artifact | `agent/saint_agent.spec` -> `dist/SAINT.exe` |

## Whitelist Web CRUD Flow

`/api/whitelist` remains a compatibility route because the current web UI still
calls it. Internally, list/delete now use the unified entry API.

```mermaid
flowchart TD
    UI["Web UI: whitelist.js"] --> GET["GET /api/whitelist"]
    UI --> POST["POST /api/whitelist"]
    UI --> DEL["DELETE /api/whitelist/<id>"]
    UI --> BULK["POST /api/whitelist/bulk or bulk-delete"]

    GET --> LOGIN["require_login + inject_current_user"]
    POST --> LOGIN
    DEL --> LOGIN
    BULK --> LOGIN

    LOGIN --> TEACHER{"Teacher request?"}
    TEACHER -->|"Yes"| RBAC["Check teacher group ownership"]
    TEACHER -->|"No"| ADMIN["Admin path"]

    RBAC --> LIST["list_domains(): service.get_all_entries(filters, limit, offset)"]
    ADMIN --> LIST
    LIST --> SHAPE["Response keeps both items[] and domains[]"]
    SHAPE --> UI

    RBAC --> ADD["add_domain(): service.add_entry(...)"]
    ADMIN --> ADD
    ADD --> STORE["Global row or group entry row"]
    STORE --> SOCKET["SocketIO whitelist_updated"]
    SOCKET --> UI

    RBAC --> DELETE["delete_domain(): service.bulk_delete_entries([id])"]
    ADMIN --> DELETE
    DELETE --> DELETEPATH{"ID type"}
    DELETEPATH -->|"Global ObjectId"| GLOBALDEL["WhitelistModel.delete_entry"]
    DELETEPATH -->|"Group entry ObjectId"| GROUPDEL["WhitelistEntryModel.delete_entry or embedded ObjectId delete"]
    DELETEPATH -->|"Legacy pseudo-ID"| PSEUDODEL["groups.whitelist[] fallback delete"]
    GLOBALDEL --> SOCKET
    GROUPDEL --> SOCKET
    PSEUDODEL --> SOCKET
```

## Agent Whitelist Sync And Merge Flow

The server always starts from global entries, then chooses either an active
profile or the group base whitelist. An active profile replaces the group base,
but global entries still remain.

```mermaid
flowchart TD
    AGENT["Agent WhitelistManager.sync_now"] --> SYNC["GET /api/whitelist/agent-sync"]
    SYNC --> AUTH["require_jwt"]
    AUTH --> SERVICE["WhitelistService.get_agent_sync_data"]

    SERVICE --> GLOBAL["Load global entries"]
    SERVICE --> AGENTGROUP["Find agent group"]
    AGENTGROUP --> PROFILE{"Active whitelist profile?"}

    PROFILE -->|"Yes"| PROFILELIST["Use active profile domains"]
    PROFILE -->|"No"| GROUPLIST["Use group base whitelist"]

    GLOBAL --> MERGE["Merge by type:value"]
    PROFILELIST --> MERGE
    GROUPLIST --> MERGE

    MERGE --> WIN{"Duplicate type:value?"}
    WIN -->|"Global + Group/Profile"| SPECIFIC["Specific scope wins; high priority is preserved"]
    WIN -->|"No duplicate"| COMBINED["Combined whitelist"]
    SPECIFIC --> COMBINED

    COMBINED --> POLICY{"Agent policy override?"}
    POLICY -->|"none"| RESPONSE["Return full/versioned sync payload"]
    POLICY -->|"isolate"| ISOLATE["Keep server host only; no public DNS injection"]
    POLICY -->|"custom_whitelist"| CUSTOM["Use custom entries + server host"]
    ISOLATE --> RESPONSE
    CUSTOM --> RESPONSE

    RESPONSE --> STATE["Agent WhitelistState.parse"]
    STATE --> NORMALIZE["Normalize URL/pattern/domain to host values"]
    NORMALIZE --> APPLY["FirewallManager applies allow rules"]
```

### Merge Rules

| Situation | Result |
| --- | --- |
| No active profile | `Global + Group base whitelist` |
| Active profile exists | `Global + Active profile whitelist`; group base is replaced |
| Same `type:value` in global and group/profile | More specific group/profile entry wins |
| `type=url` full URL | Canonicalized to hostname before store/sync |
| Wildcard URL host | Stored/synced as hostname pattern such as `*.example.com` |

## Agent Apply Firewall Flow

Agent firewall rules are IP based, so only exact domains are DNS-resolved.
Hostname patterns are used for matching state, not DNS resolution.

```mermaid
flowchart TD
    PAYLOAD["Sync payload domains[]"] --> STATE["WhitelistState buckets"]
    STATE --> DOMAINS["Exact domains"]
    STATE --> PATTERNS["Hostname patterns"]
    STATE --> STATICIPS["Static IP entries"]

    DOMAINS --> DNS["Resolve exact domains to IPv4"]
    PATTERNS --> MATCHONLY["Pattern match only; do not DNS resolve"]
    STATICIPS --> IPS["Allowed IP set"]
    DNS --> IPS

    IPS --> ESSENTIAL["Add localhost + system DNS + local IP/gateway"]
    ESSENTIAL --> RULES["Create SAINT allow rules"]
    RULES --> DENY["Enable whitelist_only default deny"]
    DENY --> SNAPSHOT["Snapshot/restore stored in %LOCALAPPDATA%/SAINT/profiles"]

    NPCAP{"Npcap/WinPcap available?"} -->|"Yes"| SNIFFER["Start packet sniffer"]
    NPCAP -->|"No"| SKIP["Mark packet_sniffer skipped; firewall/whitelist still run"]
```

## Config And Packaging Flow

```mermaid
flowchart TD
    BUILD["pyinstaller agent/saint_agent.spec --clean --noconfirm"] --> EXE["dist/SAINT.exe"]
    EXE --> START["User starts SAINT"]
    START --> CONFIGREAD["Read config candidates"]
    CONFIGREAD --> APPDATA["Prefer %LOCALAPPDATA%/SAINT/agent_config.json.enc"]
    CONFIGREAD --> LEGACY["Fallback legacy config paths read-only"]

    APPDATA --> URL{"Server URL configured?"}
    URL -->|"No"| OFFLINE["Offline first-run mode; no controller traffic"]
    URL -->|"Yes"| REGISTER["Register/heartbeat/sync/log sender"]

    START --> SNAPSHOT["Firewall snapshot relative path"]
    SNAPSHOT --> SNAPAPPDATA["Resolve to %LOCALAPPDATA%/SAINT/profiles"]
    SNAPAPPDATA --> RESTORE["Restore falls back to legacy exe/install dir snapshot if needed"]
```

## Current Warning Baseline

After the whitelist legacy service cleanup, full tests no longer emit
`get_all_domains` or `delete_domain` deprecation warnings. Remaining warnings
are JWT HMAC key length warnings from local test secrets shorter than 32 bytes.
