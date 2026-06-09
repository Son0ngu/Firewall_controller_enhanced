# SAINT Current Runtime Flows

Last checked against source: 2026-06-09.

This page is the current source-readable flow reference for the recent Agent,
Server, whitelist, packaging, and config changes. It intentionally uses
Mermaid diagrams so the flow can be reviewed without opening DrawIO.

## Source Anchors

| Area | Current source of truth |
| --- | --- |
| Web whitelist routes | `server/controllers/whitelist_controller.py` |
| Unified whitelist service | `server/services/whitelist_service.py` |
| Group/profile whitelist | `server/services/whitelist_profile_service.py`, `server/models/group_model.py` |
| Group Detail whitelist editor | `server/views/static/js/group_detail.js` |
| Logs page filters/realtime | `server/views/static/js/logs.js`, `server/services/log_service.py` |
| Agent whitelist sync | `agent/whitelist/manager.py`, `agent/whitelist/state.py` |
| Firewall allow rules | `agent/firewall/manager.py`, `agent/firewall/utils.py` |
| Server URL/config paths | `agent/shared/server_urls.py`, `agent/config/paths.py` |
| Config encryption | `agent/config/crypto.py` (Fernet + per-install salt) |
| Firewall default-deny policy | `agent/firewall/policy.py` (`enable_default_deny`, `verify_default_deny`) |
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

## Group Detail Inline Whitelist Flow

The Group Detail page no longer trusts `group.whitelist[]` for the visible
count. It resolves the group rows from the unified management API so the
banner and inline editor match the Whitelist page.

```mermaid
flowchart TD
    PAGE["Group Detail page"] --> GROUP["GET /api/groups/<group_id>"]
    PAGE --> WH["GET /api/whitelist?scope=group&group_id=<group_id>&limit=1000"]

    GROUP --> META["Group metadata / whitelist version"]
    WH --> RAW["items / domains / whitelist / data"]
    RAW --> NORMALIZE["Normalize rows to entry objects"]
    NORMALIZE --> FALLBACK{"No unified rows?"}
    FALLBACK -->|"Yes"| LEGACY["Fallback to group.whitelist[]"]
    FALLBACK -->|"No"| SET["Set wlGroupData.whitelist = unified rows"]
    LEGACY --> SET

    SET --> COUNTERS["Update wlCount / wlTotalCount / whitelistCount"]
    SET --> BANNER["Banner shows real group-base count"]
    SET --> ADDDEL["Add/Delete use /api/whitelist bulk + DELETE /api/whitelist/<id>"]
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
    ESSENTIAL --> RULES["Create SAINT allow rules + self-allow (agent program path) FIRST"]
    RULES --> DENY["enable_default_deny(): set block-outbound on ALL 3 profiles"]
    DENY --> VERIFY{"verify_default_deny(): get_current_policy() shows all 3 = block?"}
    VERIFY -->|"Yes (success_count == 3)"| ACTIVE["default_deny_enabled=True; whitelist_mode_active"]
    VERIFY -->|"No / partial"| FAILCLOSED["Return False; default_deny_enabled=False (no false 'enabled')"]
    ACTIVE --> SNAPSHOT["Snapshot/restore stored in %LOCALAPPDATA%/SAINT/profiles"]

    NPCAP{"Npcap/WinPcap available?"} -->|"Yes"| SNIFFER["Start packet sniffer"]
    NPCAP -->|"No"| SKIP["Mark packet_sniffer skipped; firewall/whitelist still run"]
```

Default-deny is fail-closed on the "enabled" claim: allow rules and the
agent self-allow rule are created *before* the policy flip, and the manager
only marks `whitelist_mode_active` when all three profiles verify as blocking.

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

## Config Encryption / Decryption Flow

`agent_config.json` holds the API key and JWT, so it is stored encrypted with
Fernet. The key is derived from machine identity **plus a per-install random
salt** (`secrets.token_bytes(32)`) kept in an ACL-restricted `.salt` file, so
the key can no longer be reproduced from public host identifiers (hostname +
MAC) alone. Configs written by the old machine-only key are migrated forward on
read.

```mermaid
flowchart TD
    ENC["encrypt_config(config, path)"] --> SALT["_load_or_create_salt(path): read .salt or generate 32 random bytes"]
    SALT --> RESTRICT["restrict_to_owner(.salt): icacls / chmod"]
    SALT --> KEY["_get_salted_key(): SHA256(hostname + MAC + salt)"]
    KEY --> WRITEENC["Write agent_config.json.enc; restrict_to_owner(.enc); delete plaintext"]

    DEC["decrypt_config(path)"] --> READ["Read .enc bytes"]
    READ --> TRY1{"_try_decrypt with salted key?"}
    TRY1 -->|"OK"| RETURN["Return config"]
    TRY1 -->|"InvalidToken"| TRY2{"_try_decrypt with LEGACY _get_machine_key()?"}
    TRY2 -->|"OK (old .enc)"| MIGRATE["Migrate: re-encrypt with salted key, then return config"]
    TRY2 -->|"Fail"| NONE["Return None (wrong machine / corrupt)"]
    MIGRATE --> RETURN
```

Limitation: a local admin who can read both the `.enc` and the `.salt` file can
still decrypt — inherent to local symmetric encryption without TPM/DPAPI. The
salt defends against ciphertext-only exposure (backup, AV quarantine, a leaked
`.enc`).

## Current Warning Baseline

After the whitelist legacy service cleanup, full tests no longer emit
`get_all_domains` or `delete_domain` deprecation warnings. Remaining warnings
are JWT HMAC key length warnings from local test secrets shorter than 32 bytes.

## Logs Filter And Realtime Flow

The Logs page uses server-side filtering for the initial fetch, but the realtime
Socket.IO stream must also respect the active client filter. This matters for
demo clones where hostname/display name can diverge from the same agent ID.

```mermaid
flowchart TD
    UI["Logs page"] --> LOAD["GET /api/logs?agent_id=&level=&search=&time_range=&limit="]
    LOAD --> SRV["LogService.get_all_logs"]
    SRV --> LIST["logsData raw buffer"]
    LIST --> MATCH["Client matcher: level + agent + search + time"]
    MATCH --> VIEW["Visible logs rendered"]

    SOCKET["Socket.IO new_log"] --> CHECK{"Matches current filters?"}
    CHECK -->|"No"| SKIP["Skip prepend"]
    CHECK -->|"Yes"| PREPEND["unshift + re-render visible list"]
```

Client filter rules:

- If selected agent and log both expose hostname/display name, compare the
  visible name first.
- If name is missing, fall back to `agent_id`.
- Search runs against domain, destination, IPs, protocol, agent labels and
  reconstructed detail text.
- `logCount` reflects the rendered subset, not the raw buffer.
