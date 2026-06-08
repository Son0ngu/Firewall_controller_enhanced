# `server/services` - Business logic layer

## Mục đích
Tầng business logic giữa controllers (HTTP) và models (DB). Mỗi service nhận một hoặc nhiều model trong constructor + tuỳ chọn `socketio`. Mọi side effect (DB write, socket emit, audit log) tập trung ở đây. Controllers chỉ validate/parse request rồi gọi service.

12 services. Pattern chung:
- Method trả `Dict` cho success/error responses HOẶC `Tuple[bool, data, error_msg]` cho auth-style flows
- Emit socketio event cho real-time UI khi side effect ảnh hưởng admin/teacher view
- Audit log qua `AuditService.log_action` cho mọi mutation

## Public API

### `services/jwt_service.py` - `JWTService`

Token operations cho Agent JWT. Token rotation hỗ trợ tuỳ chọn.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `ACCESS_TOKEN_EXPIRY_HOURS = 24` / `REFRESH_TOKEN_EXPIRY_DAYS = 7` | const | [jwt_service.py:18-19](../../../server/services/jwt_service.py#L18) | Lifetime |
| `JWT_ALGORITHM = "HS256"` | const | [jwt_service.py:20](../../../server/services/jwt_service.py#L20) | |
| `JWT_SECRET_KEY` / `JWT_REFRESH_SECRET_KEY` | env | [jwt_service.py:23-24](../../../server/services/jwt_service.py#L23) | **Production raise** nếu thiếu. Dev fallback random - tokens invalid sau restart |
| `JWTService.__init__(db=None)` | | [jwt_service.py:44](../../../server/services/jwt_service.py#L44) | Tạo `revoked_tokens` collection với TTL index nếu db provided |
| `.generate_tokens(agent_id, user_id, additional_claims=None)` | `→ Dict` | [jwt_service.py:81](../../../server/services/jwt_service.py#L81) | Issue cặp access+refresh với JTI unique. Claims: `sub, user_id, jti, type, iat, exp, iss="firewall-controller"`. Trả `access_token, refresh_token, token_type, *_expires_in, *_expires_at` |
| `.validate_access_token(token)` | `→ (bool, payload, error)` | [jwt_service.py:142](../../../server/services/jwt_service.py#L142) | Require claims `sub/jti/type/exp`. Check `type=="access"`. Check revoked qua JTI |
| `.validate_refresh_token(token)` | `→ (bool, payload, error)` | [jwt_service.py:180](../../../server/services/jwt_service.py#L180) | Tương tự nhưng `type=="refresh"` |
| `.refresh_access_token(refresh_token)` | `→ (bool, tokens, error)` | [jwt_service.py:218](../../../server/services/jwt_service.py#L218) | **Chỉ access**, refresh không đổi. Used by Agent `/api/auth/refresh` mặc định |
| `.refresh_tokens_with_rotation(refresh_token)` | | [jwt_service.py:262](../../../server/services/jwt_service.py#L262) | **Revoke refresh cũ + issue cặp mới**. Chống reuse attack. Agent gọi với `rotate=true` |
| `.revoke_token(token, token_type="access")` | `→ bool` | [jwt_service.py:316](../../../server/services/jwt_service.py#L316) | Decode (allow expired) → upsert vào `revoked_tokens` với TTL = `exp` |
| `.revoke_all_agent_tokens(agent_id)` | `→ int` | [jwt_service.py:378](../../../server/services/jwt_service.py#L378) | Ghi marker `revoke_all` theo `agent_id`; validate token sau đó sẽ chặn token cũ của agent này ngay |
| `.decode_token_without_verification(token)` | | [jwt_service.py:419](../../../server/services/jwt_service.py#L419) | Debug helper. **KHÔNG verify signature** |
| `.get_token_info(token)` | `→ Dict` | [jwt_service.py:437](../../../server/services/jwt_service.py#L437) | Status snapshot (agent_id, type, expires_at, is_expired, is_revoked) |
| `.{_is_token_revoked, _setup_indexes}` | | [jwt_service.py:408, 66](../../../server/services/jwt_service.py#L408) | Internal |
| `init_jwt_service(db=None)` | | [jwt_service.py:479](../../../server/services/jwt_service.py#L479) | Tạo singleton global `_jwt_service`. Gọi từ `app.register_controllers` |
| `get_jwt_service()` | `→ Optional[JWTService]` | [jwt_service.py:486](../../../server/services/jwt_service.py#L486) | Accessor |

### `services/rbac_service.py` - `RBACService`

Owns ownership check + query filter builder cho teacher.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(group_model=None, agent_model=None)` | | [rbac_service.py:25](../../../server/services/rbac_service.py#L25) | Optional models cho filter helpers |
| `.check_permission(role, permission)` | `→ bool` | [rbac_service.py:34](../../../server/services/rbac_service.py#L34) | Wrap `rbac_config.check_permission` |
| `.get_permissions(role)` | `→ List[str]` | [rbac_service.py:38](../../../server/services/rbac_service.py#L38) | Wrap |
| `.is_admin(role)` | `→ bool` | [rbac_service.py:42](../../../server/services/rbac_service.py#L42) | Wrap |
| `.is_owner(user_id, resource)` | `→ bool` | [rbac_service.py:50](../../../server/services/rbac_service.py#L50) | Compare `resource.created_by == user_id` |
| `.can_access_group(user, group)` | `→ bool` | [rbac_service.py:60](../../../server/services/rbac_service.py#L60) | Admin True. Teacher: `user._id ∈ group.teacher_ids` OR legacy `created_by` |
| `.filter_groups_for_user(user, groups)` | `→ List[Dict]` | [rbac_service.py:75](../../../server/services/rbac_service.py#L75) | Filter list theo access. Admin pass through |
| `.get_teacher_group_ids(user)` | `→ Optional[List[str]]` | [rbac_service.py:98](../../../server/services/rbac_service.py#L98) | Admin → None (all). Teacher → list ids. **None vs `[]` khác nhau** |
| `.get_group_query_filter(user)` | `→ Optional[Dict]` | [rbac_service.py:124](../../../server/services/rbac_service.py#L124) | None cho admin, `{"$or": [teacher_ids, created_by]}` cho teacher |
| `.get_agent_query_filter(user)` | `→ Optional[Dict]` | [rbac_service.py:139](../../../server/services/rbac_service.py#L139) | None / `{"group_id": {"$in": [...]}}` |
| `.get_log_query_filter(user)` | `→ Optional[Dict]` | [rbac_service.py:155](../../../server/services/rbac_service.py#L155) | None / `{"agent_id": {"$in": [...]}}` - chain teacher → groups → agents → logs |
| `.get_whitelist_query_filter(user)` | `→ Optional[Dict]` | [rbac_service.py:192](../../../server/services/rbac_service.py#L192) | None / `{"$or": [{"scope":"global"}, {"group_id":{"$in":[...]}}]}` |
| `.validate_group_ids_ownership(user, group_ids)` | `→ (bool, List[str])` | [rbac_service.py:214](../../../server/services/rbac_service.py#L214) | Bulk validate. Admin pass. Trả invalid ids |
| `.can_teacher_access_agent(user, agent)` | `→ bool` | [rbac_service.py:243](../../../server/services/rbac_service.py#L243) | Admin pass. Teacher check `agent.group_id ∈ teacher_group_ids` |

### `services/admin_auth_service.py` - `AdminAuthService`

Login flow cho Admin/Teacher. Bcrypt password. Session record. Brute-force protection.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `MIN_PASSWORD_LENGTH = 8` / `MAX_PASSWORD_BYTES = 72` | const | [admin_auth_service.py:24-25](../../../server/services/admin_auth_service.py#L24) | Bcrypt chỉ dùng 72 UTF-8 bytes đầu |
| `__init__(user_model, jwt_service, session_model, audit_service, socketio=None)` | | [admin_auth_service.py:31](../../../server/services/admin_auth_service.py#L31) | |
| `.login(username, password, ip_address=None, user_agent=None)` | `→ (bool, {user, tokens}, error)` | [admin_auth_service.py:45](../../../server/services/admin_auth_service.py#L45) | Flow: find_by_username → check active/locked → bcrypt verify → reset attempts → generate_tokens với `additional_claims={token_for: "admin_user", role, username}` → create session → audit `auth.login` |
| `.logout(access_token, refresh_token=None)` | `→ (bool, error)` | [admin_auth_service.py:148](../../../server/services/admin_auth_service.py#L148) | Revoke 2 JTI (session + jwt_service) |
| `.refresh_token(refresh_token)` | `→ (bool, tokens, error)` | [admin_auth_service.py:177](../../../server/services/admin_auth_service.py#L177) | **Re-issue cặp tokens với admin claims** (vì `JWTService.refresh_access_token` không carry additional_claims). Validate user còn active |
| `.change_password(user_id, old_password, new_password)` | `→ (bool, error)` | [admin_auth_service.py:225](../../../server/services/admin_auth_service.py#L225) | Verify old → validate new (length) → bcrypt hash → update → audit `profile.change_password` |
| `_hash_password / _verify_password / _validate_password / _extract_jti / _sanitize_user` | staticmethods/methods | [admin_auth_service.py:261-307](../../../server/services/admin_auth_service.py#L261) | Helpers. Sanitize loại bỏ `password_hash, failed_login_attempts, locked_until` |

### `services/audit_service.py` - `AuditService`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(audit_model)` | | [audit_service.py:21](../../../server/services/audit_service.py#L21) | |
| `.log_action(user, action, resource_type, resource_id=None, details=None, ip_address=None)` | `→ None` | [audit_service.py:25](../../../server/services/audit_service.py#L25) | Auto-detect IP từ `flask.request.remote_addr`. **Never raise** - swallow exception |
| `.get_logs(query=None, limit=100, skip=0)` | `→ List[Dict]` | [audit_service.py:71](../../../server/services/audit_service.py#L71) | Serialize ObjectId |
| `.get_user_activity(user_id, limit=50)` | | [audit_service.py:77](../../../server/services/audit_service.py#L77) | |
| `.count_logs(query=None)` | | [audit_service.py:82](../../../server/services/audit_service.py#L82) | |
| `_serialize(log)` | `@staticmethod` | [audit_service.py:86](../../../server/services/audit_service.py#L86) | `_id` → str, `user_id` → str |

### `services/user_service.py` - `UserService`

CRUD teacher accounts. Admin only operations.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(user_model, audit_service, socketio=None)` | | [user_service.py:24](../../../server/services/user_service.py#L24) | |
| `.create_user(username, password, role="teacher", email=None, created_by_user=None)` | `→ (bool, user, error)` | [user_service.py:35](../../../server/services/user_service.py#L35) | Validate username (3-50, alnum/_/.-), uniqueness, role in VALID_ROLES, password length. bcrypt rounds=12 |
| `.get_user_by_id(user_id)` | `→ Optional[Dict]` | [user_service.py:122](../../../server/services/user_service.py#L122) | Sanitized |
| `.get_all_users(query=None, limit=100, skip=0)` | | [user_service.py:129](../../../server/services/user_service.py#L129) | Sanitized list |
| `.update_user(user_id, update_data, updated_by_user=None)` | `→ (bool, error)` | [user_service.py:139](../../../server/services/user_service.py#L139) | **Allowlist `email, role, is_active`** - không update password qua đây |
| `.toggle_active(user_id, is_active, updated_by_user=None)` | | [user_service.py:176](../../../server/services/user_service.py#L176) | Block disable last admin (count check) |
| `.reset_password(user_id, new_password, reset_by_user=None)` | | [user_service.py:208](../../../server/services/user_service.py#L208) | Admin reset, không cần old_password |
| `.delete_user(user_id, deleted_by_user=None)` | | [user_service.py:245](../../../server/services/user_service.py#L245) | Block delete last admin + self-delete |
| `.ensure_default_admin(username=None, password=None)` | `→ Optional[Dict]` | [user_service.py:284](../../../server/services/user_service.py#L284) | Chỉ seed khi chưa có admin và credentials được cung cấp; không log plaintext password |
| `_sanitize_user(user)` | `@staticmethod` | [user_service.py:325](../../../server/services/user_service.py#L325) | Loại password_hash, failed_login_attempts, locked_until |

### `services/agent_service.py` - `AgentService`

Agent register + heartbeat + status calculation (active/inactive/offline based on heartbeat age).

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `active_threshold = 300` / `inactive_threshold = 1800` | instance | [agent_service.py:42-43](../../../server/services/agent_service.py#L42) | 5min / 30min |
| `__init__(agent_model, group_model, socketio=None, jwt_service=None, policy_model=None)` | | [agent_service.py:27](../../../server/services/agent_service.py#L27) | Tạo pending group lúc init. `db` lấy từ model |
| `.set_jwt_service(jwt_service)` | | [agent_service.py:48](../../../server/services/agent_service.py#L48) | Late injection |
| `.register_agent(agent_data, client_ip)` | `→ Dict` | [agent_service.py:80](../../../server/services/agent_service.py#L80) | Dedup priority: device_id → hostname/IP. Existing → update (giữ `pending/disabled` status). New → create với status="pending", assign vào pending group. Generate JWT tokens nếu service available. Trả `{agent_id, user_id, token (legacy), status, jwt: {...}}` |
| `.get_agents_with_status()` | `→ List[Dict]` | [agent_service.py:213](../../../server/services/agent_service.py#L213) | Compute status từ `last_heartbeat`: ≤5min=active, ≤30min=inactive, >30min=offline. **Persist status change** via `_persist_status_change`. Clamp future timestamps to 0 |
| `.calculate_statistics()` | `→ Dict` | [agent_service.py:304](../../../server/services/agent_service.py#L304) | Aggregate after status calc. Compute `health_status` (good/warning/critical) |
| `.process_heartbeat(agent_id, token, heartbeat_data, client_ip)` | `→ Dict` | [agent_service.py:350](../../../server/services/agent_service.py#L350) | Validate token (legacy field) + device_id consistency. Update heartbeat. Check `force_sync` từ policy override hoặc whitelist version mismatch (group_version) |
| `.get_total_agents() / .get_active_agents_count()` | | [agent_service.py:461, 469](../../../server/services/agent_service.py#L461) | |
| `.get_all_agents(filters=None)` | | [agent_service.py:478](../../../server/services/agent_service.py#L478) | Format cho API |
| `.get_agent_details(agent_id)` | `→ Dict` | [agent_service.py:535](../../../server/services/agent_service.py#L535) | |
| `.delete_agent(agent_id)` | | [agent_service.py:576](../../../server/services/agent_service.py#L576) | Emit `agent_deleted` |
| `.update_display_name(agent_id, display_name)` | | [agent_service.py:600](../../../server/services/agent_service.py#L600) | |
| `.update_position(agent_id, position)` | | [agent_service.py:608](../../../server/services/agent_service.py#L608) | Cho layout UI |
| `.move_agent_to_group(agent_id, group_id)` | `→ Dict` | [agent_service.py:623](../../../server/services/agent_service.py#L623) | Reset status="pending" nếu vào pending group, "active" nếu rời. Trả dict tương thích JSON |
| `_persist_status_change(agent, new_status)` | | [agent_service.py:53](../../../server/services/agent_service.py#L53) | Detect drift → update DB |

### `services/whitelist_service.py` - `WhitelistService`

Lớn nhất. Manage global + group + per-teacher profile whitelists. Build sync response cho agent.

Cap nhat 2026-05-27: `WhitelistService` nhan them `entry_model` (`WhitelistEntryModel`) va group-scope write moi ghi vao `whitelist_entries`. Read path merge `whitelist_entries` + legacy `groups.whitelist[]` trong compatibility window. Chi tiet: [whitelist_entries.md](whitelist_entries.md).

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(whitelist_model, agent_model, group_model, socketio=None, entry_model=None, policy_service=None, profile_service=None)` | | [whitelist_service.py](../../../server/services/whitelist_service.py) | `entry_model` la collection-first repo cho group whitelist entries. |
| `.get_all_entries(filters=None, limit=None, offset=0)` | `→ Dict` | [whitelist_service.py:180](../../../server/services/whitelist_service.py#L180) | Unified list format `{items, domains, total, success, server_time}`; `domains` giữ để tương thích UI cũ |
| `.add_entry(entry_data, client_ip)` | `→ Dict` | [whitelist_service.py:243](../../../server/services/whitelist_service.py#L243) | **Re-activate inactive entry** nếu trùng value (re-add behavior). Auto-bump version. Emit `whitelist_added` |
| `.test_entry(entry_data)` | `→ Dict` | [whitelist_service.py:418](../../../server/services/whitelist_service.py#L418) | Validate + DNS test |
| `.test_dns(domain)` | | [whitelist_service.py:471](../../../server/services/whitelist_service.py#L471) | |
| `.get_scoped_whitelist(agent_id=None, group_id=None)` | `→ Dict` | [whitelist_service.py:777](../../../server/services/whitelist_service.py#L777) | Trả `{global, group, merged, global_version, group_version, group_id, group_name}` cho UI |
| `.get_agent_sync_data(since_datetime, agent_id, global_version, group_version, agent_policy_mode="none")` | `→ Dict` | [whitelist_service.py:827](../../../server/services/whitelist_service.py#L827) | **Trái tim sync flow**. Versioned short-circuit nếu agent có version mới + policy không đổi. Otherwise: merge global + (active profile HOẶC group base). Apply policy override (isolate/custom) qua `policy_service.apply_policy_to_sync`. Trả `{domains, type: "full"|"versioned", up_to_date, ...}` |
| `.delete_entry(entry_id)` | `→ bool` | [whitelist_service.py:941](../../../server/services/whitelist_service.py#L941) | Canonical single delete cho global rows, first-class group rows, và embedded group rows có ObjectId thật |
| `.bulk_delete_entries(item_ids)` | `→ Dict` | [whitelist_service.py:1009](../../../server/services/whitelist_service.py#L1009) | Canonical bulk delete; vẫn hỗ trợ fallback pseudo-ID `group::<gid>::<type>::<value>` cho legacy embedded rows |
| `.bulk_add_entries(entries_data, client_ip)` | | [whitelist_service.py:1081](../../../server/services/whitelist_service.py#L1081) | Split scope global vs group. Max 1000 per op |
| `.get_statistics()` | | [whitelist_service.py:1236](../../../server/services/whitelist_service.py#L1236) | |
| `.update_entry(entry_id, update_data)` | `→ bool` | [whitelist_service.py:1253](../../../server/services/whitelist_service.py#L1253) | Support pseudo-ID cho group entry (toggle is_active) |
| `.add_domain(...) / .import_domains(...) / .export_domains(...)` | | [whitelist_service.py](../../../server/services/whitelist_service.py) | Legacy domain helpers còn lại; `get_all_domains` và `delete_domain` đã xóa, controller dùng unified entry API |
| `_normalize_group_entries(group, include_inactive=True)` | `→ List[Dict]` | [whitelist_service.py:607](../../../server/services/whitelist_service.py#L607) | Convert string/dict entries trong group sang dict chuẩn với pseudo-ID `group::<gid>::<type>::<value>` |
| `_merge_whitelists(global_entries, group_entries)` | | [whitelist_service.py:747](../../../server/services/whitelist_service.py#L747) | Merge theo key `type:value`. **Group entry thắng** global. Preserve priority="high" |
| `_get_detailed_changes(since_dt)` | | [whitelist_service.py:526](../../../server/services/whitelist_service.py#L526) | Diff added/removed/modified - hiện không dùng trong sync path |
| `_update_group_entry(entry_id, update_data)` | | [whitelist_service.py:1322](../../../server/services/whitelist_service.py#L1322) | Update group whitelist entry by first-class/embedded ObjectId or legacy pseudo-ID. |
| `_delete_group_entry(group_id, value, entry_type)` | | [whitelist_service.py:1422](../../../server/services/whitelist_service.py#L1422) | |

### `services/group_service.py` - `GroupService`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(group_model, agent_model, user_model=None)` | | [group_service.py:13](../../../server/services/group_service.py#L13) | Tạo pending group lúc init |
| `.list_groups(query_filter=None)` | `→ List[Dict]` | [group_service.py:40](../../../server/services/group_service.py#L40) | Enrich `created_by_username, created_by_role` từ user_model |
| `.create_group(name, description, whitelist=None, created_by=None)` | | [group_service.py:44](../../../server/services/group_service.py#L44) | |
| `.update_group(group_id, payload)` | | [group_service.py:48](../../../server/services/group_service.py#L48) | Block đổi `is_system`. Auto-bump version khi `whitelist` thay đổi |
| `.delete_group(group_id)` | `→ bool` | [group_service.py:63](../../../server/services/group_service.py#L63) | Block system group. **Move agents về pending TRƯỚC khi delete** (bulk update_many) |
| `.bump_group_whitelist_version(group_id)` | | [group_service.py:89](../../../server/services/group_service.py#L89) | |
| `.get_pending_group_id()` | | [group_service.py:95](../../../server/services/group_service.py#L95) | |
| `.get_group(group_id)` | | [group_service.py:98](../../../server/services/group_service.py#L98) | Enriched |
| `.get_default_metadata()` | | [group_service.py:104](../../../server/services/group_service.py#L104) | |

### `services/log_service.py` - `LogService`

Receive logs từ agent, store, format query results.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(log_model, agent_model=None, socketio=None)` | | [log_service.py:22](../../../server/services/log_service.py#L22) | |
| `.receive_logs(logs_data, agent_id=None)` | `→ Dict` | [log_service.py:29](../../../server/services/log_service.py#L29) | Process each log: detect protocol từ port (80/443/53), parse timestamp tolerant, normalize action (ALLOW→ALLOWED, BLOCK→BLOCKED), fill defaults. Emit `new_log` cho 5 logs cuối |
| `.get_all_logs(filters=None, limit=100, offset=0)` | `→ Dict` | [log_service.py:221](../../../server/services/log_service.py#L221) | Build query (level/action/agent_id/search/time_range/start_date/end_date). Format response |
| `.clear_logs(filters=None)` | `→ Dict` | [log_service.py:363](../../../server/services/log_service.py#L363) | Delete với filter. Emit `logs_cleared` |
| `.export_logs(filters=None, format="json")` | `→ Dict` | [log_service.py:402](../../../server/services/log_service.py#L402) | Limit 10000 |
| `.get_total_count() / .get_count_by_action(action) / .get_recent_logs(limit)` | | [log_service.py:459, 470, 480](../../../server/services/log_service.py#L459) | Pass-through wrappers |
| `.get_comprehensive_statistics(filters=None)` | `→ Dict` | [log_service.py:491](../../../server/services/log_service.py#L491) | Total + filtered counts cho 4 categories: allowed/blocked/warnings/allowed_by_ip |
| `_build_query_from_filters(filters)` | | [log_service.py:552](../../../server/services/log_service.py#L552) | |

Note 2026-06-08: web Logs page now applies the same active-agent filter on the client side for realtime `new_log` events. The server still filters the initial fetch by exact `agent_id`; the UI can additionally compare visible hostname/display_name for cloned demo machines that share stale agent IDs.

### `services/agent_policy_service.py` - `AgentPolicyService`

Override mode per-agent: `none` / `isolate` / `custom_whitelist`. Merge vào sync response.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(policy_model, agent_model, socketio=None)` | | [agent_policy_service.py:17](../../../server/services/agent_policy_service.py#L17) | |
| `.get_policy(agent_id)` | `→ Dict` | [agent_policy_service.py:26](../../../server/services/agent_policy_service.py#L26) | None → default policy dict |
| `.set_policy(agent_id, mode, applied_by_user, reason="", custom_whitelist=None, duration_minutes=None)` | `→ Dict` | [agent_policy_service.py:47](../../../server/services/agent_policy_service.py#L47) | Calculate `expires_at` từ duration. Validate agent. Emit `agent_policy_changed` |
| `.isolate_agent(agent_id, applied_by_user, reason, duration_minutes=None)` | | [agent_policy_service.py:98](../../../server/services/agent_policy_service.py#L98) | Shortcut |
| `.reset_agent(agent_id, applied_by_user)` | | [agent_policy_service.py:110](../../../server/services/agent_policy_service.py#L110) | Shortcut |
| `.apply_policy_to_sync(agent_id, group_domains, server_host=None)` | `→ Dict` | [agent_policy_service.py:150](../../../server/services/agent_policy_service.py#L150) | **Core merge**: `none` → unchanged. `isolate` → chỉ server_host. `custom_whitelist` → server + custom entries. Trả `{domains, policy_mode, policy_active}` |
| `.get_policies_for_agents(agent_ids)` | `→ Dict` | [agent_policy_service.py:210](../../../server/services/agent_policy_service.py#L210) | Batch load |
| `.get_stats()` | `→ Dict` | [agent_policy_service.py:214](../../../server/services/agent_policy_service.py#L214) | |
| `_build_system_entries(server_host=None, source="policy_system")` | `→ List[Dict]` | [agent_policy_service.py:125](../../../server/services/agent_policy_service.py#L125) | Server host only; DNS is added locally by the agent from system DNS |

### `services/whitelist_profile_service.py` - `WhitelistProfileService`

Per-teacher profile trong group. 1 active per group.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(profile_model, group_model, socketio=None)` | | [whitelist_profile_service.py:16](../../../server/services/whitelist_profile_service.py#L16) | |
| `.list_profiles(group_id, teacher_id=None)` | | [whitelist_profile_service.py:31](../../../server/services/whitelist_profile_service.py#L31) | |
| `.create_profile(group_id, teacher_id, teacher_username, name, domains=None)` | | [whitelist_profile_service.py:35](../../../server/services/whitelist_profile_service.py#L35) | Validate group exists |
| `.update_profile(profile_id, payload, user=None)` | | [whitelist_profile_service.py:52](../../../server/services/whitelist_profile_service.py#L52) | Teacher chỉ update profile mình tạo (`teacher_id`). Auto-bump version khi `domains` đổi. **Bump group version** nếu profile active |
| `.delete_profile(profile_id, user=None)` | | [whitelist_profile_service.py:77](../../../server/services/whitelist_profile_service.py#L77) | Block xoá profile active |
| `.activate_profile(profile_id, user=None)` | | [whitelist_profile_service.py:91](../../../server/services/whitelist_profile_service.py#L91) | Deactivate khác profiles trong group trước. Bump group version. Trả profile mới + info profile vừa bị deactivate |
| `.deactivate_profile(profile_id, user=None)` | | [whitelist_profile_service.py:120](../../../server/services/whitelist_profile_service.py#L120) | Bump group version |
| `.get_active_profile(group_id)` | | [whitelist_profile_service.py:137](../../../server/services/whitelist_profile_service.py#L137) | Cho agent sync (`WhitelistService.get_agent_sync_data`) |
| `.get_teacher_profiles(teacher_id, group_ids)` | `→ List[Dict]` | [whitelist_profile_service.py:142](../../../server/services/whitelist_profile_service.py#L142) | Cho /whitelist page dropdown. Enrich `group_name` |
| `_notify_group_update(group_id)` | | [whitelist_profile_service.py:171](../../../server/services/whitelist_profile_service.py#L171) | Emit `whitelist_updated` |

### `services/api_key_service.py` - `APIKeyService`

Wrap `APIKeyModel`, add socket events.

Note 2026-06-01: API key service không triển khai rate limit. Service chỉ validate name, gọi model tạo/validate/revoke/list/update key và emit Socket.IO events. Không có tham số `rate_limit`, không có hourly/sliding window, và không có logic trả `429`.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(api_key_model, socketio=None)` | | [api_key_service.py:19](../../../server/services/api_key_service.py#L19) | |
| `.create_api_key(name, description="", expires_in_days=None, permissions=None, created_by="unknown")` | | [api_key_service.py:32](../../../server/services/api_key_service.py#L32) | Validate name length; không nhận `rate_limit` |
| `.validate_api_key(api_key, required_permission="register")` | | [api_key_service.py:87](../../../server/services/api_key_service.py#L87) | Pass-through tới model; không throttle/quota |
| `.revoke_api_key(key_id, revoked_by="unknown")` | | [api_key_service.py:110](../../../server/services/api_key_service.py#L110) | Emit `api_key_revoked` |
| `.list_api_keys(include_revoked=False, page=1, limit=20)` | | [api_key_service.py:140](../../../server/services/api_key_service.py#L140) | |
| `.get_api_key(key_id)` | | [api_key_service.py:159](../../../server/services/api_key_service.py#L159) | |
| `.update_api_key(key_id, name=None, description=None, permissions=None, is_active=None, updated_by="unknown")` | | [api_key_service.py:171](../../../server/services/api_key_service.py#L171) | |
| `.get_stats()` | | [api_key_service.py:212](../../../server/services/api_key_service.py#L212) | |
| `.create_default_key_if_none()` | | [api_key_service.py:216](../../../server/services/api_key_service.py#L216) | Auto-tạo "Default Agent Key" lần đầu boot. Plaintext log warning |

## Ai gọi module này
- `server/app.py:194-274` - construct mọi service trong `register_controllers`
- `server/controllers/*` - controllers gọi service methods (rare model direct access)
- `server/middleware/auth.py` + `rbac.py` - dùng `JWTService`, `RBACService`, `APIKeyService`, `AdminAuthService` để validate

## Module này gọi ra
- `models/*` - DB CRUD
- `bcrypt` - password hashing
- `jwt` (PyJWT) - token operations
- `time_utils` - datetime helpers
- `flask.request` (audit_service) - auto-detect IP
- `socketio` - realtime emit

## Đã có sẵn - đừng viết lại
- Cần auth flow login? → `AdminAuthService.login(username, password, ip, ua)` - đã có brute-force, session, audit, tokens với admin claims
- Cần issue JWT? → `JWTService.generate_tokens(agent_id, user_id, additional_claims)` - **đừng** `jwt.encode` trực tiếp
- Cần validate JWT? → `JWTService.validate_access_token / validate_refresh_token` (check signature + revoke list)
- Cần audit log? → `AuditService.log_action(user, action, resource_type, resource_id=None, details=None)` - IP auto-detect
- Cần filter teacher data? → `RBACService.get_*_query_filter(user)` rồi merge vào query bằng `$and` (xem [controllers.md](controllers.md))
- Cần check teacher access? → `RBACService.can_access_group / can_teacher_access_agent`
- Cần bcrypt password hash? → service đã wrap (`AdminAuthService._hash_password`, `UserService.create_user`). Đừng `bcrypt.hashpw` rải rác - dễ quên rounds=12
- Cần build whitelist cho agent? → `WhitelistService.get_agent_sync_data(...)` - đã merge global+group+profile+policy
- Cần check agent online? → `AgentService.get_agents_with_status()` (auto persist status drift)
- Cần process heartbeat? → `AgentService.process_heartbeat(...)` (force_sync auto-detect)
- Cần apply policy override? → `AgentPolicyService.apply_policy_to_sync(...)`
- Cần activate profile (deactivate others)? → `WhitelistProfileService.activate_profile(...)` (atomic-ish)

## Gotchas

### JWT lifecycle
- **Production raise nếu thiếu `JWT_SECRET_KEY`** (jwt_service.py:30). Dev fallback random key → tokens invalidate sau restart (acceptable).
- **`refresh_access_token` KHÔNG carry additional_claims** (line 218): bug behavior - token mới mất `token_for, role, username`. Caller cho admin path phải dùng `AdminAuthService.refresh_token` (re-generate full claims). Agent path OK vì agent tokens không cần claims đó.
- **`refresh_tokens_with_rotation` revoke refresh cũ** (line 287-301). Nếu agent gọi refresh đồng thời từ 2 process → 1 thành công, 1 fail. Acceptable cho single-instance agent.
- **`_is_token_revoked` chỉ check `revoked_tokens` collection** - sessions revoked trong `admin_sessions` không check ở đây. Admin logout flow revoke cả 2 chỗ (`SessionModel.revoke` + `JWTService.revoke_token`).
- **TTL index `expireAfterSeconds=0`** trên `revoked_tokens.expires_at`: auto-cleanup. Hơi lag ~60s vì TTL chạy interval.

### RBAC filter logic
- **`get_teacher_group_ids` trả None ≠ `[]`**: None = admin (full access), `[]` = teacher không có group nào (block tất cả). Caller phải distinguish.
- **`get_log_query_filter` chain teacher → groups → agents → logs** (line 155-190): expensive. Mỗi lần list logs, query 2 collections trước. Acceptable cho < 1k agents.
- **`group_id_variants` support cả str và ObjectId** (rbac_service.py:175-181): tương thích DB cũ lưu `group_id` không consistent. Sửa migration sau.

### Agent service
- **Status calc mutate DB** (line 53-78 `_persist_status_change`). Mỗi lần list agents, drift detected → write. High traffic = nhiều write. Acceptable vì rare drift.
- **`process_heartbeat` chỉ check `token` field legacy** (line 358), không check JWT. JWT verify đã làm ở middleware. Agent vẫn gửi token field để backward compat.
- **`force_sync` flag**: policy change HOẶC version mismatch trigger. Agent đọc `force_sync=true` từ heartbeat response sẽ sync ngay lập tức.
- **`active_threshold / inactive_threshold` instance attr** (line 42-43) - hard-coded không từ config. Sửa giá trị cần code change + restart.

### Whitelist service complexity
- **Whitelist storage đang migrate**: global vẫn ở `whitelist`, group write mới ở `whitelist_entries`, legacy `groups.whitelist[]` chỉ còn read fallback/rollback trong compatibility window, profile vẫn ở `whitelist_profiles.domains`.
- **Pseudo-ID `group::<gid>::<type>::<value>`** hiện chỉ là fallback cho legacy embedded row chưa migrate/backfill. New group entries trả `_id` thật từ `whitelist_entries`.
- **Pseudo-ID usage marker**: mọi public path còn nhận pseudo-ID log `legacy_group_pseudo_id_used`. Trước khi xoá fallback, production logs phải không còn marker này trong một release window.
- **Re-activate on duplicate add** (line 105-114): nếu add entry trùng `value` (đã inactive), service re-activate thay vì raise. Khá hữu ích nhưng có thể bất ngờ cho user.
- **`_merge_whitelists` group thắng global** (line 432): policy decision. Đảo logic = đổi semantic.
- **Active profile override group base** (line 547-559): nếu group có active profile, agent sync nhận `profile.domains` chứ KHÔNG nhận `group.whitelist`. Inactive profile fallback group.whitelist.
- **`get_agent_sync_data` short-circuit khi version match VÀ policy không đổi** (line 532): trả empty domains + `up_to_date=True`. Agent skip update. Đây là performance optimization, nhưng nếu profile activate (đổi data nhưng group_version có thể không bump trong test bug) → agent miss update. Hiện đã handle bằng cách bump group version mỗi khi profile activate/deactivate (`whitelist_profile_service`).

### Auth flow
- **Admin tokens có `token_for=admin_user, role, username` claims**. Agent tokens KHÔNG có. Middleware phân biệt qua claim này (xem [middleware.md](middleware.md)).
- **Session record vs JWT**: session lưu để revoke + audit, JWT là source of truth cho auth. Mất sync = security gap nhỏ. TTL index session expire trước hoặc cùng JWT.
- **`change_password` không revoke existing sessions** (line 225-255): user đổi password vẫn giữ session cũ. Đáng improve nếu muốn force re-login sau change password.

### Policy
- **DNS policy split**: server policy sync no longer injects public DNS. Agent firewall adds the machine's configured system DNS locally when applying rules.
- **`get_effective_mode` auto-reset expired** (xem [models.md](models.md) `AgentPolicyModel.get_effective_mode`): side effect ẩn. Caller (`apply_policy_to_sync` line 164) gọi qua method này nên consistent - agent đang isolated mà expired → tự reset về none → agent sync nhận group base.

### Audit
- **Auto-detect IP qua `flask.request.remote_addr`** (audit_service.py:42-45) - nếu gọi service ngoài request context (vd background job) sẽ raise RuntimeError, catch, ip="unknown".
- **Never raise** (line 67-69): nếu Mongo audit collection down, business logic vẫn pass. Lost audit. Trade-off.
