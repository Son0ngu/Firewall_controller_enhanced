# `server/controllers` - HTTP routes (Flask Blueprints)

## Mục đích
Tầng HTTP. Mỗi controller class:
1. Tạo `Blueprint` ở `__init__`
2. Register routes qua `_register_routes` với decorator (auth/RBAC)
3. Handler validate request → call service → format response → emit socketio

Blueprint mount vào Flask app với `url_prefix='/api'` ở `app.py`. Tổng 10 controllers.

## Endpoint map - toàn bộ API

| Method | Path | Controller / Handler | Auth | RBAC permission | Mô tả |
|---|---|---|---|---|---|
| `POST` | `/api/agents/register` | `AgentController.register_agent` | API Key | `agent_register` | Agent đăng ký - trả `agent_id` + JWT tokens |
| `POST` | `/api/agents/heartbeat` | `AgentController.heartbeat` | JWT | - | Agent ping định kỳ |
| `GET`  | `/api/agents` | `AgentController.list_agents` | login | filtered by teacher_ids | List agents (teacher chỉ thấy của mình) |
| `GET`  | `/api/agents/statistics` | `AgentController.get_statistics` | login | filtered | Stats (active/inactive/offline %) |
| `GET`  | `/api/agents/<agent_id>` | `AgentController.get_agent` | login | `can_teacher_access_agent` | Chi tiết agent |
| `DELETE` | `/api/agents/<agent_id>` | `AgentController.delete_agent` | login | ownership | Xoá agent |
| `PATCH` | `/api/agents/<agent_id>/display-name` | `update_display_name` | login | ownership | |
| `PATCH` | `/api/agents/<agent_id>/position` | `update_position` | login | ownership | Vị trí layout |
| `PATCH` | `/api/agents/<agent_id>/group` | `update_group` | login | **admin only** | Chuyển group |
| `GET`  | `/api/agents/<agent_id>/policy` | `get_agent_policy` | login | ownership | Chế độ override |
| `PATCH` | `/api/agents/<agent_id>/policy` | `set_agent_policy` | login | ownership | Set isolate/custom |
| `GET`  | `/api/agents/debug/status` | `debug_status` | login | - | Debug snapshot — chỉ register khi `ENABLE_DEBUG_ENDPOINTS=True` (default `False`). Production: route không tồn tại → 404. |
| `GET`  | `/api/agents/debug/direct` | `debug_direct_call` | login | - | Check reachable — cùng gate `ENABLE_DEBUG_ENDPOINTS`. |
| `GET`  | `/api/whitelist/agent-sync` | `WhitelistController.agent_sync` | JWT | - | **Agent kéo whitelist** |
| `GET`  | `/api/whitelist` | `list_domains` | login | teacher filtered (global+own groups) | List unified entries; response giữ `domains` alias cho UI cũ |
| `POST` | `/api/whitelist` | `add_domain` | login | teacher: own group only | Add entry |
| `DELETE` | `/api/whitelist/<domain_id>` | `delete_domain` | login | teacher ownership | Compatibility route; internally calls `bulk_delete_entries([id])` |
| `POST` | `/api/whitelist/import` | `import_domains` | login | teacher: cần group_id | Bulk import |
| `GET`  | `/api/whitelist/export` | `export_domains` | login | - | Export JSON/TXT |
| `GET`  | `/api/whitelist/statistics` | `get_statistics` | login | - | Stats |
| `POST` | `/api/whitelist/bulk` | `bulk_add_entries` | login | teacher ownership | Bulk add (max 1000) |
| `POST` | `/api/whitelist/bulk-update` | `bulk_update_entries` | login | teacher ownership | Toggle is_active |
| `POST` | `/api/whitelist/bulk-delete` | `bulk_delete_entries` | login | teacher ownership | Bulk delete |
| `GET`  | `/api/logs/stats` | `LogController.get_statistics` | inject (optional) | teacher filtered | Log counters |
| `POST` | `/api/logs` | `receive_logs` | JWT | - | **Agent push logs** |
| `GET`  | `/api/logs` | `list_logs` | inject | teacher filtered | List logs |
| `DELETE` | `/api/logs/clear` | `clear_logs` | inject | **teacher blocked** | Clear w/ filters |
| `DELETE` | `/api/logs` | `clear_logs` (legacy alias) | inject | teacher blocked | |
| `GET`  | `/api/logs/export` | `export_logs` | inject | teacher blocked | CSV/JSON |
| `GET`  | `/api/groups` | `GroupController.list_groups` | inject | teacher filtered | |
| `POST` | `/api/groups` | `create_group` | login | `@require_admin` | |
| `GET`  | `/api/groups/<group_id>` | `get_group` | inject | teacher ownership | |
| `PATCH` | `/api/groups/<group_id>` | `update_group` | inject | teacher ownership | |
| `DELETE` | `/api/groups/<group_id>` | `delete_group` | inject | teacher ownership | Move agents → pending |
| `POST` | `/api/groups/<group_id>/teachers` | `set_teachers` | inject | admin only (in-handler) | Assign teachers |
| `GET`  | `/api/api-keys` | `APIKeyController.list_api_keys` | login | (admin only de facto) | |
| `POST` | `/api/api-keys` | `create_api_key` | login | | Tạo key - show plaintext 1 lần; không nhận/enforce `rate_limit` |
| `GET`  | `/api/api-keys/<key_id>` | `get_api_key` | login | | |
| `PUT/PATCH` | `/api/api-keys/<key_id>` | `update_api_key` | login | | |
| `DELETE` | `/api/api-keys/<key_id>` | `delete_api_key` | login | | Alias `revoke` |
| `POST` | `/api/api-keys/<key_id>/revoke` | `revoke_api_key` | login | | |
| `GET`  | `/api/api-keys/stats` | `get_stats` | login | | |
| `POST` | `/api/api-keys/validate` | `validate_key` | login | | Test một key |
| `POST` | `/api/auth/refresh` | `AgentAuthController.refresh_token` | - | - | Agent refresh JWT |
| `POST` | `/api/auth/logout` | `logout` | - | - | Revoke tokens |
| `POST` | `/api/auth/verify` | `verify_token` | - | - | Verify validity |
| `GET`  | `/api/auth/token-info` | `token_info` | - | - | Decode info |
| `POST` | `/api/admin/auth/login` | `WebAuthController.login` | - | - | Admin/teacher login → set cookies |
| `GET`  | `/api/admin/auth/me` | `get_profile` | `@require_login` | - | Current user |
| `POST` | `/api/admin/auth/refresh` | `refresh_token` | `@require_login` | - | |
| `POST` | `/api/admin/auth/logout` | `logout` | `@require_login` | - | Clear cookies |
| `PUT`  | `/api/admin/auth/change-password` | `change_password` | `@require_login` | - | |
| `PUT`  | `/api/admin/auth/profile` | `update_profile` | `@require_login` | - | Update email |
| `GET`  | `/api/admin/users` | `UserController.list_users` | `@require_login + @require_admin` | - | |
| `POST` | `/api/admin/users` | `create_user` | admin | `users:create` (de facto) | |
| `GET`  | `/api/admin/users/<user_id>` | `get_user` | admin | | |
| `PATCH` | `/api/admin/users/<user_id>` | `update_user` | admin | | |
| `DELETE` | `/api/admin/users/<user_id>` | `delete_user` | admin | block last admin + self | |
| `POST` | `/api/admin/users/<user_id>/reset-password` | `reset_password` | admin | | |
| `GET`  | `/api/admin/users/statistics` | `get_statistics` | admin | | |
| `GET`  | `/api/admin/audit` | `AuditController.list_logs` | login | `@require_permission("audit:read")` | |
| `GET`  | `/api/admin/audit/user/<user_id>` | `user_activity` | login | `audit:read` | |
| `GET`  | `/api/my-profiles` | `WhitelistProfileController.my_profiles` | login | - | Profiles của teacher |
| `GET`  | `/api/groups/<group_id>/profiles` | `list_profiles` | login | group access | |
| `POST` | `/api/groups/<group_id>/profiles` | `create_profile` | login | `whitelist_profile:create` | |
| `PATCH` | `/api/groups/<group_id>/profiles/<profile_id>` | `update_profile` | login | `whitelist_profile:update` | |
| `DELETE` | `/api/groups/<group_id>/profiles/<profile_id>` | `delete_profile` | login | `whitelist_profile:delete` | |
| `POST` | `/api/groups/<group_id>/profiles/<profile_id>/activate` | `activate_profile` | login | `whitelist_profile:activate` | |
| `POST` | `/api/groups/<group_id>/profiles/<profile_id>/deactivate` | `deactivate_profile` | login | `whitelist_profile:activate` | |

## Controller signatures và chi tiết

### `controllers/agent_controller.py`
[agent_controller.py:21](../../../server/controllers/agent_controller.py#L21)

| Constructor | `(agent_model, agent_service, rbac_service=None, socketio=None, policy_service=None)` |
|---|---|
| Helpers | `_success_response`, `_error_response`, `_validate_json_request(required_fields)`, `_get_pagination_params`, `_get_filter_params`, `_serialize_agent`, `_check_agent_ownership` |

**Handlers**:
- `register_agent()` - POST. Body: `{hostname, device_id, ip_address, platform, os_info, agent_version}`. Trả `{success, data: {agent_id, user_id, token, jwt: {...}}}`. Emit `agent_registered`
- `heartbeat()` - POST. Body: `{agent_id, token, metrics, platform, os_info, agent_version, global_version, group_version}`. Trả `{status, server_time, force_sync, policy_mode, next_heartbeat}`. Emit `agent_heartbeat`
- `list_agents()` - GET `?limit=&skip=&page=&status=&hostname=&group_id=&exclude_group_id=`. Teacher filtered by `rbac.get_teacher_group_ids`
- `get_agent(agent_id)` - GET. Ownership check
- `delete_agent(agent_id)` - DELETE. Emit `agent_deleted`
- `update_display_name(agent_id)` - PATCH `{display_name}`
- `update_position(agent_id)` - PATCH `{position}`
- `update_group(agent_id)` - PATCH `{group_id}`. **Admin only** in-handler (line 423-427). Emit `agent_group_updated`
- `get_agent_policy(agent_id)` / `set_agent_policy(agent_id)` - Policy CRUD
- `get_statistics()` - Teacher-aware re-compute từ filtered list
- `debug_status()` / `debug_direct_call()` - Diagnostic

### `controllers/whitelist_controller.py`
[whitelist_controller.py:25](../../../server/controllers/whitelist_controller.py#L25)

| Constructor | `(whitelist_model, whitelist_service, rbac_service, socketio=None)` |
|---|---|
| Helpers | `_is_teacher()`, `_teacher_can_access_group(user, group_id)`, `_error_response` |

**Handlers**:
- `agent_sync()` - GET `?since=&agent_id=&global_version=&group_version=&policy_mode=`. JWT auth. Trả format full hoặc versioned
- `list_domains()` - GET `?agent_id=&group_id=&limit=&offset=&search=`. Scoped khi có agent_id/group_id; otherwise calls unified `get_all_entries(...)` + paginated. Teacher: fetch all → filter Python → paginate.
- `add_domain()` - POST. Teacher block `scope=global` không có `group_id`. Emit `whitelist_updated`
- `delete_domain(domain_id)` - DELETE compatibility handler. Teacher block global entries; delete path uses unified bulk entry delete.
- `import_domains()` - POST `{domains: [...], category, group_id}`. Teacher require `group_id`
- `export_domains()` - GET `?format=json|txt&category=`. Teacher OK xem (whitelist:read), không có log export gate
- `get_statistics()` - GET
- `bulk_add_entries()` - POST `{items: [...]}`. Max 1000. Teacher: tất cả items phải có `group_id` thuộc về mình
- `bulk_update_entries()` - POST `{item_ids, active}`. Toggle is_active. Teacher: ownership check mỗi item (parse pseudo-ID hoặc DB lookup)
- `bulk_delete_entries()` - POST `{item_ids}`. Tương tự

### `controllers/log_controller.py`
[log_controller.py:27](../../../server/controllers/log_controller.py#L27)

| Constructor | `(log_model, log_service, rbac_service, socketio=None)` |
|---|---|
| Helpers | `_is_teacher`, `_get_teacher_log_filter`, `_get_filter_params`, `_error_response` |

**Handlers**:
- `receive_logs()` - POST `{logs: [...]}`. Agent header `X-Agent-ID`. Status 201 nếu OK
- `list_logs()` - GET filters. Teacher filter merge bằng `{"$and": [teacher_filter, user_filters]}`
- `clear_logs()` - DELETE. **Teacher 403**. Body `{action: "all"|"selected"|"old", filters, log_ids}`. "old" = older than 30 days. Emit `logs_cleared`
- `export_logs()` - GET `?format=json|csv`. **Teacher 403**
- `get_log_statistics()` - Internal, gọi từ `get_statistics`
- `get_statistics()` - Public, wrap `get_log_statistics`. Teacher: filter chains

### `controllers/group_controller.py`
[group_controller.py:17](../../../server/controllers/group_controller.py#L17)

| Constructor | `(group_service, rbac_service)` |
|---|---|
| Helpers | `_is_teacher` |

**Handlers**:
- `list_groups()` - GET. Teacher → `query_filter` từ `rbac.get_group_query_filter`
- `create_group()` - POST `{name, description, whitelist}`. `@require_login + @require_admin`. Set `created_by` từ current_user
- `get_group(group_id)` - GET. Teacher ownership check
- `update_group(group_id)` - PATCH. Teacher ownership before update
- `delete_group(group_id)` - DELETE. Teacher ownership. Service tự move agents
- `set_teachers(group_id)` - POST `{teacher_ids: [...]}`. **Admin only** in-handler. Convert string → ObjectId

### `controllers/api_key_controller.py`
[api_key_controller.py:20](../../../server/controllers/api_key_controller.py#L20)

| Constructor | `(api_key_model, api_key_service, socketio=None)` |
|---|---|

**Handlers**:
- `list_api_keys()` - GET `?page=&limit=&include_revoked=`
- `create_api_key()` - POST `{name, description, expires_in_days, permissions}`. Status 201. `expires_in_days=0` → never expires. `created_by` lấy từ `g.current_user.username` (require_login đảm bảo có) — không còn hardcode `"admin"`. Không có `rate_limit` trong contract; nếu client gửi field này thì backend bỏ qua.
- `get_api_key(key_id)` - GET
- `update_api_key(key_id)` - PUT/PATCH `{name, description, permissions, is_active}`
- `delete_api_key(key_id)` - DELETE. **Alias `revoke_api_key`**
- `revoke_api_key(key_id)` - POST
- `get_stats()` - GET
- `validate_key()` - POST `{api_key, permission}` - test endpoint

**Permission whitelist** (line 167-170, 239-242): `register, sync, logs, heartbeat, admin` (legacy) + `agent_register, agent_read, whitelist_sync, logs_write` (new). Invalid permission → 400.

**Rate limit status**: API key management chưa có rate limit thật. Không có middleware/window counter/token bucket cho API key usage, không trả `429`, và `usage_count` chỉ là counter lifetime tăng sau mỗi lần validate thành công. UI `/api-keys` đã gỡ form Rate Limit để tránh tạo cảm giác có quota theo giờ.

**Expiration status**: API key expiration co enforce that. `expires_in_days` duoc luu thanh `expires_at`; expired key bi `validate_api_key(...)` reject voi `API key has expired`, va endpoint dung `require_api_key(...)` tra `401`.

### `controllers/auth_controller.py` - Agent auth (`/api/auth/*`)
[auth_controller.py:16](../../../server/controllers/auth_controller.py#L16)

Class chính: `AgentAuthController`. Alias `AuthController = AgentAuthController` được giữ tạm cho backwards-compat (sẽ gỡ khi tất cả import migrate). Pair với `WebAuthController` ở mục dưới — agent dùng Bearer JWT, admin/web dùng httpOnly cookie; không trộn 2 luồng.

| Constructor | `(jwt_service, agent_model=None, socketio=None)` |
|---|---|

**Handlers**:
- `refresh_token()` - POST `{refresh_token, rotate?: bool}`. `rotate=true` → `refresh_tokens_with_rotation`. Error code: `REFRESH_TOKEN_EXPIRED` / `TOKEN_REVOKED`
- `logout()` - POST. Authorization header + body `{refresh_token, revoke_all}`. Emit `agent_logout`
- `verify_token()` - POST `{token, token_type: "access"|"refresh"}` - sanity check
- `token_info()` - GET. Decode info **without verify** (debug)

### `controllers/web_auth_controller.py` - Admin/Teacher auth (`/api/admin/auth/*`)
[web_auth_controller.py:52](../../../server/controllers/web_auth_controller.py#L52)

> Đổi tên từ `AdminAuthController` → `WebAuthController` (P1 #10) để tách bạch với `AgentAuthController`. Module path cũ `controllers/admin_auth_controller.py` còn lại làm shim re-export (`WebAuthController`, alias `AdminAuthController = WebAuthController`) — import legacy `from controllers.admin_auth_controller import AdminAuthController` vẫn chạy. Xóa shim khi tất cả call site dùng tên mới.

| Constructor | `(admin_auth_service, jwt_service, socketio=None)` |
|---|---|

**Cookie constants** (web_auth_controller.py:31-35): `access_token` / `refresh_token`, httponly=True, samesite=Lax, path=`/`. `secure` đọc từ `Config.ADMIN_COOKIE_SECURE` qua helper `_cookie_secure()` — default `False` (dev), `True` ở `ProductionConfig`. Override bằng env `ADMIN_COOKIE_SECURE=true|false`.

**Handlers**:
- `login()` - POST `{username, password}`. Set httpOnly cookies + return body. UA tracking
- `get_profile()` - GET. `@require_login`. Return safe user
- `refresh_token()` - POST. `@require_login`. Read refresh từ body hoặc cookie. **Re-issue tokens với admin claims** (qua `AdminAuthService.refresh_token`)
- `logout()` - POST. `@require_login`. Revoke + clear cookies
- `change_password()` - PUT `{old_password, new_password}`. `@require_login`
- `update_profile()` - PUT `{email}`. `@require_login`. Email uniqueness check + audit `profile.update` qua `audit_service.log_action(...)` (P0.4 — trước đây gọi nhầm `.log(...)` đã fix; test bảo vệ ở `tests/test_users_auth.py::TestAdminAuthController::test_update_profile_writes_audit_entry`).

### `controllers/user_controller.py` - Admin manages teacher accounts
[user_controller.py:17](../../../server/controllers/user_controller.py#L17)

| Constructor | `(user_service, socketio=None)` |
|---|---|

Mọi route wrap `@require_login + @require_admin`.

**Handlers**:
- `list_users()` - GET `?role=&search=&limit=&offset=`. Regex search on username/email
- `get_user(user_id)` - GET
- `create_user()` - POST `{username, password, role, email}`. Status 201
- `update_user(user_id)` - PATCH. Special case `is_active` only → `toggle_active`
- `delete_user(user_id)` - DELETE. Block self-delete (line 203-205) - additional layer trên service
- `reset_password(user_id)` - POST `{new_password}`
- `get_statistics()` - GET. By role + active/inactive

### `controllers/audit_controller.py`
[audit_controller.py:16](../../../server/controllers/audit_controller.py#L16)

| Constructor | `(audit_service, socketio=None)` |
|---|---|

**Handlers**:
- `list_logs()` - GET `?action=&resource_type=&username=&limit=&skip=`. `@require_login + @require_permission("audit:read")`
- `user_activity(user_id)` - GET `?limit=`. Tương tự

### `controllers/whitelist_profile_controller.py`
[whitelist_profile_controller.py:13](../../../server/controllers/whitelist_profile_controller.py#L13)

| Constructor | `(profile_service, rbac_service)` |
|---|---|
| Helpers | `_get_user`, `_check_group_access(group_id)` - return `(group, error_response)` |

**Handlers**:
- `my_profiles()` - GET. Cross-group cho teacher
- `list_profiles(group_id)` - GET. All users in group thấy all profiles
- `create_profile(group_id)` - POST `{name, domains}`. Teacher tự gán mình làm owner
- `update_profile(group_id, profile_id)` - PATCH. Service tự check ownership
- `delete_profile(group_id, profile_id)` - DELETE. Block delete active
- `activate_profile(group_id, profile_id)` - POST. Deactivate khác trong group
- `deactivate_profile(group_id, profile_id)` - POST

## Ai gọi module này
- `app.register_controllers` (server/app.py:194) - construct + `app.register_blueprint(controller.blueprint, url_prefix='/api')`
- HTTP client (agent, browser/SPA, tests) - qua HTTP

## Module này gọi ra
- `flask` (Blueprint, request, jsonify, g, make_response, Response)
- `services/*` - business logic
- `middleware/auth` - `require_api_key, require_jwt, require_jwt_or_api_key`
- `middleware/rbac` - `require_login, require_admin, require_permission, inject_current_user, get_rbac_service`
- `time_utils.now_iso, parse_agent_timestamp`
- `bson.ObjectId` - parse path params + queries

## Đã có sẵn - đừng viết lại
- Cần response format `{success, message, data}`? → `_success_response(data, message, status_code)` (mỗi controller có riêng - đáng centralize)
- Cần response error `{success, error, timestamp}`? → `_error_response(message, status_code)` (mỗi controller)
- Cần parse JSON body với required fields? → `AgentController._validate_json_request(required_fields=[...])` - raise `ValueError` nếu thiếu
- Cần pagination từ query? → `AgentController._get_pagination_params()` (limit/skip/page)
- Cần filter from query? → `AgentController._get_filter_params(allowed_filters=[...])`
- Cần serialize agent dict (ObjectId, datetime)? → `_serialize_agent(agent)` ở AgentController
- Cần check teacher access? → service-level (`rbac.can_*`) hoặc local helper `_is_teacher() + _teacher_can_access_group(user, group_id)` ở WhitelistController
- Cần register route với decorator? → `self.blueprint.add_url_rule(path, endpoint_name, decorator(handler), methods=[...])`
- Cần emit realtime? → `self.socketio.emit("event_name", {...})` (sau khi mutation success)

## Gotchas

### Response shape inconsistency
- **Mọi controller có `_success_response/_error_response` riêng** (đôi khi nhỏ khác nhau: APIKeyController spreads dict vào response). Đáng refactor thành helper module chung.
- **`success` field ở body**: hầu hết controllers trả `{success: bool, ...}`. Nhưng có chỗ trả `{success, data: {...}}`, có chỗ flatten. Frontend phải code defensive.
- **Status code conventions**:
  - 200: success
  - 201: created (register_agent, create_api_key, create_user, create_profile, add_domain success)
  - 202: log batch accepted (`POST /logs`)
  - 400: validation error
  - 401: auth missing/invalid (incl `TOKEN_EXPIRED` code)
  - 403: permission/ownership
  - 404: resource not found
  - 500: server error

### Auth & RBAC tangled
- **3 cách wrap auth**:
  - Agent endpoints: `require_api_key(permission=...)(handler)` hoặc `require_jwt(handler)`
  - Web endpoints (mọi user): `inject_current_user(handler)` - non-blocking, in-handler check
  - Web endpoints (admin): `require_login(require_admin(handler))` hoặc `require_login + @require_permission(...)`
- **`inject_current_user` vs `require_login`**: Group/Whitelist/Log routes dùng inject để cho phép agent đi qua không có cookie (vì middleware không reject). Sau đó trong handler check role. Đáng review - có thể agent leak vào teacher path. Hiện safe vì agent không gọi `/api/whitelist` (chỉ `/api/whitelist/agent-sync`).
- **WhitelistController bulk operations**: ownership check duplicate logic (parse pseudo-ID + DB lookup) trong từng method bulk_*. Đáng extract helper.

### Pseudo-ID convention
- **`group::<gid>::<type>::<value>`** (legacy `group|<gid>|<type>|<value>`): định danh group whitelist entries trong UI. Parse split `"::"` → 4 parts. Đừng dùng giá trị thật chứa `::`.
- Mọi `delete/update` controller method support cả 2 ID format (global ObjectId vs pseudo).

### Teacher data filtering
- **List endpoints fetch all → filter Python** (WhitelistController:184-208): O(n) ở app level. Acceptable cho < 10k entries. Production scale cần push filter vào model (như LogController dùng `$and`).
- **Stats filtering** (AgentController.get_statistics:530-555): re-compute từ filtered list. Đắt. Có thể cache theo user nếu cần.
- **`agent_id` field trong filters**: agent gửi `agent_id` qua URL hoặc body inconsistent. Header `X-Agent-ID` (log) hoặc body `agent_id` (heartbeat) hoặc query (sync).

### Admin-only checks duplicated
- `UserController` wrap mọi route `@require_admin`. `AgentController.update_group` check trong handler (line 423). `GroupController.set_teachers` check trong handler (line 140). Inconsistent - đáng centralize với `@require_admin` decorator (đã có sẵn).

### Cookie + body dual auth
- **WebAuthController** chấp nhận token từ httpOnly cookie HOẶC body (refresh endpoint). Cookie ưu tiên. Cho phép cả SPA (cookie) lẫn mobile app (body). Hiện chưa có rate-limit ⇒ chỉ rely brute-force trong UserModel.

### Audit gaps
- **API key operations không audit** trừ create. Revoke không gọi `audit_service.log_action`. Đáng add.
- **Group set_teachers không audit**.
- **Agent operations (display name, position, group move) không audit** - coi như non-sensitive.

### Socket events
- **Mỗi mutation có socketio emit** nhưng tên event không consistent: `agent_registered`, `agent_heartbeat`, `agent_deleted`, `agent_group_updated`, `agent_policy_changed`, `whitelist_added`, `whitelist_updated`, `whitelist_deleted` (one of), `whitelist_bulk_added`, `api_key_created`, `api_key_revoked`, `admin_login`, `user_created`, `token_refreshed`, `agent_logout`, `logs_cleared`, `new_log`. Frontend subscribe gì = nó decide.
- **Race condition**: emit AFTER DB write nhưng không transactional. Nếu DB write fail sau emit (hiếm), client thấy event mà data chưa lưu. Acceptable.

### Legacy/duplicated routes
- `/logs` DELETE và `/logs/clear` DELETE → cùng handler `clear_logs`. Endpoint name khác (`clear_logs_legacy`). UI cũ vẫn dùng `/logs` DELETE.
- `delete_api_key(key_id)` aliasing `revoke_api_key(key_id)`.

### Token cookies
- **`secure` đọc từ config** (`web_auth_controller.py:_cookie_secure()`): default `False` ở `Config`, `True` ở `ProductionConfig`. Có thể override bằng env `ADMIN_COOKIE_SECURE`. Trước đây hardcode `False` — đã chuyển sang config (P0.2).

### Admin-only check ở `delete_agent`
- `AgentController.delete_agent` thêm role check (`role != 'admin' → 403`) trước cả ownership filter (P0/RBAC consistency). Lý do: trước đây `_check_agent_ownership` chỉ chặn teacher cross-group, nên teacher vẫn xóa được agent trong group mình — nhưng `agents:delete` được khai báo admin-only trong `rbac_config.ADMIN_EXTRA_PERMISSIONS`. Test bảo vệ: `tests/test_teacher_data_filtering.py::TestAgentControllerTeacherFiltering::test_delete_agent_teacher_blocked`.
