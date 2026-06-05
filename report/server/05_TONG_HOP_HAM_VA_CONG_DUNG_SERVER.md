# Tổng hợp hàm và công dụng - Server



Tài liệu này được sinh từ phân tích AST source code, không import module và không chạy runtime.

> Cập nhật thủ công 2026-05-26: phần bootstrap/routes bên dưới phản ánh refactor mới nhất. `server/app.py` không còn chứa app factory implementation, controller composition, page route, error handler hoặc SocketIO handler; các phần đó đã tách sang `server/bootstrap/` và `server/routes/`.

> Cập nhật thủ công 2026-05-28: baseline validation mới nhất là Render full deep E2E run `20260528_141158` (`24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0`, `CLEANUP_OK=43`). Các web-facing group/log endpoints phải dùng `require_login(...)`; `inject_current_user(...)` chỉ là optional context injection. Các hotfix đã thêm regression test cho public auth leak, active profile domain sync, masked Mongo URI logging và E2E heartbeat envelope unwrap.

> Cập nhật thủ công 2026-06-01: API key không có rate limit thật. Backend không có `rate_limit` parameter/storage, không có hourly/sliding window, không trả `429`; `usage_count` chỉ là counter trọn đời. UI `/api-keys` đã gỡ form Rate Limit và progress bar giả. Modal Create API Key dùng lại shared custom select cho Expiration; dropdown tự mở lên/scroll trong modal nên không còn bị cắt ở `7 days`.


## Package `server`


### `server/app.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `create_app` | Imported/exported từ `bootstrap.app_factory` để giữ tương thích `from app import create_app`. | `server/app.py:12` |

`server/app.py` hiện chỉ làm entrypoint: chạy `gevent.monkey.patch_all()` ở đầu file, cấu hình logging, import `create_app`, và trong nhánh `if __name__ == "__main__"` gọi `socketio.run(...)`.


### `server/bootstrap/app_factory.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `create_app()` | Tạo Flask app đầy đủ: load config, template filter, validate config, CORS, SocketIO, DB, indexes, container, page routes, error handlers, SocketIO events. | `server/bootstrap/app_factory.py:19` |


### `server/bootstrap/container.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `initialize_database_indexes(app, db)` | Khởi tạo index cho các model chính và log warning nếu index setup gặp vấn đề không chặn startup. | `server/bootstrap/container.py:46` |
| `initialize_container(app, socketio, db)` | Tạo model/service/controller, init auth/RBAC middleware, chạy startup tasks, đăng ký blueprint `/api`, attach các service runtime lên Flask app. | `server/bootstrap/container.py:60` |


### `server/bootstrap/startup_tasks.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `run_startup_tasks(user_service, api_key_service)` | Seed default admin và tạo default API key nếu chưa có, giữ behavior startup cũ nhưng tách khỏi app factory. | `server/bootstrap/startup_tasks.py:8` |


### `server/routes/pages.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `register_page_routes(app)` | Đăng ký dashboard/page routes, redirect `/admin/change-password` về `/profile`, và các endpoint metadata `/api/health`, `/api/config`. | `server/routes/pages.py:10` |


### `server/routes/errors.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `register_error_handlers(app)` | Đăng ký 404/500 handler, trả JSON cho `/api/*` và HTML template cho page route. | `server/routes/errors.py:8` |


### `server/routes/socketio_events.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `register_socketio_events(socketio)` | Đăng ký inbound SocketIO events `connect`, `disconnect`, `ping` và emit `server_message`/`pong`. | `server/routes/socketio_events.py:12` |


### `server/time_utils.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `now_vietnam()` | Return the current datetime in Vietnam (timezone aware). | `server/time_utils.py:33` |
| `now_iso()` | Return the current Vietnam time as an ISO 8601 string. | `server/time_utils.py:37` |
| `to_vietnam(dt)` | Ensure ``dt`` is expressed in the Vietnam timezone. | `server/time_utils.py:41` |
| `_normalise_future_timestamp(dt)` | Clamp timestamps that sit unreasonably far in the future. | `server/time_utils.py:53` |
| `_parse_with_known_formats(value)` | Try to parse ``value`` using a list of known datetime formats. | `server/time_utils.py:104` |
| `parse_agent_timestamp(value)` | Normalise any timestamp sent by an agent to Vietnam local time. | `server/time_utils.py:123` |
| `format_datetime(value, fmt)` | Format ``value`` (string or datetime) using Vietnam local time. | `server/time_utils.py:164` |
| `calculate_age_seconds(value)` | Return the age of ``value`` in seconds relative to Vietnam time. | `server/time_utils.py:185` |
| `get_time_ago_string(value)` | Return a human readable "time ago" string for ``value``. | `server/time_utils.py:195` |


## Package `server/config`


### `server/config/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `server/config/rbac_config.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `get_all_permissions(role)` | Get all permissions for a role. | `server/config/rbac_config.py:97` |
| `check_permission(role, permission)` | Check if role has specific permission. | `server/config/rbac_config.py:102` |
| `can_access_group(user, group)` | Check if user can access a specific group. | `server/config/rbac_config.py:107` |
| `is_admin(role)` | Check if role is admin. | `server/config/rbac_config.py:124` |


## Package `server/controllers`


### `server/controllers/web_auth_controller.py`

> Đổi tên từ `AdminAuthController` → `WebAuthController` (P1 #10 — tách rõ agent auth vs web auth). Module `admin_auth_controller.py` cũ trở thành shim re-export `WebAuthController` + alias `AdminAuthController = WebAuthController` để không vỡ import legacy. Xóa alias khi tất cả call site migrate.

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WebAuthController` | Controller for admin/teacher web-UI authentication (login/logout/refresh/profile, httpOnly cookie) | `server/controllers/web_auth_controller.py:52` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WebAuthController` | `__init__(self, admin_auth_service, jwt_service, socketio)` | Khởi tạo controller, gắn blueprint `admin_auth`. | `server/controllers/web_auth_controller.py:55` |
| `WebAuthController` | `_register_routes(self)` | Register routes `/admin/auth/*` (login/me/refresh/logout/change-password/profile). | `server/controllers/web_auth_controller.py:64` |
| `WebAuthController` | `_success(self, data, message, status_code)` | Helper response thành công (JSON `{success: true, ...}`). | `server/controllers/web_auth_controller.py:89` |
| `WebAuthController` | `_error(self, message, status_code, code)` | Helper response lỗi (`{success: false, error, code}`). | `server/controllers/web_auth_controller.py:95` |
| `WebAuthController` | `login(self)` | `POST /api/admin/auth/login` — username/password → set httpOnly cookies. | `server/controllers/web_auth_controller.py:105` |
| `WebAuthController` | `get_profile(self)` | `GET /api/admin/auth/me` — trả profile user hiện tại. | `server/controllers/web_auth_controller.py:174` |
| `WebAuthController` | `refresh_token(self)` | `POST /api/admin/auth/refresh` — issue access token mới. | `server/controllers/web_auth_controller.py:196` |
| `WebAuthController` | `logout(self)` | `POST /api/admin/auth/logout` — revoke session, clear cookies. | `server/controllers/web_auth_controller.py:242` |
| `WebAuthController` | `change_password(self)` | `PUT /api/admin/auth/change-password`. | `server/controllers/web_auth_controller.py:273` |
| `WebAuthController` | `update_profile(self)` | `PUT /api/admin/auth/profile` — cập nhật email, audit `profile.update` qua `audit_service.log_action(...)`. | `server/controllers/web_auth_controller.py:303` |


### `server/controllers/agent_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentController` | Controller for agent operations | `server/controllers/agent_controller.py:21` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentController` | `__init__(self, agent_model, agent_service, rbac_service, socketio, policy_service)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/agent_controller.py:24` |
| `AgentController` | `_register_routes(self)` | Register routes for this controller | `server/controllers/agent_controller.py:35` |
| `AgentController` | `_success_response(self, data, message, status_code)` | Helper method for success responses | `server/controllers/agent_controller.py:66` |
| `AgentController` | `_error_response(self, message, status_code)` | Helper method for error responses | `server/controllers/agent_controller.py:73` |
| `AgentController` | `_validate_json_request(self, required_fields)` | Validate JSON request | `server/controllers/agent_controller.py:77` |
| `AgentController` | `_get_pagination_params(self)` | Get pagination parameters | `server/controllers/agent_controller.py:93` |
| `AgentController` | `_get_filter_params(self, allowed_filters)` | Get filter parameters | `server/controllers/agent_controller.py:107` |
| `AgentController` | `_serialize_agent(self, agent)` | Ensure agent dict is JSON serializable. | `server/controllers/agent_controller.py:118` |
| `AgentController` | `register_agent(self)` | Register a new agent | `server/controllers/agent_controller.py:134` |
| `AgentController` | `heartbeat(self)` | Process agent heartbeat | `server/controllers/agent_controller.py:162` |
| `AgentController` | `_check_agent_ownership(self, agent)` | Check if current teacher can access this agent. Returns error response or None. | `server/controllers/agent_controller.py:218` |
| `AgentController` | `list_agents(self)` | List all agents with filtering - COMPLETE VERSION - vietnam only | `server/controllers/agent_controller.py:225` |
| `AgentController` | `get_agent(self, agent_id)` | Get detailed agent information | `server/controllers/agent_controller.py:328` |
| `AgentController` | `delete_agent(self, agent_id)` | Delete an agent | `server/controllers/agent_controller.py:346` |
| `AgentController` | `update_display_name(self, agent_id)` | Update agent display name | `server/controllers/agent_controller.py:379` |
| `AgentController` | `update_position(self, agent_id)` | Update agent position | `server/controllers/agent_controller.py:397` |
| `AgentController` | `update_group(self, agent_id)` | Move agent to a new group | `server/controllers/agent_controller.py:416` |
| `AgentController` | `get_agent_policy(self, agent_id)` | GET /agents/<agent_id>/policy - View current policy of agent | `server/controllers/agent_controller.py:457` |
| `AgentController` | `set_agent_policy(self, agent_id)` | PATCH /agents/<agent_id>/policy - Set policy for agent | `server/controllers/agent_controller.py:477` |
| `AgentController` | `get_statistics(self)` | Get agent statistics - RBAC-aware: teacher only sees their agents | `server/controllers/agent_controller.py:529` |
| `AgentController` | `debug_status(self)` | Return debug information for troubleshooting | `server/controllers/agent_controller.py:563` |
| `AgentController` | `debug_direct_call(self)` | Simple endpoint to verify controller accessibility | `server/controllers/agent_controller.py:589` |


### `server/controllers/api_key_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `APIKeyController` | Controller for API key management operations | `server/controllers/api_key_controller.py:20` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `APIKeyController` | `__init__(self, api_key_model, api_key_service, socketio)` | Initialize API Key Controller. | `server/controllers/api_key_controller.py:23` |
| `APIKeyController` | `_register_routes(self)` | Register routes for this controller (all require admin login) | `server/controllers/api_key_controller.py:39` |
| `APIKeyController` | `_success_response(self, data, message, status_code)` | Helper method for success responses | `server/controllers/api_key_controller.py:77` |
| `APIKeyController` | `_error_response(self, message, status_code)` | Helper method for error responses | `server/controllers/api_key_controller.py:87` |
| `APIKeyController` | `list_api_keys(self)` | GET /api/api-keys | `server/controllers/api_key_controller.py:95` |
| `APIKeyController` | `create_api_key(self)` | POST /api/api-keys | `server/controllers/api_key_controller.py:126` |
| `APIKeyController` | `get_api_key(self, key_id)` | GET /api/api-keys/<key_id> | `server/controllers/api_key_controller.py:196` |
| `APIKeyController` | `update_api_key(self, key_id)` | PUT/PATCH /api/api-keys/<key_id> | `server/controllers/api_key_controller.py:213` |
| `APIKeyController` | `delete_api_key(self, key_id)` | DELETE /api/api-keys/<key_id> | `server/controllers/api_key_controller.py:268` |
| `APIKeyController` | `revoke_api_key(self, key_id)` | POST /api/api-keys/<key_id>/revoke | `server/controllers/api_key_controller.py:279` |
| `APIKeyController` | `get_stats(self)` | GET /api/api-keys/stats | `server/controllers/api_key_controller.py:299` |
| `APIKeyController` | `validate_key(self)` | POST /api/api-keys/validate | `server/controllers/api_key_controller.py:312` |


### `server/controllers/audit_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AuditController` | Controller for audit log viewing (Admin only) | `server/controllers/audit_controller.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AuditController` | `__init__(self, audit_service, socketio)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/audit_controller.py:19` |
| `AuditController` | `_register_routes(self)` | Register routes | `server/controllers/audit_controller.py:26` |
| `AuditController` | `_success(self, data, message, status_code)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/audit_controller.py:36` |
| `AuditController` | `_error(self, message, status_code)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/audit_controller.py:42` |
| `AuditController` | `list_logs(self)` | GET /api/admin/audit?action=user.create&resource_type=users&limit=100&skip=0 | `server/controllers/audit_controller.py:51` |
| `AuditController` | `user_activity(self, user_id)` | GET /api/admin/audit/user/<user_id>?limit=50 | `server/controllers/audit_controller.py:89` |


### `server/controllers/auth_controller.py`

> **Tên class chính: `AgentAuthController`** (đổi tên ở Quick Wins phase). Alias `AuthController = AgentAuthController` được giữ để không vỡ import cũ; sẽ gỡ khi tất cả call site migrate. Cặp với `WebAuthController` (file `controllers/web_auth_controller.py`, đổi tên từ `AdminAuthController`) — agent dùng Bearer JWT qua header, web dùng httpOnly cookie qua `/api/admin/auth/*`.

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentAuthController` | Controller cho JWT auth của AGENT (refresh, logout, verify, token-info). | `server/controllers/auth_controller.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentAuthController` | `__init__(self, jwt_service, agent_model, socketio)` | Initialize Agent Auth Controller. | `server/controllers/auth_controller.py:19` |
| `AgentAuthController` | `_register_routes(self)` | Register routes for this controller | `server/controllers/auth_controller.py:35` |
| `AgentAuthController` | `_success_response(self, data, message, status_code)` | Helper method for success responses | `server/controllers/auth_controller.py:63` |
| `AgentAuthController` | `_error_response(self, message, status_code, code)` | Helper method for error responses | `server/controllers/auth_controller.py:70` |
| `AgentAuthController` | `refresh_token(self)` | Refresh access token using refresh token. | `server/controllers/auth_controller.py:77` |
| `AgentAuthController` | `logout(self)` | Logout agent by revoking tokens. | `server/controllers/auth_controller.py:152` |
| `AgentAuthController` | `verify_token(self)` | Verify if a token is valid. | `server/controllers/auth_controller.py:220` |
| `AgentAuthController` | `token_info(self)` | Get information about a token without full validation. | `server/controllers/auth_controller.py:275` |


### `server/controllers/group_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `GroupController` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:17` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `GroupController` | `__init__(self, group_service, rbac_service)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:18` |
| `GroupController` | `_register_routes(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:25` |
| `GroupController` | `_is_teacher(self)` | Check if current request is from a teacher via web UI. | `server/controllers/group_controller.py:41` |
| `GroupController` | `list_groups(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:51` |
| `GroupController` | `get_group(self, group_id)` | Get single group details | `server/controllers/group_controller.py:64` |
| `GroupController` | `create_group(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:81` |
| `GroupController` | `update_group(self, group_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:102` |
| `GroupController` | `delete_group(self, group_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/group_controller.py:120` |
| `GroupController` | `set_teachers(self, group_id)` | Admin-only: Set the list of teacher_ids for a group. | `server/controllers/group_controller.py:137` |

Auth note 2026-05-28: toàn bộ route web-facing của `GroupController` đi qua `require_login(...)`; create và set-teachers tiếp tục yêu cầu admin qua `require_admin(...)`. Đây là hotfix cho lỗi `/api/groups` từng trả dữ liệu khi chưa đăng nhập.


### `server/controllers/log_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `LogController` | Controller for log operations | `server/controllers/log_controller.py:27` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `LogController` | `__init__(self, log_model, log_service, rbac_service, socketio)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/log_controller.py:30` |
| `LogController` | `_register_routes(self)` | Register all log routes | `server/controllers/log_controller.py:41` |
| `LogController` | `_is_teacher(self)` | Check if current request is from a teacher via web UI. | `server/controllers/log_controller.py:80` |
| `LogController` | `_get_teacher_log_filter(self, user)` | Get log filter for teacher - only logs from agents in teacher's groups. | `server/controllers/log_controller.py:87` |
| `LogController` | `receive_logs(self)` | Receive logs from agent | `server/controllers/log_controller.py:95` |
| `LogController` | `list_logs(self)` | Get all logs with filtering and pagination | `server/controllers/log_controller.py:125` |
| `LogController` | `clear_logs(self)` | Clear logs with optional filters | `server/controllers/log_controller.py:158` |
| `LogController` | `export_logs(self)` | Export logs | `server/controllers/log_controller.py:217` |
| `LogController` | `get_log_statistics(self)` | Get comprehensive log statistics for frontend | `server/controllers/log_controller.py:245` |
| `LogController` | `get_statistics(self)` | Get basic log statistics (legacy endpoint) | `server/controllers/log_controller.py:286` |
| `LogController` | `_get_filter_params(self)` | Extract filter parameters from request | `server/controllers/log_controller.py:298` |
| `LogController` | `_error_response(self, message, status_code)` | Create error response - vietnam only | `server/controllers/log_controller.py:317` |

Auth note 2026-05-28: `POST /api/logs` vẫn là agent-facing và dùng `require_jwt(...)`; các route web-facing như `GET /api/logs`, `/api/logs/stats`, `/api/logs/clear`, legacy DELETE `/api/logs` và `/api/logs/export` đều phải qua `require_login(...)`.


### `server/controllers/user_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `UserController` | Controller for user management (admin only) | `server/controllers/user_controller.py:17` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `UserController` | `__init__(self, user_service, socketio)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:20` |
| `UserController` | `_register_routes(self)` | Register all user management routes - admin only | `server/controllers/user_controller.py:27` |
| `UserController` | `list_users(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:71` |
| `UserController` | `get_user(self, user_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:108` |
| `UserController` | `create_user(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:121` |
| `UserController` | `update_user(self, user_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:155` |
| `UserController` | `delete_user(self, user_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:198` |
| `UserController` | `reset_password(self, user_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:224` |
| `UserController` | `get_statistics(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:252` |
| `UserController` | `_err(message, code)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/user_controller.py:264` |


### `server/controllers/whitelist_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistController` | Controller for whitelist operations | `server/controllers/whitelist_controller.py:25` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistController` | `__init__(self, whitelist_model, whitelist_service, rbac_service, socketio)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_controller.py:28` |
| `WhitelistController` | `_register_routes(self)` | Register all whitelist routes | `server/controllers/whitelist_controller.py:38` |
| `WhitelistController` | `_is_teacher(self)` | Check if current request is from a teacher via web UI. | `server/controllers/whitelist_controller.py:89` |
| `WhitelistController` | `_teacher_can_access_group(self, user, group_id)` | Check if teacher owns this group_id. | `server/controllers/whitelist_controller.py:96` |
| `WhitelistController` | `agent_sync(self)` | Sync whitelist for agents - vietnam ONLY | `server/controllers/whitelist_controller.py:109` |
| `WhitelistController` | `list_domains(self)` | Compatibility GET `/api/whitelist`; list unified whitelist entries via `WhitelistService.get_all_entries`, giữ `domains` alias cho UI cũ. | `server/controllers/whitelist_controller.py:170` |
| `WhitelistController` | `add_domain(self)` | Add new entry to whitelist | `server/controllers/whitelist_controller.py:223` |
| `WhitelistController` | `delete_domain(self, domain_id)` | Compatibility DELETE `/api/whitelist/<id>`; validate RBAC rồi gọi `WhitelistService.bulk_delete_entries([id])`. | `server/controllers/whitelist_controller.py:285` |
| `WhitelistController` | `import_domains(self)` | Import multiple domains - vietnam ONLY | `server/controllers/whitelist_controller.py:315` |
| `WhitelistController` | `export_domains(self)` | Export whitelist domains - vietnam ONLY | `server/controllers/whitelist_controller.py:355` |
| `WhitelistController` | `get_statistics(self)` | Get whitelist statistics - vietnam ONLY | `server/controllers/whitelist_controller.py:384` |
| `WhitelistController` | `bulk_add_entries(self)` | Bulk add multiple whitelist entries | `server/controllers/whitelist_controller.py:399` |
| `WhitelistController` | `bulk_update_entries(self)` | Bulk update multiple whitelist entries | `server/controllers/whitelist_controller.py:435` |
| `WhitelistController` | `bulk_delete_entries(self)` | Bulk delete multiple whitelist entries | `server/controllers/whitelist_controller.py:498` |
| `WhitelistController` | `_error_response(self, message, status_code)` | Create error response - vietnam ONLY | `server/controllers/whitelist_controller.py:548` |


### `server/controllers/whitelist_profile_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistProfileController` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:13` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistProfileController` | `__init__(self, profile_service, rbac_service)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:14` |
| `WhitelistProfileController` | `_register_routes(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:21` |
| `WhitelistProfileController` | `_get_user(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:51` |
| `WhitelistProfileController` | `_check_group_access(self, group_id)` | Verify user can access this group. Returns (group, error_response). | `server/controllers/whitelist_profile_controller.py:54` |
| `WhitelistProfileController` | `my_profiles(self)` | GET /api/my-profiles - Return all profiles owned by current teacher. | `server/controllers/whitelist_profile_controller.py:70` |
| `WhitelistProfileController` | `list_profiles(self, group_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:94` |
| `WhitelistProfileController` | `create_profile(self, group_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:108` |
| `WhitelistProfileController` | `update_profile(self, group_id, profile_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:135` |
| `WhitelistProfileController` | `delete_profile(self, group_id, profile_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:153` |
| `WhitelistProfileController` | `activate_profile(self, group_id, profile_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:170` |
| `WhitelistProfileController` | `deactivate_profile(self, group_id, profile_id)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/controllers/whitelist_profile_controller.py:185` |


## Package `server/database`


### `server/database/config.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `Config` | Configuration class for the application - vietnam ONLY | `server/database/config.py:39` |
| `DevelopmentConfig` | Development configuration - vietnam ONLY | `server/database/config.py:134` |
| `ProductionConfig` | Production configuration - vietnam ONLY | `server/database/config.py:139` |
| `TestingConfig` | Testing configuration - vietnam ONLY | `server/database/config.py:148` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `get_env(key, default)` | Get value from environment variable with proper type conversion. | `server/database/config.py:26` |
| `_mask_connection_uri(uri)` | Mask username/password trong MongoDB URI trước khi log, tránh lộ plaintext secret trên Render logs. | `server/database/config.py:41` |
| `get_mongo_client(config)` | Get MongoDB client with optimized settings - vietnam logging | `server/database/config.py:75` |
| `close_mongo_client()` | Close MongoDB client - vietnam logging | `server/database/config.py:112` |
| `get_config()` | Get configuration instance. | `server/database/config.py:120` |
| `get_database(config)` | Get database instance | `server/database/config.py:124` |
| `get_config_by_name(config_name)` | Get configuration by environment name | `server/database/config.py:154` |
| `validate_config(config)` | Validate configuration settings - vietnam logging | `server/database/config.py:167` |
| `get_connection_info()` | Get MongoDB connection information with vietnam timestamp | `server/database/config.py:201` |
| `log_config_status(config)` | Log current configuration status with vietnam timestamps | `server/database/config.py:227` |


## Package `server/middleware`


### `server/middleware/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `server/middleware/auth.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `APIKeyMiddleware` | Flask middleware class for API key authentication. | `server/middleware/auth.py:172` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `APIKeyMiddleware` | `__init__(self, api_key_service, protected_prefixes)` | Initialize middleware. | `server/middleware/auth.py:178` |
| `APIKeyMiddleware` | `before_request(self)` | Check API key before each request. | `server/middleware/auth.py:191` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `init_auth_middleware(api_key_service, jwt_service)` | Initialize the auth middleware with the API Key Service and JWT Service. | `server/middleware/auth.py:20` |
| `get_api_key_from_request()` | Extract API key from request. | `server/middleware/auth.py:35` |
| `require_api_key(permission)` | Decorator to require valid API key for endpoint access. | `server/middleware/auth.py:71` |
| `optional_api_key(f)` | Decorator that validates API key if provided, but doesn't require it. | `server/middleware/auth.py:136` |
| `get_jwt_from_request()` | Extract JWT token from request. | `server/middleware/auth.py:241` |
| `require_jwt(f)` | Decorator to require valid JWT token for endpoint access. | `server/middleware/auth.py:273` |
| `optional_jwt(f)` | Decorator that validates JWT if provided, but doesn't require it. | `server/middleware/auth.py:343` |
| `require_jwt_or_api_key(permission)` | Decorator that accepts either JWT token or API key. | `server/middleware/auth.py:381` |


### `server/middleware/rbac.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `init_rbac_middleware(admin_auth_service, rbac_service, jwt_service, user_model)` | Initialize RBAC middleware with required services. | `server/middleware/rbac.py:26` |
| `get_rbac_service()` | Get the RBAC service instance (for controllers that need ownership validation). | `server/middleware/rbac.py:39` |
| `_extract_token()` | Extract JWT token from request. | `server/middleware/rbac.py:44` |
| `_validate_admin_token(token)` | Validate token and ensure it belongs to an admin/teacher user. | `server/middleware/rbac.py:62` |
| `require_login(f)` | Decorator: Require valid admin/teacher JWT. | `server/middleware/rbac.py:98` |
| `require_admin(f)` | Decorator: Require admin role. | `server/middleware/rbac.py:146` |
| `require_permission(permission)` | Decorator: Require specific permission (resource:action format). | `server/middleware/rbac.py:170` |
| `inject_current_user(f)` | Decorator: Inject g.current_user without blocking. | `server/middleware/rbac.py:204` |
| `require_group_ownership(group_id_param)` | Decorator: Check Teacher ownership on Group. | `server/middleware/rbac.py:228` |


## Package `server/models`


### `server/models/agent_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentModel` | Model for agent data operations | `server/models/agent_model.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/agent_model.py:19` |
| `AgentModel` | `_setup_indexes(self)` | Setup indexes for agents collection | `server/models/agent_model.py:25` |
| `AgentModel` | `register_agent(self, agent_data)` | Register a new agent (CREATE only, not update) - vietnam ONLY | `server/models/agent_model.py:44` |
| `AgentModel` | `update_agent(self, agent_id, update_data)` | Update existing agent - vietnam ONLY | `server/models/agent_model.py:68` |
| `AgentModel` | `update_agent_group(self, agent_id, group_id, status)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/agent_model.py:82` |
| `AgentModel` | `update_heartbeat(self, agent_id, update_data)` | Update agent heartbeat - vietnam ONLY | `server/models/agent_model.py:93` |
| `AgentModel` | `find_by_agent_id(self, agent_id)` | Find agent by agent_id | `server/models/agent_model.py:116` |
| `AgentModel` | `count_by_group(self, group_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/agent_model.py:124` |
| `AgentModel` | `move_agents_to_group(self, source_group_id, target_group_id)` | Bulk move agents sang group khác, dùng khi xóa group và cần chuyển agent về Pending. | `server/models/agent_model.py:131` |
| `AgentModel` | `find_agent_ids_by_group_ids(self, group_ids)` | Trả danh sách `agent_id` thuộc các group, phục vụ RBAC log filter mà không để service query collection trực tiếp. | `server/models/agent_model.py:145` |
| `AgentModel` | `find_by_hostname(self, hostname)` | Find agents by hostname | `server/models/agent_model.py:131` |
| `AgentModel` | `find_by_device_id(self, device_id)` | Find agent by device ID | `server/models/agent_model.py:139` |
| `AgentModel` | `get_all_agents(self, query, limit, skip)` | Get all agents with optional filtering | `server/models/agent_model.py:147` |
| `AgentModel` | `count_agents(self, query)` | Count agents with optional filtering | `server/models/agent_model.py:157` |
| `AgentModel` | `get_active_agents(self, inactive_threshold_minutes)` | Get list of active agents - vietnam ONLY | `server/models/agent_model.py:167` |
| `AgentModel` | `get_inactive_agents(self, inactive_threshold_minutes)` | Get list of inactive agents - vietnam ONLY | `server/models/agent_model.py:180` |
| `AgentModel` | `delete_agent(self, agent_id)` | Delete an agent | `server/models/agent_model.py:193` |
| `AgentModel` | `get_agent_statistics(self, inactive_threshold_minutes)` | Get agent statistics - vietnam ONLY | `server/models/agent_model.py:203` |


### `server/models/agent_policy_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentPolicyModel` | Collection: agent_policies | `server/models/agent_policy_model.py:18` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentPolicyModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/agent_policy_model.py:42` |
| `AgentPolicyModel` | `_setup_indexes(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/agent_policy_model.py:48` |
| `AgentPolicyModel` | `get_policy(self, agent_id)` | Get policy for an agent. Returns None if not set (= mode none). | `server/models/agent_policy_model.py:65` |
| `AgentPolicyModel` | `get_effective_mode(self, agent_id)` | Return effective mode (considering expires_at). | `server/models/agent_policy_model.py:74` |
| `AgentPolicyModel` | `set_policy(self, agent_id, mode, applied_by_user, reason, custom_whitelist, expires_at)` | Create or update policy for an agent. | `server/models/agent_policy_model.py:103` |
| `AgentPolicyModel` | `reset_policy(self, agent_id, applied_by_user)` | Shortcut: reset to mode none. | `server/models/agent_policy_model.py:144` |
| `AgentPolicyModel` | `get_custom_whitelist(self, agent_id)` | Get custom whitelist entries for agent (only meaningful when mode=custom_whitelist). | `server/models/agent_policy_model.py:148` |
| `AgentPolicyModel` | `list_isolated_agents(self)` | List of agent_ids currently isolated. | `server/models/agent_policy_model.py:160` |
| `AgentPolicyModel` | `list_policies_by_agent_ids(self, agent_ids)` | Batch load policies for multiple agents (used for dashboard). | `server/models/agent_policy_model.py:168` |
| `AgentPolicyModel` | `count_by_mode(self)` | Count agents by mode (for dashboard stats). | `server/models/agent_policy_model.py:179` |


### `server/models/api_key_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `APIKeyModel` | Model for API Key data operations | `server/models/api_key_model.py:31` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `APIKeyModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/api_key_model.py:37` |
| `APIKeyModel` | `_setup_indexes(self)` | Setup indexes for api_keys collection | `server/models/api_key_model.py:43` |
| `APIKeyModel` | `generate_api_key()` | Generate a new API key. | `server/models/api_key_model.py:58` |
| `APIKeyModel` | `hash_api_key(api_key)` | Hash an API key for secure storage using HMAC-SHA256. | `server/models/api_key_model.py:70` |
| `APIKeyModel` | `_hash_api_key_legacy(api_key)` | Legacy plain SHA-256 hash - for backward compat with old keys only. | `server/models/api_key_model.py:87` |
| `APIKeyModel` | `create_api_key(self, name, description, expires_in_days, permissions, created_by)` | Create a new API key. | `server/models/api_key_model.py:91` |
| `APIKeyModel` | `validate_api_key(self, api_key, required_permission)` | Validate API key format/hash/active/expiration/permission, update `last_used_at` và tăng `usage_count`; không rate-limit. | `server/models/api_key_model.py:164` |
| `APIKeyModel` | `revoke_api_key(self, key_id, revoked_by)` | Revoke an API key. | `server/models/api_key_model.py:267` |
| `APIKeyModel` | `list_api_keys(self, include_revoked, page, limit)` | List all API keys (without showing the actual keys). | `server/models/api_key_model.py:299` |
| `APIKeyModel` | `get_api_key_by_id(self, key_id)` | Get API key details by ID (without the actual key). | `server/models/api_key_model.py:354` |
| `APIKeyModel` | `update_api_key(self, key_id, name, description, permissions, is_active)` | Update API key properties. | `server/models/api_key_model.py:379` |
| `APIKeyModel` | `get_stats(self)` | Get API key statistics. | `server/models/api_key_model.py:428` |


### `server/models/audit_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AuditModel` | Model for audit log operations (collection: audit_logs) | `server/models/audit_model.py:17` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AuditModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/audit_model.py:20` |
| `AuditModel` | `_setup_indexes(self)` | Setup indexes for audit_logs collection | `server/models/audit_model.py:26` |
| `AuditModel` | `log(self, audit_data)` | Create an audit log entry | `server/models/audit_model.py:44` |
| `AuditModel` | `get_logs(self, query, limit, skip)` | Get audit logs with optional filtering | `server/models/audit_model.py:60` |
| `AuditModel` | `get_user_activity(self, user_id, limit)` | Get audit logs for a specific user | `server/models/audit_model.py:75` |
| `AuditModel` | `count_logs(self, query)` | Count audit logs | `server/models/audit_model.py:87` |


### `server/models/group_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `GroupModel` | Model for managing agent groups and their whitelists. | `server/models/group_model.py:11` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `GroupModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:14` |
| `GroupModel` | `_setup_indexes(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:20` |
| `GroupModel` | `ensure_pending_group(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:30` |
| `GroupModel` | `find_pending_group(self)` | Tìm system group Pending hiện có, phục vụ `GroupService.delete_group()` mà không truy cập `.collection` trong service. | `server/models/group_model.py:59` |
| `GroupModel` | `create_group(self, name, description, whitelist, is_system, created_by)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:59` |
| `GroupModel` | `add_teacher(self, group_id, teacher_id)` | Add a teacher to the group's teacher_ids list. | `server/models/group_model.py:76` |
| `GroupModel` | `remove_teacher(self, group_id, teacher_id)` | Remove a teacher from the group's teacher_ids list. | `server/models/group_model.py:84` |
| `GroupModel` | `set_teachers(self, group_id, teacher_ids)` | Set the full teacher_ids list for a group. | `server/models/group_model.py:92` |
| `GroupModel` | `list_groups(self, query_filter)` | List groups, optionally filtered (e.g. by created_by for teacher). | `server/models/group_model.py:100` |
| `GroupModel` | `find_by_id(self, group_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:104` |
| `GroupModel` | `find_accessible_group_ids_for_teacher(self, teacher_id)` | Trả group IDs mà teacher được gán hoặc tạo, giữ legacy `created_by` fallback cho RBAC. | `server/models/group_model.py:108` |
| `GroupModel` | `update_group(self, group_id, update_data)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:110` |
| `GroupModel` | `delete_group(self, group_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:138` |
| `GroupModel` | `bump_whitelist_version(self, group_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/group_model.py:142` |


### `server/models/log_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `LogModel` | Model for log data operations - vietnam ONLY | `server/models/log_model.py:25` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `LogModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/log_model.py:28` |
| `LogModel` | `_create_indexes(self)` | Create necessary indexes for performance | `server/models/log_model.py:36` |
| `LogModel` | `count_logs(self, query)` | Count logs with error handling and debugging | `server/models/log_model.py:62` |
| `LogModel` | `find_all_logs(self, query, limit, offset)` | Find all logs with enhanced debugging - vietnam ONLY | `server/models/log_model.py:78` |
| `LogModel` | `delete_logs(self, query)` | Delete logs with optional query | `server/models/log_model.py:134` |
| `LogModel` | `insert_logs(self, logs)` | Insert multiple log entries with vietnam timezone | `server/models/log_model.py:150` |
| `LogModel` | `_parse_timestamp(self, timestamp)` | Parse timestamp and convert to Vietnam aware datetime. | `server/models/log_model.py:171` |
| `LogModel` | `get_total_count(self)` | Get total count of all logs | `server/models/log_model.py:182` |
| `LogModel` | `get_count_by_action(self, action)` | Get count of logs by action | `server/models/log_model.py:190` |
| `LogModel` | `get_recent_logs(self, limit)` | Get recent logs in vietnam timezone | `server/models/log_model.py:198` |
| `LogModel` | `find_logs(self, query, limit, skip, sort_field, sort_order)` | Find logs with query - vietnam ONLY | `server/models/log_model.py:226` |
| `LogModel` | `get_logs_summary(self, since)` | Get logs summary statistics since a date in vietnam timezone | `server/models/log_model.py:258` |


### `server/models/session_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `SessionModel` | Model for admin session operations (collection: admin_sessions) | `server/models/session_model.py:17` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `SessionModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/session_model.py:20` |
| `SessionModel` | `_setup_indexes(self)` | Setup indexes for admin_sessions collection | `server/models/session_model.py:26` |
| `SessionModel` | `create(self, session_data)` | Create a new session | `server/models/session_model.py:49` |
| `SessionModel` | `find_by_access_jti(self, jti)` | Find session by access token JTI | `server/models/session_model.py:64` |
| `SessionModel` | `find_by_refresh_jti(self, jti)` | Find session by refresh token JTI | `server/models/session_model.py:72` |
| `SessionModel` | `get_user_sessions(self, user_id)` | Get all active sessions for a user | `server/models/session_model.py:80` |
| `SessionModel` | `revoke(self, jti)` | Revoke a session by JTI (access or refresh) | `server/models/session_model.py:95` |
| `SessionModel` | `revoke_all_user(self, user_id)` | Revoke all sessions for a user | `server/models/session_model.py:110` |
| `SessionModel` | `is_session_revoked(self, jti)` | Check if a session is revoked by JTI | `server/models/session_model.py:123` |
| `SessionModel` | `cleanup_expired(self)` | Manually cleanup expired sessions (TTL index handles this automatically) | `server/models/session_model.py:139` |


### `server/models/user_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `UserModel` | Model for admin/teacher user operations | `server/models/user_model.py:23` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `UserModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/user_model.py:26` |
| `UserModel` | `_setup_indexes(self)` | Setup indexes for users collection | `server/models/user_model.py:32` |
| `UserModel` | `create(self, user_data)` | Create a new user | `server/models/user_model.py:48` |
| `UserModel` | `find_by_id(self, user_id)` | Find user by _id | `server/models/user_model.py:75` |
| `UserModel` | `find_by_username(self, username)` | Find user by username (case-insensitive, regex-safe) | `server/models/user_model.py:83` |
| `UserModel` | `find_by_email(self, email)` | Find user by email (case-insensitive, regex-safe) | `server/models/user_model.py:94` |
| `UserModel` | `get_all_users(self, query, limit, skip)` | Get all users with optional filtering | `server/models/user_model.py:105` |
| `UserModel` | `count_users(self, query)` | Count users | `server/models/user_model.py:120` |
| `UserModel` | `update(self, user_id, update_data)` | Update user by _id | `server/models/user_model.py:134` |
| `UserModel` | `update_last_login(self, user_id)` | Update last login timestamp | `server/models/user_model.py:147` |
| `UserModel` | `increment_failed_attempts(self, user_id)` | Increment failed login attempts, lock if >= MAX | `server/models/user_model.py:163` |
| `UserModel` | `reset_failed_attempts(self, user_id)` | Reset failed login attempts after successful login | `server/models/user_model.py:188` |
| `UserModel` | `is_locked(self, user)` | Check if user account is currently locked | `server/models/user_model.py:204` |
| `UserModel` | `lock_account(self, user_id, duration_minutes)` | Manually lock an account | `server/models/user_model.py:211` |
| `UserModel` | `delete(self, user_id)` | Delete a user | `server/models/user_model.py:230` |
| `UserModel` | `get_user_statistics(self)` | Get user statistics by role | `server/models/user_model.py:244` |


### `server/models/whitelist_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistModel` | Model for whitelist data operations - vietnam ONLY | `server/models/whitelist_model.py:18` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_model.py:21` |
| `WhitelistModel` | `_ensure_global_meta(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_model.py:31` |
| `WhitelistModel` | `get_global_version(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_model.py:44` |
| `WhitelistModel` | `bump_global_version(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_model.py:51` |
| `WhitelistModel` | `_create_indexes(self)` | Create necessary indexes with enhanced conflict handling | `server/models/whitelist_model.py:66` |
| `WhitelistModel` | `insert_entry(self, entry_data)` | Insert a new whitelist entry - vietnam ONLY | `server/models/whitelist_model.py:168` |
| `WhitelistModel` | `find_all_entries(self, query, sort_field, sort_order)` | Find all whitelist entries with proper sorting - vietnam ONLY | `server/models/whitelist_model.py:207` |
| `WhitelistModel` | `_convert_entry_timezones(self, entry)` | Convert entry datetime fields for display - vietnam ONLY | `server/models/whitelist_model.py:246` |
| `WhitelistModel` | `find_entry_by_value(self, value, active_only)` | Find entry by value (case-insensitive) | `server/models/whitelist_model.py:272` |
| `WhitelistModel` | `reactivate_entry(self, entry_id)` | Reactivate entry đã tồn tại khi add trùng inactive entry. | `server/models/whitelist_model.py:290` |
| `WhitelistModel` | `find_raw_entries(self, query, projection, sort_field, sort_order)` | Trả raw whitelist documents cho service change tracking, giữ query trực tiếp trong model layer. | `server/models/whitelist_model.py:304` |
| `WhitelistModel` | `find_entry_access_info(self, entry_id)` | Lookup tối thiểu `_id`, `scope`, `group_id`, `is_active` để service kiểm tra quyền teacher trên entry thật. | `server/models/whitelist_model.py:316` |
| `WhitelistModel` | `cleanup_expired_entries(self)` | Remove expired entries - vietnam ONLY | `server/models/whitelist_model.py:290` |
| `WhitelistModel` | `validate_entry_value(self, entry_type, value)` | Validate entry value based on type | `server/models/whitelist_model.py:314` |
| `WhitelistModel` | `_validate_domain(self, domain)` | Validate domain format | `server/models/whitelist_model.py:334` |
| `WhitelistModel` | `_validate_ip(self, ip)` | Validate IP address format | `server/models/whitelist_model.py:344` |
| `WhitelistModel` | `_validate_url(self, url)` | Validate URL format | `server/models/whitelist_model.py:353` |
| `WhitelistModel` | `delete_entry(self, entry_id)` | Delete entry by ID | `server/models/whitelist_model.py:364` |
| `WhitelistModel` | `update_entry(self, entry_id, update_data)` | Update entry by ID - vietnam ONLY | `server/models/whitelist_model.py:381` |
| `WhitelistModel` | `get_statistics(self)` | Get whitelist statistics | `server/models/whitelist_model.py:406` |
| `WhitelistModel` | `find_entry_by_id(self, entry_id, active_only)` | Find entry by ID. Set active_only=True to skip inactive entries. | `server/models/whitelist_model.py:433` |
| `WhitelistModel` | `get_entries_for_sync(self, since_date, scope, group_id)` | Get entries for agent synchronization - vietnam ONLY | `server/models/whitelist_model.py:451` |
| `WhitelistModel` | `bulk_insert_entries(self, entries)` | Bulk insert multiple entries - vietnam ONLY | `server/models/whitelist_model.py:488` |
| `WhitelistModel` | `build_query_from_filters(self, filters)` | Build MongoDB query from filters | `server/models/whitelist_model.py:516` |
| `WhitelistModel` | `verify_dns(self, domain)` | Verify DNS resolution for a domain | `server/models/whitelist_model.py:542` |


### `server/models/whitelist_profile_model.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistProfileModel` | Model for per-teacher whitelist profiles. | `server/models/whitelist_profile_model.py:18` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistProfileModel` | `__init__(self, db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:21` |
| `WhitelistProfileModel` | `_setup_indexes(self)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:27` |
| `WhitelistProfileModel` | `create_profile(self, group_id, teacher_id, teacher_username, name, domains)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:36` |
| `WhitelistProfileModel` | `find_by_id(self, profile_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:55` |
| `WhitelistProfileModel` | `list_by_group(self, group_id, teacher_id)` | List profiles for a group, optionally filtered by teacher. | `server/models/whitelist_profile_model.py:61` |
| `WhitelistProfileModel` | `list_by_teacher_groups(self, teacher_id, group_ids)` | List profile theo teacher và danh sách group được phép, thay cho direct `.collection` ở service. | `server/models/whitelist_profile_model.py:68` |
| `WhitelistProfileModel` | `update_profile(self, profile_id, update_data)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:68` |
| `WhitelistProfileModel` | `bump_version(self, profile_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:82` |
| `WhitelistProfileModel` | `delete_profile(self, profile_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:89` |
| `WhitelistProfileModel` | `activate(self, profile_id)` | Activate a profile. Caller must deactivate others in group first. | `server/models/whitelist_profile_model.py:93` |
| `WhitelistProfileModel` | `deactivate(self, profile_id)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/models/whitelist_profile_model.py:101` |
| `WhitelistProfileModel` | `deactivate_all_in_group(self, group_id)` | Deactivate all active profiles in a group. Returns count updated. | `server/models/whitelist_profile_model.py:108` |
| `WhitelistProfileModel` | `get_active_profile(self, group_id)` | Get the currently active profile for a group (for agent sync). | `server/models/whitelist_profile_model.py:116` |


## Package `server/scripts`


### `server/scripts/seed_rbac.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `seed_rbac(admin_username, admin_password)` | Seed default admin user (roles are defined in config, not database) | `server/scripts/seed_rbac.py:38` |


## Package `server/services`


### `server/services/admin_auth_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AdminAuthService` | Service for admin/teacher authentication | `server/services/admin_auth_service.py:28` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AdminAuthService` | `__init__(self, user_model, jwt_service, session_model, audit_service, socketio)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/admin_auth_service.py:31` |
| `AdminAuthService` | `login(self, username, password, ip_address, user_agent)` | Authenticate admin/teacher user. | `server/services/admin_auth_service.py:45` |
| `AdminAuthService` | `logout(self, access_token, refresh_token)` | Logout by revoking tokens | `server/services/admin_auth_service.py:148` |
| `AdminAuthService` | `refresh_token(self, refresh_token)` | Refresh access token for admin/teacher. | `server/services/admin_auth_service.py:177` |
| `AdminAuthService` | `change_password(self, user_id, old_password, new_password)` | Change user's own password | `server/services/admin_auth_service.py:225` |
| `AdminAuthService` | `_hash_password(password)` | Hash password with bcrypt | `server/services/admin_auth_service.py:262` |
| `AdminAuthService` | `_verify_password(password, password_hash)` | Verify password against hash | `server/services/admin_auth_service.py:270` |
| `AdminAuthService` | `_validate_password(password)` | Validate password policy | `server/services/admin_auth_service.py:281` |
| `AdminAuthService` | `_extract_jti(self, token)` | Extract JTI from token without verification | `server/services/admin_auth_service.py:289` |
| `AdminAuthService` | `_sanitize_user(user)` | Remove sensitive fields | `server/services/admin_auth_service.py:297` |


### `server/services/agent_policy_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentPolicyService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/agent_policy_service.py:15` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentPolicyService` | `__init__(self, policy_model, agent_model, socketio)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/agent_policy_service.py:17` |
| `AgentPolicyService` | `get_policy(self, agent_id)` | Get current effective policy for an agent. | `server/services/agent_policy_service.py:26` |
| `AgentPolicyService` | `set_policy(self, agent_id, mode, applied_by_user, reason, custom_whitelist, duration_minutes)` | Set policy for agent. | `server/services/agent_policy_service.py:47` |
| `AgentPolicyService` | `isolate_agent(self, agent_id, applied_by_user, reason, duration_minutes)` | Shortcut: completely cut network for an agent. | `server/services/agent_policy_service.py:98` |
| `AgentPolicyService` | `reset_agent(self, agent_id, applied_by_user)` | Shortcut: remove isolate/custom, return to normal group whitelist. | `server/services/agent_policy_service.py:110` |
| `AgentPolicyService` | `_build_system_entries(self, server_host, source)` | Build list of system domains/IPs that MUST be present in all policy overrides. | `server/services/agent_policy_service.py:125` |
| `AgentPolicyService` | `apply_policy_to_sync(self, agent_id, group_domains, server_host)` | Core function: Merge agent policy into whitelist sync response. | `server/services/agent_policy_service.py:150` |
| `AgentPolicyService` | `get_policies_for_agents(self, agent_ids)` | Batch load policies (for list_agents dashboard). | `server/services/agent_policy_service.py:210` |
| `AgentPolicyService` | `get_stats(self)` | Policy statistics (for dashboard). | `server/services/agent_policy_service.py:214` |


### `server/services/agent_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentService` | Service class for agent business logic - vietnam ONLY | `server/services/agent_service.py:24` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentService` | `__init__(self, agent_model, group_model, socketio, jwt_service, policy_model)` | Initialize AgentService with proper parameters | `server/services/agent_service.py:27` |
| `AgentService` | `set_jwt_service(self, jwt_service)` | Set JWT service (for late initialization) | `server/services/agent_service.py:48` |
| `AgentService` | `_persist_status_change(self, agent, new_status)` | Persist status change to database when calculated status differs | `server/services/agent_service.py:53` |
| `AgentService` | `register_agent(self, agent_data, client_ip)` | Register a new agent using hostname+IP as identifier - vietnam ONLY | `server/services/agent_service.py:80` |
| `AgentService` | `get_agents_with_status(self)` | Get all agents with status calculation - vietnam ONLY | `server/services/agent_service.py:213` |
| `AgentService` | `calculate_statistics(self)` | Calculate agent statistics - vietnam ONLY | `server/services/agent_service.py:304` |
| `AgentService` | `process_heartbeat(self, agent_id, token, heartbeat_data, client_ip)` | Process agent heartbeat - vietnam ONLY | `server/services/agent_service.py:350` |
| `AgentService` | `get_total_agents(self)` | Get total number of agents | `server/services/agent_service.py:461` |
| `AgentService` | `get_active_agents_count(self)` | Get count of active agents | `server/services/agent_service.py:469` |
| `AgentService` | `get_all_agents(self, filters)` | Get all agents with optional filtering - vietnam ONLY | `server/services/agent_service.py:478` |
| `AgentService` | `get_agent_details(self, agent_id)` | Get detailed agent information - vietnam ONLY | `server/services/agent_service.py:535` |
| `AgentService` | `delete_agent(self, agent_id)` | Delete an agent and related data - vietnam ONLY | `server/services/agent_service.py:576` |
| `AgentService` | `update_display_name(self, agent_id, display_name)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/agent_service.py:600` |
| `AgentService` | `update_position(self, agent_id, position)` | Update agent position in layout | `server/services/agent_service.py:608` |
| `AgentService` | `move_agent_to_group(self, agent_id, group_id)` | Move agent to a new group | `server/services/agent_service.py:623` |


### `server/services/api_key_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `APIKeyService` | Service class for API key business logic | `server/services/api_key_service.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `APIKeyService` | `__init__(self, api_key_model, socketio)` | Initialize APIKeyService. | `server/services/api_key_service.py:19` |
| `APIKeyService` | `create_api_key(self, name, description, expires_in_days, permissions, created_by)` | Create a new API key. | `server/services/api_key_service.py:32` |
| `APIKeyService` | `validate_api_key(self, api_key, required_permission)` | Validate an API key for a specific permission; pass-through, không throttle/quota. | `server/services/api_key_service.py:87` |
| `APIKeyService` | `revoke_api_key(self, key_id, revoked_by)` | Revoke an API key. | `server/services/api_key_service.py:110` |
| `APIKeyService` | `list_api_keys(self, include_revoked, page, limit)` | List all API keys. | `server/services/api_key_service.py:140` |
| `APIKeyService` | `get_api_key(self, key_id)` | Get API key details. | `server/services/api_key_service.py:159` |
| `APIKeyService` | `update_api_key(self, key_id, name, description, permissions, is_active, updated_by)` | Update API key properties. | `server/services/api_key_service.py:171` |
| `APIKeyService` | `get_stats(self)` | Get API key statistics. | `server/services/api_key_service.py:212` |
| `APIKeyService` | `create_default_key_if_none(self)` | Create a default API key if none exist. | `server/services/api_key_service.py:216` |


### `server/services/audit_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AuditService` | Service for audit logging | `server/services/audit_service.py:18` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AuditService` | `__init__(self, audit_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/audit_service.py:21` |
| `AuditService` | `log_action(self, user, action, resource_type, resource_id, details, ip_address)` | Log an action to the audit trail. | `server/services/audit_service.py:25` |
| `AuditService` | `get_logs(self, query, limit, skip)` | Get audit logs with optional filtering | `server/services/audit_service.py:71` |
| `AuditService` | `get_user_activity(self, user_id, limit)` | Get activity logs for a specific user | `server/services/audit_service.py:77` |
| `AuditService` | `count_logs(self, query)` | Count audit logs | `server/services/audit_service.py:82` |
| `AuditService` | `_serialize(log)` | Convert ObjectId to string for JSON serialization | `server/services/audit_service.py:87` |


### `server/services/group_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `GroupService` | Business logic for group management. | `server/services/group_service.py:10` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `GroupService` | `__init__(self, group_model, agent_model, user_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:13` |
| `GroupService` | `_serialize(self, group)` | Convert ObjectIds to strings for JSON response. | `server/services/group_service.py:20` |
| `GroupService` | `_enrich_owner(self, group)` | Add created_by_username to group if user_model available. | `server/services/group_service.py:31` |
| `GroupService` | `list_groups(self, query_filter)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:40` |
| `GroupService` | `create_group(self, name, description, whitelist, created_by)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:44` |
| `GroupService` | `update_group(self, group_id, payload)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:48` |
| `GroupService` | `delete_group(self, group_id)` | Xóa group an toàn: không xóa system group, tìm Pending qua `GroupModel.find_pending_group`, chuyển agent qua `AgentModel.move_agents_to_group`, rồi xóa group. | `server/services/group_service.py:63` |
| `GroupService` | `bump_group_whitelist_version(self, group_id)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:89` |
| `GroupService` | `get_pending_group_id(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:95` |
| `GroupService` | `get_group(self, group_id)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:98` |
| `GroupService` | `get_default_metadata(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/group_service.py:104` |


### `server/services/jwt_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `JWTService` | Service for JWT token operations | `server/services/jwt_service.py:41` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `JWTService` | `__init__(self, db)` | Initialize JWT Service. | `server/services/jwt_service.py:44` |
| `JWTService` | `_setup_indexes(self)` | Setup MongoDB indexes for revoked tokens | `server/services/jwt_service.py:66` |
| `JWTService` | `generate_tokens(self, agent_id, user_id, additional_claims)` | Generate access and refresh tokens for an agent. | `server/services/jwt_service.py:81` |
| `JWTService` | `validate_access_token(self, token)` | Validate an access token. | `server/services/jwt_service.py:142` |
| `JWTService` | `validate_refresh_token(self, token)` | Validate a refresh token. | `server/services/jwt_service.py:180` |
| `JWTService` | `refresh_access_token(self, refresh_token)` | Refresh an access token using a valid refresh token. | `server/services/jwt_service.py:218` |
| `JWTService` | `refresh_tokens_with_rotation(self, refresh_token)` | Refresh both access and refresh tokens (token rotation for extra security). | `server/services/jwt_service.py:262` |
| `JWTService` | `revoke_token(self, token, token_type)` | Revoke a token by adding it to the revoked tokens list. | `server/services/jwt_service.py:316` |
| `JWTService` | `revoke_all_agent_tokens(self, agent_id)` | Revoke all tokens for a specific agent. | `server/services/jwt_service.py:378` |
| `JWTService` | `_is_token_revoked(self, jti)` | Check if a token is revoked by its JTI | `server/services/jwt_service.py:408` |
| `JWTService` | `decode_token_without_verification(self, token)` | Decode a token without verifying signature (for debugging/logging). | `server/services/jwt_service.py:419` |
| `JWTService` | `get_token_info(self, token)` | Get information about a token. | `server/services/jwt_service.py:437` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `init_jwt_service(db)` | Initialize the global JWT service instance | `server/services/jwt_service.py:479` |
| `get_jwt_service()` | Get the global JWT service instance | `server/services/jwt_service.py:486` |


### `server/services/log_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `LogService` | Service class for log business logic - vietnam ONLY | `server/services/log_service.py:19` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `LogService` | `__init__(self, log_model, agent_model, socketio)` | Initialize LogService with optional agent_model for agent lookups | `server/services/log_service.py:22` |
| `LogService` | `receive_logs(self, logs_data, agent_id)` | Receive and process logs from agents - vietnam ONLY | `server/services/log_service.py:29` |
| `LogService` | `get_all_logs(self, filters, limit, offset)` | Get all logs with filtering - vietnam ONLY | `server/services/log_service.py:221` |
| `LogService` | `clear_logs(self, filters)` | Clear logs with optional filters - vietnam ONLY | `server/services/log_service.py:363` |
| `LogService` | `export_logs(self, filters, format)` | Export logs in specified format - vietnam ONLY | `server/services/log_service.py:402` |
| `LogService` | `get_total_count(self)` | Get total count of logs via model wrapper - vietnam ONLY | `server/services/log_service.py:459` |
| `LogService` | `get_count_by_action(self, action)` | Get count of logs for a specific action - vietnam ONLY | `server/services/log_service.py:470` |
| `LogService` | `get_recent_logs(self, limit)` | Get recent logs via model wrapper - vietnam ONLY | `server/services/log_service.py:480` |
| `LogService` | `get_comprehensive_statistics(self, filters)` | Get comprehensive log statistics - vietnam ONLY | `server/services/log_service.py:491` |
| `LogService` | `_build_query_from_filters(self, filters)` | Build MongoDB query from filters | `server/services/log_service.py:552` |


### `server/services/rbac_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `RBACService` | Service for role-based access control logic | `server/services/rbac_service.py:22` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `RBACService` | `__init__(self, group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/rbac_service.py:25` |
| `RBACService` | `check_permission(self, user_role, permission)` | Check if role has a specific permission | `server/services/rbac_service.py:34` |
| `RBACService` | `get_permissions(self, role)` | Get all permissions for a role | `server/services/rbac_service.py:38` |
| `RBACService` | `is_admin(self, role)` | Check if role is admin | `server/services/rbac_service.py:42` |
| `RBACService` | `is_owner(self, user_id, resource)` | Check if user is the owner of a resource. | `server/services/rbac_service.py:50` |
| `RBACService` | `can_access_group(self, user, group)` | Check if user can access a specific group. | `server/services/rbac_service.py:60` |
| `RBACService` | `filter_groups_for_user(self, user, groups)` | Filter groups list based on user access. | `server/services/rbac_service.py:75` |
| `RBACService` | `get_teacher_group_ids(self, user)` | Return list of group_id strings that the teacher is assigned to; dùng `GroupModel.find_accessible_group_ids_for_teacher`. | `server/services/rbac_service.py:96` |
| `RBACService` | `get_group_query_filter(self, user)` | Get MongoDB query filter for groups based on user role. | `server/services/rbac_service.py:124` |
| `RBACService` | `get_agent_query_filter(self, user)` | Get MongoDB query filter for agents based on user role. | `server/services/rbac_service.py:139` |
| `RBACService` | `get_log_query_filter(self, user)` | Get MongoDB query filter for logs based on user role; lấy agent ids qua `AgentModel.find_agent_ids_by_group_ids`. | `server/services/rbac_service.py:146` |
| `RBACService` | `get_whitelist_query_filter(self, user)` | Get query filter for whitelist based on user role; không query collection trực tiếp trong service. | `server/services/rbac_service.py:169` |
| `RBACService` | `validate_group_ids_ownership(self, user, group_ids)` | Validate that ALL group_ids belong to the current user. | `server/services/rbac_service.py:214` |
| `RBACService` | `can_teacher_access_agent(self, user, agent)` | Check if teacher can access a specific agent. | `server/services/rbac_service.py:243` |


### `server/services/user_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `UserService` | Service for user CRUD operations (Admin manages Teachers) | `server/services/user_service.py:21` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `UserService` | `__init__(self, user_model, audit_service, socketio)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/user_service.py:24` |
| `UserService` | `create_user(self, username, password, role, email, created_by_user)` | Create a new user (Admin creates Teacher). | `server/services/user_service.py:35` |
| `UserService` | `get_user_by_id(self, user_id)` | Get sanitized user by id | `server/services/user_service.py:122` |
| `UserService` | `get_all_users(self, query, limit, skip)` | Get all users (sanitized) | `server/services/user_service.py:129` |
| `UserService` | `update_user(self, user_id, update_data, updated_by_user)` | Update user (Admin only) | `server/services/user_service.py:139` |
| `UserService` | `toggle_active(self, user_id, is_active, updated_by_user)` | Enable/disable user account | `server/services/user_service.py:176` |
| `UserService` | `reset_password(self, user_id, new_password, reset_by_user)` | Admin reset Teacher password | `server/services/user_service.py:208` |
| `UserService` | `delete_user(self, user_id, deleted_by_user)` | Delete user (Admin only) | `server/services/user_service.py:245` |
| `UserService` | `ensure_default_admin(self, username, password)` | Create default admin if no admin exists | `server/services/user_service.py:284` |
| `UserService` | `_sanitize_user(user)` | Remove sensitive fields | `server/services/user_service.py:326` |


### `server/services/whitelist_profile_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistProfileService` | Service for managing per-teacher whitelist profiles within groups. | `server/services/whitelist_profile_service.py:13` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistProfileService` | `__init__(self, profile_model, group_model, socketio)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:16` |
| `WhitelistProfileService` | `_serialize(self, profile)` | Convert ObjectIds to strings for JSON response. | `server/services/whitelist_profile_service.py:22` |
| `WhitelistProfileService` | `list_profiles(self, group_id, teacher_id)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:31` |
| `WhitelistProfileService` | `create_profile(self, group_id, teacher_id, teacher_username, name, domains)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:35` |
| `WhitelistProfileService` | `update_profile(self, profile_id, payload, user)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:52` |
| `WhitelistProfileService` | `delete_profile(self, profile_id, user)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:77` |
| `WhitelistProfileService` | `activate_profile(self, profile_id, user)` | Activate a profile. Returns dict with profile + deactivated_profile info. | `server/services/whitelist_profile_service.py:91` |
| `WhitelistProfileService` | `deactivate_profile(self, profile_id, user)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/services/whitelist_profile_service.py:120` |
| `WhitelistProfileService` | `get_active_profile(self, group_id)` | Get the active profile for a group (used by agent sync). | `server/services/whitelist_profile_service.py:137` |
| `WhitelistProfileService` | `get_teacher_profiles(self, teacher_id, group_ids)` | Get all profiles owned by this teacher across specified groups qua `WhitelistProfileModel.list_by_teacher_groups`. | `server/services/whitelist_profile_service.py:141` |
| `WhitelistProfileService` | `_notify_group_update(self, group_id)` | Notify agents in this group to re-sync whitelist. | `server/services/whitelist_profile_service.py:171` |


### `server/services/whitelist_service.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistService` | Service class for whitelist business logic | `server/services/whitelist_service.py:107` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistService` | `__init__(self, whitelist_model, agent_model, group_model, socketio=None, entry_model=None, policy_service=None, profile_service=None)` | Khởi tạo service với model + tuỳ chọn `entry_model` (`WhitelistEntryModel`) để ghi/đọc collection `whitelist_entries` mới; fallback embedded khi `entry_model=None`. | `server/services/whitelist_service.py:110` |
| `WhitelistService` | `validate_teacher_entry_access(self, item_id, teacher_group_ids, action)` | Kiểm tra quyền teacher trên global/group whitelist entry và pseudo-ID `group::<group_id>::<type>::<value>`; controller không query Mongo trực tiếp. | `server/services/whitelist_service.py:123` |
| `WhitelistService` | `get_all_entries(self, filters, limit, offset)` | Unified whitelist entry listing; trả cả `items` và `domains` để tương thích UI cũ. | `server/services/whitelist_service.py:180` |
| `WhitelistService` | `add_entry(self, entry_data, client_ip)` | Add new entry to whitelist; canonicalize URL/domain trước khi lưu. | `server/services/whitelist_service.py:243` |
| `WhitelistService` | `test_entry(self, entry_data)` | Test an entry before adding it. | `server/services/whitelist_service.py:418` |
| `WhitelistService` | `test_dns(self, domain)` | Test DNS resolution for a domain. | `server/services/whitelist_service.py:471` |
| `WhitelistService` | `_get_detailed_changes(self, since_dt)` | Get detailed changes since specified time. | `server/services/whitelist_service.py:526` |
| `WhitelistService` | `_normalize_group_entries(self, group, include_inactive)` | Normalize entries from `group.whitelist[]`; chấp nhận shape mới và legacy keys, bỏ qua entry không có value thật. | `server/services/whitelist_service.py:607` |
| `WhitelistService` | `_merge_whitelists(self, global_entries, group_entries)` | Merge theo `type:value`; group/profile entry thắng global duplicate. | `server/services/whitelist_service.py:747` |
| `WhitelistService` | `get_scoped_whitelist(self, agent_id, group_id)` | Return global and group whitelist entries with version metadata. | `server/services/whitelist_service.py:777` |
| `WhitelistService` | `get_agent_sync_data(self, since_datetime, agent_id, global_version, group_version, agent_policy_mode)` | Build agent sync payload: global + active profile hoặc group base; apply policy override. | `server/services/whitelist_service.py:827` |
| `WhitelistService` | `delete_entry(self, entry_id)` | Canonical single delete cho global rows, first-class group rows và embedded group rows có ObjectId thật. | `server/services/whitelist_service.py:941` |
| `WhitelistService` | `bulk_delete_entries(self, item_ids)` | Canonical bulk delete; vẫn hỗ trợ pseudo-ID fallback cho legacy embedded group rows. | `server/services/whitelist_service.py:1009` |
| `WhitelistService` | `bulk_add_entries(self, entries_data, client_ip)` | Bulk add entries to whitelist with global/group support. | `server/services/whitelist_service.py:1081` |
| `WhitelistService` | `get_statistics(self)` | Get whitelist statistics. | `server/services/whitelist_service.py:1236` |
| `WhitelistService` | `update_entry(self, entry_id, update_data)` | Update global, group ObjectId, or legacy pseudo-ID entry. | `server/services/whitelist_service.py:1253` |
| `WhitelistService` | `_update_group_entry(self, entry_id, update_data)` | Update group whitelist entry by first-class/embedded ObjectId or pseudo-ID. | `server/services/whitelist_service.py:1322` |
| `WhitelistService` | `_delete_group_entry(self, group_id, value, entry_type)` | Delete an entry from a group's whitelist by value and type. | `server/services/whitelist_service.py:1422` |
| `WhitelistService` | `add_domain(self, domain_value, category)` | Legacy compatibility helper for adding a domain entry. | `server/services/whitelist_service.py:1470` |
| `WhitelistService` | `import_domains(self, domains, category)` | Legacy compatibility helper for importing domain entries. | `server/services/whitelist_service.py:1526` |
| `WhitelistService` | `export_domains(self, format, category)` | Legacy compatibility helper for exporting domain entries. | `server/services/whitelist_service.py:1592` |


## Package `server/tests`


### `server/tests/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `server/tests/test_agent_full.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `_set_current_user` | Context manager to set g.current_user inside a Flask app context. | `server/tests/test_agent_full.py:138` |
| `TestAgentModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agent_full.py:161` |
| `TestAgentService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:294` |
| `TestAgentPolicyModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agent_full.py:369` |
| `TestAgentPolicyService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:486` |
| `TestAgentController` | Controller trung tâm nối GUI với Agent worker/lifecycle. | `server/tests/test_agent_full.py:578` |
| `TestRBACAgentTeacher` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:711` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `_set_current_user` | `__init__(self, app, user, rbac_svc)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:140` |
| `_set_current_user` | `__enter__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:145` |
| `_set_current_user` | `__exit__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:152` |
| `TestAgentModel` | `test_register_agent(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:163` |
| `TestAgentModel` | `test_find_by_agent_id(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:176` |
| `TestAgentModel` | `test_find_by_agent_id_not_found(self, agent_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:183` |
| `TestAgentModel` | `test_find_by_device_id(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:186` |
| `TestAgentModel` | `test_find_by_hostname(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:199` |
| `TestAgentModel` | `test_update_agent(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:205` |
| `TestAgentModel` | `test_update_agent_group(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:213` |
| `TestAgentModel` | `test_update_heartbeat(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:222` |
| `TestAgentModel` | `test_delete_agent(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:231` |
| `TestAgentModel` | `test_delete_agent_not_found(self, agent_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:237` |
| `TestAgentModel` | `test_count_by_group(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:240` |
| `TestAgentModel` | `test_get_all_agents(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:247` |
| `TestAgentModel` | `test_count_agents(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:253` |
| `TestAgentModel` | `test_get_agent_statistics(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:258` |
| `TestAgentModel` | `test_get_active_agents(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:264` |
| `TestAgentModel` | `test_get_inactive_agents(self, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:270` |
| `TestAgentService` | `test_register_new_agent(self, agent_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:296` |
| `TestAgentService` | `test_get_agents_with_status(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:306` |
| `TestAgentService` | `test_calculate_statistics(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:314` |
| `TestAgentService` | `test_get_agent_details(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:320` |
| `TestAgentService` | `test_get_agent_details_not_found(self, agent_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:327` |
| `TestAgentService` | `test_delete_agent_via_service(self, agent_service, agent_model, group_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:331` |
| `TestAgentService` | `test_update_display_name(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:337` |
| `TestAgentService` | `test_move_agent_to_group(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:345` |
| `TestAgentService` | `test_get_total_agents(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:354` |
| `TestAgentService` | `test_get_active_agents_count(self, agent_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:359` |
| `TestAgentPolicyModel` | `test_set_policy_isolate(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:371` |
| `TestAgentPolicyModel` | `test_set_policy_custom_whitelist(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:379` |
| `TestAgentPolicyModel` | `test_set_policy_invalid_mode_raises(self, policy_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:389` |
| `TestAgentPolicyModel` | `test_get_policy(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:393` |
| `TestAgentPolicyModel` | `test_get_policy_not_found(self, policy_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:402` |
| `TestAgentPolicyModel` | `test_get_effective_mode_none(self, policy_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:405` |
| `TestAgentPolicyModel` | `test_get_effective_mode_isolate(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:408` |
| `TestAgentPolicyModel` | `test_get_effective_mode_expired_resets(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:414` |
| `TestAgentPolicyModel` | `test_reset_policy(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:422` |
| `TestAgentPolicyModel` | `test_get_custom_whitelist(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:429` |
| `TestAgentPolicyModel` | `test_get_custom_whitelist_empty(self, policy_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:438` |
| `TestAgentPolicyModel` | `test_list_isolated_agents(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:441` |
| `TestAgentPolicyModel` | `test_list_policies_by_agent_ids(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:451` |
| `TestAgentPolicyModel` | `test_count_by_mode(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:463` |
| `TestAgentPolicyModel` | `test_upsert_overwrites_policy(self, policy_model, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:472` |
| `TestAgentPolicyService` | `test_get_policy_default(self, policy_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:488` |
| `TestAgentPolicyService` | `test_set_policy_isolate(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:492` |
| `TestAgentPolicyService` | `test_set_policy_agent_not_found_raises(self, policy_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:499` |
| `TestAgentPolicyService` | `test_isolate_agent_shortcut(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:503` |
| `TestAgentPolicyService` | `test_reset_agent_shortcut(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:509` |
| `TestAgentPolicyService` | `test_set_policy_with_duration(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:516` |
| `TestAgentPolicyService` | `test_apply_policy_to_sync_none(self, policy_service)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_agent_full.py:523` |
| `TestAgentPolicyService` | `test_apply_policy_to_sync_isolate(self, policy_service, agent_model, group_model)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_agent_full.py:530` |
| `TestAgentPolicyService` | `test_apply_policy_to_sync_custom(self, policy_service, agent_model, group_model)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_agent_full.py:545` |
| `TestAgentPolicyService` | `test_get_policies_for_agents(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:559` |
| `TestAgentPolicyService` | `test_get_stats(self, policy_service, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:566` |
| `TestAgentController` | `app(self, agent_model, agent_service, rbac_service, policy_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:581` |
| `TestAgentController` | `test_list_agents_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:618` |
| `TestAgentController` | `test_get_statistics(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:625` |
| `TestAgentController` | `test_register_agent_via_api(self, app, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:632` |
| `TestAgentController` | `test_get_agent_detail(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:644` |
| `TestAgentController` | `test_delete_agent_via_api(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:653` |
| `TestAgentController` | `test_update_display_name_via_api(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:662` |
| `TestAgentController` | `test_update_group_via_api(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:673` |
| `TestAgentController` | `test_get_agent_policy_via_api(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:685` |
| `TestAgentController` | `test_set_agent_policy_via_api(self, app, agent_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:694` |
| `TestRBACAgentTeacher` | `_make_rbac_app(self, agent_model, agent_service, rbac_service, policy_service, user)` | Build app with g.current_user set via before_request + rbac_service wired. | `server/tests/test_agent_full.py:713` |
| `TestRBACAgentTeacher` | `test_teacher_sees_only_own_group_agents(self, agent_model, agent_service, rbac_service, policy_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:753` |
| `TestRBACAgentTeacher` | `test_teacher_cannot_delete_other_agent(self, agent_model, agent_service, rbac_service, policy_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:772` |
| `TestRBACAgentTeacher` | `test_teacher_cannot_move_agent_to_other_group(self, agent_model, agent_service, rbac_service, policy_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:784` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:45` |
| `db(mongo_client)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:61` |
| `agent_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agent_full.py:70` |
| `group_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agent_full.py:75` |
| `policy_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agent_full.py:80` |
| `agent_service(agent_model, group_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:85` |
| `policy_service(policy_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:90` |
| `rbac_service(group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agent_full.py:95` |
| `make_admin()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:103` |
| `make_teacher(tid)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:107` |
| `create_group(group_model, name, created_by, whitelist)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `server/tests/test_agent_full.py:111` |
| `insert_agent(agent_model, group_id, hostname, agent_id)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `server/tests/test_agent_full.py:115` |
| `_mock_auth(user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agent_full.py:130` |


### `server/tests/test_agents.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestAgentModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:149` |
| `TestAgentServiceRegistration` | Registration flow - new agent, duplicate device_id, missing fields. | `server/tests/test_agents.py:317` |
| `TestAgentServiceHeartbeat` | Heartbeat processing - token validation, device_id mismatch, status. | `server/tests/test_agents.py:376` |
| `TestAgentServiceStatus` | Status calculation - active/inactive/offline thresholds. | `server/tests/test_agents.py:442` |
| `TestAgentServiceGroupMove` | Move agent between groups - status transitions. | `server/tests/test_agents.py:530` |
| `TestCrossTeacherIsolation` | Test agent KHÔNG thể bị truy cập cross-teacher. | `server/tests/test_agents.py:574` |
| `TestAgentEdgeCases` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:673` |
| `TestAgentPolicyInteraction` | Test policy ảnh hưởng đến heartbeat response. | `server/tests/test_agents.py:800` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestAgentModel` | `test_model_register_agent(self, agent_model)` | Register agent - insert vào DB, trả về đủ fields. | `server/tests/test_agents.py:151` |
| `TestAgentModel` | `test_model_find_by_agent_id(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:167` |
| `TestAgentModel` | `test_model_find_by_agent_id_not_found(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:177` |
| `TestAgentModel` | `test_model_find_by_device_id(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:180` |
| `TestAgentModel` | `test_model_find_by_device_id_not_found(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:190` |
| `TestAgentModel` | `test_model_duplicate_agent_id_fails(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:193` |
| `TestAgentModel` | `test_model_duplicate_device_id_fails(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:205` |
| `TestAgentModel` | `test_model_update_agent(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:217` |
| `TestAgentModel` | `test_model_update_agent_not_found(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:228` |
| `TestAgentModel` | `test_model_update_agent_group(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:231` |
| `TestAgentModel` | `test_model_update_heartbeat(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:244` |
| `TestAgentModel` | `test_model_delete_agent(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:256` |
| `TestAgentModel` | `test_model_delete_nonexistent(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:265` |
| `TestAgentModel` | `test_model_count_by_group(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:268` |
| `TestAgentModel` | `test_model_get_all_agents(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:279` |
| `TestAgentModel` | `test_model_get_all_agents_with_filter(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:288` |
| `TestAgentModel` | `test_model_get_agent_statistics(self, agent_model)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:301` |
| `TestAgentServiceRegistration` | `test_register_new_agent(self, agent_service)` | Register brand new agent - trả về agent_id, token, pending status. | `server/tests/test_agents.py:320` |
| `TestAgentServiceRegistration` | `test_register_duplicate_device_id_updates(self, agent_service)` | Register cùng device_id → update existing, không tạo mới. | `server/tests/test_agents.py:330` |
| `TestAgentServiceRegistration` | `test_register_missing_hostname_fails(self, agent_service)` | Register thiếu hostname - raise ValueError. | `server/tests/test_agents.py:343` |
| `TestAgentServiceRegistration` | `test_register_missing_device_id_fails(self, agent_service)` | Register thiếu device_id - raise ValueError. | `server/tests/test_agents.py:350` |
| `TestAgentServiceRegistration` | `test_register_assigns_to_pending_group(self, agent_service, agent_model)` | New agent tự động vào pending group. | `server/tests/test_agents.py:357` |
| `TestAgentServiceRegistration` | `test_register_localhost_ip_replaced(self, agent_service, agent_model)` | Agent gửi ip 127.0.0.1 nhưng client_ip khác → dùng client_ip. | `server/tests/test_agents.py:366` |
| `TestAgentServiceHeartbeat` | `_register_agent(self, agent_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:379` |
| `TestAgentServiceHeartbeat` | `test_heartbeat_valid(self, agent_service)` | Heartbeat hợp lệ - trả về status, next_heartbeat. | `server/tests/test_agents.py:384` |
| `TestAgentServiceHeartbeat` | `test_heartbeat_unknown_agent(self, agent_service)` | Heartbeat từ agent không tồn tại - raise. | `server/tests/test_agents.py:398` |
| `TestAgentServiceHeartbeat` | `test_heartbeat_invalid_token(self, agent_service)` | Heartbeat với sai token - raise. | `server/tests/test_agents.py:405` |
| `TestAgentServiceHeartbeat` | `test_heartbeat_device_id_mismatch(self, agent_service, agent_model)` | Heartbeat gửi device_id khác với DB - raise. | `server/tests/test_agents.py:413` |
| `TestAgentServiceHeartbeat` | `test_heartbeat_pending_status_preserved(self, agent_service, agent_model)` | Agent pending - heartbeat không thay đổi status thành active. | `server/tests/test_agents.py:426` |
| `TestAgentServiceStatus` | `test_status_active(self, agent_service, agent_model, group_model)` | Agent heartbeat < 5 min ago → active. | `server/tests/test_agents.py:445` |
| `TestAgentServiceStatus` | `test_status_inactive(self, agent_service, agent_model, group_model)` | Agent heartbeat 10 min ago → inactive. | `server/tests/test_agents.py:460` |
| `TestAgentServiceStatus` | `test_status_offline(self, agent_service, agent_model, group_model)` | Agent heartbeat > 30 min ago → offline. | `server/tests/test_agents.py:474` |
| `TestAgentServiceStatus` | `test_status_no_heartbeat(self, agent_service, agent_model, group_model)` | Agent không có heartbeat → offline. | `server/tests/test_agents.py:488` |
| `TestAgentServiceStatus` | `test_statistics(self, agent_service, agent_model, group_model)` | Statistics - đếm đúng active/inactive/offline/pending. | `server/tests/test_agents.py:507` |
| `TestAgentServiceGroupMove` | `test_move_to_active_group(self, agent_service, agent_model, group_model)` | Move agent from pending → active group → status becomes active. | `server/tests/test_agents.py:533` |
| `TestAgentServiceGroupMove` | `test_move_to_pending_group(self, agent_service, agent_model, group_model)` | Move agent back to pending group → status becomes pending. | `server/tests/test_agents.py:546` |
| `TestAgentServiceGroupMove` | `test_move_to_nonexistent_group(self, agent_service, agent_model, group_model)` | Move to group không tồn tại - raise. | `server/tests/test_agents.py:555` |
| `TestAgentServiceGroupMove` | `test_move_nonexistent_agent(self, agent_service, group_model)` | Move agent không tồn tại - raise. | `server/tests/test_agents.py:563` |
| `TestCrossTeacherIsolation` | `test_teacher_sees_only_own_agents(self, rbac_service, agent_model, group_model, teacher_a, teacher_b)` | Teacher A thấy agents trong group mình, không thấy của Teacher B. | `server/tests/test_agents.py:581` |
| `TestCrossTeacherIsolation` | `test_admin_sees_all_agents(self, rbac_service, agent_model, group_model, admin_user)` | Admin thấy tất cả agents, không bị filter. | `server/tests/test_agents.py:609` |
| `TestCrossTeacherIsolation` | `test_teacher_cannot_access_other_teacher_agent(self, rbac_service, agent_model, group_model, teacher_a)` | Teacher A không thể access agent trong group của Teacher B. | `server/tests/test_agents.py:624` |
| `TestCrossTeacherIsolation` | `test_teacher_can_access_own_agent(self, rbac_service, agent_model, group_model, teacher_a)` | Teacher A có thể access agent trong group mình tạo. | `server/tests/test_agents.py:635` |
| `TestCrossTeacherIsolation` | `test_agent_in_pending_group_not_owned(self, rbac_service, agent_model, group_model, teacher_a)` | Agent trong pending group (system) - teacher không có quyền. | `server/tests/test_agents.py:646` |
| `TestCrossTeacherIsolation` | `test_teacher_empty_groups_sees_nothing(self, rbac_service, agent_model, group_model, teacher_b)` | Teacher chưa tạo group nào - thấy 0 agents. | `server/tests/test_agents.py:655` |
| `TestAgentEdgeCases` | `test_agent_with_none_fields(self, agent_model)` | Agent với fields None/undefined - không crash. | `server/tests/test_agents.py:675` |
| `TestAgentEdgeCases` | `test_agent_empty_string_fields(self, agent_model)` | Agent với empty string - vẫn lưu được. | `server/tests/test_agents.py:692` |
| `TestAgentEdgeCases` | `test_heartbeat_with_no_timestamp(self, agent_service)` | Heartbeat không có timestamp - server dùng now_vietnam(). | `server/tests/test_agents.py:705` |
| `TestAgentEdgeCases` | `test_heartbeat_with_future_timestamp(self, agent_service)` | Heartbeat với timestamp tương lai - vẫn xử lý, clamp to 0. | `server/tests/test_agents.py:717` |
| `TestAgentEdgeCases` | `test_register_same_hostname_different_device(self, agent_service, agent_model)` | 2 agents cùng hostname nhưng khác device_id - tạo 2 agents riêng. | `server/tests/test_agents.py:730` |
| `TestAgentEdgeCases` | `test_update_display_name(self, agent_service, agent_model, group_model)` | Update display name - chỉ thay display_name, giữ hostname. | `server/tests/test_agents.py:740` |
| `TestAgentEdgeCases` | `test_update_display_name_empty_fails(self, agent_service, agent_model, group_model)` | Display name rỗng - raise. | `server/tests/test_agents.py:750` |
| `TestAgentEdgeCases` | `test_update_position(self, agent_service, agent_model, group_model)` | Update vị trí agent trên room layout. | `server/tests/test_agents.py:758` |
| `TestAgentEdgeCases` | `test_delete_agent(self, agent_service, agent_model, group_model)` | Delete agent - xóa khỏi DB. | `server/tests/test_agents.py:767` |
| `TestAgentEdgeCases` | `test_delete_nonexistent_agent(self, agent_service)` | Delete agent không tồn tại - raise. | `server/tests/test_agents.py:776` |
| `TestAgentEdgeCases` | `test_get_agent_details(self, agent_service, agent_model, group_model)` | Get agent details - đầy đủ fields. | `server/tests/test_agents.py:781` |
| `TestAgentEdgeCases` | `test_get_agent_details_not_found(self, agent_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:791` |
| `TestAgentPolicyInteraction` | `test_heartbeat_no_policy_model(self, agent_service)` | Agent service không có policy_model → force_sync=False. | `server/tests/test_agents.py:803` |
| `TestAgentPolicyInteraction` | `test_heartbeat_with_active_policy(self, agent_model, group_model)` | Agent có policy isolate → heartbeat trả force_sync=True. | `server/tests/test_agents.py:816` |
| `TestAgentPolicyInteraction` | `test_heartbeat_policy_none_no_sync(self, agent_model, group_model)` | Agent policy = none → force_sync=False. | `server/tests/test_agents.py:833` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:43` |
| `db(mongo_client)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:59` |
| `agent_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:69` |
| `group_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_agents.py:74` |
| `agent_service(agent_model, group_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agents.py:79` |
| `rbac_service(group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_agents.py:84` |
| `admin_user()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:98` |
| `teacher_a()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:103` |
| `teacher_b()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_agents.py:108` |
| `make_agent_data(hostname, device_id, ip)` | Helper - tạo agent registration data. | `server/tests/test_agents.py:112` |
| `insert_agent(agent_model, group_id, hostname, device_id, agent_id)` | Helper - insert agent trực tiếp vào DB. | `server/tests/test_agents.py:124` |


### `server/tests/test_audit.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestAuditModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_audit.py:89` |
| `TestAuditService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_audit.py:185` |
| `TestAuditController` | AuditController uses @require_login and @require_permission as method decorators, | `server/tests/test_audit.py:296` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestAuditModel` | `test_log_creates_entry(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:91` |
| `TestAuditModel` | `test_log_sets_timestamp(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:106` |
| `TestAuditModel` | `test_get_logs_empty(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:115` |
| `TestAuditModel` | `test_get_logs_returns_entries(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:119` |
| `TestAuditModel` | `test_get_logs_with_filter(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:126` |
| `TestAuditModel` | `test_get_logs_limit(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:133` |
| `TestAuditModel` | `test_get_logs_skip(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:139` |
| `TestAuditModel` | `test_get_logs_sorted_desc(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:147` |
| `TestAuditModel` | `test_get_user_activity(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:154` |
| `TestAuditModel` | `test_get_user_activity_limit(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:162` |
| `TestAuditModel` | `test_count_logs(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:169` |
| `TestAuditModel` | `test_count_logs_no_filter(self, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:175` |
| `TestAuditService` | `test_log_action_basic(self, audit_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:187` |
| `TestAuditService` | `test_log_action_auto_ip(self, audit_service, audit_model)` | When no ip_address provided and outside request context, uses 'unknown'. | `server/tests/test_audit.py:200` |
| `TestAuditService` | `test_log_action_with_flask_request(self, audit_service, audit_model)` | Within Flask request context, auto-detects IP. | `server/tests/test_audit.py:212` |
| `TestAuditService` | `test_log_action_stores_user_info(self, audit_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:225` |
| `TestAuditService` | `test_get_logs_serialized(self, audit_service, audit_model)` | Chuẩn hóa dữ liệu trước khi trả response, lưu DB hoặc hiển thị. | `server/tests/test_audit.py:238` |
| `TestAuditService` | `test_get_user_activity_serialized(self, audit_service, audit_model)` | Chuẩn hóa dữ liệu trước khi trả response, lưu DB hoặc hiển thị. | `server/tests/test_audit.py:247` |
| `TestAuditService` | `test_count_logs(self, audit_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:254` |
| `TestAuditService` | `test_log_action_never_raises(self, audit_service)` | Audit logging should never block the main operation. | `server/tests/test_audit.py:260` |
| `TestAuditService` | `test_log_action_with_resource_id(self, audit_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:269` |
| `TestAuditService` | `test_log_action_without_resource_id(self, audit_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:281` |
| `TestAuditController` | `app(self, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:304` |
| `TestAuditController` | `test_list_logs(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:312` |
| `TestAuditController` | `test_list_logs_with_action_filter(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:324` |
| `TestAuditController` | `test_list_logs_with_resource_type_filter(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:336` |
| `TestAuditController` | `test_list_logs_with_username_filter(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:347` |
| `TestAuditController` | `test_list_logs_pagination(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:357` |
| `TestAuditController` | `test_user_activity(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:369` |
| `TestAuditController` | `test_user_activity_limit(self, app, audit_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:381` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:31` |
| `db(mongo_client)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:47` |
| `audit_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_audit.py:56` |
| `audit_service(audit_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_audit.py:61` |
| `make_admin()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:69` |
| `make_teacher(tid)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:73` |
| `_mock_auth(user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_audit.py:77` |


### `server/tests/test_groups.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestGroupModel` | Test GroupModel - thao tác trực tiếp MongoDB collection. | `server/tests/test_groups.py:158` |
| `TestGroupService` | Test GroupService - business logic + ObjectId serialization. | `server/tests/test_groups.py:323` |
| `TestGroupController` | Test GroupController - HTTP endpoints qua Flask test client. | `server/tests/test_groups.py:485` |
| `TestRBACGroupFiltering` | Test RBACService - group-related filtering logic. | `server/tests/test_groups.py:723` |
| `TestGroupIntegration` | Integration tests - full flow qua nhiều layer. | `server/tests/test_groups.py:813` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestGroupModel` | `test_model_create_group_basic(self, group_model)` | Tạo group cơ bản - phải có đầy đủ fields. | `server/tests/test_groups.py:161` |
| `TestGroupModel` | `test_model_create_group_with_owner(self, group_model)` | Tạo group với created_by - cho RBAC ownership. | `server/tests/test_groups.py:173` |
| `TestGroupModel` | `test_model_create_group_with_whitelist(self, group_model)` | Tạo group kèm whitelist entries. | `server/tests/test_groups.py:179` |
| `TestGroupModel` | `test_model_create_duplicate_name_fails(self, group_model)` | Tạo 2 group cùng tên - MongoDB unique index phải reject. | `server/tests/test_groups.py:186` |
| `TestGroupModel` | `test_model_find_by_id(self, group_model)` | Tìm group bằng ID - cả string và ObjectId. | `server/tests/test_groups.py:192` |
| `TestGroupModel` | `test_model_find_by_id_not_found(self, group_model)` | Tìm group không tồn tại - trả None. | `server/tests/test_groups.py:201` |
| `TestGroupModel` | `test_model_find_by_id_invalid(self, group_model)` | ID không hợp lệ - trả None thay vì crash. | `server/tests/test_groups.py:206` |
| `TestGroupModel` | `test_model_list_groups_empty(self, group_model)` | List groups khi DB rỗng - trả empty list. | `server/tests/test_groups.py:211` |
| `TestGroupModel` | `test_model_list_groups_all(self, group_model)` | List tất cả groups - không filter. | `server/tests/test_groups.py:218` |
| `TestGroupModel` | `test_model_list_groups_with_filter(self, group_model)` | List groups với query filter - chỉ trả groups match. | `server/tests/test_groups.py:227` |
| `TestGroupModel` | `test_model_update_group_name(self, group_model)` | Update tên group. | `server/tests/test_groups.py:236` |
| `TestGroupModel` | `test_model_update_group_description(self, group_model)` | Update description. | `server/tests/test_groups.py:245` |
| `TestGroupModel` | `test_model_update_group_whitelist(self, group_model)` | Update whitelist entries. | `server/tests/test_groups.py:253` |
| `TestGroupModel` | `test_model_update_group_layout(self, group_model)` | Update layout (room layout config). | `server/tests/test_groups.py:266` |
| `TestGroupModel` | `test_model_update_nonexistent_group(self, group_model)` | Update group không tồn tại - trả None. | `server/tests/test_groups.py:275` |
| `TestGroupModel` | `test_model_delete_group(self, group_model)` | Xóa group - trả True. | `server/tests/test_groups.py:280` |
| `TestGroupModel` | `test_model_delete_nonexistent_group(self, group_model)` | Xóa group không tồn tại - trả False. | `server/tests/test_groups.py:288` |
| `TestGroupModel` | `test_model_bump_whitelist_version(self, group_model)` | Bump whitelist version - tăng 1. | `server/tests/test_groups.py:292` |
| `TestGroupModel` | `test_model_ensure_pending_group_created(self, group_model)` | Ensure pending group - tạo nếu chưa có. | `server/tests/test_groups.py:304` |
| `TestGroupModel` | `test_model_ensure_pending_group_idempotent(self, group_model)` | Ensure pending group - gọi lại không tạo duplicate. | `server/tests/test_groups.py:312` |
| `TestGroupService` | `test_service_list_groups_serialization(self, group_service, group_model)` | List groups - _id và created_by phải là string, không phải ObjectId. | `server/tests/test_groups.py:326` |
| `TestGroupService` | `test_service_list_groups_with_filter(self, group_service, group_model)` | List groups với teacher filter - chỉ trả groups thuộc teacher. | `server/tests/test_groups.py:338` |
| `TestGroupService` | `test_service_create_group(self, group_service)` | Tạo group qua service - _id phải là string. | `server/tests/test_groups.py:349` |
| `TestGroupService` | `test_service_create_group_with_owner(self, group_service)` | Tạo group với owner - created_by phải là string sau serialize. | `server/tests/test_groups.py:355` |
| `TestGroupService` | `test_service_get_group(self, group_service, group_model)` | Get single group - serialized correctly. | `server/tests/test_groups.py:361` |
| `TestGroupService` | `test_service_get_group_not_found(self, group_service)` | Get group không tồn tại - raise ValueError. | `server/tests/test_groups.py:371` |
| `TestGroupService` | `test_service_update_group(self, group_service, group_model)` | Update group - serialized correctly. | `server/tests/test_groups.py:376` |
| `TestGroupService` | `test_service_update_group_not_found(self, group_service)` | Update group không tồn tại - raise ValueError. | `server/tests/test_groups.py:387` |
| `TestGroupService` | `test_service_update_whitelist_bumps_version(self, group_service, group_model)` | Update whitelist - version tự tăng. | `server/tests/test_groups.py:392` |
| `TestGroupService` | `test_service_update_system_group_flag_rejected(self, group_service, group_model)` | Không cho phép thay đổi is_system flag. | `server/tests/test_groups.py:402` |
| `TestGroupService` | `test_service_delete_group(self, group_service, group_model)` | Xóa group thành công. | `server/tests/test_groups.py:411` |
| `TestGroupService` | `test_service_delete_group_not_found(self, group_service)` | Xóa group không tồn tại - raise ValueError. | `server/tests/test_groups.py:422` |
| `TestGroupService` | `test_service_delete_system_group_rejected(self, group_service, group_model)` | Không cho phép xóa system group (pending). | `server/tests/test_groups.py:427` |
| `TestGroupService` | `test_service_delete_group_with_agents_rejected(self, group_service, group_model, agent_model)` | Không cho xóa group có agents. | `server/tests/test_groups.py:435` |
| `TestGroupService` | `test_service_bump_whitelist_version(self, group_service, group_model)` | Bump whitelist version qua service. | `server/tests/test_groups.py:450` |
| `TestGroupService` | `test_service_get_pending_group_id(self, group_service)` | Get pending group ID - string format. | `server/tests/test_groups.py:459` |
| `TestGroupService` | `test_service_json_serializable(self, group_service, group_model)` | Tất cả output của service phải JSON serializable - không còn ObjectId. | `server/tests/test_groups.py:465` |
| `TestGroupController` | `_mock_auth(self, user)` | Return patch context manager that fakes auth for given user. | `server/tests/test_groups.py:493` |
| `TestGroupController` | `test_controller_list_groups_admin(self, app, client, group_model, admin_user)` | Admin list groups - thấy tất cả. | `server/tests/test_groups.py:503` |
| `TestGroupController` | `test_controller_list_groups_teacher_filtered(self, app, client, group_model, teacher_a)` | Teacher list groups - chỉ thấy groups mình tạo. | `server/tests/test_groups.py:518` |
| `TestGroupController` | `test_controller_list_groups_teacher_empty(self, app, client, group_model, teacher_b)` | Teacher mới - chưa tạo group nào, list trả rỗng (trừ pending). | `server/tests/test_groups.py:532` |
| `TestGroupController` | `test_controller_get_group_admin(self, app, client, group_model, admin_user)` | Admin get bất kỳ group nào - OK. | `server/tests/test_groups.py:547` |
| `TestGroupController` | `test_controller_get_group_teacher_own(self, app, client, group_model, teacher_a)` | Teacher get group mình tạo - OK. | `server/tests/test_groups.py:558` |
| `TestGroupController` | `test_controller_get_group_teacher_forbidden(self, app, client, group_model, teacher_a)` | Teacher get group của teacher khác - 403. | `server/tests/test_groups.py:569` |
| `TestGroupController` | `test_controller_get_group_not_found(self, app, client, admin_user)` | Get group không tồn tại - 404. | `server/tests/test_groups.py:579` |
| `TestGroupController` | `test_controller_create_group_admin(self, app, client, admin_user)` | Admin tạo group - created_by = admin ID. | `server/tests/test_groups.py:588` |
| `TestGroupController` | `test_controller_create_group_teacher(self, app, client, teacher_a)` | Teacher tạo group - created_by = teacher ID. | `server/tests/test_groups.py:601` |
| `TestGroupController` | `test_controller_create_group_no_name(self, app, client, admin_user)` | Tạo group thiếu name - 400. | `server/tests/test_groups.py:613` |
| `TestGroupController` | `test_controller_create_group_with_whitelist(self, app, client, admin_user)` | Tạo group kèm whitelist. | `server/tests/test_groups.py:621` |
| `TestGroupController` | `test_controller_create_group_duplicate_name(self, app, client, group_model, admin_user)` | Tạo group trùng tên - 400. | `server/tests/test_groups.py:632` |
| `TestGroupController` | `test_controller_update_group_admin(self, app, client, group_model, admin_user)` | Admin update bất kỳ group - OK. | `server/tests/test_groups.py:643` |
| `TestGroupController` | `test_controller_update_group_teacher_own(self, app, client, group_model, teacher_a)` | Teacher update group mình tạo - OK. | `server/tests/test_groups.py:654` |
| `TestGroupController` | `test_controller_update_group_teacher_forbidden(self, app, client, group_model, teacher_a)` | Teacher update group của teacher khác - 403. | `server/tests/test_groups.py:664` |
| `TestGroupController` | `test_controller_delete_group_admin(self, app, client, group_model, admin_user)` | Admin xóa group - OK. | `server/tests/test_groups.py:676` |
| `TestGroupController` | `test_controller_delete_group_teacher_own(self, app, client, group_model, teacher_a)` | Teacher xóa group mình tạo - OK. | `server/tests/test_groups.py:687` |
| `TestGroupController` | `test_controller_delete_group_teacher_forbidden(self, app, client, group_model, teacher_a)` | Teacher xóa group của teacher khác - 403. | `server/tests/test_groups.py:697` |
| `TestGroupController` | `test_controller_delete_system_group_rejected(self, app, client, group_model, admin_user)` | Xóa system group (pending) - 400. | `server/tests/test_groups.py:707` |
| `TestRBACGroupFiltering` | `test_rbac_admin_sees_all_groups(self, rbac_service, admin_user)` | Admin - get_group_query_filter trả None (no filter). | `server/tests/test_groups.py:726` |
| `TestRBACGroupFiltering` | `test_rbac_teacher_filter_by_ownership(self, rbac_service, teacher_a)` | Teacher - filter groups by created_by. | `server/tests/test_groups.py:731` |
| `TestRBACGroupFiltering` | `test_rbac_can_access_group_admin(self, rbac_service, admin_user)` | Admin can access any group. | `server/tests/test_groups.py:736` |
| `TestRBACGroupFiltering` | `test_rbac_can_access_group_teacher_own(self, rbac_service, teacher_a)` | Teacher can access own group. | `server/tests/test_groups.py:741` |
| `TestRBACGroupFiltering` | `test_rbac_can_access_group_teacher_other(self, rbac_service, teacher_a)` | Teacher cannot access other teacher's group. | `server/tests/test_groups.py:746` |
| `TestRBACGroupFiltering` | `test_rbac_can_access_group_no_owner(self, rbac_service, teacher_a)` | Teacher cannot access group with no created_by (legacy). | `server/tests/test_groups.py:751` |
| `TestRBACGroupFiltering` | `test_rbac_is_owner(self, rbac_service)` | is_owner - match by string comparison. | `server/tests/test_groups.py:756` |
| `TestRBACGroupFiltering` | `test_rbac_filter_groups_in_memory(self, rbac_service, admin_user, teacher_a)` | filter_groups_for_user - admin gets all, teacher gets own. | `server/tests/test_groups.py:762` |
| `TestRBACGroupFiltering` | `test_rbac_get_teacher_group_ids(self, rbac_service, group_model, teacher_a, admin_user)` | get_teacher_group_ids - teacher gets list, admin gets None. | `server/tests/test_groups.py:776` |
| `TestRBACGroupFiltering` | `test_rbac_validate_group_ids_ownership(self, rbac_service, group_model, teacher_a, admin_user)` | validate_group_ids_ownership - teacher chỉ sở hữu groups mình tạo. | `server/tests/test_groups.py:790` |
| `TestGroupIntegration` | `test_create_then_list_then_delete(self, group_service)` | Full lifecycle: create → list → delete. | `server/tests/test_groups.py:816` |
| `TestGroupIntegration` | `test_teacher_isolation_full_flow(self, group_service, rbac_service, group_model, teacher_a, teacher_b)` | Teacher A tạo group, Teacher B không thấy và không access được. | `server/tests/test_groups.py:831` |
| `TestGroupIntegration` | `test_update_whitelist_version_consistency(self, group_service, group_model)` | Update whitelist qua service - version tăng đúng. | `server/tests/test_groups.py:851` |
| `TestGroupIntegration` | `test_json_response_no_objectid(self, app, client, group_model, admin_user)` | API response phải JSON-safe - không có ObjectId nào leak. | `server/tests/test_groups.py:866` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Create MongoDB client using same config as server (.env). | `server/tests/test_groups.py:43` |
| `db(mongo_client)` | Fresh test database - dropped after each test. | `server/tests/test_groups.py:64` |
| `group_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_groups.py:72` |
| `agent_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_groups.py:77` |
| `group_service(group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_groups.py:82` |
| `rbac_service(group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_groups.py:87` |
| `admin_user()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_groups.py:101` |
| `teacher_a()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_groups.py:111` |
| `teacher_b()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_groups.py:121` |
| `app()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_groups.py:135` |
| `group_controller(group_service, rbac_service)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_groups.py:143` |
| `client(app, group_controller)` | Flask test client with group blueprint registered. | `server/tests/test_groups.py:148` |


### `server/tests/test_teacher_data_filtering.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestRBACServiceGetTeacherGroupIds` | Test get_teacher_group_ids() - core helper. | `server/tests/test_teacher_data_filtering.py:120` |
| `TestRBACServiceGetGroupQueryFilter` | Test get_group_query_filter(). | `server/tests/test_teacher_data_filtering.py:166` |
| `TestRBACServiceGetLogQueryFilter` | Test get_log_query_filter() - chains teacher → groups → agents → logs. | `server/tests/test_teacher_data_filtering.py:184` |
| `TestRBACServiceGetWhitelistQueryFilter` | Test get_whitelist_query_filter(). | `server/tests/test_teacher_data_filtering.py:254` |
| `TestRBACServiceCanTeacherAccessAgent` | Test can_teacher_access_agent(). | `server/tests/test_teacher_data_filtering.py:284` |
| `TestRBACServiceCanAccessGroup` | Test can_access_group() - ownership check for groups. | `server/tests/test_teacher_data_filtering.py:326` |
| `TestRBACConfigPermissions` | Verify permission matrix from rbac_config.py. | `server/tests/test_teacher_data_filtering.py:362` |
| `TestGroupControllerTeacherFiltering` | Test GroupController with teacher data filtering. | `server/tests/test_teacher_data_filtering.py:413` |
| `TestAgentControllerTeacherFiltering` | Test AgentController with teacher data filtering. | `server/tests/test_teacher_data_filtering.py:596` |
| `TestWhitelistControllerTeacherFiltering` | Test WhitelistController with teacher data filtering. | `server/tests/test_teacher_data_filtering.py:772` |
| `TestLogControllerTeacherFiltering` | Test LogController with teacher data filtering. | `server/tests/test_teacher_data_filtering.py:932` |
| `TestAgentAPIBackwardCompatibility` | CRITICAL: Agent-to-server API must NOT be affected by RBAC changes. | `server/tests/test_teacher_data_filtering.py:1107` |
| `TestEdgeCases` | Edge cases and boundary conditions. | `server/tests/test_teacher_data_filtering.py:1157` |
| `TestInjectCurrentUserDecorator` | Test `inject_current_user` như cơ chế nạp context non-blocking; không phải auth gate. | `server/tests/test_teacher_data_filtering.py:1237` |
| `TestGroupServiceWithCreatedBy` | Test GroupService passes created_by correctly. | `server/tests/test_teacher_data_filtering.py:1270` |
| `TestGroupModelWithQueryFilter` | Test GroupModel.list_groups with query_filter parameter. | `server/tests/test_teacher_data_filtering.py:1313` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestRBACServiceGetTeacherGroupIds` | `test_admin_returns_none(self, mock_group_model, mock_agent_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:123` |
| `TestRBACServiceGetTeacherGroupIds` | `test_teacher_returns_list(self, mock_group_model, mock_agent_model, teacher_user, sample_groups)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:131` |
| `TestRBACServiceGetTeacherGroupIds` | `test_teacher_no_groups_returns_empty(self, mock_group_model, mock_agent_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:149` |
| `TestRBACServiceGetTeacherGroupIds` | `test_no_group_model_returns_empty(self, mock_agent_model, teacher_user)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_teacher_data_filtering.py:158` |
| `TestRBACServiceGetGroupQueryFilter` | `test_admin_returns_none(self, mock_group_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:169` |
| `TestRBACServiceGetGroupQueryFilter` | `test_teacher_returns_created_by_filter(self, mock_group_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:176` |
| `TestRBACServiceGetLogQueryFilter` | `test_admin_returns_none(self, mock_group_model, mock_agent_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:187` |
| `TestRBACServiceGetLogQueryFilter` | `test_teacher_with_groups_and_agents(self, mock_group_model, mock_agent_model, teacher_user, sample_groups, sample_agents)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:194` |
| `TestRBACServiceGetLogQueryFilter` | `test_teacher_no_groups_returns_empty_filter(self, mock_group_model, mock_agent_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:221` |
| `TestRBACServiceGetLogQueryFilter` | `test_teacher_groups_but_no_agents(self, mock_group_model, mock_agent_model, teacher_user, sample_groups)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:230` |
| `TestRBACServiceGetLogQueryFilter` | `test_no_agent_model_returns_empty(self, mock_group_model, teacher_user, sample_groups)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_teacher_data_filtering.py:242` |
| `TestRBACServiceGetWhitelistQueryFilter` | `test_admin_returns_none(self, mock_group_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:257` |
| `TestRBACServiceGetWhitelistQueryFilter` | `test_teacher_returns_or_filter(self, mock_group_model, teacher_user, sample_groups)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:264` |
| `TestRBACServiceCanTeacherAccessAgent` | `test_admin_always_true(self, mock_group_model, mock_agent_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:287` |
| `TestRBACServiceCanTeacherAccessAgent` | `test_teacher_can_access_own_group_agent(self, mock_group_model, mock_agent_model, teacher_user, sample_groups)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:294` |
| `TestRBACServiceCanTeacherAccessAgent` | `test_teacher_cannot_access_other_group_agent(self, mock_group_model, mock_agent_model, teacher_user, sample_groups)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:306` |
| `TestRBACServiceCanTeacherAccessAgent` | `test_agent_without_group_returns_false(self, mock_group_model, mock_agent_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:318` |
| `TestRBACServiceCanAccessGroup` | `test_admin_always_true(self, mock_group_model, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:329` |
| `TestRBACServiceCanAccessGroup` | `test_teacher_own_group(self, mock_group_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:336` |
| `TestRBACServiceCanAccessGroup` | `test_teacher_other_group(self, mock_group_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:343` |
| `TestRBACServiceCanAccessGroup` | `test_group_no_created_by(self, mock_group_model, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:350` |
| `TestRBACConfigPermissions` | `test_admin_has_all_permissions(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:365` |
| `TestRBACConfigPermissions` | `test_teacher_allowed_permissions(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:378` |
| `TestRBACConfigPermissions` | `test_teacher_denied_permissions(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:390` |
| `TestRBACConfigPermissions` | `test_invalid_role_has_no_permissions(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:404` |
| `TestGroupControllerTeacherFiltering` | `_make_controller(self, mock_group_service, mock_rbac_service)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_teacher_data_filtering.py:416` |
| `TestGroupControllerTeacherFiltering` | `test_list_groups_admin_no_filter(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:421` |
| `TestGroupControllerTeacherFiltering` | `test_list_groups_teacher_filtered(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:443` |
| `TestGroupControllerTeacherFiltering` | `test_list_groups_agent_request_no_filter(self, app)` | Agent request (no cookie) → g.current_user=None → no filter. | `server/tests/test_teacher_data_filtering.py:464` |
| `TestGroupControllerTeacherFiltering` | `test_get_group_teacher_own_group(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:483` |
| `TestGroupControllerTeacherFiltering` | `test_get_group_teacher_other_group_403(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:499` |
| `TestGroupControllerTeacherFiltering` | `test_create_group_sets_created_by(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:515` |
| `TestGroupControllerTeacherFiltering` | `test_create_group_agent_no_created_by(self, app)` | Agent request: no cookie → created_by=None. | `server/tests/test_teacher_data_filtering.py:537` |
| `TestGroupControllerTeacherFiltering` | `test_delete_group_teacher_own_group(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:559` |
| `TestGroupControllerTeacherFiltering` | `test_delete_group_teacher_other_group_403(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:575` |
| `TestAgentControllerTeacherFiltering` | `_make_controller(self, app)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_teacher_data_filtering.py:599` |
| `TestAgentControllerTeacherFiltering` | `test_list_agents_admin_sees_all(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:607` |
| `TestAgentControllerTeacherFiltering` | `test_list_agents_teacher_filtered(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:626` |
| `TestAgentControllerTeacherFiltering` | `test_list_agents_agent_request_no_filter(self, app)` | Agent/no-cookie request sees all agents. | `server/tests/test_teacher_data_filtering.py:651` |
| `TestAgentControllerTeacherFiltering` | `test_get_agent_teacher_own_group(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:671` |
| `TestAgentControllerTeacherFiltering` | `test_get_agent_teacher_other_group_403(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:685` |
| `TestAgentControllerTeacherFiltering` | `test_delete_agent_teacher_blocked(self, app, teacher_user)` | Teacher does NOT have agents:delete permission. | `server/tests/test_teacher_data_filtering.py:699` |
| `TestAgentControllerTeacherFiltering` | `test_delete_agent_admin_allowed(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:712` |
| `TestAgentControllerTeacherFiltering` | `test_update_group_teacher_checks_source_and_target(self, app, teacher_user)` | Teacher moving agent: must own both source and target group. | `server/tests/test_teacher_data_filtering.py:725` |
| `TestAgentControllerTeacherFiltering` | `test_get_statistics_teacher_filtered(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:743` |
| `TestWhitelistControllerTeacherFiltering` | `_make_controller(self, app)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_teacher_data_filtering.py:775` |
| `TestWhitelistControllerTeacherFiltering` | `test_list_domains_teacher_sees_global_plus_own(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:783` |
| `TestWhitelistControllerTeacherFiltering` | `test_list_domains_teacher_pagination(self, app, teacher_user)` | Teacher post-filter pagination works correctly. | `server/tests/test_teacher_data_filtering.py:810` |
| `TestWhitelistControllerTeacherFiltering` | `test_add_domain_teacher_blocked_global(self, app, teacher_user)` | Teacher cannot add to global whitelist. | `server/tests/test_teacher_data_filtering.py:841` |
| `TestWhitelistControllerTeacherFiltering` | `test_add_domain_teacher_own_group_ok(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:853` |
| `TestWhitelistControllerTeacherFiltering` | `test_add_domain_teacher_other_group_403(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:868` |
| `TestWhitelistControllerTeacherFiltering` | `test_delete_domain_teacher_blocked_global(self, app, teacher_user)` | Teacher cannot delete global whitelist entry. | `server/tests/test_teacher_data_filtering.py:881` |
| `TestWhitelistControllerTeacherFiltering` | `test_import_domains_teacher_must_specify_group(self, app, teacher_user)` | Teacher must specify group_id when importing. | `server/tests/test_teacher_data_filtering.py:897` |
| `TestWhitelistControllerTeacherFiltering` | `test_bulk_add_teacher_checks_group_ids(self, app, teacher_user)` | Teacher bulk add: all items must be in teacher's groups. | `server/tests/test_teacher_data_filtering.py:909` |
| `TestLogControllerTeacherFiltering` | `_make_controller(self, app)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_teacher_data_filtering.py:935` |
| `TestLogControllerTeacherFiltering` | `test_list_logs_admin_no_filter(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:943` |
| `TestLogControllerTeacherFiltering` | `test_list_logs_teacher_filtered(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:963` |
| `TestLogControllerTeacherFiltering` | `test_list_logs_teacher_preserves_user_filter_with_and(self, app, teacher_user)` | CRITICAL: Teacher filter + user filter should use $and, not overwrite. | `server/tests/test_teacher_data_filtering.py:985` |
| `TestLogControllerTeacherFiltering` | `test_list_logs_agent_request_no_filter(self, app)` | Agent/no-cookie request: no teacher filter. | `server/tests/test_teacher_data_filtering.py:1012` |
| `TestLogControllerTeacherFiltering` | `test_clear_logs_teacher_blocked(self, app, teacher_user)` | Teacher does NOT have logs:delete permission. | `server/tests/test_teacher_data_filtering.py:1031` |
| `TestLogControllerTeacherFiltering` | `test_clear_logs_admin_allowed(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1044` |
| `TestLogControllerTeacherFiltering` | `test_export_logs_teacher_blocked(self, app, teacher_user)` | Teacher does NOT have logs:export permission. | `server/tests/test_teacher_data_filtering.py:1057` |
| `TestLogControllerTeacherFiltering` | `test_export_logs_admin_allowed(self, app, admin_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1068` |
| `TestLogControllerTeacherFiltering` | `test_get_statistics_teacher_filtered(self, app, teacher_user)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1079` |
| `TestAgentAPIBackwardCompatibility` | `test_register_uses_require_api_key(self)` | Verify register_agent route uses require_api_key, not inject_current_user. | `server/tests/test_teacher_data_filtering.py:1113` |
| `TestAgentAPIBackwardCompatibility` | `test_whitelist_agent_sync_uses_require_jwt(self)` | Verify agent_sync route uses require_jwt, not inject_current_user. | `server/tests/test_teacher_data_filtering.py:1132` |
| `TestAgentAPIBackwardCompatibility` | `test_log_receive_uses_require_jwt(self)` | Verify receive_logs route uses require_jwt, not inject_current_user. | `server/tests/test_teacher_data_filtering.py:1142` |
| `TestEdgeCases` | `test_teacher_with_empty_group_ids_sees_nothing(self, app, teacher_user)` | Teacher who hasn't created any groups sees empty results everywhere. | `server/tests/test_teacher_data_filtering.py:1160` |
| `TestEdgeCases` | `test_group_with_none_created_by_invisible_to_teacher(self, mock_group_model, teacher_user)` | Groups created by agents (created_by=None) are invisible to teacher. | `server/tests/test_teacher_data_filtering.py:1183` |
| `TestEdgeCases` | `test_agent_in_no_group_invisible_to_teacher(self, mock_group_model, mock_agent_model, teacher_user)` | Agent without group_id is inaccessible to teacher. | `server/tests/test_teacher_data_filtering.py:1191` |
| `TestEdgeCases` | `test_objectid_string_comparison(self, mock_group_model, mock_agent_model, teacher_user)` | Verify group_id comparison works with both string and ObjectId formats. | `server/tests/test_teacher_data_filtering.py:1199` |
| `TestEdgeCases` | `test_two_teachers_see_different_groups(self, mock_group_model, teacher_user, teacher_user_2)` | Two teachers should see only their own groups. | `server/tests/test_teacher_data_filtering.py:1216` |
| `TestInjectCurrentUserDecorator` | `test_no_token_sets_none(self, app)` | No cookie/token → g.current_user = None. | `server/tests/test_teacher_data_filtering.py:1240` |
| `TestInjectCurrentUserDecorator` | `test_decorator_does_not_block_request(self, app)` | inject_current_user should NEVER return 401/403 - it's non-blocking. | `server/tests/test_teacher_data_filtering.py:1253` |
| `TestGroupServiceWithCreatedBy` | `test_create_group_passes_created_by(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1273` |
| `TestGroupServiceWithCreatedBy` | `test_list_groups_passes_query_filter(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1291` |
| `TestGroupModelWithQueryFilter` | `test_list_groups_no_filter(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1316` |
| `TestGroupModelWithQueryFilter` | `test_list_groups_with_filter(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1329` |
| `TestGroupModelWithQueryFilter` | `test_create_group_with_created_by(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_teacher_data_filtering.py:1344` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `app()` | Create a minimal Flask app for testing. | `server/tests/test_teacher_data_filtering.py:37` |
| `admin_user()` | Admin user - toan quyen, no ownership filter. | `server/tests/test_teacher_data_filtering.py:46` |
| `teacher_user()` | Teacher user - limited by ownership. | `server/tests/test_teacher_data_filtering.py:57` |
| `teacher_user_2()` | Second teacher - different user, different groups. | `server/tests/test_teacher_data_filtering.py:68` |
| `mock_group_model()` | Mock GroupModel with collection. | `server/tests/test_teacher_data_filtering.py:79` |
| `mock_agent_model()` | Mock AgentModel with collection. | `server/tests/test_teacher_data_filtering.py:87` |
| `sample_groups(teacher_user)` | Groups created by teacher_user. | `server/tests/test_teacher_data_filtering.py:95` |
| `sample_agents()` | Agents in various groups. | `server/tests/test_teacher_data_filtering.py:106` |


### `server/tests/test_users_auth.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestUserModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_users_auth.py:139` |
| `TestUserService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:273` |
| `TestSessionModel` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_users_auth.py:426` |
| `TestAdminAuthService` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:547` |
| `TestUserController` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `server/tests/test_users_auth.py:655` |
| `TestAdminAuthController` | Tên class test giữ nguyên cho backwards-compat khi chọn test theo class name; nội dung test target `WebAuthController` (file `controllers/web_auth_controller.py`). | `server/tests/test_users_auth.py:772` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestUserModel` | `test_create_user(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:141` |
| `TestUserModel` | `test_find_by_id(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:150` |
| `TestUserModel` | `test_find_by_id_not_found(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:156` |
| `TestUserModel` | `test_find_by_username(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:159` |
| `TestUserModel` | `test_find_by_username_case_insensitive(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:164` |
| `TestUserModel` | `test_find_by_email(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:169` |
| `TestUserModel` | `test_get_all_users(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:174` |
| `TestUserModel` | `test_count_users(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:180` |
| `TestUserModel` | `test_count_users_with_filter(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:184` |
| `TestUserModel` | `test_update_user(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:189` |
| `TestUserModel` | `test_update_last_login(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:196` |
| `TestUserModel` | `test_delete_user(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:203` |
| `TestUserModel` | `test_delete_user_not_found(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:208` |
| `TestUserModel` | `test_increment_failed_attempts(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:212` |
| `TestUserModel` | `test_lock_after_max_attempts(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:219` |
| `TestUserModel` | `test_reset_failed_attempts(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:228` |
| `TestUserModel` | `test_is_locked_false_when_no_lock(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:237` |
| `TestUserModel` | `test_is_locked_false_when_expired(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:241` |
| `TestUserModel` | `test_lock_account_manual(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:252` |
| `TestUserModel` | `test_get_user_statistics(self, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:260` |
| `TestUserService` | `test_create_user_success(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:275` |
| `TestUserService` | `test_create_user_short_username(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:285` |
| `TestUserService` | `test_create_user_invalid_chars(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:292` |
| `TestUserService` | `test_create_user_duplicate(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:298` |
| `TestUserService` | `test_create_user_invalid_role(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:306` |
| `TestUserService` | `test_create_user_short_password(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:313` |
| `TestUserService` | `test_create_user_with_audit(self, user_service, audit_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:320` |
| `TestUserService` | `test_get_user_by_id(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:330` |
| `TestUserService` | `test_get_user_by_id_not_found(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:336` |
| `TestUserService` | `test_get_all_users_sanitized(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:339` |
| `TestUserService` | `test_update_user(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:346` |
| `TestUserService` | `test_update_user_not_found(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:353` |
| `TestUserService` | `test_update_user_invalid_role(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:357` |
| `TestUserService` | `test_toggle_active(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:364` |
| `TestUserService` | `test_toggle_active_last_admin_protection(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:371` |
| `TestUserService` | `test_reset_password(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:377` |
| `TestUserService` | `test_reset_password_too_short(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:384` |
| `TestUserService` | `test_delete_user(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:389` |
| `TestUserService` | `test_delete_last_admin_protection(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:395` |
| `TestUserService` | `test_delete_self_protection(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:402` |
| `TestUserService` | `test_ensure_default_admin(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:411` |
| `TestUserService` | `test_ensure_default_admin_skips_if_exists(self, user_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:416` |
| `TestSessionModel` | `test_create_session(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:428` |
| `TestSessionModel` | `test_find_by_access_jti(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:440` |
| `TestSessionModel` | `test_find_by_refresh_jti(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:450` |
| `TestSessionModel` | `test_get_user_sessions(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:460` |
| `TestSessionModel` | `test_revoke_by_access_jti(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:471` |
| `TestSessionModel` | `test_revoke_by_refresh_jti(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:482` |
| `TestSessionModel` | `test_revoke_all_user(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:491` |
| `TestSessionModel` | `test_is_session_revoked_false(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:508` |
| `TestSessionModel` | `test_is_session_revoked_true(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:517` |
| `TestSessionModel` | `test_is_session_revoked_unknown_jti(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:527` |
| `TestSessionModel` | `test_cleanup_expired(self, session_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:531` |
| `TestAdminAuthService` | `test_login_success(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:549` |
| `TestAdminAuthService` | `test_login_wrong_password(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:558` |
| `TestAdminAuthService` | `test_login_user_not_found(self, auth_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:564` |
| `TestAdminAuthService` | `test_login_disabled_account(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:568` |
| `TestAdminAuthService` | `test_login_locked_account(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:574` |
| `TestAdminAuthService` | `test_login_increments_failed_attempts(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:581` |
| `TestAdminAuthService` | `test_login_resets_attempts_on_success(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:588` |
| `TestAdminAuthService` | `test_login_sets_cookies_data(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:595` |
| `TestAdminAuthService` | `test_logout(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:603` |
| `TestAdminAuthService` | `test_refresh_token(self, auth_service, user_model)` | Xử lý token xác thực, refresh, revoke hoặc kiểm tra hiệu lực. | `server/tests/test_users_auth.py:610` |
| `TestAdminAuthService` | `test_refresh_token_invalid(self, auth_service)` | Xử lý token xác thực, refresh, revoke hoặc kiểm tra hiệu lực. | `server/tests/test_users_auth.py:618` |
| `TestAdminAuthService` | `test_change_password_success(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:622` |
| `TestAdminAuthService` | `test_change_password_wrong_old(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:633` |
| `TestAdminAuthService` | `test_change_password_too_short(self, auth_service, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:642` |
| `TestUserController` | `app(self, user_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:658` |
| `TestUserController` | `test_list_users(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:685` |
| `TestUserController` | `test_list_users_filter_role(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:694` |
| `TestUserController` | `test_create_user_via_api(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:701` |
| `TestUserController` | `test_create_user_duplicate_via_api(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:712` |
| `TestUserController` | `test_get_user_via_api(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:724` |
| `TestUserController` | `test_get_user_not_found(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:732` |
| `TestUserController` | `test_update_user_via_api(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:737` |
| `TestUserController` | `test_delete_user_via_api(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:745` |
| `TestUserController` | `test_reset_password_via_api(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:751` |
| `TestUserController` | `test_get_statistics(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:759` |
| `TestAdminAuthController` | `app(self, auth_service, jwt_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:779` |
| `TestAdminAuthController` | `test_login_endpoint(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:787` |
| `TestAdminAuthController` | `test_login_missing_fields(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:804` |
| `TestAdminAuthController` | `test_login_wrong_password(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:812` |
| `TestAdminAuthController` | `test_login_not_json(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:821` |
| `TestAdminAuthController` | `test_get_profile(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:826` |
| `TestAdminAuthController` | `test_logout_endpoint(self, app, user_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:835` |
| `TestAdminAuthController` | `test_refresh_endpoint(self, app, user_model, auth_service)` | Refresh access token bằng refresh token hợp lệ. | `server/tests/test_users_auth.py:844` |
| `TestAdminAuthController` | `test_update_profile_writes_audit_entry(self, app, user_model, audit_model)` | P0.4 verification: `PUT /api/admin/auth/profile` đổi email → ghi audit `profile.update` với `details.updated_fields=["email"]`. | `server/tests/test_users_auth.py:866` |
| `TestAdminAuthController` | `test_update_profile_no_change_skips_audit(self, app, user_model, audit_model)` | Body rỗng → 200 "No changes", không ghi audit. | `server/tests/test_users_auth.py:894` |
| `TestAdminAuthController` | `test_update_profile_duplicate_email_rejected(self, app, user_model, audit_model)` | Email trùng user khác → 400, không ghi audit. | `server/tests/test_users_auth.py:911` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:41` |
| `db(mongo_client)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:57` |
| `user_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_users_auth.py:66` |
| `session_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_users_auth.py:71` |
| `audit_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_users_auth.py:76` |
| `audit_service(audit_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:81` |
| `jwt_service(db)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:86` |
| `user_service(user_model, audit_service)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:91` |
| `auth_service(user_model, jwt_service, session_model, audit_service)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_users_auth.py:96` |
| `_hash(password)` | Xử lý bảo mật dữ liệu nhạy cảm bằng hash/mã hóa. | `server/tests/test_users_auth.py:104` |
| `_create_user(user_model, username, password, role, email, is_active)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `server/tests/test_users_auth.py:108` |
| `make_admin_user(user_model, username, password)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_users_auth.py:122` |
| `_mock_auth(user)` | Patch middleware internals so @require_login passes and sets g.current_user. | `server/tests/test_users_auth.py:126` |


### `server/tests/test_whitelist_and_logs.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TestWhitelistModel` | Test WhitelistModel CRUD, validation, versioning. | `server/tests/test_whitelist_and_logs.py:161` |
| `TestWhitelistService` | Test WhitelistService business logic. | `server/tests/test_whitelist_and_logs.py:323` |
| `TestLogModel` | Test LogModel CRUD, query, statistics. | `server/tests/test_whitelist_and_logs.py:471` |
| `TestLogService` | Test LogService business logic. | `server/tests/test_whitelist_and_logs.py:589` |
| `TestWhitelistController` | Test WhitelistController HTTP endpoints. | `server/tests/test_whitelist_and_logs.py:711` |
| `TestLogController` | Test LogController HTTP endpoints. | `server/tests/test_whitelist_and_logs.py:809` |
| `TestRBACWhitelistTeacher` | Teacher cannot add/delete global whitelist, can only access own groups. | `server/tests/test_whitelist_and_logs.py:896` |
| `TestRBACLogTeacher` | Teacher cannot delete/export logs. Can only see logs from own agents. | `server/tests/test_whitelist_and_logs.py:986` |
| `TestPendingGroupIsolation` | Agent in Pending group: logs invisible to teachers, visible to admin. | `server/tests/test_whitelist_and_logs.py:1081` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TestWhitelistModel` | `test_insert_entry_domain(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:164` |
| `TestWhitelistModel` | `test_insert_entry_ip(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:174` |
| `TestWhitelistModel` | `test_insert_entry_lowercase_trim(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:183` |
| `TestWhitelistModel` | `test_insert_entry_empty_value_raises(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:190` |
| `TestWhitelistModel` | `test_find_entry_by_value(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:194` |
| `TestWhitelistModel` | `test_find_entry_by_value_case_insensitive(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:200` |
| `TestWhitelistModel` | `test_find_entry_by_value_not_found(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:205` |
| `TestWhitelistModel` | `test_delete_entry(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:209` |
| `TestWhitelistModel` | `test_delete_entry_not_found(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:214` |
| `TestWhitelistModel` | `test_update_entry(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:218` |
| `TestWhitelistModel` | `test_find_all_entries_default_scope(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:225` |
| `TestWhitelistModel` | `test_find_all_entries_group_scope(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:233` |
| `TestWhitelistModel` | `test_global_version_bump(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:240` |
| `TestWhitelistModel` | `test_global_version_no_bump_for_group(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:246` |
| `TestWhitelistModel` | `test_bulk_insert_entries(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:252` |
| `TestWhitelistModel` | `test_bulk_insert_empty(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:261` |
| `TestWhitelistModel` | `test_validate_domain_valid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:265` |
| `TestWhitelistModel` | `test_validate_domain_invalid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:269` |
| `TestWhitelistModel` | `test_validate_ip_valid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:273` |
| `TestWhitelistModel` | `test_validate_ip_invalid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:277` |
| `TestWhitelistModel` | `test_validate_url_valid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:281` |
| `TestWhitelistModel` | `test_validate_url_invalid(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:285` |
| `TestWhitelistModel` | `test_validate_unknown_type(self, whitelist_model)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `server/tests/test_whitelist_and_logs.py:289` |
| `TestWhitelistModel` | `test_get_statistics(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:293` |
| `TestWhitelistModel` | `test_get_entries_for_sync(self, whitelist_model)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_whitelist_and_logs.py:301` |
| `TestWhitelistModel` | `test_cleanup_expired_entries(self, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:307` |
| `TestWhitelistService` | `test_add_entry_domain(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:326` |
| `TestWhitelistService` | `test_add_entry_duplicate_raises(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:333` |
| `TestWhitelistService` | `test_add_entry_empty_value_raises(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:338` |
| `TestWhitelistService` | `test_add_entry_invalid_domain_raises(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:342` |
| `TestWhitelistService` | `test_get_all_entries(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:346` |
| `TestWhitelistService` | `test_delete_entry_via_service(self, whitelist_service)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_whitelist_and_logs.py:352` |
| `TestWhitelistService` | `test_delete_entry_not_found_raises(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:357` |
| `TestWhitelistService` | `test_update_entry_via_service(self, whitelist_service)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_whitelist_and_logs.py:361` |
| `TestWhitelistService` | `test_get_statistics(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:367` |
| `TestWhitelistService` | `test_get_scoped_whitelist_by_group(self, whitelist_service, group_model, agent_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:372` |
| `TestWhitelistService` | `test_get_scoped_whitelist_by_agent(self, whitelist_service, group_model, agent_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:383` |
| `TestWhitelistService` | `test_bulk_add_entries(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:394` |
| `TestWhitelistService` | `test_bulk_add_entries_with_invalid(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:403` |
| `TestWhitelistService` | `test_bulk_delete_entries_global(self, whitelist_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:412` |
| `TestWhitelistService` | `test_bulk_delete_group_entries(self, whitelist_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:419` |
| `TestWhitelistService` | `test_agent_sync_data_full(self, whitelist_service, group_model, agent_model)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_whitelist_and_logs.py:429` |
| `TestWhitelistService` | `test_agent_sync_data_up_to_date(self, whitelist_service, group_model, agent_model)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_whitelist_and_logs.py:445` |
| `TestWhitelistService` | `test_agent_sync_no_agent_id_raises(self, whitelist_service)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `server/tests/test_whitelist_and_logs.py:462` |
| `TestLogModel` | `test_insert_logs(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:474` |
| `TestLogModel` | `test_insert_logs_empty(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:484` |
| `TestLogModel` | `test_find_all_logs(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:488` |
| `TestLogModel` | `test_find_all_logs_with_limit(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:496` |
| `TestLogModel` | `test_find_all_logs_with_offset(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:504` |
| `TestLogModel` | `test_count_logs(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:513` |
| `TestLogModel` | `test_count_logs_with_query(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:521` |
| `TestLogModel` | `test_delete_logs(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:528` |
| `TestLogModel` | `test_delete_logs_all(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:535` |
| `TestLogModel` | `test_get_total_count(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:543` |
| `TestLogModel` | `test_get_count_by_action(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:550` |
| `TestLogModel` | `test_get_recent_logs(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:557` |
| `TestLogModel` | `test_get_logs_summary(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:565` |
| `TestLogModel` | `test_timestamp_auto_assigned(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:574` |
| `TestLogModel` | `test_server_received_at_set(self, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:579` |
| `TestLogService` | `test_receive_logs_success(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:592` |
| `TestLogService` | `test_receive_logs_empty(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:601` |
| `TestLogService` | `test_receive_logs_no_logs_key(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:606` |
| `TestLogService` | `test_protocol_detection_443(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:610` |
| `TestLogService` | `test_protocol_detection_80(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:616` |
| `TestLogService` | `test_protocol_detection_53(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:622` |
| `TestLogService` | `test_protocol_detection_custom_port(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:628` |
| `TestLogService` | `test_action_normalization_allow(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:634` |
| `TestLogService` | `test_action_normalization_deny(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:640` |
| `TestLogService` | `test_get_all_logs_with_filters(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:646` |
| `TestLogService` | `test_get_all_logs_time_range(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:654` |
| `TestLogService` | `test_clear_logs(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:661` |
| `TestLogService` | `test_export_logs_json(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:669` |
| `TestLogService` | `test_export_logs_csv(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:677` |
| `TestLogService` | `test_comprehensive_statistics(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:685` |
| `TestLogService` | `test_source_ip_fallback(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:694` |
| `TestLogService` | `test_destination_fallback(self, log_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:700` |
| `TestWhitelistController` | `app(self, whitelist_model, whitelist_service, rbac_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:715` |
| `TestWhitelistController` | `test_list_domains_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:723` |
| `TestWhitelistController` | `test_add_domain_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:732` |
| `TestWhitelistController` | `test_add_domain_no_value(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:741` |
| `TestWhitelistController` | `test_add_domain_not_json(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:748` |
| `TestWhitelistController` | `test_delete_domain_admin(self, app, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:755` |
| `TestWhitelistController` | `test_delete_domain_invalid_id(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:763` |
| `TestWhitelistController` | `test_get_statistics(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:770` |
| `TestWhitelistController` | `test_bulk_add_entries(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:777` |
| `TestWhitelistController` | `test_bulk_add_no_items(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:789` |
| `TestWhitelistController` | `test_bulk_delete_entries(self, app, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:796` |
| `TestLogController` | `app(self, log_model, log_service, rbac_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:813` |
| `TestLogController` | `test_receive_logs_via_jwt(self, agent_model, group_model)` | Agent sends logs via POST with JWT - no RBAC check. | `server/tests/test_whitelist_and_logs.py:821` |
| `TestLogController` | `test_list_logs_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:856` |
| `TestLogController` | `test_list_logs_with_filters(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:863` |
| `TestLogController` | `test_get_statistics(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:870` |
| `TestLogController` | `test_clear_logs_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:877` |
| `TestLogController` | `test_export_logs_admin(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:884` |
| `TestRBACWhitelistTeacher` | `app(self, whitelist_model, whitelist_service, rbac_service, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:900` |
| `TestRBACWhitelistTeacher` | `test_teacher_cannot_add_global(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:908` |
| `TestRBACWhitelistTeacher` | `test_teacher_cannot_add_to_other_group(self, app, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:917` |
| `TestRBACWhitelistTeacher` | `test_teacher_can_add_to_own_group(self, app, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:931` |
| `TestRBACWhitelistTeacher` | `test_teacher_cannot_delete_global(self, app, whitelist_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:945` |
| `TestRBACWhitelistTeacher` | `test_teacher_cannot_delete_other_group_entry(self, app, whitelist_model, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:953` |
| `TestRBACWhitelistTeacher` | `test_teacher_bulk_add_blocked_for_other_group(self, app, group_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:968` |
| `TestRBACLogTeacher` | `app(self, log_model, log_service, rbac_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:990` |
| `TestRBACLogTeacher` | `test_teacher_cannot_clear_logs(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:998` |
| `TestRBACLogTeacher` | `test_teacher_cannot_export_logs(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1007` |
| `TestRBACLogTeacher` | `test_teacher_can_list_logs(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1014` |
| `TestRBACLogTeacher` | `test_teacher_log_filter_applied(self, app, log_model, group_model, agent_model)` | Teacher only sees logs from agents in their groups. | `server/tests/test_whitelist_and_logs.py:1021` |
| `TestRBACLogTeacher` | `test_admin_sees_all_logs(self, app, log_model)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1047` |
| `TestRBACLogTeacher` | `test_admin_can_clear_logs(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1062` |
| `TestRBACLogTeacher` | `test_admin_can_export_logs(self, app)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1069` |
| `TestPendingGroupIsolation` | `app(self, log_model, log_service, rbac_service)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:1085` |
| `TestPendingGroupIsolation` | `test_pending_agent_logs_invisible_to_teacher(self, app, log_model, group_model, agent_model)` | Teacher cannot see logs from agent in Pending (system) group. | `server/tests/test_whitelist_and_logs.py:1093` |
| `TestPendingGroupIsolation` | `test_pending_agent_logs_invisible_to_any_teacher(self, app, log_model, group_model, agent_model)` | Even a teacher with no groups cannot see pending agent logs. | `server/tests/test_whitelist_and_logs.py:1119` |
| `TestPendingGroupIsolation` | `test_pending_agent_logs_visible_to_admin(self, app, log_model, group_model, agent_model)` | Admin CAN see logs from agents in Pending group. | `server/tests/test_whitelist_and_logs.py:1140` |
| `TestPendingGroupIsolation` | `test_pending_agent_moves_to_teacher_group_logs_become_visible(self, app, log_model, group_model, agent_model)` | After moving agent from Pending to teacher's group, logs become visible. | `server/tests/test_whitelist_and_logs.py:1159` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `mongo_client()` | Create MongoDB client using same config as server (.env). | `server/tests/test_whitelist_and_logs.py:52` |
| `db(mongo_client)` | Fresh test database with Vietnam timezone codec - dropped after each test. | `server/tests/test_whitelist_and_logs.py:71` |
| `whitelist_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_whitelist_and_logs.py:81` |
| `log_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_whitelist_and_logs.py:86` |
| `agent_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_whitelist_and_logs.py:91` |
| `group_model(db)` | Lớp truy cập MongoDB collection, query/index/CRUD cho tài nguyên tương ứng. | `server/tests/test_whitelist_and_logs.py:96` |
| `rbac_service(group_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_whitelist_and_logs.py:101` |
| `whitelist_service(whitelist_model, agent_model, group_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_whitelist_and_logs.py:106` |
| `log_service(log_model, agent_model)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `server/tests/test_whitelist_and_logs.py:111` |
| `make_admin()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:119` |
| `make_teacher(teacher_id)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `server/tests/test_whitelist_and_logs.py:123` |
| `create_group(group_model, name, created_by, whitelist)` | Insert a group and return it. | `server/tests/test_whitelist_and_logs.py:127` |
| `insert_agent(agent_model, group_id, hostname, agent_id)` | Register an agent in a group. | `server/tests/test_whitelist_and_logs.py:132` |
| `_mock_auth(user)` | Patch RBAC middleware to simulate authenticated user. | `server/tests/test_whitelist_and_logs.py:148` |

## Cap nhat 2026-05-27 - Whitelist entries collection

Group whitelist da co model/collection moi cho migration tu embedded array sang first-class documents:

| Symbol | Cong dung | Vi tri |
| --- | --- | --- |
| `WhitelistEntryModel` | Repository cho collection `whitelist_entries`. | `server/models/whitelist_entry_model.py` |
| `WhitelistEntryModel.insert_entry(...)` | Insert group whitelist row va tra `_id` that. | `server/models/whitelist_entry_model.py` |
| `WhitelistEntryModel.list_group_entries(...)` | List group rows tu collection moi. | `server/models/whitelist_entry_model.py` |
| `WhitelistEntryModel.find_entry_access_info(...)` | Lookup toi thieu `scope/group_id` cho RBAC. | `server/models/whitelist_entry_model.py` |
| `WhitelistService._get_group_entries(...)` | Merge `whitelist_entries` voi legacy `groups.whitelist[]`; collection row thang neu trung `type:value`. | `server/services/whitelist_service.py` |
| `2026_migrate_group_whitelist_to_entries.py` | Dry-run/write migration copy embedded rows sang `whitelist_entries`, giu `legacy_embedded_id`. | `server/scripts/migrations/2026_migrate_group_whitelist_to_entries.py` |

Test moi trong `server/tests/test_whitelist_and_logs.py`: collection-first bulk add, embedded fallback, partial migration merge, update/delete bang real `_id`. Reference chi tiet: `docs/reference/server/whitelist_entries.md`.

## Cap nhat 2026-05-28 - Render full deep E2E va hotfix bao mat

Baseline production moi nhat:

| Hang muc | Ket qua |
| --- | --- |
| Render full deep E2E `20260528_141158` | `24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0`, `cleanup_failures=0`, `CLEANUP_OK=43` |
| Web-facing group/log auth | Public smoke sau deploy xac nhan `/api/groups`, `/api/logs?limit=1`, `/api/logs/stats` tra `401` khi chua dang nhap |
| Agent heartbeat policy | `deep_policy_matrix` PASS; isolate heartbeat tra `force_sync=true`, `policy_mode=isolate` |
| Active profile sync | `deep_whitelist_conflict_matrix` PASS; domain profile khong con sync thanh `value: null` |
| Real firewall Default Deny | PASS voi backend `powershell`/NetSecurity; restore ve allow va residual managed rules = 0 |

Test/regression moi can nho khi doc source:

| Test | Muc dich |
| --- | --- |
| `test_controller_web_routes_require_login` | Bao ve `/api/groups` web routes khong public khi chua dang nhap. |
| `test_web_routes_require_login` | Bao ve `/api/logs`, `/api/logs/stats`, clear/export web routes phai login. |
| `test_agent_sync_active_profile_accepts_domain_key` | Bao ve active profile payload legacy `domain` van sync ra value dung. |
| `test_mask_connection_uri_hides_credentials` | Bao ve Mongo URI logging chi ghi masked credential. |

Ton dong khong nam trong source test hien tai: multi-machine vat ly, reboot cycle that, soak dai hon 30 phut, Render log/secret rotation neu log cu tung lo secret, va whitelist fallback/pseudo-ID cutover sau backup + migration production.

## Cap nhat 2026-06-01 - API key rate limit

## Cap nhat 2026-06-01 - API key expiration

Ket luan source audit: API key expiration co enforce that. `APIKeyController.create_api_key()` validate `expires_in_days`; `0`/`null` la never expires, so am bi reject. `APIKeyModel.create_api_key()` luu `expires_at`; `APIKeyModel.validate_api_key()` reject khi `expires_at < now_vietnam()` voi `API key has expired` truoc khi tang usage. Endpoint boc `require_api_key(...)` tra HTTP `401` cho expired key. UI `/api-keys` da tach status `expired` khoi `revoked`, them filter `Expired`, va khong tinh expired key vao stat `Active`. Regression moi `server/tests/test_api_key_expiration.py`: 4 passed.

Ket luan source audit: API key khong co rate limit that. `server/requirements.txt` khong co Flask-Limiter hay thu vien rate-limit tuong duong; `server/middleware/auth.py::require_api_key` chi extract key va goi validate; `APIKeyService.create_api_key(...)` va `APIKeyModel.create_api_key(...)` khong nhan/lưu `rate_limit`; `APIKeyModel.validate_api_key(...)` chi `$inc usage_count` va update `last_used_at`. Khong co hourly window, sliding window, token bucket hay response `429`.

Thay doi da lam: xoa field Rate Limit khoi modal `/api-keys`, xoa payload `rate_limit`, xoa hien thi `usage_count / rate_limit`, xoa progress bar usage gia va CSS `.usage-bar`. `usage_count` tiep tuc co nghia la tong so lan validate thanh cong trong vong doi key, khong phai quota.

Them fix UI cung dot 2026-06-01: `keyExpiry` tiep tuc goi `window.initCustomSelect(...)` de giu dung style dropdown chung. Shared custom select trong `base.js` da tinh boundary cua modal, tu mo len bang `drop-up` khi khong du cho ben duoi, va `.custom-options` co `max-height` + `overflow-y: auto`; nhờ đó Expiration khong con bi Bootstrap modal cat mat cac option sau `7 days`.
