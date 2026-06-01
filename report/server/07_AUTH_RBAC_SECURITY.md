# Authentication, RBAC và bảo mật Server

## Authentication

| Luồng | Source | Cơ chế |
| --- | --- | --- |
| Agent register | `middleware/auth.py`, `api_key_service.py` | API Key hash/HMAC permission `agent_register`. Token chỉ đọc qua `X-API-Key` hoặc `Authorization: Bearer/ApiKey ...`. Query string `?api_key=` mặc định bị **từ chối** — chỉ chấp nhận khi env `DEBUG_AUTH_QUERY_TOKEN=true` (dev-only, có log warning). |
| Agent API | `AgentAuthController` (`controllers/auth_controller.py`) + `require_jwt` | JWT Agent cho heartbeat, whitelist sync, logs. `AgentAuthController` (đổi tên từ `AuthController`, alias backwards-compat) handle `/api/auth/refresh\|logout\|verify\|token-info`. Token đọc qua header (Bearer/X-Access-Token) — không đọc cookie ở luồng này để tránh trộn với admin web auth. |
| Admin/Teacher login | `WebAuthController` (`controllers/web_auth_controller.py`) + `admin_auth_service.py` | Username/password bcrypt, token đặt trong **httpOnly cookie**. `WebAuthController` đổi tên từ `AdminAuthController` (P1 #10 — tách bạch agent vs web auth); module `admin_auth_controller.py` còn lại làm shim re-export, alias `AdminAuthController = WebAuthController` cho backwards-compat. Cookie `secure` flag đọc từ `Config.ADMIN_COOKIE_SECURE` (default `False` ở dev, `True` ở `ProductionConfig`); override bằng env `ADMIN_COOKIE_SECURE`. `samesite=Lax`. |
| Token refresh/revoke | `jwt_service.py`, `session_model.py` | Access/refresh token, JTI, revoked token collection. |
| Audit | `services/audit_service.py` | Method canonical là `AuditService.log_action(user, action, resource_type, resource_id=None, details=None, ip_address=None)`. Mọi mutation quan trọng (login, profile.update, user.create/update/delete, api_keys, whitelist, ...) đều ghi. Profile update trước đây gọi nhầm `.log(...)` đã được fix (P0.4) — `WebAuthController.update_profile` hiện gọi đúng `audit_service.log_action(action="profile.update", resource_type="users", details={"updated_fields": [...]})`. Test bảo vệ ở `tests/test_users_auth.py::TestAdminAuthController::test_update_profile_writes_audit_entry`. |

Ghi chú 2026-06-01: API key hiện **không có rate limit thật**. Auth middleware chỉ kiểm tra format/tồn tại/active/expiration/permission; model chỉ tăng `usage_count` trọn đời sau validate thành công. Không có thư viện rate-limit, không có window counter/token bucket, và không có response `429`. UI Rate Limit đã bị xóa để tránh hiểu nhầm.

## RBAC

`server/config/rbac_config.py` định nghĩa 2 role:

- `admin`: toàn quyền, kế thừa toàn bộ `TEACHER_PERMISSIONS` cộng `ADMIN_EXTRA_PERMISSIONS` (users, api_keys, logs export/delete, audit, system **và `groups:create` / `groups:delete`** — group lifecycle là admin-only).
- `teacher`: chỉ đọc/cập nhật tài nguyên trong group **được admin gán qua `teacher_ids`**, quản lý whitelist profile, xem logs thuộc Agent của group mình. Teacher **không** có `groups:create`, `groups:delete`, `agents:delete`, `logs:export`, `logs:delete`, `users:*`, `api_keys:*`, `audit:read`, `system:config`.

`controllers/agent_controller.py::delete_agent` enforce thêm role check (`role != 'admin' → 403`) trước cả ownership filter — đóng gap trước đây teacher trong nhóm vẫn xóa được agent vì `_check_agent_ownership` chỉ chặn cross-group.

## Data filtering

`RBACService.get_group_query_filter(user)` trả `{"$or": [{"teacher_ids": user._id}, {"created_by": user._id}]}` cho teacher — `teacher_ids` là model hiện tại (admin gán teacher vào group), `created_by` giữ làm legacy fallback cho dữ liệu cũ. Admin → `None` (không filter). `get_teacher_group_ids` dùng `GroupModel.find_accessible_group_ids_for_teacher(...)`; log filter dùng tiếp `AgentModel.find_agent_ids_by_group_ids(...)`, nên RBAC service không còn query Mongo trực tiếp bằng `.collection`.

Controller web-facing phải dùng `require_login(...)`, `require_permission(...)` hoặc `require_admin(...)` làm auth gate bắt buộc. `inject_current_user(...)` chỉ được dùng để nạp ngữ cảnh user tùy chọn và không được đứng một mình trên endpoint trả dữ liệu web-facing, vì decorator này cố ý non-blocking và không trả 401/403.

Hotfix 2026-05-28 đã siết lại các route từng hở public: `/api/groups`, `/api/groups/<id>` GET/PATCH/DELETE, `/api/groups/<id>/teachers`, `/api/logs`, `/api/logs/stats`, `/api/logs/clear`, legacy DELETE `/api/logs` và `/api/logs/export` đều đi qua `require_login(...)`. Route gán teacher dùng `require_login(require_admin(...))`. Agent-facing `POST /api/logs` giữ `require_jwt(...)`, không trộn với web cookie auth.

Với whitelist, controller gọi `WhitelistService.validate_teacher_entry_access(...)` để kiểm tra quyền trên global collection entry, pseudo-ID group entry và real embedded ObjectId trong `groups.whitelist[]`, thay vì tự query collection.

## Brute-force và session

`UserModel` có failed attempts, lock account; `AdminAuthService` xác thực bcrypt và quản lý session/token. `AuditService` ghi log thao tác quan trọng.

## Client IP và audit

Các luồng đăng nhập, audit, Agent register/heartbeat, receive logs và whitelist dùng `utils.request_ip.get_client_ip()` để lấy IP client. Thứ tự ưu tiên là `X-Forwarded-For` (IP đầu tiên), `X-Real-IP`, rồi `request.remote_addr`.

Khi triển khai sau reverse proxy, chỉ nên để proxy tin cậy set các header này. Nếu Server mở trực tiếp ra mạng và vẫn tin `X-Forwarded-For`, client có thể tự gửi header giả mạo IP.
