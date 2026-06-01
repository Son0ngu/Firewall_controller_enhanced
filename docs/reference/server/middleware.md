# `server/middleware` - Auth (API key + JWT) + RBAC decorators

## Mục đích
Hai module decorator độc lập:
- **`auth.py`**: Xác thực **Agent** (API key cho register, JWT cho operations). Caller chỉ định permission. Lưu kết quả vào `flask.g`.
- **`rbac.py`**: Xác thực **Admin/Teacher** (cookie JWT > Authorization header). Kết hợp permission check (`resource:action`) và ownership check (Teacher chỉ tới Groups được assign).
- **`csrf.py`**: Double-submit CSRF token cho cookie-authenticated admin mutations. `SaintAPI` tự gửi `X-CSRF-Token`; API key/Bearer endpoints được exempt.

Auth/RBAC middleware chạy **song song** - agent endpoints dùng `auth.py`, web/admin endpoints dùng `rbac.py`. CSRF là global `before_request` hook cho unsafe methods trên cookie-authenticated admin requests.

## Public API

### `server/middleware/auth.py` - Agent authentication

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `init_auth_middleware(api_key_service, jwt_service=None)` | | [auth.py:20](../../../server/middleware/auth.py#L20) | One-time wire, đặt globals `_api_key_service`, `_jwt_service`. Gọi từ `app.register_controllers` |
| `get_api_key_from_request()` | `() -> Optional[str]` | [auth.py:35](../../../server/middleware/auth.py#L35) | Thứ tự: `X-API-Key` header → `Authorization: Bearer/ApiKey ...`. `?api_key=` query chỉ được đọc nếu `Config.DEBUG_AUTH_QUERY_TOKEN=True` (default `False`); khi đó log warning kèm endpoint + IP. |
| `get_jwt_from_request()` | `() -> Optional[str]` | [auth.py:241](../../../server/middleware/auth.py#L241) | Thứ tự: `Authorization: Bearer ...` → `X-Access-Token` header. `?access_token=` query cũng gate bằng `DEBUG_AUTH_QUERY_TOKEN`. **Không đọc cookie ở đây** — đó là admin/web flow (`middleware/rbac.py`); trộn vào sẽ cho cookie admin xác thực như agent. |
| `@require_api_key(permission="register")` | decorator factory | [auth.py:71](../../../server/middleware/auth.py#L71) | Set `g.api_key_info`, `g.api_key_id`, `g.api_key_name` on success. 401 nếu thiếu/invalid. Không rate-limit |
| `@optional_api_key` | decorator | [auth.py:136](../../../server/middleware/auth.py#L136) | Set `g.api_key_*` nếu có, None nếu không. Không reject |
| `@require_jwt` | decorator | [auth.py:273](../../../server/middleware/auth.py#L273) | Set `g.jwt_payload`, `g.agent_id`, `g.user_id`, `g.token_jti`. 401. Token expired → `code: TOKEN_EXPIRED` để agent refresh |
| `@optional_jwt` | decorator | [auth.py:343](../../../server/middleware/auth.py#L343) | Như optional_api_key nhưng cho JWT |
| `@require_jwt_or_api_key(permission=None)` | decorator factory | [auth.py:381](../../../server/middleware/auth.py#L381) | Thử JWT trước → API key. 401 nếu cả 2 đều fail |
| `APIKeyMiddleware` class | | [auth.py:172](../../../server/middleware/auth.py#L172) | Alternative `before_request` style - **không dùng** ở `app.py`. Decorator pattern thắng |

### `server/middleware/rbac.py` - Admin/Teacher RBAC

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `init_rbac_middleware(admin_auth_service, rbac_service, jwt_service, user_model)` | | [rbac.py:26](../../../server/middleware/rbac.py#L26) | One-time wire |
| `get_rbac_service()` | `() -> RBACService` | [rbac.py:39](../../../server/middleware/rbac.py#L39) | Cho controller dùng ownership filter |
| `@require_login` | decorator | [rbac.py:98](../../../server/middleware/rbac.py#L98) | Set `g.current_user`, `g.current_user_id`, `g.current_role`. Reject: API path → JSON 401, page → redirect `/login` |
| `@require_admin` | decorator | [rbac.py:146](../../../server/middleware/rbac.py#L146) | Phải dùng SAU `@require_login`. 403 nếu role != admin |
| `@require_permission(permission)` | decorator factory | [rbac.py:170](../../../server/middleware/rbac.py#L170) | Phải dùng SAU `@require_login`. Check `config.rbac_config.check_permission(role, permission)`. 403 + `required: <permission>` |
| `@inject_current_user` | decorator | [rbac.py:204](../../../server/middleware/rbac.py#L204) | Non-blocking version: set `g.current_user` nếu có token, None nếu không. Trang hiện nội dung khác nhau theo login state |
| `@require_group_ownership(group_id_param="group_id")` | decorator factory | [rbac.py:228](../../../server/middleware/rbac.py#L228) | Phải dùng SAU `@require_login`. Admin pass, Teacher check `RBACService.can_access_group(user, group)`. Lấy `group_id` từ URL kwargs hoặc JSON body. 403 nếu không own |
| `_extract_token()` | `() -> Optional[str]` | [rbac.py:44](../../../server/middleware/rbac.py#L44) | Cookie `access_token` trước, fallback `Authorization: Bearer` |
| `_validate_admin_token(token)` | `(str) -> (bool, user_dict, error)` | [rbac.py:62](../../../server/middleware/rbac.py#L62) | Decode JWT → check `token_for == "admin_user"` → load user → check active/locked |

### `server/middleware/csrf.py` - Cookie-authenticated mutation protection

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `register_csrf(app)` | `(Flask) -> None` | [csrf.py](../../../server/middleware/csrf.py) | Cài global `before_request` hook. |
| `set_csrf_cookie(response, token=None)` | `(Response, Optional[str]) -> str` | [csrf.py](../../../server/middleware/csrf.py) | Set cookie `csrf_token` non-httpOnly để JS đọc và echo qua header. |
| `delete_csrf_cookie(response)` | `(Response) -> None` | [csrf.py](../../../server/middleware/csrf.py) | Xóa CSRF cookie khi logout. |
| `mint_csrf_token()` | `() -> str` | [csrf.py](../../../server/middleware/csrf.py) | Tạo token ngẫu nhiên 32 bytes hex. |

## `flask.g` namespace (sau decorator)

| Key | Set bởi | Kiểu |
|---|---|---|
| `g.api_key_info` | `require_api_key`, `optional_api_key` | `Dict` (key_id, name, permissions, ...) |
| `g.api_key_id` | ↑ | `str` |
| `g.api_key_name` | ↑ | `str` |
| `g.jwt_payload` | `require_jwt`, `optional_jwt`, `require_jwt_or_api_key` | `Dict` (sub, user_id, jti, type, exp, iss, iat, ...) |
| `g.agent_id` | ↑ | `str` (từ `sub` claim) - KHÔNG phải admin user ID |
| `g.user_id` | ↑ | `str` (từ `user_id` claim) |
| `g.token_jti` | ↑ | `str` |
| `g.current_user` | `require_login`, `inject_current_user` | `Dict` (full user doc) |
| `g.current_user_id` | ↑ | `str` (ObjectId stringified) |
| `g.current_role` | ↑ | `"admin"` hoặc `"teacher"` |

## Ai gọi module này
- `server/controllers/*.py` - mọi controller dùng decorators để wrap handler.
- `server/bootstrap/container.py` - init auth/RBAC middleware.
- `server/bootstrap/app_factory.py` - `register_csrf(app)`.

## Module này gọi ra
- `flask` (request, g, jsonify, redirect)
- `services.api_key_service.APIKeyService.validate_api_key`
- `services.jwt_service.JWTService.validate_access_token`
- `config.rbac_config.check_permission, is_admin`
- `models.user_model.UserModel.find_by_id, is_locked`

## Đã có sẵn - đừng viết lại
- Cần auth agent? → `@require_api_key("perm")` cho register, `@require_jwt` cho operations
- Cần auth admin/teacher web? → `@require_login` + `@require_permission("res:action")` (hoặc `@require_admin`)
- Cần check teacher owns group? → `@require_group_ownership("group_id")` - sau `@require_login`
- Cần inject user nếu có (non-blocking)? → `@inject_current_user`
- Cần lấy current user trong handler? → `g.current_user`, `g.current_role`, `g.current_user_id`
- Cần lấy current agent? → `g.agent_id` (từ JWT) hoặc `g.api_key_id` (từ API key)
- Cần extract token thủ công cho logic phức tạp? → `get_jwt_from_request()` / `get_api_key_from_request()` (auth.py) hoặc `_extract_token()` (rbac.py - internal nhưng có thể public hoá)

API key expired: `@require_api_key(...)` tra JSON `401 {"success": false, "error": "API key has expired"}`; key do khong duoc set vao `g.api_key_*`.

## Gotchas

### Auth (Agent)
- **`init_auth_middleware` PHẢI gọi trước register routes** (app.py:241). Nếu không, mọi `require_api_key` sẽ return 500 ("Server configuration error").
- **`Authorization` header parse khác nhau**: `auth.py` chấp nhận cả `Bearer` và `ApiKey` prefix (auth.py:55-59) - endpoint dùng API key có thể nhận token kiểu `Bearer fc_...`. `get_jwt_from_request` chỉ accept `Bearer` (không `ApiKey`).
- **Query param `?api_key=` & `?access_token=`**: default **bị từ chối** (P0.1). Phải set env `DEBUG_AUTH_QUERY_TOKEN=true` mới được đọc, và mỗi lần dùng đều log warning. Lý do: token trong URL leak qua proxy log, browser history, Referer header. Production tuyệt đối không bật.
- **Không có API key rate limit ở middleware**: `require_api_key` chỉ extract key, gọi `APIKeyService.validate_api_key`, kiểm tra kết quả và set `g.api_key_*`. Không có per-key counter window, token bucket, hoặc response `429`.
- **Token expired → status `code: TOKEN_EXPIRED`** (auth.py:316-321): agent dùng key này detect refresh moment. Đừng thay đổi.
- **`require_jwt_or_api_key` clear lẫn nhau** (auth.py:413, 426): nếu JWT pass, set `api_key_info = None`. Caller phải check `g.agent_id` (JWT path) hoặc `g.api_key_id` (key path) để biết auth source.

### RBAC (Admin/Teacher)
- **Cookie name `access_token`** (rbac.py:51): set bởi `WebAuthController.login` (đổi tên từ `AdminAuthController` ở P1 #10). Nếu sửa name, sync cả 2 chỗ.
- **`token_for == "admin_user"` check** (rbac.py:76-77): JWT của agent có `sub=<agent_id>` nhưng KHÔNG có `token_for` → reject. Token của admin có `token_for="admin_user"` được set ở `AdminAuthService.login`. Ngăn cross-use.
- **Order decorator quan trọng**: `@require_login` PHẢI trước `@require_admin`/`@require_permission`/`@require_group_ownership`. Sai thứ tự → `g.current_user` chưa set → KeyError hoặc 401 silent.
- **API path vs page path** (rbac.py:113-119): `request.path.startswith("/api/")` → JSON, ngược lại → redirect. Đừng dùng `/api/admin/...` cho trang HTML - sẽ trả JSON.
- **`@inject_current_user` SET `g.current_user = None` trước khi check** (rbac.py:212-214) - caller có thể `if g.current_user:` an toàn. Đừng dựa vào `hasattr`.
- **`require_group_ownership` lookup group qua `GroupModel.find_by_id()` mỗi request**: nếu endpoint cũng cần group → query 2 lần. Acceptable cho clarity; không gọi `.collection` trực tiếp trong middleware.
- **`is_admin(role)` từ `config.rbac_config`** - đừng tự `role == "admin"` rải rác. Tập trung 1 chỗ để dễ đổi.
- **Token revoked không check trong `_validate_admin_token`** (rbac.py:62-91) - `JWTService.validate_access_token` đã check `_is_token_revoked` qua `revoked_tokens` collection. Logout = revoke = JWT next call 401.

### CSRF
- **Unsafe cookie-authenticated requests phải có `X-CSRF-Token`**: `SaintAPI` đọc cookie `csrf_token` và tự attach header cho same-origin POST/PUT/PATCH/DELETE.
- **Bearer/API key requests exempt**: browser không tự attach các header này, nên không nằm trong CSRF threat model.
- **CORS phải allow `X-CSRF-Token` và `PATCH`**: app factory đã cấu hình trong `API_CORS_OPTIONS`. Nếu thêm custom CSRF header mới, update CORS cùng lúc.

### Cả hai
- **`flask.g` per-request scope**: an toàn dùng giữa decorators và handler. Không leak qua request.
- **Middleware `auth.py` không log username** (chỉ log endpoint + remote_addr). RBAC log username. Đối tượng audit khác nhau.
