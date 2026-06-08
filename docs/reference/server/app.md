# `server/app.py` + bootstrap split + `server/time_utils.py` - Bootstrap + Time helpers

> Sau refactor 2026-05-26 `server/app.py` được tách thành nhiều file nhỏ trong
> `server/bootstrap/` và `server/routes/`. Các link trong bảng dưới trỏ thẳng
> tới chỗ code hiện tại; `server/app.py` chỉ còn là entrypoint mỏng (~51
> dòng) khởi tạo logging và gọi `socketio.run`.

## Mục đích
- `app.py`: Entrypoint Flask. Chỉ áp `gevent.monkey.patch_all()` ở line 1-6, set `sys.path`, gọi `create_app()` từ `bootstrap.app_factory` và `socketio.run(...)`. Không còn DI logic ở đây.
- `bootstrap/app_factory.py`: Factory thật — Flask app, CORS, SocketIO (có fallback `gevent` → `threading`), connect Mongo, gọi container, register CSRF middleware, register page routes / error handlers / socketio events.
- `bootstrap/container.py`: DI chain models → services → controllers; chạy `run_startup_tasks` (admin bootstrap chỉ khi có env, API key bootstrap bị skip) với config gate.
- `routes/pages.py`: HTML page routes (`/`, `/agents`, `/groups`, `/whitelist`, `/logs`, `/api-keys`, `/login`, `/admin/users`, `/admin/audit`, `/profile`) + health (`/api/health`, `/api/config`).
- `routes/errors.py`: 404/500 handler (JSON cho `/api/`, HTML cho page).
- `routes/socketio_events.py`: `connect`, `disconnect`, `ping`.
- `time_utils.py`: Helpers timezone Việt Nam — độc lập với `agent/shared/time_utils.py`.

## Public API

### `server/app.py` (entrypoint)

| Symbol | Vị trí | Mô tả |
|---|---|---|
| Monkey patch gevent | [app.py:1-6](../../../server/app.py#L1-L6) | Phải chạy đầu tiên trước mọi import. Có guard `try/except ImportError` để fallback sang Socket.IO `threading` mode khi gevent thiếu. |
| `sys.path.insert` | [app.py:12](../../../server/app.py#L12) | Cho phép `from models.X` không cần prefix `server.`. |
| `__main__` block | [app.py:24-51](../../../server/app.py#L24-L51) | Gọi `create_app()`, log config summary, `socketio.run(use_reloader=False)`. Trap KeyboardInterrupt + Exception → đóng Mongo client. |

### `server/bootstrap/app_factory.py`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `create_app()` | `() -> (Flask, SocketIO)` | [app_factory.py:46](../../../server/bootstrap/app_factory.py#L46) | Single-shot factory. Validate config → CORS → SocketIO (với fallback) → connect Mongo → `initialize_container` → `register_csrf` → page routes → error handlers → SocketIO events. Trả về `(app, socketio)`. |
| `_create_socketio(app, async_mode)` | `(Flask, str) -> SocketIO` | [app_factory.py:19](../../../server/bootstrap/app_factory.py#L19) | Thử `async_mode` cấu hình; nếu `ValueError: Invalid async_mode` (backend không cài) → fallback `threading` + log warning. Test bảo vệ: `server/tests/test_app_factory.py`. |
| `format_datetime_filter(dt, format)` | template filter | [app_factory.py:59](../../../server/bootstrap/app_factory.py#L59) | Jinja filter `format_datetime` — parse ISO via `parse_agent_timestamp` rồi `format_datetime`. |

### `server/bootstrap/container.py`

| Symbol | Vị trí | Mô tả |
|---|---|---|
| `initialize_database_indexes(app, db)` | [container.py](../../../server/bootstrap/container.py) | Construct mọi Model class một lần để trigger `_setup_indexes()` của từng model. |
| `initialize_container(app, socketio, db)` | [container.py](../../../server/bootstrap/container.py) | Trái tim DI: models → jwt_service → services → middleware init → controllers → blueprints (`url_prefix="/api"`). Gọi `run_startup_tasks(user_service, api_key_service)` (admin bootstrap theo env; API key bootstrap skipped) với config gate. |

### `server/routes/pages.py`

| Symbol | Vị trí | Mô tả |
|---|---|---|
| `register_page_routes(app)` | [pages.py:10](../../../server/routes/pages.py#L10) | Render HTML pages: `/`, `/agents`, `/groups`, `/groups/<id>`, `/whitelist`, `/logs`, `/api-keys`, `/login`, `/admin/users`, `/admin/audit`, `/profile`, `/admin/change-password` (redirect → `/profile`). Plus health: `/api/health`, `/api/config`. |

### `server/routes/errors.py`

| Symbol | Vị trí | Mô tả |
|---|---|---|
| `register_error_handlers(app)` | [errors.py](../../../server/routes/errors.py) | 404/500 → JSON nếu path bắt đầu `/api/`, ngược lại render `404.html`/`500.html`. |

### `server/routes/socketio_events.py`

| Symbol | Vị trí | Mô tả |
|---|---|---|
| `register_socketio_events(socketio)` | [socketio_events.py](../../../server/routes/socketio_events.py) | `connect`, `disconnect`, `ping`. |

### `server/middleware/csrf.py` (mới)

| Symbol | Vị trí | Mô tả |
|---|---|---|
| `register_csrf(app)` | [csrf.py](../../../server/middleware/csrf.py) | Cài before_request hook double-submit cookie. Mutating cookie-authed request phải gửi `X-CSRF-Token` matches cookie `csrf_token`. Bearer / X-API-Key / login / refresh path bypass. Test: `server/tests/test_csrf.py`. |

### `server/time_utils.py`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `VIETNAM_TZ` | `ZoneInfo("Asia/Ho_Chi_Minh")` | [time_utils.py:26](../../../server/time_utils.py#L26) | Constant |
| `FUTURE_DRIFT_TOLERANCE` | `timedelta(minutes=5)` | [time_utils.py:27](../../../server/time_utils.py#L27) | Ngưỡng "timestamp tương lai bất thường" |
| `now_vietnam()` | `() -> datetime` | [time_utils.py:33](../../../server/time_utils.py#L33) | `datetime.now(VIETNAM_TZ)` (aware) |
| `now_iso()` | `() -> str` | [time_utils.py:37](../../../server/time_utils.py#L37) | ISO 8601 VN |
| `to_vietnam(dt)` | `(Optional[datetime]) -> Optional[datetime]` | [time_utils.py:41](../../../server/time_utils.py#L41) | Naive → gắn tz VN. Aware → convert. None → None |
| `parse_agent_timestamp(value)` | `(Any) -> datetime` | [time_utils.py:123](../../../server/time_utils.py#L123) | **Sponge function**: nhận `datetime`/`int`/`float`/`str`. Hỗ trợ ISO + 3 format strftime. Bất kỳ giá trị nào không parse được → `now_vietnam()`. Áp dụng `_normalise_future_timestamp` để clamp |
| `format_datetime(value, fmt="%Y-%m-%d %H:%M:%S")` | `(Any, str) -> str` | [time_utils.py:164](../../../server/time_utils.py#L164) | None → `"N/A"`. Parse rồi strftime |
| `calculate_age_seconds(value)` | `(Any) -> float` | [time_utils.py:185](../../../server/time_utils.py#L185) | `(now_vietnam() - dt).total_seconds()` |
| `get_time_ago_string(value)` | `(Any) -> str` | [time_utils.py:195](../../../server/time_utils.py#L195) | `"5 minutes ago"` / `"2 hours ago"` / ... |
| `_normalise_future_timestamp(dt, reference=None)` | | [time_utils.py:53](../../../server/time_utils.py#L53) | **Quan trọng**: nếu `dt` xa hơn reference > 5 phút, thử trừ UTC offset (sửa double-conversion legacy bugs) hoặc clamp về reference. Log warning |
| `_parse_with_known_formats(value)` | | [time_utils.py:104](../../../server/time_utils.py#L104) | Fallback parse 3 format string |

## Ai gọi module này

`app.py`:
- Là entrypoint. Chạy bằng `python app.py` từ `server/`. Production thường wrap qua gunicorn/uvicorn nhưng repo này dùng `socketio.run` trực tiếp.

`bootstrap/*` và `routes/*`:
- Chỉ được `app_factory.create_app()` gọi. Test có thể import trực tiếp để mock.

`time_utils.py`:
- Mọi model, service, controller server-side - gần như **tất cả file `.py` trong `server/`**
- Tests import `now_vietnam` để dựng fixture

## Module này gọi ra
- `flask`, `flask_socketio`, `flask_cors`
- `pymongo` (gián tiếp qua `database.config`)
- `gevent.monkey` cho async (optional, fallback sang threading)
- stdlib `datetime`, `zoneinfo`

## Đã có sẵn - đừng viết lại
- Cần ISO timestamp gửi client? → `time_utils.now_iso()` - **đừng** dùng `datetime.now().isoformat()` (mất tz)
- Cần parse timestamp lạ (agent gửi format khác nhau)? → `parse_agent_timestamp(value)` - đã handle datetime/int/float/str ISO/strftime + clamp drift
- Cần format datetime cho template? → đã register filter `{{ dt|format_datetime }}` - không tự strftime
- Cần "5 minutes ago"? → `get_time_ago_string(value)`
- Cần Mongo db? → `database.config.get_database(config)` - **đừng** `MongoClient(...)` thẳng (xem [database.md](database.md))
- Cần auth header check? → middleware decorator (xem [middleware.md](middleware.md))
- Cần CSRF protect endpoint mới? → `register_csrf(app)` đã set global hook; không cần per-route. Nếu endpoint mới dùng Bearer/X-API-Key thay vì cookie, nó tự exempt.
- Cần lifecycle log entry chuẩn? → ở server log nhận agent record, không có helper riêng - agent có `build_lifecycle_log`

## Gotchas

### App bootstrap
- **Monkey patch ở `app.py:1-6` PHẢI là đầu tiên** - bất kỳ `import socket` nào trước đó (kể cả gián tiếp) sẽ làm `ssl` & `requests` chạy blocking. Đừng đặt logging/dotenv lên trên.
- **`_app_initialized` flag đã bỏ** sau refactor 2026-05-26. `create_app()` mỗi lần gọi luôn trả app đầy đủ blueprint; không còn nhánh "minimal app" lén lút thiếu route. Dev mode bật reloader tự xử lý qua `use_reloader=False` ở `socketio.run` (app.py:40).
- **Socket.IO fallback** (app_factory.py:19): nếu `gevent` thiếu trong Python env, `_create_socketio` log warning và fallback `threading`. App vẫn boot.
- **Startup mutation đã chuyển ra khỏi boot** (P0.3): `register_controllers` cũ chạy `whitelist_profile_model.collection.delete_many({"is_default": True})` mỗi lần boot. Đã gỡ — app boot phải idempotent, không sửa dữ liệu nghiệp vụ. Migration một lần: `server/scripts/migrations/2026_remove_default_profiles.py` (hỗ trợ `--dry-run`).
- **`run_startup_tasks` chỉ seed admin khi có `DEFAULT_ADMIN_USERNAME` + `DEFAULT_ADMIN_PASSWORD`**. API key không auto-tạo nữa, nên boot không còn dump plaintext key.
- **`gevent` async mode** trên SocketIO: tránh dùng blocking I/O trong controller - sẽ block toàn bộ worker. Nếu cần CPU-heavy, dùng `flask_executor` hoặc background task.
- **CORS allow `*`** (app_factory.py:73): chấp nhận mọi origin cho dev. Production nên restrict.
- **CSRF middleware** (app_factory.py:108 sau khi container init): mọi POST/PUT/PATCH/DELETE cookie-authed phải có `X-CSRF-Token` header matches cookie. Mới thêm middleware → chạy test_csrf.py để chắc không phá.
- **CSRF fetch shim cho legacy raw fetch** (`server/views/static/js/core/csrf-fetch-shim.js`): wrap `window.fetch` để tự attach `X-CSRF-Token` cho same-origin POST/PUT/PATCH/DELETE chưa có header. Tồn tại tạm thời vì 4 page script (`group_detail.js`, `whitelist.js`, `agents.js`, `logs.js`) còn ~40 raw `fetch()` chưa migrate sang `SaintAPI`. **Xóa shim khi migration xong**.

### Time utils
- **Server `time_utils.py` ≠ Agent `shared/time_utils.py`**: 2 file độc lập, có overlap chức năng (`now_vietnam`, `now_iso`, `parse_agent_timestamp`). Agent có thêm uptime, cache helpers; server có thêm `parse_agent_timestamp` lượng dữ liệu lớn hơn (handles datetime/int/float/str) + `format_datetime` + drift normalisation.
- **`parse_agent_timestamp` rất khoan dung**: input không hợp lệ → return `now_vietnam()`, không raise. Caller không phải try-except. Nhưng cũng nghĩa là silent data corruption nếu agent gửi sai format - kiểm log warning.
- **Drift normalisation logic**: timestamp > 5 phút tương lai → thử `dt - dt.utcoffset()` (sửa lỗi UTC convert 2 lần) → nếu vẫn lệch thì clamp về `reference_time`. Hiện hữu cho heartbeat của các agent legacy có bug timezone.
- **Default fallback `now_vietnam()` cho mọi unknown input** - không ý thức được sẽ overwrite ngầm. Nếu thấy log "Unrecognised timestamp" hay "ahead of reference", agent đang bug.
- **Format strftime 3 dạng** (`%Y-%m-%d %H:%M:%S.%f / %Y-%m-%d %H:%M:%S / %Y/%m/%d %H:%M:%S`): nếu format khác (DD/MM/YYYY) sẽ fail và rơi vào fallback `now_vietnam()`. Đừng thêm format mới bừa - agent phải gửi ISO.
- **Codec options `tz_aware=True, tzinfo=VIETNAM_TZ`** (database/config.py:24): mọi datetime đọc từ Mongo **đã gắn tz VN**. Đừng `to_vietnam()` lại trừ khi giá trị đến từ source khác (string từ JSON).

### Web routes
- **Dashboard stats fake 0** (pages.py:16-21): server-side template render `total_logs=0` để tránh leak global stats cho teacher trước khi JS fetch và áp RBAC filter. Đừng "fix" bằng cách pass stats thật vào template.
- **Page routes có cả pre-login pages** (`/login`) và **các page mà auth check do JS làm** (`/admin/users`, `/admin/audit`) - Flask không kiểm token. JS gọi `/api/admin/auth/me` rồi redirect nếu fail. Nếu user disable JS, trang vẫn render nhưng API call sẽ 401. Acceptable tradeoff cho SPA-lite.
- **Login form không cần CSRF token**: `/api/admin/auth/login` được exempt vì chưa có session để bảo vệ. Sau khi login thành công, server set cookie `csrf_token` (non-httpOnly) qua `set_csrf_cookie` và `SaintAPI` tự attach `X-CSRF-Token` cho mọi POST/PUT/PATCH/DELETE.
