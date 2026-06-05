# Architecture Review & Cleanup Plan

Ngày rà soát: 2026-05-26

Phạm vi: toàn bộ `server`, `agent`, `server/views/static`, `server/views/templates` và các tài liệu hiện có trong `report`.

Ghi chú: đây là rà soát kiến trúc ở mức source code. Báo cáo tập trung vào ranh giới module, duplicate, legacy/dead code, rủi ro vận hành và hướng refactor để hệ thống dễ bảo trì hơn.

## Cập nhật trạng thái sau refactor 2026-05-26

Phần review bên dưới giữ lại lịch sử phát hiện ban đầu. Trạng thái hiện tại sau các đợt sửa gần nhất:

## Cập nhật validation production 2026-05-28

Render full deep E2E run `20260528_141158` là baseline vận hành mới nhất: `24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0`, `cleanup_failures=0`, `CLEANUP_OK=43`. Run này đã xác nhận Server API/RBAC, GUI, Socket.IO, Agent register/JWT/heartbeat/sync/log, active profile sync, isolate heartbeat `force_sync=true`, synthetic classroom scale, service/autostart readiness, 30-minute soak và real Windows Firewall Default Deny với backend `powershell`/NetSecurity.

Các giới hạn chưa test thật sự vẫn còn: multi-machine vật lý trên nhiều máy Windows, reboot cycle thật, soak dài hơn 30 phút, canary firewall backend trên thêm máy lab, Render log audit/secret rotation và whitelist fallback/pseudo-ID cutover sau backup + migration production.

## Cập nhật API key rate limit 2026-06-01

Source audit xác nhận API key chưa có rate limit thật: không có dependency/middleware quota, không có window counter/token bucket, `validate_api_key` chỉ kiểm tra key và tăng `usage_count` trọn đời. UI Rate Limit trên `/api-keys` là false affordance nên đã bị gỡ. Nếu cần rate limit thật sau này, phải thiết kế backend enforcement trước rồi mới đưa control trở lại UI.

UI follow-up cùng ngày: Expiration trong modal Create API Key dùng lại shared custom select ở `base.js`. Dropdown giờ tự mở lên khi modal không đủ chỗ bên dưới và `.custom-options` có `max-height` + `overflow-y:auto`, nên giữ đúng style UI mà không còn bị Bootstrap modal cắt ở `7 days`.

## Cập nhật baseline source/docs 2026-06-05

Sau đợt cleanup whitelist legacy và cập nhật tài liệu flow, baseline hiện tại là:

| Hạng mục | Trạng thái hiện tại |
| --- | --- |
| Legacy whitelist domain service | `WhitelistService.get_all_domains()` và `WhitelistService.delete_domain()` đã bị xóa. Route tương thích `/api/whitelist` dùng `get_all_entries`; `DELETE /api/whitelist/<id>` dùng `bulk_delete_entries([id])`. |
| Whitelist merge flow | Global whitelist luôn được giữ; group whitelist của active profile được merge thêm và override duplicate cùng `type:value`; đổi profile sẽ thay group entries theo profile mới. |
| Whitelist URL handling | Full URL được canonicalize về hostname; wildcard chỉ áp dụng ở hostname pattern; DNS resolver không nhận URL/path/query/wildcard. |
| Local regression | `agent/tests + server/tests`: **576 passed, 22 warnings**. Warning còn lại là JWT test secret ngắn, không còn whitelist deprecation warning. |
| Whitelist regression | `server/tests/test_whitelist_and_logs.py`: **127 passed**; targeted whitelist flow suite: **170 passed**. |
| Flow documentation | Cập nhật `docs/reference/current-flows.md` và `report/2026-06-05_CURRENT_CODE_DOC_FLOW_AUDIT.md`. |

| Nhóm vấn đề | Trạng thái | Ghi chú hiện tại |
| --- | --- | --- |
| Audit IP luôn `127.0.0.1` | Đã xử lý | Thêm `server/utils/request_ip.py`; audit/auth/agent/log/whitelist dùng `get_client_ip()` với ưu tiên `X-Forwarded-For`, `X-Real-IP`, rồi `remote_addr`. |
| Profile Change Password bị trắng chữ khi không hover | Đã xử lý | `profile.html` dùng class riêng `profile-change-password-btn`; `profile.css` định nghĩa normal/hover/focus/disabled rõ ràng. |
| Token API/JWT qua query string | Đã xử lý | `middleware/auth.py` chỉ nhận query token khi `DEBUG_AUTH_QUERY_TOKEN=true`; default production/dev config là `False`. |
| Cookie secure hardcode `False` | Đã xử lý | `WebAuthController` đọc `ADMIN_COOKIE_SECURE` từ config/env; `ProductionConfig` default `True`. |
| Startup xóa legacy Default Profile mỗi lần boot | Đã xử lý | App boot không còn `delete_many({"is_default": True})`; cleanup được chuyển sang migration script `server/scripts/migrations/2026_remove_default_profiles.py`. |
| Audit update profile gọi sai method | Đã xử lý | `WebAuthController.update_profile` gọi `AuditService.log_action(...)`; đã có test bảo vệ. |
| Agent fallback về `http://localhost:5000` khi chưa cấu hình | Đã xử lý | Các component dùng `agent/shared/server_urls.py::collect_server_urls(config, allow_dev_default=False)`; first-run offline không tự gọi localhost. |
| Debug endpoint agent luôn register | Đã xử lý | Các route debug agent chỉ register khi `ENABLE_DEBUG_ENDPOINTS=True`. |
| `server/app.py` quá lớn | Đã xử lý | `server/app.py` là entrypoint mỏng; app factory/container/startup task/page/error/socketio route đã tách sang `server/bootstrap/` và `server/routes/`. |
| `_app_initialized` trả app minimal thiếu blueprint | Đã xử lý | Đã bỏ cơ chế `_app_initialized`; mỗi lần `create_app()` trả app đầy đủ route. |
| Socket.IO `gevent` làm app không khởi động khi dependency thiếu | Đã xử lý | `server/bootstrap/app_factory.py::_create_socketio(...)` thử async mode cấu hình trước; nếu backend không khả dụng (`Invalid async_mode`) thì fallback sang `threading` và log warning. Có test bảo vệ ở `server/tests/test_app_factory.py`. |
| Controller/service/middleware gọi trực tiếp Mongo `.collection` | Đã xử lý trong server app | `rg -n "\.collection\." server/controllers server/services server/middleware` không còn kết quả. Query/update trực tiếp đã chuyển xuống model methods. `require_group_ownership` dùng `GroupModel.find_by_id(...)` thay vì query collection trực tiếp. |
| Template/CSS change_password chết | Đã xử lý | File template/CSS riêng của trang change password đã bị xóa; route legacy `/admin/change-password` redirect về `/profile`. |
| Whitelist dual storage và pseudo-ID | Đã chuyển sang collection-first dual path | Thêm `WhitelistEntryModel`/collection `whitelist_entries` và migration `2026_migrate_group_whitelist_to_entries.py`. New group writes (`add_entry`, `bulk_add_entries`) ghi vào `whitelist_entries`, bump `groups.whitelist_version`, API/frontend nhận `_id` thật. Read path merge `whitelist_entries` + legacy `groups.whitelist[]` trong một release; collection row thắng khi trùng `type:value`. Pseudo-ID chỉ còn là fallback cho legacy embedded row chưa migrate/backfill. |
| RBAC duplicate giữa config và service | Đã xử lý | `RBACService.is_teacher_request()` (static) + `assert_group_access()` là single owner; controllers chỉ delegate. `rbac_config.py` chỉ còn permission matrix constants, không còn data-access logic. |
| Legacy whitelist domain APIs | Đang thu gọn | `get_all_domains` và `delete_domain` đã xóa khỏi `WhitelistService`; controller `/api/whitelist` dùng `get_all_entries`, `DELETE /api/whitelist/<id>` dùng `bulk_delete_entries([id])`. Các helper legacy còn lại: `add_domain`, `import_domains`, `export_domains`. |
| Agent singleton/lifecycle/netsh side effect | Lifecycle + firewall facade đã xử lý | `AgentRuntime` injectable giữ nguyên; lifecycle đã có `LifecycleContext`, `AgentComponent.start/stop/health`, `build_default_components`, `start_components`, `stop_components`. Firewall read/write đi qua `FirewallProvider`; write mặc định vẫn là `netsh` để giữ tương thích, có opt-in `FIREWALL_WRITE_BACKEND=powershell` cho NetSecurity. Backend PowerShell/NetSecurity đã pass full deep run `20260528_141158` trên một máy Windows Administrator; vẫn cần canary thêm máy lab trước khi đổi default rộng. `settings.py` delegate restore/clear qua `FirewallApplicationService` thay vì tự gọi netsh inline. |
| Frontend helper/JS/CSS duplicate | Đã xử lý (core layer + fetch migration + browser smoke) | `server/views/static/js/core/{api,toast,date,log,utils}.js` cung cấp shared `SaintAPI`, `SaintToast`, `SaintDate`, `SaintLog`, `SaintUtils`. Inline scripts trong `profile.html`, `api_keys.html`, `admin_audit.html`, `login.html` đã extract sang `static/js/pages/`. Admin page raw `fetch()` đã migrate sang `SaintAPI`; `rg "fetch\(" server/views/static/js` chỉ còn `core/api.js`, `error_500.js` health-check, và `pages/login.js` exempt. Đã thêm Playwright smoke suite cho login, dashboard/admin pages, profile change-password visual state, và CSRF header qua `SaintAPI`. |
| DNS resolver thread pool không shutdown ở cleanup | Đã xử lý | `WhitelistManager.cleanup()` gọi `OptimizedDNSResolver.shutdown()` và xóa reference; `agent/core/lifecycle.py::cleanup()` gọi `agent.whitelist.cleanup()` (đầy đủ teardown) thay vì chỉ `stop_sync()`. Ephemeral resolver trong `agent/firewall/manager.py::_resolve_domains_to_ips()` được wrap try/finally để shutdown ngay sau khi dùng. Qt `WhitelistView.closeEvent` shutdown DNS resolver nếu đã lazy-build. |
| CSRF cho admin web | Đã xử lý | Thêm `server/middleware/csrf.py` (double-submit cookie pattern). `register_csrf(app)` cài `before_request` hook. POST/PUT/PATCH/DELETE cookie-authed phải gửi header `X-CSRF-Token` matches cookie `csrf_token` (constant-time compare); bypass cho Bearer/X-API-Key/login/refresh path. `WebAuthController` mint cookie ở login, rotate ở refresh, xóa ở logout. `SaintAPI` tự đọc cookie và attach header. CORS đã allow `PATCH` và `X-CSRF-Token` trong `API_CORS_OPTIONS`. `ENFORCE_CSRF` toggle (default True; TestingConfig False). Test bảo vệ ở `server/tests/test_csrf.py` + `test_app_factory.py`. |
| Bare `except:` trong token_manager nuốt lỗi parse | Đã xử lý | 8 bare except ở `agent/core/token_manager.py` (lines 55/62/165/220/230/256/422/429 trước fix) đã đổi sang specific exception type (`ValueError`, `AttributeError`, `TypeError`, `OverflowError`) + `logger.warning(...)`/`debug(...)` có context. `rg "except:" agent/core/token_manager.py` không còn kết quả. |
| Bare/catch-all except ở firewall/dns/server models | Đã xử lý | `agent/firewall/manager.py:629` (hostname resolve) narrow xuống `socket.gaierror/herror` + log có exception type. `agent/network/dns_resolver.py:277` (IP fallback) narrow xuống `ValueError` + debug log. `server/models/agent_model.py:153` (ObjectId conversion trong `find_agent_ids_by_group_ids`) narrow xuống `bson.errors.InvalidId/TypeError` + debug log; cần import `bson.errors`. `server/models/group_model.py:185` (`find_by_id` — line 28 mà audit ban đầu báo thực tế là no-op branch, không phải swallow) narrow xuống `bson.errors.InvalidId/TypeError` + debug log. |
| Daemon thread mất events khi process thoát | Đã xử lý | `agent/logging_module/sender.py` đăng ký `atexit.register(self._atexit_flush)` khi `start()`; flush queue qua `_flush_queue()` trước khi daemon thread bị kill ở interpreter shutdown. `agent/services/heartbeat.py` đăng ký `atexit.register(self._atexit_stop)` để flip `_running=False` đánh thức interruptible sleep — heartbeat idempotent nên không cần flush. Cờ `_atexit_registered` chặn đăng ký 2 lần. |
| Token refresh callback không có error boundary | Đã xử lý | Dispatcher trong `TokenManager._do_refresh` và `_trigger_reregistration` đã wrap try/except cho `_on_token_refreshed`/`_on_token_expired`. Bổ sung defense-in-depth: `agent/core/lifecycle.py::on_token_expired` chia làm 3 step (`register_agent` → `reset_reregistration_flag` → `_load_tokens_from_config`) mỗi step có try/except riêng, tránh trạng thái half-applied nếu một bước raise. |
| Lifecycle `initialize_components` quá lớn | Đã xử lý bằng component contract | `agent/core/lifecycle.py` giữ helper cũ để giảm blast radius, nhưng orchestration chính đi qua `AgentComponent` stack. Start theo thứ tự registration → token → whitelist → firewall → log sender → heartbeat → packet sniffer; cleanup stop ngược. `start_components(...)` cleanup phần đã start nếu một component raise hoặc record `STATUS_FAILED`. |
| `AGENT_DEVICE_ID` import eager qua PEP 562 | Đã xử lý | Audit ban đầu báo file đã "Đã giảm rủi ro" — sai. `from .agent import AGENT_DEVICE_ID` ở module level KÍCH HOẠT `__getattr__` PEP 562 ngay tại thời điểm import (PEP 562 fires on lookup, không phải attribute access sau đó), nên `registry.py:12` và `handlers.py:6` cũ vẫn chạy PowerShell ở import time. Đã đổi sang `from .agent import DeviceIdentityProvider` và resolve giá trị qua `DeviceIdentityProvider.get_device_id()` / `.get_hostname()` tại call site. Static check trên `core/registry.py` và `core/handlers.py` top-level confirmed clean. |
| Heartbeat / log sender retry không có backoff | Đã xử lý | `agent/services/heartbeat.py::_backoff_seconds()` capped exponential backoff với full jitter (recipe AWS Architecture Blog) — `random.uniform(0, min(cap, base * 2**n))`. Config: `heartbeat.retry_interval` (base) và `heartbeat.max_retry_interval` (cap, default 300s). Reset implicit khi `_consecutive_failures=0` ở success. `agent/logging_module/sender.py::_record_send_failure()` / `_record_send_success()` cùng pattern; gate `_next_send_allowed_at` chặn `_sender_loop` send sớm. Config: `send_interval` (base) và `max_retry_interval` (cap, default 300s). Fleet không còn thunder khi server xuống. |
| Frontend `console.log` debug rò production | Đã xử lý | Thêm `server/views/static/js/core/log.js::SaintLog` — `debug/info` chỉ in khi `window.__SAINT_DEBUG__===true`; `warn/error` luôn in. `base.html` load file core mới. Toàn bộ `console.log(` trong `agents.js`, `dashboard.js`, `group_detail.js`, `groups.js`, `logs.js`, `whitelist.js` đã đổi sang `SaintLog.debug(`. Còn 1 `console.log` ở `error_404.js` (fallback offline) và 2 ở `core/log.js` (intentional). |
| Stale TODO/FIXME comments | Đã xử lý | `server/views/static/js/groups.js::bulkSyncWhitelist` — bỏ TODO, thay bằng comment giải thích server đã tự push qua heartbeat force_sync; toast đổi "Agents will sync on next heartbeat (≤20s)". `server/views/templates/whitelist.html` — bỏ 3 `<!-- FIX: ... -->` không còn relevant. `server/views/static/js/whitelist.js::handleApiResponse` — bỏ `// FIX: ...` (đã handle thực tế). |
| API key `created_by` hardcode "admin" | Đã xử lý | `server/controllers/api_key_controller.py` thêm helper `_current_actor()` đọc `g.current_user.username` (fallback `current_user_id` → `"unknown"`). `create_api_key`, `update_api_key`, `revoke_api_key` đều dùng helper thay cho hardcode "admin". |
| Doc link lệch sau bootstrap split | Đã xử lý | `docs/reference/server/app.md` viết lại — bảng API liệt kê `app.py` (entrypoint), `bootstrap/app_factory.py::create_app/_create_socketio`, `bootstrap/container.py::initialize_container`, `routes/pages.py::register_page_routes`, `routes/errors.py`, `routes/socketio_events.py`, `middleware/csrf.py::register_csrf` với link đúng tới file/line hiện tại. Thêm note CSRF middleware vào Gotchas. |
| Agent config file permission | Đã xử lý | `agent/config/crypto.py::restrict_to_owner(path)` — POSIX `chmod 0o600`; Windows `icacls /inheritance:r /grant:r "<user>:F"` (drop "Users" group, giữ SYSTEM/Administrators cho service manager). `encrypt_config()` gọi `restrict_to_owner(enc_path)` ngay sau `write_bytes`. Best-effort, never raises (icacls timeout / missing / OSError đều log debug và bỏ qua). |
| Whitelist sync không phân loại lỗi | Đã xử lý | `agent/whitelist/sync.py` thêm constants `ERROR_OFFLINE/AUTH/NETWORK/SERVER/CLIENT/UNKNOWN`. `sync_with_server` trả thêm field `category` trong result dict (cùng với `success`/`error`/`data`). 401/403 → ERROR_AUTH (skip retry + skip fallback servers vì cùng token sẽ fail tiếp). 5xx → ERROR_SERVER. Timeout/ConnectionError → ERROR_NETWORK. JSON decode fail → ERROR_SERVER. Caller có thể decide retry/re-register/UI prompt mà không string-match `error`. |

### Verification đã chạy

- `rg -n "\.collection\." server/controllers server/services server/middleware` → không còn kết quả.
- `git diff --check` → pass cho các file đã chạm, chỉ còn cảnh báo CRLF theo cấu hình hiện tại.
- `python -m py_compile` trên các file server refactor → pass.
- `python -m py_compile server\models\group_model.py server\services\whitelist_service.py agent\core\lifecycle.py server\tests\test_groups.py server\tests\test_whitelist_and_logs.py server\tests\test_teacher_data_filtering.py` → pass.
- `pytest server\tests\test_groups.py::TestGroupModel::test_model_update_group_whitelist_normalizes_string_id server\tests\test_groups.py::TestGroupModel::test_model_update_group_whitelist_stamps_missing_id server\tests\test_whitelist_and_logs.py::TestWhitelistService::test_delete_domain_accepts_real_embedded_object_id server\tests\test_whitelist_and_logs.py::TestWhitelistService::test_bulk_add_entries_tolerates_legacy_string_group_whitelist server\tests\test_teacher_data_filtering.py::TestWhitelistServiceTeacherEntryAccess -q --tb=short` → 6 passed, 1 expected `DeprecationWarning`.
- `pytest server\tests\test_groups.py server\tests\test_whitelist_and_logs.py server\tests\test_teacher_data_filtering.py -q --tb=short` → 260 passed, 3 expected `DeprecationWarning`.
- Smoke `from app import create_app`, gọi `create_app()` nhiều lần và `/api/health` → pass.
- `pytest server/tests/test_groups.py -q -x --tb=short` → 70 passed.
- `pytest server/tests/test_teacher_data_filtering.py -q -x --tb=short` → 75 passed.
- `pytest server/tests/test_whitelist_and_logs.py -q -x --tb=short` → 109 passed.
- `pytest server/tests/test_request_ip.py server/tests/test_audit.py server/tests/test_users_auth.py::TestAdminAuthController -q -x --tb=short` → 44 passed.
- `pytest server/tests/ -q --tb=line` (đầy đủ sau refactor whitelist + AgentRuntime + frontend core) → **497 passed, 0 failed, 22 warnings** ở mốc refactor trước.
- `pytest server\tests -q --tb=short` sau khi khép các lỗ whitelist ObjectId/RBAC, lifecycle lazy identity và Socket.IO fallback → **505 passed, 0 failed, 23 warnings**. Warnings gồm `DeprecationWarning` chủ ý từ legacy `*_domain` API và `InsecureKeyLengthWarning` trong test JWT dùng secret ngắn.
- `python scripts\migrations\2026_backfill_group_whitelist_entry_ids.py --dry-run` trên DB đang cấu hình → pass; `scanned_groups=0`, `scanned_entries=0`, `updated_groups=0`, `new_ids_assigned=0`, `ids_normalized=0`, không cần chạy write migration ở trạng thái hiện tại.
- Flask test-client smoke sau app factory fallback → `/api/health`, `/api/config`, `/profile`, `/admin/audit`, `/groups`, `/whitelist` trả 200; `/admin/change-password` trả 302 về `/profile`; Socket.IO chạy bằng `threading` khi `gevent` chưa có trong Python env.
- `pytest server\tests\test_app_factory.py -q --tb=short` → 3 passed sau khi thêm check CORS `PATCH` + `X-CSRF-Token`.
- Sau bản vá 2026-05-27 nhỏ: CORS allow `PATCH` + `X-CSRF-Token`, `middleware/rbac.py` không còn direct `.collection`, `APIKeyService` fallback actor không còn `"admin"` giả. `python -m py_compile server\bootstrap\app_factory.py server\middleware\rbac.py server\services\api_key_service.py server\tests\test_app_factory.py server\tests\test_teacher_data_filtering.py` → pass. `pytest server\tests\test_app_factory.py server\tests\test_teacher_data_filtering.py::TestRBACMiddlewareGroupOwnership -q --tb=short` → **4 passed**. `rg -n "\.collection\." server\controllers server\services server\middleware` → không còn kết quả. `pytest server\tests\test_app_factory.py server\tests\test_csrf.py server\tests\test_teacher_data_filtering.py server\tests\test_users_auth.py -q --tb=short` → **180 passed, 20 warnings**.
- Full server regression sau các bản vá trên: `pytest server\tests -q --tb=short` → **519 passed, 0 failed, 23 warnings**.
- Sau bản vá DNS resolver shutdown + CSRF middleware (2026-05-26 batch P0): `python -m py_compile` toàn bộ file đã chạm → pass. `pytest server\tests\test_csrf.py -q --tb=short` → **12 passed**. `pytest server\tests -q --tb=line` đầy đủ sau khi thêm CSRF → **517 passed, 0 failed, 23 warnings** (tăng +12 so với baseline 505 nhờ test_csrf.py).
- Sau bản vá P1 (bare except + atexit + callback error boundary, 2026-05-26 batch P1): `rg "except:" agent/core/token_manager.py` → 0 kết quả. `python -m py_compile` cho `agent/core/token_manager.py`, `agent/core/lifecycle.py`, `agent/firewall/manager.py`, `agent/network/dns_resolver.py`, `agent/logging_module/sender.py`, `agent/services/heartbeat.py`, `server/models/agent_model.py`, `server/models/group_model.py` → pass. `pytest server\tests\test_groups.py server\tests\test_agents.py server\tests\test_app_factory.py server\tests\test_csrf.py -q --tb=short` → **144 passed** (regression cho file đã chạm phía server).
- Sau bản vá P2 (lifecycle helper split + backoff + lazy AGENT_DEVICE_ID + frontend SaintLog + api_key_controller actor + crypto restrict_to_owner + sync error category + TODO cleanup + docs/app.md rewrite + CSRF fetch shim, 2026-05-27 batch P2): `python -m py_compile` cho `agent/core/lifecycle.py` (orchestrator + 9 `_init_*` helpers), `agent/core/registry.py`, `agent/core/handlers.py`, `agent/services/heartbeat.py`, `agent/logging_module/sender.py`, `agent/config/crypto.py`, `agent/whitelist/sync.py`, `server/controllers/api_key_controller.py` → pass. Static check: top-level của `core/registry.py` và `core/handlers.py` không còn eager-import `AGENT_DEVICE_ID`/`AGENT_HOSTNAME` (PEP 562 lookup chỉ chạy khi caller thực sự cần giá trị). `pytest server\tests\test_app_factory.py test_csrf.py test_groups.py test_agents.py -q --tb=short` → **144 passed** (regression chính sau khi đụng `api_key_controller`). Thêm `csrf-fetch-shim.js` bridge cho ~40 raw `fetch()` còn lại — wrap `window.fetch` injects `X-CSRF-Token` same-origin unsafe-method requests; idempotent; không overwrite header explicit; load sau `core/api.js` và trước page scripts.
- Sau bản vá P3 + frontend fetch migration (2026-05-27 batch P3): **Hoàn tất migration raw `fetch()` → `SaintAPI`** cho toàn bộ admin pages (`logs.js`, `agents.js`, `group_detail.js`, `whitelist.js`, `groups.js`, `dashboard.js`, `admin_users.js`, `base.js`, `auth.js`). `rg "fetch\(" server/views/static/js` chỉ còn `core/api.js` (chính SaintAPI), `error_500.js` (GET health-check), `pages/login.js` (exempt path — chưa có session). **Đã xóa `csrf-fetch-shim.js`** + dòng load trong `base.html` vì không còn raw unsafe-method fetch nào. P3: `escHtml`/`escapeHtml`/`wlEscapeHtml` gom về `core/utils.js::SaintUtils.escapeHtml` (6 call site delegate qua shim); accessibility `for=profileSelect` + `aria-label`/`aria-hidden` cho inline agent buttons; legacy `*_domain` API có `LEGACY_DOMAIN_API_REMOVAL="2026-Q4"` trong text DeprecationWarning; xóa `install.ps1` (Understand-Anything installer, untracked, không thuộc project). `python -m py_compile server/services/whitelist_service.py` → pass. `pytest server\tests\test_csrf.py test_whitelist_and_logs.py test_app_factory.py -q --tb=short` → **125 passed** (DeprecationWarning hiển thị text mới với ngày xóa dự kiến).
- Sau bản vá Playwright smoke (2026-05-27): thêm `package.json`, `playwright.config.js`, `tools/e2e-server.js`, và `tests/e2e/saint-admin-smoke.spec.js`. Suite login bằng admin local, kiểm tra shared core globals, mở 9 page admin chính, assert nút `#changeBtn` không bị trắng ở normal state, và gọi POST `/api/api-keys/validate` qua `SaintAPI` để verify `X-CSRF-Token`. `npm.cmd run e2e` → **4 passed**.
- Sau bản vá Agent lifecycle component + whitelist_entries collection-first (2026-05-27): `python -m py_compile` cho `agent/core/{agent,lifecycle,__init__}.py`, `agent/tests/test_lifecycle_components.py`, `server/models/whitelist_entry_model.py`, `server/services/whitelist_service.py`, `server/bootstrap/container.py`, migration script mới, và `server/tests/test_whitelist_and_logs.py` → pass. `rg -n "\.collection\." server/controllers server/services server/middleware` → không còn kết quả. `git diff --check` → pass, chỉ có cảnh báo CRLF theo config hiện tại. `pytest agent\tests\test_lifecycle_components.py -q --tb=short` → **3 passed**. `pytest server\tests\test_whitelist_and_logs.py -q -x --tb=short` → **115 passed, 3 expected DeprecationWarning**. `pytest server\tests\test_groups.py server\tests\test_teacher_data_filtering.py server\tests\test_app_factory.py -q -x --tb=short` → **153 passed**. `python server\scripts\migrations\2026_migrate_group_whitelist_to_entries.py` dry-run → `groups_scanned=0`, `embedded_entries_scanned=0`, `entries_inserted=0`, `dry_run=True`.
- Sau bản vá firewall write-provider facade + GUI settings service (2026-05-27): `RulesManager`/`PolicyManager` nhận `write_provider`, `NetshFirewallProvider` và `NetSecurityFirewallProvider` đều implement write API, `FirewallApplicationService` là facade cho GUI restore/clear. `agent/tests/test_firewall_provider_writes.py` cover create/delete/clear rule delegation, restore policy delegation, và GUI service path. `python -m py_compile` cho firewall/service/test files → pass. `pytest agent\tests -q --tb=short` → **6 passed**. `pytest server\tests\test_whitelist_and_logs.py -q -x --tb=short` → **115 passed, 3 expected DeprecationWarning**. `rg -n "\.collection\." server\controllers server\services server\middleware` → không còn kết quả. `git diff --check` → pass, chỉ có cảnh báo CRLF theo config hiện tại.
- Sau bản vá runbook cutover (2026-05-27): thêm `docs/runbooks/whitelist-firewall-cutover.md`; migration `2026_migrate_group_whitelist_to_entries.py` có `--json`, `--fail-on-invalid`, và sample `invalid_entries`; `WhitelistService` log marker `legacy_group_pseudo_id_used` khi còn caller dùng pseudo-ID. Test mới cover logging cho bulk delete/update pseudo-ID.

## Vẫn deferred (cần điều kiện riêng để verify an toàn)

| Item | Vì sao chưa làm | Điều kiện để làm |
| --- | --- | --- |
| Whitelist final cleanup: xóa fallback embedded/pseudo-ID sau migration | Code đã collection-first và có migration script, nhưng xóa fallback là operational cutover phụ thuộc dữ liệu staging/production. Hiện đã có log marker để đo usage. | Chạy `2026_backfill_group_whitelist_entry_ids.py --write` nếu còn row thiếu `_id`, chạy `2026_migrate_group_whitelist_to_entries.py --write --json --fail-on-invalid` trên staging/production, verify logs không còn `legacy_group_pseudo_id_used`, rồi mới xóa fallback trong release sau. |
| Agent lifecycle production smoke | Component contract đã implement và có fake-component tests, nhưng chưa có smoke trên agent thật/GUI Qt trong môi trường Windows admin. | Khi có máy test, chạy start/cleanup agent thật, verify firewall/whitelist/log/heartbeat/sniffer đều start/stop sạch và GUI vẫn render trạng thái đúng. |
| Firewall write-side PowerShell cutover | Write path đã đi qua provider chung và NetSecurity write API đã có, nhưng default vẫn là `netsh` để giữ behavior cũ. Chưa nên bật PowerShell mặc định khi chưa verify elevation/idempotency trên agent thật. | Windows host + admin + agent thật: bật `FIREWALL_WRITE_BACKEND=powershell`, start whitelist_only, confirm rules/policy tạo đúng, restart agent, restore snapshot, verify không lock mạng. |

### Đã hoàn tất (trước đây deferred)

- **Bulk `fetch()` → `SaintAPI` migration (mục #17)**: ĐÃ XONG ở batch P3 (2026-05-27). Toàn bộ raw `fetch()` trong admin pages (`logs.js`, `agents.js`, `group_detail.js`, `whitelist.js`, `groups.js`, `dashboard.js`, `admin_users.js`, `base.js`, `auth.js`) đã chuyển sang `SaintAPI.get/post/put/patch/del`. Blob/special-case dùng `SaintAPI.raw`. `csrf-fetch-shim.js` đã bị xóa (không còn raw unsafe-method fetch). Raw fetch còn lại chỉ ở `core/api.js` (SaintAPI nội bộ), `error_500.js` (GET health-check), `pages/login.js` (exempt path).
- **Playwright/browser smoke golden path**: ĐÃ XONG (2026-05-27). `tests/e2e/saint-admin-smoke.spec.js` cover login, dashboard/shared core, agents/groups/whitelist/logs/api-keys/users/audit/profile render, profile change-password normal style, và unsafe POST qua `SaintAPI` có CSRF token. `npm.cmd run e2e` → **4 passed**.
- **Agent lifecycle `Component.start/stop/health`**: ĐÃ XONG (2026-05-27). `LifecycleContext`, `AgentComponent`, production components, `start_components`, `stop_components` đã có; `initialize_components`/`cleanup` vẫn giữ public API cũ. `agent/tests/test_lifecycle_components.py` cover start order, reverse stop, start failure cleanup, và component-reported failure cleanup.
- **Firewall write-provider facade + GUI settings cleanup**: ĐÃ XONG (2026-05-27). `RulesManager` và `PolicyManager` không gọi write command trực tiếp nữa mà delegate qua `FirewallProvider` write API. Default write backend là `netsh`; `FIREWALL_WRITE_BACKEND=powershell` opt-in sang NetSecurity. `SettingsView._manual_restore()` gọi `FirewallApplicationService`, không còn tự restore policy/xóa SAINT rules bằng netsh inline. Unit tests dùng fake provider, không cần quyền admin.

Hệ thống đã có chia lớp `models / services / controllers` và agent cũng đã tách tương đối rõ `core / firewall / whitelist / gui_qt`. Sau refactor 2026-05-26, hai vấn đề server lớn nhất đã giảm rủi ro đáng kể (`server/app.py` đã tách, direct `.collection` ngoài model đã dọn). Các vấn đề kiến trúc cần theo dõi gồm:

1. `server/app.py` từng là "composition root" quá lớn; hiện đã tách sang `server/bootstrap/` và `server/routes/`, cần tiếp tục giữ entrypoint mỏng khi thêm feature mới.
2. Ranh giới `controller -> service -> model` từng bị phá bởi direct `.collection`; hiện đã dọn khỏi controller/service, cần giữ quality gate để tránh tái phát.
3. Whitelist có 2 mô hình dữ liệu song song: global whitelist trong collection riêng, group whitelist nhúng trong document group. Điều này tạo pseudo-ID, nhiều nhánh xử lý đặc biệt, và làm bulk/update/delete phức tạp không cần thiết.
4. Agent có nhiều singleton/global và lifecycle quá nhiều side effect: device id được generate khi import, controller là singleton, lifecycle start/stop toàn bộ component trong một file lớn.
5. Frontend đang lặp lại nhiều helper: `fetch`, toast, date formatting, table render, filter/export. Một số template còn chứa inline JS lớn, khó test và dễ tạo bug CSS/JS chéo.

## Mức ưu tiên

### P0 - Cần sửa sớm vì có thể gây lỗi bảo mật/vận hành

#### 1. API key và JWT vẫn được nhận qua query string — Đã xử lý bằng config gate

Trạng thái hiện tại:

- `server/middleware/auth.py` chỉ lấy API key/JWT từ query parameter khi `DEBUG_AUTH_QUERY_TOKEN=true`.
- Default config để `DEBUG_AUTH_QUERY_TOKEN=False`; production không nhận token qua URL.

Rủi ro ban đầu:

- Token trong URL dễ lọt vào browser history, proxy log, server log, referer header.
- Token query string chỉ còn là dev-only escape hatch có log warning.

Hướng sửa đã áp dụng:

- Chỉ cho phép token qua `Authorization` header hoặc httpOnly cookie với admin web.
- Nếu thật sự cần debug, bọc bằng `config.DEBUG_AUTH_QUERY_TOKEN == True`, default `False`.
- Thêm test đảm bảo production config không nhận token từ query string.

#### 2. Cookie secure đang hardcode `False` — Đã xử lý bằng `ADMIN_COOKIE_SECURE`

Trạng thái hiện tại:

- `server/controllers/web_auth_controller.py` đọc `ADMIN_COOKIE_SECURE` từ config/env ở request time.
- `server/controllers/admin_auth_controller.py` chỉ còn là shim compatibility cho `WebAuthController`.

Rủi ro ban đầu:

- Khi deploy HTTPS, cookie auth vẫn có thể gửi qua HTTP nếu app/proxy cấu hình sai.

Hướng sửa đã áp dụng:

- Đưa vào config: `SESSION_COOKIE_SECURE` hoặc `ADMIN_COOKIE_SECURE`.
- Local dev có thể `False`, production phải `True`.
- Cùng lúc cấu hình `SameSite` theo môi trường nếu frontend/API khác domain.

#### 3. `server/app.py` xóa legacy Default Profile ở mỗi lần startup — Đã chuyển sang migration

Trạng thái hiện tại:

- `server/app.py` không còn mutate dữ liệu nghiệp vụ khi boot.
- Cleanup legacy Default Profile nằm trong migration script `server/scripts/migrations/2026_remove_default_profiles.py`.

Rủi ro ban đầu:

- Startup app không nên tự ý mutate dữ liệu nghiệp vụ ngoài migration có version.
- Nếu logic "Default Profile" còn được code cũ hoặc test dùng lại, dữ liệu bị xóa âm thầm.

Hướng sửa đã áp dụng:

- Chuyển thành migration script có id/version rõ ràng.
- Ghi audit/migration log khi chạy.
- Chỉ chạy một lần, có rollback hoặc backup nếu là dữ liệu người dùng.

#### 4. Audit khi update profile đang gọi sai method — Đã xử lý

Trạng thái hiện tại:

- `server/controllers/web_auth_controller.py::update_profile` gọi `self.auth_service.audit_service.log_action(...)`.
- `AuditService` vẫn giữ API canonical `log_action(...)`.

Rủi ro ban đầu:

- Profile update vẫn thành công nhưng audit bị lỗi và chỉ bị catch/log.
- Admin audit có thể thiếu hành động quan trọng.

Hướng sửa đã áp dụng:

- Đổi sang `log_action(...)` hoặc thêm adapter method có cùng contract.
- Thêm test cho `PUT /api/admin/auth/profile` để đảm bảo audit entry được tạo.

#### 5. Agent fallback về `http://localhost:5000` không thống nhất với first-run offline mode — Đã xử lý

Trạng thái hiện tại:

- `agent/shared/server_urls.py::collect_server_urls(config, allow_dev_default=False)` là helper chung.
- `agent/whitelist/manager.py`, `agent/services/heartbeat.py`, `agent/logging_module/sender.py`, `agent/core/registry.py` đều dùng helper này và không fallback localhost khi chưa cấu hình.

Rủi ro ban đầu:

- Cùng một trạng thái "chưa cấu hình server" nhưng các component hành xử khác nhau.
- Có thể tạo kết nối ngoài ý muốn hoặc gây log lỗi nhiễu trong môi trường production.

Hướng sửa đã áp dụng:

- Chuẩn hóa một hàm `collect_server_urls(config, allow_dev_default=False)`.
- Default production: không có URL thì component ở trạng thái offline/skipped.
- Chỉ dùng `localhost:5000` khi config dev bật rõ ràng.

### P1 - Nên sửa để kiến trúc vững và giảm bug

#### 6. `server/app.py` đang ôm quá nhiều trách nhiệm — Đã xử lý trong refactor 2026-05-26

Dấu hiệu ban đầu:

- `create_app()` xử lý config, CORS, SocketIO, DB, index, controller registration.
- `register_controllers()` tạo toàn bộ model/service/controller, seed admin, tạo default API key, cleanup legacy data.
- `register_main_routes()` chứa toàn bộ page route.
- `_app_initialized` nếu đã initialized thì trả về một minimal app khác.

Rủi ro ban đầu:

- Khó test app factory theo từng phần.
- App reloader hoặc import nhiều lần có thể nhận app thiếu blueprint nếu rơi vào nhánh minimal.
- Startup side effect quá nhiều: seed admin, default API key, cleanup data, log route.

Hướng sửa đã áp dụng:

- Tách thành:
  - `server/bootstrap/app_factory.py`: tạo Flask app, CORS, SocketIO.
  - `server/bootstrap/container.py`: tạo model/service/controller.
  - `server/routes/pages.py`: page routes.
  - `server/bootstrap/startup_tasks.py`: seed/migration có config gate.
- Bỏ `_app_initialized` hoặc thay bằng app factory idempotent không trả app thiếu route.

#### 7. Controller/service gọi thẳng Mongo collection — Đã xử lý trong refactor 2026-05-26

Dấu hiệu ban đầu:

- `server/controllers/whitelist_controller.py` gọi `self.model.collection.find_one(...)`.
- `server/services/rbac_service.py` gọi `group_model.collection.find(...)`, `agent_model.collection.find(...)`.
- `server/services/group_service.py` gọi `self.model.collection.find_one(...)` và `self.agent_model.collection.update_many(...)`.
- `server/services/whitelist_service.py` gọi `self.model.collection.find(...)`, `update_one(...)`.
- `server/services/whitelist_profile_service.py` gọi `self.model.collection.find(...)`.

Rủi ro ban đầu:

- Model/repository không còn là điểm kiểm soát duy nhất cho schema, index, serialization.
- Business rule bị lặp ở controller và service, ví dụ RBAC ownership check nằm trong whitelist controller.
- Test phải mock Mongo trực tiếp nhiều hơn, khó thay đổi schema.

Trạng thái 2026-05-27: đã xử lý trong phạm vi `server/controllers`, `server/services` và `server/middleware`; static guard `rg -n "\.collection\." server/controllers server/services server/middleware` không còn kết quả. Bản vá cuối cùng dọn `middleware/rbac.py::require_group_ownership` khỏi `group_model.collection.find_one(...)`, chuyển sang `GroupModel.find_by_id(...)`.

Hướng sửa đã áp dụng:

- Quy tắc mới: chỉ repository/model được gọi `collection`.
- Service nhận repository/model method có nghĩa nghiệp vụ: `find_entries_for_scope`, `bulk_delete_by_ids`, `find_group_owned_entry`.
- Controller chỉ parse request, gọi service, trả response.
- Thêm `rg ".collection"` vào quality gate để phát hiện truy cập sai tầng.

#### 8. Whitelist đang có 2 nguồn dữ liệu song song — Đã giảm rủi ro (rollout giai đoạn 1)

Dấu hiệu ban đầu:

- Global whitelist nằm trong `whitelist` collection.
- Group whitelist nằm trong `groups.whitelist`.
- Service phải tạo ID dạng `group::<group_id>::<type>::<value>`.
- `WhitelistService.bulk_delete_entries`, `update_entry`, `_update_group_entry`, `_delete_group_entry` đều có nhánh xử lý pseudo-ID.

Trạng thái 2026-05-26:

- Pseudo-ID format đã centralised ở `server/services/whitelist_entry_id.py` (`make_group_pseudo_id`, `parse_group_pseudo_id`, `is_group_pseudo_id`). Trước đây format được tái implement ở 4+ chỗ.
- New embedded entries qua `bulk_add_entries` được stamp `ObjectId()` thật từ service.
- `GroupModel.create_group` normalises mọi whitelist seed passed in: dict không `_id` → stamp; bare string → promote sang dict + stamp.
- `GroupModel.update_group` cũng normalises `groups.whitelist[]`: `_id` string từ frontend được convert lại thành `ObjectId`, entry mới không `_id` được stamp, legacy bare string được promote sang dict. Điểm này chặn lỗi PATCH group vô tình lưu `_id` dạng string khiến dotted-path query `whitelist._id` không match.
- `_normalize_group_entries` trong serializer ưu tiên trả `_id` thật cho frontend; chỉ fallback sang pseudo-ID khi entry chưa migrated.
- `WhitelistService._update_group_entry` + `_delete_group_entry_by_oid` accept cả pseudo-ID lẫn real ObjectId. `delete_entry` thử global collection → embedded by ObjectId trước khi báo not-found.
- `DELETE /api/whitelist/<id>` vẫn là route tương thích cho UI, nhưng controller hiện gọi `WhitelistService.bulk_delete_entries([id])`. `WhitelistService.delete_domain(...)` đã bị xóa.
- `WhitelistService.validate_teacher_entry_access(...)` đã check real embedded ObjectId bằng `GroupModel.find_group_with_embedded_entry(oid)` sau khi không tìm thấy collection entry. Teacher không còn bypass được RBAC bằng cách gửi `_id` thật của embedded entry thuộc group khác.
- `bulk_add_entries` tolerate legacy `groups.whitelist[]` dạng bare string khi check duplicate, tránh crash trong dữ liệu chưa backfill.
- `GroupModel.find_group_with_embedded_entry(oid)` query bằng dotted-path `whitelist._id`.
- Migration script `server/scripts/migrations/2026_backfill_group_whitelist_entry_ids.py` stamps `_id` lên embedded rows cũ; có `--dry-run`.
- 5 legacy method `*_domain` emit `DeprecationWarning`.

Vì sao chưa fully resolved:

- Cap nhat 2026-05-27: bước move sang collection đã có foundation và write path. `WhitelistEntryModel` quản lý `whitelist_entries`; `WhitelistService` ghi group entry mới vào collection, read path merge collection + embedded fallback, update/delete dùng real `_id` collection. Migration `2026_migrate_group_whitelist_to_entries.py` copy embedded rows sang collection và giữ `legacy_embedded_id`.
- Frontend/API hiện nhận `_id` thật cho group entry mới; pseudo-ID chỉ còn compatibility fallback cho embedded row chưa migrate/backfill.
- Chưa nên xóa fallback embedded/pseudo-ID ngay trong release này vì cần chạy migration write trên staging/production và xác nhận không còn legacy client.

Hướng sửa tốt nhất:

- Collection thống nhất `whitelist_entries` đã được tạo cho group scope:
  - `_id`
  - `scope`: `global | group | profile`
  - `group_id`
  - `profile_id`
  - `type`
  - `value`
  - `is_active`
  - `created_by`, `created_at`, `updated_at`
  - `version`
- Group/profile chỉ lưu metadata, không nhúng list whitelist lớn.
- API trả `_id` thật cho mọi entry, bỏ pseudo-ID.
- Migration:
  1. copy `groups.whitelist` sang collection mới;
  2. dual-read ngắn hạn;
  3. đổi frontend dùng `_id`;
  4. bỏ field `groups.whitelist` sau khi test pass.

#### 9. RBAC đang duplicate logic trong service và config

Dấu hiệu:

- `server/config/rbac_config.py` có `can_access_group`.
- `server/services/rbac_service.py` cũng có `can_access_group`.
- Logic teacher access lặp lại ở nhiều hàm: `teacher_ids` hoặc legacy `created_by`.

Vì sao chưa hợp lý:

- Khi rule phân quyền đổi, dễ sửa thiếu một chỗ.
- Một số controller tự kiểm ownership nên càng dễ lệch.

Hướng sửa:

- Giữ `RBACService` làm nơi duy nhất quyết định data access.
- `rbac_config.py` chỉ nên chứa constant permission/role matrix, không query/business rule.
- Tạo method dùng chung:
  - `group_access_filter(user)`
  - `assert_group_access(user, group_id)`
  - `filter_owned_entry_query(user, scope, group_id)`

#### 10. Auth stack agent/admin bị đặt tên và contract dễ nhầm

Dấu hiệu:

- `server/controllers/auth_controller.py` xử lý agent auth/JWT.
- `server/controllers/admin_auth_controller.py` xử lý admin/teacher cookie auth.
- Cả hai đều có refresh/logout/verify/token concepts.
- Route vừa có `/api/auth/*`, vừa có `/api/admin/auth/*`.

Vì sao chưa hợp lý:

- Đúng là có 2 loại auth, nhưng hiện tên `AuthController` quá chung.
- Middleware cũng có `require_jwt`, `require_api_key`, `require_jwt_or_api_key` với nhiều nhánh fallback.

Hướng sửa:

- Rename rõ:
  - `AgentAuthController`
  - `WebAuthController` hoặc `AdminSessionController`
- Tách token contract:
  - Agent: Bearer JWT/API key, không cookie.
  - Web: httpOnly cookie, CSRF strategy nếu cần.
- Gom response helper/error code cho auth để frontend xử lý ổn định.

#### 11. API key controller chưa dùng user context

Dấu hiệu:

- `server/controllers/api_key_controller.py` có `created_by="admin"` kèm TODO.

Vì sao chưa hợp lý:

- Audit/ownership của API key không đúng.
- Khi có nhiều admin, không biết key do ai tạo.

Hướng sửa:

- Dùng `g.current_user_id` và `g.current_user.username`.
- Bổ sung permission riêng: `api_keys:create`, `api_keys:revoke`.
- Test admin tạo key phải ghi đúng `created_by`.

#### 12. Debug/legacy endpoint đang nằm trong production controller

Dấu hiệu:

- `server/controllers/agent_controller.py` register `/agents/debug/status`, `/agents/debug/direct`.
- `server/controllers/log_controller.py` còn legacy `DELETE /api/logs` và legacy stats.

Vì sao chưa hợp lý:

- Debug endpoint có thể lộ cấu trúc services/routes.
- Legacy endpoint làm API surface khó kiểm soát và dễ bị frontend dùng nhầm.

Hướng sửa:

- Gỡ khỏi production hoặc chỉ register khi `config.ENABLE_DEBUG_ENDPOINTS=True`.
- Ghi deprecation note cho legacy route, thêm test route disabled ở production.

#### 13. Agent lifecycle là một hàm quá lớn và nhiều side effect

Dấu hiệu:

- `agent/core/lifecycle.py` có `initialize_components(config)` dài, làm register, token, whitelist, firewall, log sender, heartbeat, sniffer.
- `cleanup()` cũng tự biết toàn bộ component và cleanup theo từng loại.

Vì sao chưa hợp lý:

- Khó test từng component độc lập.
- Một thay đổi nhỏ ở firewall/whitelist dễ ảnh hưởng flow startup.
- Cleanup thiếu contract chung, phải check `hasattr`.

Hướng sửa:

- Tạo interface nhẹ cho component:
  - `name`
  - `start(context) -> ComponentStatus`
  - `stop(context) -> None`
  - `health()`
- Lifecycle chỉ chạy danh sách component theo thứ tự và rollback/cleanup ngược.
- Tách builder:
  - `RegistrationComponent`
  - `TokenRefreshComponent`
  - `WhitelistSyncComponent`
  - `FirewallComponent`
  - `HeartbeatComponent`
  - `CaptureComponent`

#### 14. Agent dùng global/singleton làm test và lifecycle khó kiểm soát — Đã xử lý (constructor injection)

Dấu hiệu ban đầu:

- `agent/core/agent.py` generate `AGENT_DEVICE_ID` ngay khi import.
- `agent/controllers/agent_controller.py` là singleton bằng `__new__`.
- `AgentController._agent_worker()` import và mutate global `Agent`.

Trạng thái 2026-05-26:

- `DeviceIdentityProvider` lazy class với cached `get_device_id()`/`get_hostname()`. Module-level `__getattr__` (PEP 562) keeps `AGENT_DEVICE_ID`/`AGENT_HOSTNAME` import API intact mà KHÔNG fire PowerShell ở import time. Tests gọi `DeviceIdentityProvider.reset()` để clear cache.
- `AgentRuntime` class (`agent/core/agent.py`) là plain-data injectable runtime container — không singleton. Holds config, attached component handles, state dict, running flag.
- `Agent` cũ giờ là singleton subclass của `AgentRuntime` — backwards-compat cho mọi caller doing `from agent.core import Agent, get_agent`. State dict aliased về module-level `agent_state` để legacy code thấy in-place mutations.
- `make_runtime(state=None)` factory cho test/multi-tenant.
- `Agent.reset_for_test()` + `AgentController.reset_for_test()` drop singletons.
- `initialize_components(config, runtime=None)` và `cleanup(config, runtime=None)` accept injected runtime; default to singleton.
- `AgentController(runtime=None)` constructor accept runtime; `_agent_worker` dùng `self._runtime` thay vì re-resolve singleton.
- `agent/core/lifecycle.py` không còn import `AGENT_DEVICE_ID`/`AGENT_HOSTNAME` ở module load. Heartbeat dùng `agent.device_id`, lifecycle log gọi `DeviceIdentityProvider.get_device_id()` / `get_hostname()` tại thời điểm build log. Nhờ đó import lifecycle không còn vô tình kích hoạt PowerShell/hardware probing trước khi runtime được inject.
- Tk-style `process_events(root)` + `set_root` xóa hoàn toàn — Qt frontends wire `QtSignalBridge(self.signals)` thẳng.

Còn lại:

- Lifecycle đã split sang `AgentComponent` interface (`name`, `start(context)`, `stop(context)`, `health(context)`) với `LifecycleContext`, `build_default_components`, `start_components`, `stop_components`. `initialize_components` chỉ còn giữ public API cũ và orchestration mỏng để giảm blast radius.

#### 15. Agent signal bridge còn kiểu Tk trong app Qt — Đã xử lý

Dấu hiệu ban đầu:

- `AgentSignals.process_events(root)` dùng `root.after(...)`.
- GUI chính đang là Qt.

Trạng thái 2026-05-26:

- `process_events(root)` + `set_root(root)` xóa khỏi `agent/controllers/agent_controller.py`. Comment ở chỗ cũ giải thích vì sao không reintroduce.
- Qt frontend wire `QtSignalBridge(self.signals)` (`agent/gui_qt/signal_bridge.py`) — `QObject` + `pyqtSignal` + `QTimer`-backed drain. Đã có từ trước; giờ là sole consumer.
- `AgentSignals` vẫn giữ `_event_queue` để bridge poll. Constants `DRAIN_INTERVAL_MS=50` và `MAX_EVENTS_PER_TICK=100` mirror sang `QtSignalBridge` — comment trên cả 2 file chỉ rõ phải đổi đồng thời.

#### 16. Firewall rule parsing phụ thuộc output tiếng Anh của `netsh` — Đã xử lý bằng provider facade

Dấu hiệu ban đầu:

- `agent/firewall/rules.py` parse các dòng `Rule Name:`, `Direction:`, `Action:`, `RemoteIP:`.
- `agent/gui_qt/views/firewall.py` và `settings.py` cũng có fallback parse/drive `netsh`.

Trạng thái 2026-05-27:

- `agent/firewall/provider.py` định nghĩa `FirewallProvider` ABC + `FirewallRule`/`FirewallPolicyStatus` TypedDicts. `get_default_provider()` factory chọn backend dựa trên platform + env var `SAINT_FIREWALL_PROVIDER`.
- `NetSecurityFirewallProvider` (`netsecurity_provider.py`) — PowerShell `Get-NetFirewallRule` + `Get-NetFirewallAddressFilter` + `Get-NetFirewallPortFilter` + `Get-NetFirewallApplicationFilter`, một script call duy nhất → JSON. Robust với non-English Windows.
- `NetshFirewallProvider` (`netsh_provider.py`) — wraps text parsing cũ, dùng làm fallback.
- `RulesManager.load_existing_rules` + `get_rule_count` delegate qua provider thay vì parse text inline.
- GUI `agent/gui_qt/views/firewall.py`: `_get_rules_from_netsh` + `_get_policy_from_netsh` đi qua provider; vẫn dùng tên cũ để không touch call sites.

Còn lại (operational cutover):

- Add/delete rule trong `RulesManager` đã delegate qua `FirewallProvider` write API. Default write backend vẫn là `netsh` để giữ behavior cũ; `FIREWALL_WRITE_BACKEND=powershell` bật NetSecurity write path khi cần smoke. Chưa nên đổi default sang PowerShell trước khi test Windows admin thật vì rule write sai có thể khóa traffic.
- `agent/gui_qt/views/settings.py` không còn restore policy/xóa SAINT rules bằng netsh inline; view gọi `FirewallApplicationService`, service delegate sang `FirewallManager`/`RulesManager`.

### P2 - Nên xử lý để giảm duplicate và chi phí bảo trì

#### 17. Frontend JS page files quá lớn và lặp helper

Dấu hiệu:

- `server/views/static/js/group_detail.js` khoảng 2070 dòng.
- `server/views/static/js/logs.js` khoảng 1561 dòng.
- `server/views/static/js/whitelist.js` khoảng 1413 dòng.
- `server/views/static/js/agents.js` khoảng 1381 dòng.
- Nhiều nơi tự viết `showToast`, `formatDate`, `loadGroups`, filter/export.

Vì sao chưa hợp lý:

- Bug UI dễ lặp lại ở nhiều page.
- Khó review vì mỗi file vừa fetch API, render HTML, xử lý state, modal, drag/drop.

Trạng thái hiện tại:

- Shared core đã có: `server/views/static/js/core/api.js` (`SaintAPI` — fetch wrapper với credentials, JSON, structured error), `core/toast.js` (`SaintToast` — dismissible toast, escapes message HTML), `core/date.js` (`SaintDate.formatVN`/`formatVNFull`/`formatDateOnly`/`relativeTime` Intl-based, vi-VN locale).
- `base.html` load core helpers trước page scripts. Global shim: `window.showToast = SaintToast.show`, `window.formatDate = SaintDate.formatVN`, `SaintLog`, `SaintUtils.escapeHtml`.
- Local helpers ở `admin_users.js`, `group_detail.js`, `logs.js`, `agents.js`, `whitelist.js`, `groups.js`, `dashboard.js`, `base.js`, `auth.js` đã delegate qua shared core.
- `api_keys.js` (sau khi extract khỏi inline) đã fully migrated sang `SaintAPI`/`SaintToast`/`SaintDate` — không còn raw `fetch()`.
- Bulk raw `fetch()` → `SaintAPI` migration đã xong cho admin pages; `rg "fetch\(" server/views/static/js` chỉ còn `core/api.js` (wrapper), `error_500.js` (GET health check), `pages/login.js` (login exempt path).
- `core/table.js` và `core/auth-state.js` chưa tạo (orchestration helpers đang fit trong page scripts, không có duplicate đủ lớn để extract).

Còn lại:

- Đã có Playwright/browser smoke golden path sau frontend migration (`tests/e2e/saint-admin-smoke.spec.js`, `npm.cmd run e2e` → 4 passed).
- Page split (`group_detail.js` → `agents/positions/policies/profiles/teachers.js`) chưa làm — đây là maintainability phase, không còn là bug helper/fetch duplicate.

#### 18. Inline JS còn nằm trong template — Đã xử lý 4 template chính

Dấu hiệu ban đầu:

- `server/views/templates/admin_audit.html` có JS load/render/filter table.
- `server/views/templates/api_keys.html` có JS API key và own toast.
- `server/views/templates/profile.html` có JS profile/change password.
- `server/views/templates/login.html` có JS login.

Trạng thái 2026-05-26:

- 4 template được extract sang file riêng trong `server/views/static/js/pages/`:
  - `pages/profile.js` (rewritten qua `SaintAPI`/`SaintDate`).
  - `pages/admin_audit.js` (rewritten qua `SaintAPI`/`SaintDate`).
  - `pages/api_keys.js` (fully migrated `fetch` → `SaintAPI`, `showToast` → `SaintToast`, `formatDate` → `SaintDate`).
  - `pages/login.js` (kept raw fetch — login page runs before any auth cookie exists, hence direct fetch with explicit credentials).
- Template còn lại chỉ là markup + `<script src="..." >` include. Không còn `<script>...inline code...</script>` ở profile/admin_audit/api_keys/login.
- `admin_users.html` đã link `static/js/admin_users.js` từ trước; chỉ helper local của nó được route qua `SaintDate`.

#### 19. CSS component chưa thống nhất

Dấu hiệu:

- `server/views/static/css/base.css` lớn và nhiều page CSS.
- Bug mới ở profile: `btn-warning text-white` làm nút chỉ rõ khi hover/focus.
- Nhiều style button/card/status nằm rải rác.

Vì sao chưa hợp lý:

- Một class Bootstrap/page override có thể phá màu ở page khác.
- Khó đảm bảo trạng thái normal/hover/focus/disabled đồng nhất.

Hướng sửa:

- Định nghĩa design tokens và component class rõ:
  - `.saint-btn-primary`
  - `.saint-btn-warning`
  - `.saint-card`
  - `.saint-status-*`
- Page CSS chỉ override layout cục bộ.
- Thêm visual smoke test cho các page chính.

#### 20. Time utilities tồn tại ở cả server và agent

Dấu hiệu:

- `server/time_utils.py`
- `agent/shared/time_utils.py`

Vì sao chưa hợp lý:

- Có thể hợp lý vì server/agent là 2 runtime khác nhau, nhưng API thời gian và format nên nhất quán.
- Nếu sửa timezone/format ở một bên, bên kia dễ lệch.

Hướng sửa:

- Nếu chưa muốn tạo shared package, ít nhất ghi contract chung:
  - timestamp gửi qua API luôn ISO timezone-aware.
  - server lưu UTC hoặc Vietnam timezone nhất quán.
  - agent chỉ gửi ISO, không gửi format hiển thị.
- Thêm test contract giữa log sender và log service.

#### 21. Agent GUI đang chứa logic nghiệp vụ firewall/config — Đã xử lý phần firewall restore

Dấu hiệu:

- `agent/gui_qt/views/settings.py` trước đây tự restore snapshot, gọi netsh, clear SAINT rules.
- `agent/gui_qt/views/firewall.py` fallback parse netsh khi không có manager.

Trạng thái hiện tại:

- `settings.py` đã delegate restore/clear qua `FirewallApplicationService`; view chỉ còn admin guard, confirm dialog và hiển thị kết quả.
- `firewall.py` read fallback đã đi qua `FirewallProvider` thay vì giữ parser netsh riêng.
- GUI không còn là owner của write command firewall. Backend switch nằm trong `FirewallProvider` / `FIREWALL_WRITE_BACKEND`.

Hướng còn lại:

- Mở rộng `FirewallApplicationService` nếu GUI cần thêm command-level use case ngoài restore/clear.
- Smoke trên Windows admin để verify restore snapshot + clear rules từ GUI thật.

#### 22. Group/detail frontend chứa nhiều feature trong một file

Dấu hiệu:

- `group_detail.js` xử lý group agents, drag/drop, custom whitelist, profiles, teacher assignment, context menu, position updates.

Vì sao chưa hợp lý:

- File trở thành mini application không có module boundary.
- State global dễ va nhau.

Hướng sửa:

- Tách theo bounded context:
  - `group_detail/agents.js`
  - `group_detail/positions.js`
  - `group_detail/policies.js`
  - `group_detail/profiles.js`
  - `group_detail/teachers.js`
  - `group_detail/state.js`

### P3 - Cleanup/dead code/legacy nên dọn sau khi có test bảo vệ

#### 23. Trang change password riêng có vẻ đã dead — Đã xử lý

Trạng thái hiện tại:

- `server/routes/pages.py` giữ route `/admin/change-password` redirect về `/profile` để không vỡ bookmark cũ.
- `server/views/templates/change_password.html` đã xóa.
- `server/views/static/css/change_password.css` đã xóa.

Hướng sửa đã áp dụng:

- Đổi mật khẩu trực tiếp trên `profile.html`.
- CSS nút đổi mật khẩu dùng class riêng `profile-change-password-btn`.
- Report/API docs đã cập nhật trạng thái route redirect.

#### 24. Legacy whitelist domain methods còn nằm trong service

Dấu hiệu:

- `server/services/whitelist_service.py` đã bỏ `get_all_domains` và `delete_domain`; còn các helper domain cũ ít dùng hơn như `add_domain`, `import_domains`, `export_domains`.
- Comment ghi `sync_for_agent removed - dead code`, nhưng nhiều legacy path khác vẫn còn.

Hướng sửa:

- Lập danh sách endpoint/frontend còn gọi method cũ.
- Nếu không còn dùng: xóa.
- Nếu còn cần tương thích: mark deprecated, chuyển implementation gọi API entry mới.

#### 25. Log legacy endpoints và debug functions cần quyết định giữ/bỏ

Dấu hiệu:

- `server/controllers/log_controller.py` có legacy `DELETE /api/logs`.
- `server/controllers/log_controller.py` có legacy statistics endpoint.

Hướng sửa:

- Giữ một endpoint canonical: ví dụ `/api/logs/clear`, `/api/logs/stats`.
- Legacy endpoint trả `410 Gone` hoặc redirect nội bộ trong 1 version, sau đó xóa.

#### 26. Agent legacy token fallback cần lộ trình kết thúc

Dấu hiệu:

- `agent/core/token_manager.py` fallback về legacy token.
- `server/services/agent_service.py` cũng còn nhánh fallback legacy.

Hướng sửa:

- Ghi version migration: JWT là chuẩn, legacy token chỉ cho agent cũ.
- Thêm config `ALLOW_LEGACY_AGENT_TOKEN`.
- Sau khi agent mới stable, tắt mặc định và xóa code fallback.

#### 27. TODO và comment "removed/deprecated/fallback" rải rác

Dấu hiệu:

- `server/controllers/api_key_controller.py`: TODO `created_by`.
- `server/views/static/js/groups.js`: TODO sync via SocketIO.
- Nhiều comment `legacy`, `fallback`, `removed` trong server/agent.

Hướng sửa:

- Chuyển TODO thành issue list có owner/priority.
- Code comment chỉ giữ nếu mô tả decision còn đúng.
- Comment "removed" nên đi kèm xóa code thật hoặc ticket migration.

## Kiến trúc mục tiêu đề xuất

### Server

Mục tiêu: controller mỏng, service giữ business rule, repository/model giữ Mongo, app factory không chứa side effect nghiệp vụ.

Đề xuất cấu trúc:

```text
server/
  bootstrap/
    app_factory.py
    container.py
    startup_tasks.py
  routes/
    pages.py
  controllers/
    agent_auth_controller.py
    web_auth_controller.py
    ...
  services/
    whitelist_service.py
    rbac_service.py
    ...
  repositories/
    whitelist_repository.py
    group_repository.py
    ...
  policies/
    permissions.py
    group_access.py
  models/
    schemas_or_serializers.py
```

Luồng chuẩn:

```text
HTTP request
  -> controller parse/validate request
  -> service apply business rule + RBAC
  -> repository/model query Mongo
  -> service returns DTO
  -> controller returns JSON
```

Quy tắc:

- Controller không gọi `.collection`.
- Service không tự biết chi tiết Mongo nếu repository đã có method.
- Startup không xóa/sửa dữ liệu ngoài migration.
- Auth web và auth agent có contract riêng.

### Agent

Mục tiêu: lifecycle có component contract rõ ràng, GUI không gọi firewall/netsh trực tiếp, không generate hardware id khi import.

Đề xuất cấu trúc:

```text
agent/
  core/
    runtime.py
    component.py
    identity.py
    lifecycle.py
  components/
    registration.py
    token_refresh.py
    whitelist_sync.py
    firewall_enforcement.py
    heartbeat.py
    packet_capture.py
  firewall/
    provider.py
    netsecurity_provider.py
    netsh_provider.py
  gui_qt/
    bridges/
      agent_bridge.py
    viewmodels/
      settings_vm.py
      firewall_vm.py
```

Luồng chuẩn:

```text
Qt UI
  -> AgentController/Runtime
  -> Component service
  -> FirewallProvider / WhitelistSyncer / HeartbeatSender
```

Quy tắc:

- Không singleton nếu constructor injection làm được.
- Không gọi OS command khi import module.
- GUI không parse `netsh`.
- Component có `start/stop/health`.

### Frontend

Mục tiêu: shared JS/CSS component, template ít inline JS, page module nhỏ.

Đề xuất:

```text
server/views/static/js/
  core/
    api.js
    toast.js
    date.js
    auth.js
    table.js
  pages/
    profile.js
    admin_audit.js
    api_keys.js
    logs.js
    whitelist/
      index.js
      bulk.js
      profiles.js
    group_detail/
      index.js
      agents.js
      profiles.js
      teachers.js
```

## Lộ trình refactor đề xuất

### Phase 0 - Chốt baseline và quality gate

- Chạy full test hiện có và ghi lại test đang fail thật sự.
- Sửa test drift trước khi refactor lớn. Hiện `test_users_auth.py` có mismatch message tiếng Việt/tiếng Anh.
- Thêm `git diff --check`, `pytest`, và một lệnh `rg ".collection"` để kiểm soát direct collection access ngoài model/repository.

### Phase 1 - Dọn code thừa ít rủi ro

- Đã xóa `change_password.html` và `change_password.css`.
- Đã gate debug endpoints bằng `ENABLE_DEBUG_ENDPOINTS`.
- Đã gate token/API key qua query string bằng `DEBUG_AUTH_QUERY_TOKEN`; production default `False`.
- Đã sửa audit profile update gọi `log_action`.
- Đã đưa cookie secure vào `ADMIN_COOKIE_SECURE`.

### Phase 2 - Siết lại server boundary

- Đã tách `server/app.py` sang `server/bootstrap/` và `server/routes/`.
- Đã tạo model methods thay cho direct `.collection` ngoài model.
- Đã chuyển whitelist teacher entry access check khỏi controller sang `WhitelistService.validate_teacher_entry_access(...)`; vẫn nên tiếp tục gom các rule data-access còn lại về `RBACService`.
- Đã tách tên `AgentAuthController` và `WebAuthController`; `admin_auth_controller.py` còn là shim backwards-compat.

### Phase 3 - Chuẩn hóa whitelist data model

- Đã tạo `whitelist_entries` + `WhitelistEntryModel` cho group scope.
- Đã thêm migration dry-run/write `2026_migrate_group_whitelist_to_entries.py`.
- New group writes trả `_id` thật từ collection; read path merge collection + embedded fallback.
- Xóa pseudo-ID `group::<gid>::<type>::<value>` chuyển sang release sau khi migration staging/production xác nhận không còn legacy client.

### Phase 4 - Làm gọn agent lifecycle

- Đã tạo `AgentRuntime` và `AgentComponent.start/stop/health` interface.
- Đã thêm `LifecycleContext`, `start_components`, `stop_components`, fake-component tests.
- Lazy-load identity/device id.
- Xóa Tk-style `root.after` bridge nếu Qt là GUI duy nhất.
- Tách firewall provider structured thay vì parse text netsh trong GUI.

### Phase 5 - Làm gọn frontend

- Tách inline JS ra file.
- Tạo shared `api/toast/date/table`.
- Chia `group_detail.js`, `logs.js`, `whitelist.js`, `agents.js` theo module nhỏ.
- Chuẩn hóa button/card/status CSS để tránh bug màu như profile change password.

### Phase 6 - Test và vận hành

- Baseline production mới nhất: Render full deep E2E `20260528_141158` PASS sạch (`24 PASS / 0 FAIL / 0 SKIP`) và real firewall Default Deny rollback sạch.
- Unit test service/repository cho RBAC và whitelist.
- Integration test auth cookie/JWT/API key.
- Agent test cho lifecycle start/stop với fake component.
- Frontend smoke test bằng Playwright cho dashboard, agents, whitelist, logs, profile, admin audit đã có; nên mở rộng thêm modal/create/edit/delete flows khi refactor page module.
- Migration test cho whitelist group embedded -> collection.
- Operational gates còn lại: multi-machine vật lý, reboot thật, soak dài hơn 30 phút, Render log/secret audit và whitelist fallback cutover sau migration production.

## Danh sách duplicate/thừa cụ thể nên xử lý

| Nhóm | File/điểm code | Tình trạng | Hướng xử lý |
|---|---|---|---|
| Change password page | `server/views/templates/change_password.html`, `server/views/static/css/change_password.css` | Đã xóa; route legacy redirect về `/profile` | Giữ redirect một release, sau đó cân nhắc xóa route |
| Whitelist legacy domain API | `server/services/whitelist_service.py` | `get_all_domains` và `delete_domain` đã xóa; controller dùng `get_all_entries` và `bulk_delete_entries`. Còn `add_domain`/`import_domains`/`export_domains` là helper legacy ít dùng | Migrate nốt import/export nếu frontend đổi sang entry API hoàn toàn |
| Group whitelist pseudo-ID | `server/services/whitelist_service.py`, `server/models/whitelist_entry_model.py`, `whitelist_entry_id.py` | Group write mới đã chuyển sang `whitelist_entries` với `_id` thật. Read path merge collection + embedded fallback; collection thắng khi trùng `type:value`. Update/delete/RBAC accept real collection `_id`, real embedded ObjectId, và pseudo-ID legacy. Migration script `2026_migrate_group_whitelist_to_entries.py` copy embedded rows sang collection | Chạy migration write staging/production → xác nhận không còn legacy pseudo-ID client → release sau xóa fallback embedded + pseudo-ID generator |
| Direct Mongo outside model | `server/controllers/*`, `server/services/*`, `server/middleware/rbac.py` | Đã dọn; controller gọi service validator, service/middleware gọi model/service methods. `require_group_ownership` dùng `GroupModel.find_by_id(...)` | Giữ static guard `rg -n "\.collection\." server/controllers server/services server/middleware` |
| RBAC duplicate | `server/config/rbac_config.py`, `server/services/rbac_service.py` | Đã xử lý. `RBACService.is_teacher_request` (static) + `assert_group_access` là single owner; controllers chỉ thin-wrap | Khi đổi rule, sửa ở service rồi update test ở `test_teacher_data_filtering.py` |
| Auth naming | `auth_controller.py`, `admin_auth_controller.py` | Đã có `AgentAuthController`/`WebAuthController`; còn shim legacy | Xóa shim khi toàn bộ import cũ đã migrate |
| Debug endpoint | `server/controllers/agent_controller.py` | Đã gate bằng `ENABLE_DEBUG_ENDPOINTS` | Giữ default off trong production |
| Log legacy route | `server/controllers/log_controller.py` | `DELETE /api/logs` trả 410 Gone + `Deprecation`/`Link` headers (RFC 8594); legacy `get_statistics` indirection đã bỏ | Drop route hoàn toàn sau 1 release nếu access log không thấy hit |
| API key created_by | `server/controllers/api_key_controller.py`, `server/services/api_key_service.py` | Đã xử lý. Controller dùng `g.current_user.username`/`current_user_id`; service fallback không còn `"admin"` giả mà dùng `"unknown"` hoặc `"system"` cho default key | Giữ audit fields theo actor thật |
| Startup mutation | `server/app.py` | Đã bỏ khỏi app boot; cleanup nằm trong migration script | Chạy migration có kiểm soát khi cần |
| Agent localhost fallback | `agent/whitelist/manager.py`, `agent/services/heartbeat.py`, `agent/logging_module/sender.py` | Đã dùng URL resolver chung, không fallback localhost ở first-run offline | Chỉ bật dev default bằng config rõ ràng nếu cần |
| Agent singleton/global identity | `agent/core/agent.py`, `agent/core/lifecycle.py`, `agent/controllers/agent_controller.py` | Đã xử lý: `DeviceIdentityProvider` lazy + `AgentRuntime` injectable (`Agent` là-is-a). `initialize_components`/`cleanup`/`AgentController` accept `runtime=` parameter. Lifecycle hiện dùng `AgentComponent.start/stop/health`, `LifecycleContext`, `start_components`, `stop_components`; có fake-component tests | Chỉ còn production GUI/Windows smoke khi có môi trường thật |
| Agent Tk bridge | `agent/controllers/agent_controller.py` | Đã xóa `process_events(root)` + `set_root`. Qt bridge `QtSignalBridge` là sole consumer | — |
| Netsh parsing duplicate | `agent/firewall/rules.py`, `agent/gui_qt/views/firewall.py`, `agent/gui_qt/views/settings.py` | Read side đã xử lý bằng `FirewallProvider`; GUI firewall view dùng provider. Write side đã delegate qua provider write API; default backend vẫn `netsh`, NetSecurity/PowerShell opt-in qua `FIREWALL_WRITE_BACKEND=powershell`. `settings.py` restore/clear đi qua `FirewallApplicationService`. | PowerShell backend đã pass run `20260528_141158` trên một máy Windows admin; trước khi đổi default vẫn cần canary thêm máy lab |
| Frontend toast/date/api/log/utils | `core/{api,toast,date,log,utils}.js` | Shared `SaintAPI`/`SaintToast`/`SaintDate`/`SaintLog`/`SaintUtils` ở `static/js/core/`. **Bulk fetch() migration DONE** (batch P3): mọi admin page dùng `SaintAPI`; `csrf-fetch-shim.js` đã xóa. `escapeHtml`/`escHtml`/`wlEscapeHtml` gom về `SaintUtils.escapeHtml`. `console.log` gate qua `SaintLog.debug` (`window.__SAINT_DEBUG__`). Playwright smoke golden path đã có và pass 4 tests. | Mở rộng browser tests cho modal/create/edit/delete flows khi tách page module |
| Inline JS | `profile.html`, `admin_audit.html`, `api_keys.html`, `login.html` | Đã tách sang `static/js/pages/{profile,admin_audit,api_keys,login}.js`. Template chỉ còn `<script src>` | — |
| CSS button/status | `base.css` và page CSS | Override dễ gây bug màu | Component CSS/tokens |

## Kết quả tốt nhất cần đạt

Mục tiêu không phải chỉ là xóa bớt dòng code. Kết quả tốt nhất nên là:

- Mỗi nghiệp vụ có một nguồn sự thật: whitelist entry, RBAC rule, auth contract, firewall provider.
- Controller không chứa business rule sâu.
- Service không bị buộc hiểu cả hai kiểu schema cũ/mới.
- Agent start/stop có lifecycle rõ, test được bằng fake components.
- GUI/frontend không chứa logic hệ thống như firewall/netsh, không lặp helper.
- Code legacy còn lại phải có config gate, deprecation note và ngày xóa dự kiến.

Nếu làm theo thứ tự Phase 0 -> Phase 6, rủi ro thấp nhất là bắt đầu từ các cleanup có test bảo vệ, sau đó mới đụng vào whitelist data model và agent lifecycle vì đây là hai vùng có blast radius lớn nhất.
