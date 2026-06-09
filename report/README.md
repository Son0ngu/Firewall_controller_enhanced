# Cap nhat 2026-06-09 (batch 3 - bo so do day du)

- Bo so do hoan chinh cho toan bo code. Chi muc tap trung: `docs/diagrams/README.md`.
- Use-case: `docs/diagrams/usecase_diagram.puml` (them Validate/Stats API key).
- Class TONG QUAN moi: `docs/diagrams/class_overview_agent.puml`, `class_overview_server.puml`. Class CHI TIET: `class_diagram_agent.puml`, `class_diagram_server.puml` (da co, render lai SVG).
- Flow tung phan (Mermaid trong `report/diagrams/`): them 5 agent (`agent_registration_jwt`, `dns_resolution_cache`, `firewall_default_deny`, `heartbeat_flow`, `gui_signal_flow`) + 11 server (`server_agent_register_apikey`, `server_agent_heartbeat`, `server_agent_sync_merge_policy`, `server_whitelist_crud`, `server_whitelist_profile`, `server_agent_policy`, `server_logs_ingest_realtime`, `server_group_management`, `server_user_management`, `server_apikey_lifecycle`, `server_socketio_events`). Tong 24 flow.
- Render: PlantUML -> SVG bang `plantuml.jar` local; Mermaid de dang nguon (xem VS Code/mermaid.live).
- Mermaid flow `.mmd` da validate 24/24 bang mermaid-cli (sua `;`/`+`/`>=` trong text sequence diagram).
- Draw.io `docs/flow-diagrams/*.drawio`: sua node stale theo code moi — `20` (allow rules + self-allow TRUOC, roi Default Deny verify fail-closed), `09`+`21` (retry dung full-jitter backoff qua `_interruptible_sleep`, khong con "Sleep 5s" co dinh), `25` (enable_default_deny du 3 profile + verify per-profile), `33` (state.update: bo "incremental merge", them anti-wipe guard + always REPLACE). XML van well-formed.
- Xuat 24 flow `.mmd` -> SVG + PNG vao `report/diagrams/` (mermaid-cli + chrome-headless-shell).
- Audit lai TOAN BO 33 `.drawio` so voi code/reference (cu tu thang 5-6). Da fix (33/33 XML OK, residual stale = 0): route profile `/api/whitelist-profiles` -> `/api/groups/:gid/profiles`; `/api/audit` -> `/api/admin/audit`; SocketIO `logs_received` -> `new_log`; `is_domain_allowed` -> `is_allowed`; `AuditService.log()` -> `log_action()`; password `8-128` -> `>=8 chars, <=72 bytes`; bo `cpu_percent` (heartbeat chi memory/disk/uptime); snapshot `backup.wfw` -> `backup.saint-snapshot.json`; user update `PUT` -> `PATCH`; `/api/groups/:id/agents` -> `PATCH /api/agents/:id/group`; `inserted_count`->`processed_count` (log), `added/failed_count`->`inserted/error_count` (bulk); 17 (teacher whitelist write = 403, bang RBAC teacher group add/delete -> 403); 22 (bo nhanh incremental/merge -> always REPLACE); 23 (firewall_enabled? -> OBSERVED/ALLOWED/ALLOWED_BY_IP/BLOCKED, bo 3-mode monitor/warn). 
- Da fix NOT cac muc con lai (batch 4): `15` teacher RBAC -> read-only (create/update/delete = admin); `16` bang alias "Alias/Canonical (both valid)" + them `agent_read`; `18` import dung `import_domains` (strings-only/global) + response `{added_count, duplicate_count, error_count, total_processed}` + filename `whitelist.txt`; `19` bang audit actions: bo auth.logout/group.*/whitelist.*, them auth.failed + profile.update (rowspan Auth 3->4); `20` go row WhitelistMonitor (khong start); `27` danh dau `stats_update`/`agent_update` la NOT emitted (client polls/ghost); `32` DAO edge firewall section 6: collect_ips -> diff_calc -> add_rules -> default_deny -> fw_active (allow TRUOC, deny SAU). Toan bo 33/33 .drawio XML well-formed.

# Cap nhat 2026-06-09 (batch 2 - high-priority)

- Xu ly nhom uu tien cao. Chi tiet agent (Firewall-6 + Crypto-1) tai `agent/11_CAP_NHAT_2026_06_09_HIGH_PRIORITY_FIREWALL_CRYPTO.md`; chi tiet server (Server-4/5/9) tai `server/13_CAP_NHAT_2026_06_09_HIGH_PRIORITY_WHITELIST_FILTER.md`.
- **Phat hien khi kiem chung code**: Server-4 (`get_agent_sync_data`), Server-5 (`_merge_whitelists`), Server-10 (`get_group_query_filter`) deu KHONG phai bug chuc nang — chi kho doc / khac style. Server-4/5 → refactor do-ro **giu nguyen hanh vi**; Server-10 → de nguyen (tranh them import).
- **Bug that da fix**: Server-9 — `validate_teacher_entry_access` doi `except: return True, None` (fail-open) thanh `return False, "Invalid entry id"` (fail-closed) khi `ObjectId(item_id)` loi. Firewall-6 — `enable_default_deny` yeu cau du ca 3 profile (`== len(profiles)`), verify fail → khong bao thanh cong gia; `verify_default_deny` kiem per-profile qua `get_current_policy()` thay vi dem chuoi 'block'.
- **Crypto-1** — khoa Fernet ma hoa config truoc chi tu hostname+MAC (public). Them salt ngau nhien 32 byte (`secrets`) luu file `.salt` ACL-restricted qua `restrict_to_owner`; khoa = `SHA256(hostname+MAC+salt)`; `decrypt_config` migrate `.enc` cu (khoa legacy → re-encrypt khoa salt). +4 test `agent/tests/test_crypto.py`.
- Verify: agent **51 passed**, server **551 passed**, 0 fail. Reference docs (`docs/reference/agent/config.md`, `firewall.md`, `core.md`, `logging_module.md`, `services.md`, `server/services.md`) da dong bo.
- Diagram/flow da cap nhat: `docs/diagrams/class_diagram_agent.puml` (crypto salt/migration, PolicyManager all-3+verify, LogSender `_logs_sent`, HeartbeatSender `_interruptible_sleep`), `docs/diagrams/class_diagram_server.puml` (WhitelistService merge/validate/bulk_delete), `docs/reference/current-flows.md` (firewall default-deny fail-closed + flow ma hoa config moi), `report/diagrams/config_crypto_flow.mmd` (moi), `report/diagrams/agent_startup_sequence.mmd`. **Luu y:** SVG (`*.svg`) chua regen vi moi truong nay chan mang toi plantuml.com — chay `python docs/diagrams/render_plantuml.py docs/diagrams/*.puml` tren may co mang de tao lai SVG.

# Cap nhat 2026-06-09

- Batch-fix 8 loi "NEW ISSUES" (phat hien khi verify lai cac review report truoc): chi tiet agent tai `agent/10_CAP_NHAT_2026_06_09_NEW_ISSUES_BATCH_FIX.md`, chi tiet server tai `server/12_CAP_NHAT_2026_06_09_NEW_ISSUES_BATCH_FIX.md`.
- Agent (6): `LogSender` them counter `_logs_sent` (stat `logs_sent` het luon = 0); heartbeat them `_interruptible_sleep` ngu ca phan le (het busy-spin khi backoff < 1s); settings `_save_config` gop `server.urls` qua `collect_server_urls` (giu fallback URL); default heartbeat UI 30 → 20 cho khop `DEFAULT_CONFIG`; `restore_original_policy` doi return `== len(self._original_policies)` (dong bo voi `restore_default_policy`); `token_manager` giam `timeout` refresh 15 → 10.
- Server (2): bo import thua `get_all_permissions` o `admin_auth_service.py` + `user_service.py`; `bulk_delete_entries` dem `len(matched)` thay vi so phan tu mang nen `deleted_count` khong vuot so id gui.
- Khong tao class/module/signal moi; chi them counter `_logs_sent` (da thong nhat voi user), helper `_interruptible_sleep`, va vai bien local. Verify: `py_compile` PASS toan bo file da cham; reference docs trong `docs/reference/` da dong bo.

# Cap nhat 2026-06-08

- Group Detail whitelist count va Logs agent filter realtime update duoc ghi chi tiet tai `server/11_CAP_NHAT_2026_06_08_GROUP_DETAIL_WHITELIST_LOG_FILTER.md`.
- Noi dung chinh: Group Detail khong con dem `group.whitelist[]` cu ma doc `/api/whitelist?scope=group&group_id=...`, banner `Using Group Base Whitelist` hien dung count that; Logs page dung matcher chung cho API/search/socket, `new_log` realtime khong chen vao list neu khong match agent filter hien tai.
- Verification trong phien: `node --check` cho `group_detail.js` va `logs.js` pass; targeted group whitelist add/delete tests `3 passed`.

# Cap nhat 2026-06-05

- Server whitelist group filter/status update duoc ghi chi tiet tai `server/10_CAP_NHAT_2026_06_05_WHITELIST_GROUP_FILTER_STATUS.md`.
- Noi dung chinh: tach management list khoi effective whitelist, All Groups hien global + group, filter group chi hien group entries, Active/Inactive co tac dung that va inactive khong sync xuong agent, teacher chi read whitelist va dung Whitelist Profile, group/whitelist management la admin-only.

# Cap nhat 2026-06-04

- Agent build/GUI/firewall/URL update duoc ghi chi tiet tai `agent/08_CAP_NHAT_2026_06_04_AGENT_BUILD_GUI_FIREWALL_URL.md`.
- Noi dung chinh: PyInstaller onefile `dist/SAINT.exe`, SaaS GUI redesign, fix hidden imports `agent.*`, firewall guard khi whitelist sync fail, System DNS only, normalize Server URL co giu deployment subpath, fix config permission denied bang `%LOCALAPPDATA%\SAINT`, va test references.

# Bộ report kỹ thuật SAINT

Cập nhật 2026-06-01: API key expiration có enforce thật. Expired key bị `validate_api_key(...)` reject với `API key has expired`, endpoint dùng `require_api_key(...)` trả `401`, và expired key không tăng `usage_count`.
UI `/api-keys` cũng đã tách trạng thái `expired` riêng khỏi `revoked`, thêm filter `Expired`, và không tính expired key vào stat `Active`.

## Cập nhật 2026-06-01

- Xác nhận API key hiện không có rate limit backend thật: không có thư viện/middleware quota, không có window counter/token bucket, không có response `429`; `usage_count` chỉ là counter trọn đời.
- Đã gỡ UI Rate Limit giả khỏi trang `/api-keys`: bỏ input `1000/hour`, bỏ payload `rate_limit`, bỏ hiển thị `usage / limit` và progress bar.
- Đã sửa dropdown Expiration trong modal Create API Key bằng shared custom select ở `base.js`: menu tự mở lên khi modal không đủ chỗ bên dưới và có scroll thật, nên vẫn giữ đúng style UI và chọn được đầy đủ `Never expires`, `7 days`, `30 days`, `90 days`, `1 year`.

## Cập nhật 2026-05-28

- `2026-05-28_E2E_VALIDATION_AND_OPEN_ITEMS.md` là baseline validation mới nhất. Render full deep E2E run `20260528_141158` PASS sạch: `24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0`, `cleanup_failures=0`, `CLEANUP_OK=43`.
- Run cuối đã cover Server API/RBAC, GUI, Socket.IO, Agent register/JWT/heartbeat/sync/log, profile sync, policy force sync, synthetic classroom scale, 30-minute soak và real Windows Firewall Default Deny với backend `powershell`/NetSecurity.
- Hotfix public auth leak đã được verify trên Render: `/api/groups`, `/api/logs?limit=1`, `/api/logs/stats` đều trả `401` khi chưa đăng nhập.
- Firewall-only run `20260527_235108` chỉ còn là smoke lịch sử; kết quả firewall hiện tại nên đọc từ full deep run `20260528_141158`.
- Tồn đọng vận hành còn lại: kiểm tra Render logs và rotate secret nếu từng lộ, canary PowerShell firewall backend trên thêm máy lab, test multi-machine vật lý, test reboot/autostart thật, soak dài hơn 30 phút và chưa xóa whitelist fallback/pseudo-ID trước khi migration production được chứng minh sạch.

Bộ tài liệu này được tạo từ source code hiện tại trong `agent/` và `server/`, không dựa vào tài liệu cũ trong `docs/` làm nguồn chính.

## Cập nhật 2026-05-26

- Report đã được cập nhật theo refactor mới nhất: `server/app.py` là entrypoint mỏng, phần tạo app/container/startup task/page route/error handler/SocketIO handler đã tách sang `server/bootstrap/` và `server/routes/`.
- Ranh giới tầng server đã được ghi lại theo trạng thái hiện tại: controller/service không còn truy cập Mongo trực tiếp qua `.collection`; các query/update trực tiếp được chuyển xuống model layer.
- Các mục review kiến trúc đã được đánh dấu trạng thái: phần đã fix, phần còn tồn đọng và hướng sửa tiếp theo.

## Cách đọc nhanh

- `PROJECT_OVERVIEW.md`: bức tranh tổng thể hệ thống.
- `agent/`: kiến trúc, công nghệ, API Agent tiêu thụ, luồng hoạt động, bảo mật/rủi ro.
- `server/`: kiến trúc Flask/MongoDB, API, models/collections, RBAC, SocketIO, testing/deployment.
- `diagrams/`: sơ đồ Mermaid có thể render trong Markdown viewer.

## Cảnh báo vận hành

Không chạy `dist/SAINT.exe`, `agent/agent_gui.py`, hoặc bất kỳ thành phần Agent runtime nào khi chỉ cần đọc tài liệu. Source hiện tại có chế độ `whitelist_only` dùng Default Deny trên Windows Firewall; nếu chạy thật với quyền Administrator và cấu hình không đúng, máy có thể mất kết nối mạng.
