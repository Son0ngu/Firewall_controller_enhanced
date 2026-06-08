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
