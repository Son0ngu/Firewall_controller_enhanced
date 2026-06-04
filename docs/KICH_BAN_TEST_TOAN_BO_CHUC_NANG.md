# Kịch bản test toàn bộ chức năng SAINT

Tài liệu này tổng hợp kịch bản kiểm thử end-to-end, API, GUI, bảo mật, vận hành và hồi quy cho hệ thống SAINT dựa trên source hiện tại trong `agent/`, `server/`, `docs/reference/` và `report/`.

## 1. Phạm vi và mục tiêu

### 1.1. Phạm vi test

| Nhóm | Thành phần | Mục tiêu |
|---|---|---|
| Server bootstrap | Flask app, MongoDB, SocketIO, health/config | Server khởi động đúng, kết nối DB, đăng ký controller, seed admin/API key |
| Auth/RBAC | Admin/Teacher login, JWT, session, permission | Xác thực đúng, phân quyền đúng, Teacher không xem/sửa dữ liệu ngoài group |
| User management | Admin tạo/sửa/xóa user, reset password | Quản lý tài khoản giáo viên/admin an toàn |
| API Key | CRUD API key, validate/revoke | Agent register chỉ qua key hợp lệ và đúng permission |
| Group | CRUD group, assign teacher, move/delete group | Quản lý phòng/lab và ownership |
| Agent server API | Register, heartbeat, list/detail, policy, group, position | Server quản lý agent, trạng thái, policy và realtime event |
| Whitelist | Global/group whitelist, import/export/bulk, agent-sync, profile | Policy whitelist hoạt động đúng theo group/version/profile |
| Logs | Agent push logs, web list/filter/export/clear/stats | Log mạng lưu, lọc, export và phân quyền đúng |
| Web dashboard | Các page server-rendered + static JS | UI web gọi API, hiển thị dữ liệu, xử lý lỗi |
| SocketIO | connect/ping và realtime business events | Browser/client nhận realtime event khi dữ liệu đổi |
| Agent GUI | PySide6 dashboard, firewall, whitelist, logs, settings | UI agent signal-driven, không freeze, thao tác đúng |
| Agent lifecycle | Offline/degraded/online, token refresh, cleanup | Agent start/stop an toàn, không tự khóa máy |
| Enforcement | Windows Firewall, DNS resolve, Scapy sniffer, log sender | Whitelist-only enforcement và monitoring đúng |
| Deployment | Docker server, PyInstaller agent | Build/run được trong môi trường triển khai |
| Recovery/security | Token revoke, brute force, firewall restore, invalid input | Fail-safe và chống misuse cơ bản |

### 1.2. Tiêu chí hoàn thành

- Tất cả test case mức `P0` pass.
- Không có lỗi 500 không kiểm soát trong Server khi chạy flow chính.
- Agent không làm mất kết nối tới Server/DNS khi bật firewall whitelist mode.
- Khi dừng Agent, Windows Firewall được restore hoặc có đường restore thủ công.
- Teacher chỉ xem/sửa dữ liệu thuộc group được gán.
- Logs, whitelist, heartbeat, agent status cập nhật realtime hoặc sau refresh API đúng như thiết kế.

## 2. Chuẩn bị môi trường

### 2.1. Máy Server

| Hạng mục | Yêu cầu |
|---|---|
| OS | Windows/Linux đều được cho Server |
| Python | Theo `server/requirements.txt` |
| MongoDB | Local `mongodb://localhost:27017/Monitoring` hoặc Atlas |
| Port | `5000` mở được từ Agent |
| Env | `MONGO_URI`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `API_KEY_HMAC_SECRET` |

### 2.2. Máy Agent

| Hạng mục | Yêu cầu |
|---|---|
| OS | Windows |
| Quyền | Administrator cho test firewall enforcement |
| Python | Theo `agent/requirements.txt` |
| Network | Truy cập được Server qua HTTP port 5000 |
| Rủi ro | Test firewall nên chạy trên máy lab/VM có snapshot hoặc có quyền restore firewall |

### 2.3. Lệnh setup cơ bản

Server:

```powershell
cd server
copy .env-example .env
# sửa .env theo môi trường test
python -m pip install -r requirements.txt
python scripts/seed_rbac.py --username admin --password admin123456
python app.py
```

Hoặc Docker:

```powershell
cd server
docker compose up -d --build
```

Agent:

```powershell
cd agent
python -m pip install -r requirements.txt
python agent_gui.py
```

Test tự động Server:

```powershell
cd server
python -m pytest tests/ -v
```

## 3. Dữ liệu test chuẩn

| Loại | Giá trị mẫu |
|---|---|
| Admin | `admin / admin123456` |
| Teacher A | `teacher_a / Teacher@123456` |
| Teacher B | `teacher_b / Teacher@123456` |
| Group A | `Lab A` |
| Group B | `Lab B` |
| Agent A | hostname `SAINT-AGENT-A`, device_id `test-device-a` |
| Agent B | hostname `SAINT-AGENT-B`, device_id `test-device-b` |
| Domain allowed | `example.com`, `wikipedia.org` |
| Pattern allowed | `*.edu.vn` |
| IP allowed | IP nội bộ test, ví dụ `192.168.1.10` |
| Domain blocked | `facebook.com` hoặc domain ngoài whitelist |
| API key permission | `agent_register`, `whitelist_sync`, `logs_write` |

## 4. Test Server bootstrap, health và cấu hình

### TC-SRV-001 - Khởi động Server với MongoDB hợp lệ

Mức ưu tiên: `P0`

Điều kiện:
- MongoDB đang chạy.
- `.env` có đủ secret.

Bước test:
1. Chạy `python server/app.py`.
2. Quan sát log startup.
3. Gọi `GET http://localhost:5000/api/health`.
4. Gọi `GET http://localhost:5000/api/config`.

Kết quả mong đợi:
- Server log có MongoDB connected, MVC components initialized, controllers registered.
- `/api/health` trả `200`, `status=healthy`, có `timestamp`.
- `/api/config` trả `socketio_enabled=true`, `timezone=vietnam`.
- Nếu chưa có admin/API key, startup seed default admin và default API key.

### TC-SRV-002 - Khởi động Server khi MongoDB sai

Mức ưu tiên: `P0`

Bước test:
1. Sửa `MONGO_URI` sang URI sai.
2. Chạy `python server/app.py`.

Kết quả mong đợi:
- Server không chạy ở trạng thái half-initialized.
- Log báo `MongoDB connection failed` hoặc `Database connection failed`.
- Không expose API hoạt động giả.

### TC-SRV-003 - Kiểm tra route web public render đúng template

Mức ưu tiên: `P1`

Bước test:
1. Mở lần lượt `/`, `/login`, `/agents`, `/groups`, `/whitelist`, `/logs`, `/api-keys`, `/admin/users`, `/admin/audit`, `/profile`.
2. Kiểm tra HTML trả về không lỗi 500.
3. Mở `/unknown-page`.

Kết quả mong đợi:
- Các page chính render `200`.
- `/unknown-page` trả 404 template.
- Các page admin có thể render shell, nhưng JS/API phải chặn nếu chưa login.

## 5. Test đăng nhập, session, JWT và RBAC

### TC-AUTH-001 - Admin login thành công

Mức ưu tiên: `P0`

Bước test:
1. `POST /api/admin/auth/login` với `{ "username": "admin", "password": "admin123456" }`.
2. Kiểm tra response JSON.
3. Kiểm tra cookie `access_token`, `refresh_token`.
4. Gọi `GET /api/admin/auth/me` bằng cookie vừa nhận.

Kết quả mong đợi:
- Login trả `success=true`.
- Cookie httpOnly được set.
- `/me` trả user role `admin`, không trả `password_hash`.

### TC-AUTH-002 - Login sai mật khẩu và lock account

Mức ưu tiên: `P0`

Bước test:
1. Tạo user test riêng.
2. Login sai mật khẩu liên tiếp 5 lần.
3. Login lại với mật khẩu đúng.

Kết quả mong đợi:
- Các lần sai trả 401/400 theo service.
- Sau ngưỡng sai, account bị locked.
- Login đúng trong thời gian lock vẫn bị từ chối.
- Audit log có hành vi login failure nếu service ghi.

### TC-AUTH-003 - Refresh admin token

Mức ưu tiên: `P1`

Bước test:
1. Login admin.
2. Gọi `POST /api/admin/auth/refresh` bằng cookie/session.
3. Gọi `/api/admin/auth/me` lại.

Kết quả mong đợi:
- Token/cookie mới được issue.
- Session vẫn hợp lệ.
- Không mất role/permission claims.

### TC-AUTH-004 - Logout admin

Mức ưu tiên: `P0`

Bước test:
1. Login admin.
2. Gọi `POST /api/admin/auth/logout`.
3. Gọi lại `/api/admin/auth/me`.

Kết quả mong đợi:
- Logout trả success.
- Cookies bị clear.
- `/me` trả 401 hoặc redirect/API error.

### TC-AUTH-005 - Teacher không gọi được API admin-only

Mức ưu tiên: `P0`

Bước test:
1. Admin tạo `teacher_a`.
2. Login bằng `teacher_a`.
3. Gọi `GET /api/admin/users`.
4. Gọi `POST /api/groups` tạo group mới.
5. Gọi `GET /api/admin/audit`.

Kết quả mong đợi:
- Các API admin-only trả 403.
- Teacher không nhận dữ liệu user/audit toàn hệ thống.

### TC-AUTH-006 - Agent JWT verify, refresh, logout

Mức ưu tiên: `P0`

Điều kiện:
- Có API key hợp lệ để agent register.

Bước test:
1. Register agent qua `POST /api/agents/register`.
2. Lấy `jwt.access_token` và `jwt.refresh_token`.
3. Gọi `POST /api/auth/verify` với access token.
4. Gọi `GET /api/auth/token-info`.
5. Gọi `POST /api/auth/refresh` với refresh token.
6. Gọi `POST /api/auth/logout` để revoke token.
7. Verify lại token cũ.

Kết quả mong đợi:
- Verify token hợp lệ trả success.
- Token-info decode được claims.
- Refresh trả access token mới.
- Token cũ sau revoke không dùng được cho endpoint JWT.

## 6. Test quản lý user

### TC-USER-001 - Admin tạo Teacher

Mức ưu tiên: `P0`

Bước test:
1. Login admin.
2. `POST /api/admin/users` với username/password/email/role `teacher`.
3. `GET /api/admin/users?role=teacher`.

Kết quả mong đợi:
- Tạo user trả 201.
- Password không xuất hiện trong response.
- User mới nằm trong danh sách teacher.
- Event `user_created` được emit nếu có SocketIO client.

### TC-USER-002 - Trùng username/email

Mức ưu tiên: `P1`

Bước test:
1. Tạo user `teacher_a`.
2. Tạo lại user cùng username.
3. Tạo user khác nhưng cùng email.

Kết quả mong đợi:
- Server trả 400 hoặc lỗi validation rõ ràng.
- Không tạo duplicate trong MongoDB.

### TC-USER-003 - Update role/is_active/email

Mức ưu tiên: `P1`

Bước test:
1. Admin gọi `PATCH /api/admin/users/<user_id>` đổi email.
2. Gọi `PATCH` đổi `is_active=false`.
3. Login bằng user đó.
4. Bật lại `is_active=true`.

Kết quả mong đợi:
- Email đổi đúng.
- User inactive không login được.
- Active lại thì login được.

### TC-USER-004 - Reset password

Mức ưu tiên: `P1`

Bước test:
1. Admin gọi `POST /api/admin/users/<id>/reset-password`.
2. Login bằng mật khẩu cũ.
3. Login bằng mật khẩu mới.

Kết quả mong đợi:
- Mật khẩu cũ bị từ chối.
- Mật khẩu mới login thành công.

### TC-USER-005 - Chặn xóa self và last admin

Mức ưu tiên: `P0`

Bước test:
1. Admin đang login tự gọi `DELETE /api/admin/users/<self_id>`.
2. Nếu hệ thống chỉ có 1 admin, gọi delete admin đó qua user khác hoặc trực tiếp API test.

Kết quả mong đợi:
- Không cho self-delete.
- Không cho xóa admin cuối cùng.

## 7. Test API Key

### TC-KEY-001 - Tạo API key hợp lệ

Mức ưu tiên: `P0`

Bước test:
1. Login admin.
2. `POST /api/api-keys` với name, description, permissions `["agent_register", "whitelist_sync", "logs_write"]`.
3. Lưu plaintext key trả về.
4. `GET /api/api-keys`.

Kết quả mong đợi:
- Response tạo key chỉ hiển thị plaintext một lần.
- List không hiển thị secret plaintext.
- Key có status active.

### TC-KEY-002 - Validate API key

Mức ưu tiên: `P0`

Bước test:
1. Gọi `POST /api/api-keys/validate` với plaintext key và permission `agent_register`.
2. Gọi validate với permission không có.
3. Gọi validate với key sai.

Kết quả mong đợi:
- Permission đúng trả valid.
- Permission thiếu hoặc key sai trả invalid/403.

### TC-KEY-003 - Invalid permission bị reject

Mức ưu tiên: `P1`

Bước test:
1. Tạo key với permission `invalid_permission`.

Kết quả mong đợi:
- Server trả 400.
- Không tạo key.

### TC-KEY-004 - Revoke/delete API key

Mức ưu tiên: `P0`

Bước test:
1. Tạo API key.
2. Revoke bằng `POST /api/api-keys/<id>/revoke` hoặc `DELETE`.
3. Dùng key đó để register agent.

Kết quả mong đợi:
- Key chuyển revoked/inactive.
- Agent register bị từ chối.

## 8. Test Group và RBAC theo group

### TC-GRP-001 - Admin tạo group

Mức ưu tiên: `P0`

Bước test:
1. Login admin.
2. `POST /api/groups` tạo `Lab A`.
3. `GET /api/groups`.
4. Mở `/groups/<group_id>`.

Kết quả mong đợi:
- Group tạo thành công.
- List có `Lab A`.
- Detail page render đúng.

### TC-GRP-002 - Assign teacher vào group

Mức ưu tiên: `P0`

Bước test:
1. Tạo `teacher_a`, `teacher_b`.
2. Gọi `POST /api/groups/<lab_a_id>/teachers` với `teacher_a`.
3. Login `teacher_a`, gọi `GET /api/groups`.
4. Login `teacher_b`, gọi `GET /api/groups`.

Kết quả mong đợi:
- `teacher_a` thấy `Lab A`.
- `teacher_b` không thấy `Lab A`.
- Admin thấy tất cả.

### TC-GRP-003 - Teacher update group của mình, bị chặn group ngoài phạm vi

Mức ưu tiên: `P0`

Bước test:
1. Admin tạo `Lab A` gán teacher_a, `Lab B` gán teacher_b.
2. Login teacher_a.
3. PATCH `Lab A` description.
4. PATCH `Lab B` description.

Kết quả mong đợi:
- Update `Lab A` được phép nếu controller cho ownership update.
- Update `Lab B` trả 403/404 theo filter.

### TC-GRP-004 - Delete group và agent chuyển về pending

Mức ưu tiên: `P1`

Bước test:
1. Tạo group và gán agent vào group.
2. Delete group.
3. Query agent detail.
4. Query pending group.

Kết quả mong đợi:
- Group bị xóa.
- Agent không bị xóa; được chuyển về pending/default group hoặc group_id null theo service.
- Không còn whitelist group cũ áp vào agent.

## 9. Test Agent server API

### TC-AGT-001 - Agent register bằng API key hợp lệ

Mức ưu tiên: `P0`

Bước test:
1. Tạo API key có `agent_register`.
2. `POST /api/agents/register` với header API key và body:

```json
{
  "hostname": "SAINT-AGENT-A",
  "device_id": "test-device-a",
  "ip_address": "192.168.56.10",
  "platform": "Windows",
  "os_info": {"name": "Windows 11", "version": "23H2"},
  "agent_version": "1.0.0"
}
```

Kết quả mong đợi:
- Trả `agent_id`, legacy token nếu còn dùng, `jwt.access_token`, `jwt.refresh_token`, `status`.
- MongoDB có record agent.
- Agent mới nằm trong pending group nếu chưa assign.
- Event `agent_registered` emit.

### TC-AGT-002 - Register lại cùng device_id

Mức ưu tiên: `P0`

Bước test:
1. Register agent với `device_id=test-device-a`.
2. Register lại cùng `device_id` nhưng IP/hostname khác.
3. Query agents.

Kết quả mong đợi:
- Không tạo duplicate agent.
- Agent hiện có được update metadata.
- Token/JWT mới được trả.

### TC-AGT-003 - Register thiếu required field

Mức ưu tiên: `P1`

Bước test:
1. Bỏ `device_id` hoặc `hostname`.
2. Gửi register.

Kết quả mong đợi:
- Trả 400, message field thiếu.
- Không ghi agent rác.

### TC-AGT-004 - Heartbeat thành công

Mức ưu tiên: `P0`

Bước test:
1. Register agent lấy JWT.
2. `POST /api/agents/heartbeat` với Authorization Bearer và body gồm `agent_id`, `metrics`, `global_version`, `group_version`, `platform`, `os_info`.
3. Query agent detail/statistics.

Kết quả mong đợi:
- Heartbeat trả `status`, `server_time`, `force_sync`, `policy_mode`, `next_heartbeat`.
- Agent last_seen cập nhật.
- Agent status online/active.
- Event `agent_heartbeat` emit.

### TC-AGT-005 - Heartbeat token sai/hết hạn

Mức ưu tiên: `P0`

Bước test:
1. Gửi heartbeat không có Authorization.
2. Gửi heartbeat với token sai.
3. Revoke token rồi gửi heartbeat.

Kết quả mong đợi:
- Server trả 401.
- Không update last_seen.

### TC-AGT-006 - List/detail/statistics theo Admin và Teacher

Mức ưu tiên: `P0`

Bước test:
1. Tạo `Lab A`, `Lab B`, agent A thuộc A, agent B thuộc B.
2. Gán teacher_a vào Lab A.
3. Admin gọi `GET /api/agents`, `GET /api/agents/statistics`.
4. teacher_a gọi các API tương tự.
5. teacher_a gọi `GET /api/agents/<agent_b_id>`.

Kết quả mong đợi:
- Admin thấy A+B.
- teacher_a chỉ thấy A.
- teacher_a bị chặn khi truy cập agent B.
- Statistics của teacher tính trên tập đã filter.

### TC-AGT-007 - Update display name và position

Mức ưu tiên: `P1`

Bước test:
1. PATCH `/api/agents/<id>/display-name` với tên mới.
2. PATCH `/api/agents/<id>/position` với tọa độ/layout JSON.
3. Query detail.

Kết quả mong đợi:
- Tên hiển thị và position lưu đúng.
- Teacher chỉ update được agent trong group của mình.

### TC-AGT-008 - Chuyển group agent

Mức ưu tiên: `P0`

Bước test:
1. Admin PATCH `/api/agents/<id>/group`.
2. Teacher gọi cùng endpoint.

Kết quả mong đợi:
- Admin chuyển group thành công, emit `agent_group_updated`.
- Teacher bị chặn vì endpoint admin-only.

### TC-AGT-009 - Agent policy isolate/custom/reset

Mức ưu tiên: `P1`

Bước test:
1. GET `/api/agents/<id>/policy`.
2. PATCH policy sang isolate/custom theo payload service hỗ trợ.
3. Gọi `/api/whitelist/agent-sync` cho agent.
4. Reset policy.

Kết quả mong đợi:
- Policy lưu đúng.
- `agent-sync` phản ánh `policy_mode`/entries hiệu lực.
- Event `agent_policy_changed` emit.

## 10. Test Whitelist global/group/bulk/import/export

### TC-WL-001 - Admin thêm global whitelist domain/IP/pattern

Mức ưu tiên: `P0`

Bước test:
1. Login admin.
2. POST `/api/whitelist` thêm `example.com` scope global.
3. POST thêm `*.edu.vn` type pattern.
4. POST thêm một IP nội bộ test, ví dụ `192.168.1.10`, type ip.
5. GET `/api/whitelist`.

Kết quả mong đợi:
- Entries tạo thành công.
- Type/scope/category/is_active đúng.
- Event `whitelist_added` hoặc `whitelist_updated` emit.

### TC-WL-002 - Teacher không thêm global whitelist

Mức ưu tiên: `P0`

Bước test:
1. Login teacher_a.
2. POST `/api/whitelist` với scope global, không có group_id.
3. POST với group_id thuộc Lab A.
4. POST với group_id thuộc Lab B.

Kết quả mong đợi:
- Global bị chặn.
- Lab A thành công.
- Lab B bị chặn.

### TC-WL-003 - List whitelist theo RBAC

Mức ưu tiên: `P0`

Bước test:
1. Có global entry, Lab A entry, Lab B entry.
2. Admin GET `/api/whitelist`.
3. teacher_a GET `/api/whitelist`.

Kết quả mong đợi:
- Admin thấy tất cả.
- teacher_a thấy global + Lab A, không thấy Lab B.

### TC-WL-004 - Delete whitelist ownership

Mức ưu tiên: `P0`

Bước test:
1. Teacher_a delete Lab A entry.
2. Teacher_a delete global entry.
3. Teacher_a delete Lab B entry.
4. Admin delete bất kỳ entry nào.

Kết quả mong đợi:
- Teacher chỉ xóa được entry thuộc group của mình.
- Global/Lab B bị chặn.
- Admin xóa được.
- Group/global version bump để agent sync nhận thay đổi.

### TC-WL-005 - Import whitelist

Mức ưu tiên: `P1`

Bước test:
1. Admin import danh sách domain/IP.
2. Teacher import nhưng không truyền group_id.
3. Teacher import với group_id của mình.
4. Teacher import với group_id ngoài phạm vi.

Kết quả mong đợi:
- Admin import thành công.
- Teacher thiếu group_id bị chặn.
- Teacher với group của mình thành công.
- Teacher group ngoài bị chặn.

### TC-WL-006 - Export whitelist JSON/TXT

Mức ưu tiên: `P1`

Bước test:
1. Admin gọi `/api/whitelist/export?format=json`.
2. Admin gọi `/api/whitelist/export?format=txt`.
3. Teacher gọi export.

Kết quả mong đợi:
- JSON/TXT đúng format.
- Teacher chỉ export dữ liệu được phép xem.
- Không có field nhạy cảm không cần thiết.

### TC-WL-007 - Bulk add/update/delete

Mức ưu tiên: `P1`

Bước test:
1. POST `/api/whitelist/bulk` với 3 items hợp lệ.
2. POST `/api/whitelist/bulk-update` toggle `active=false`.
3. POST `/api/whitelist/bulk-delete`.
4. Test bulk hơn 1000 items.

Kết quả mong đợi:
- Bulk hợp lệ thành công.
- Toggle active ảnh hưởng agent-sync.
- Bulk quá giới hạn trả 400.
- Teacher bị kiểm tra ownership từng item.

### TC-WL-008 - Agent whitelist sync versioned

Mức ưu tiên: `P0`

Bước test:
1. Register agent A, gán vào Lab A.
2. Tạo global + Lab A whitelist.
3. Gọi `GET /api/whitelist/agent-sync?agent_id=<id>&global_version=&group_version=`.
4. Lưu `global_version`, `group_version`.
5. Gọi lại với version mới nhất.
6. Thêm entry mới, gọi sync lại.

Kết quả mong đợi:
- Sync đầu trả full whitelist có domain/pattern/IP đúng.
- Sync lần hai có thể trả up_to_date/no changes.
- Sau khi thêm entry, sync trả thay đổi/version mới.
- Không trả Lab B entries cho agent A.

## 11. Test whitelist profile

### TC-PROF-001 - Teacher tạo profile cho group của mình

Mức ưu tiên: `P1`

Bước test:
1. Login teacher_a.
2. POST `/api/groups/<lab_a_id>/profiles` với name/domains.
3. GET `/api/my-profiles`.
4. GET `/api/groups/<lab_a_id>/profiles`.

Kết quả mong đợi:
- Profile tạo thành công.
- Owner/teacher_username đúng.
- Teacher thấy profile của mình.

### TC-PROF-002 - Teacher bị chặn profile group khác

Mức ưu tiên: `P0`

Bước test:
1. teacher_a POST profile vào Lab B.
2. teacher_a list profiles Lab B.

Kết quả mong đợi:
- Trả 403/404 theo check group access.

### TC-PROF-003 - Activate/deactivate profile

Mức ưu tiên: `P1`

Bước test:
1. Tạo 2 profile trong Lab A.
2. Activate profile 1.
3. Activate profile 2.
4. Query active profile hoặc agent-sync.
5. Deactivate profile 2.

Kết quả mong đợi:
- Chỉ một profile active trong group.
- Activate profile 2 tự deactivate profile 1.
- Group whitelist version bump.
- Event `whitelist_updated` emit.

### TC-PROF-004 - Không xóa profile active

Mức ưu tiên: `P1`

Bước test:
1. Activate profile.
2. Delete profile đó.
3. Deactivate rồi delete.

Kết quả mong đợi:
- Active profile bị chặn xóa.
- Sau deactivate, delete thành công.

## 12. Test Logs API và UI

### TC-LOG-001 - Agent push batch logs

Mức ưu tiên: `P0`

Bước test:
1. Register agent lấy JWT.
2. POST `/api/logs` với body:

```json
{
  "logs": [
    {
      "agent_id": "<agent_id>",
      "timestamp": "2026-05-25T10:00:00+07:00",
      "level": "INFO",
      "action": "ALLOWED",
      "domain": "example.com",
      "source_ip": "192.168.56.10",
      "dest_ip": "93.184.216.34",
      "protocol": "HTTPS",
      "port": 443
    }
  ]
}
```

Kết quả mong đợi:
- API trả 201/202 hoặc success theo controller.
- Log được lưu MongoDB.
- Event `new_log` emit.

### TC-LOG-002 - Push log thiếu field optional

Mức ưu tiên: `P1`

Bước test:
1. POST log chỉ có `agent_id`, `timestamp`, `action`, `level`.
2. Query list logs.

Kết quả mong đợi:
- Server không 500.
- Missing fields được fill hoặc hiển thị `unknown` theo format.
- UI Logs dựng detail text có ích thay vì chỉ `"Log entry"`.

### TC-LOG-003 - List/filter logs

Mức ưu tiên: `P0`

Bước test:
1. Tạo logs `ALLOWED`, `BLOCKED`, `OBSERVED`, nhiều domain/agent.
2. GET `/api/logs?action=BLOCKED`.
3. GET `/api/logs?agent_id=<id>`.
4. GET `/api/logs?search=example`.
5. Mở `/logs` và dùng filter/search UI.

Kết quả mong đợi:
- API trả đúng tập logs.
- UI hiển thị action/domain/source/destination/detail chính xác.
- Search client-side cũng tìm theo detail text.

### TC-LOG-004 - Teacher logs filtering

Mức ưu tiên: `P0`

Bước test:
1. Agent A ở Lab A, Agent B ở Lab B, logs cho cả hai.
2. teacher_a GET `/api/logs`.
3. teacher_a GET `/api/logs/stats`.

Kết quả mong đợi:
- Teacher chỉ thấy logs của Agent A.
- Stats chỉ tính Lab A.

### TC-LOG-005 - Clear/export logs permission

Mức ưu tiên: `P0`

Bước test:
1. teacher_a gọi `GET /api/logs/export`.
2. teacher_a gọi `DELETE /api/logs/clear`.
3. admin gọi export JSON/CSV.
4. admin clear selected/all/old logs.

Kết quả mong đợi:
- Teacher bị 403 cho export/clear.
- Admin export được file đúng format.
- Admin clear đúng filter, emit `logs_cleared`.

### TC-LOG-006 - XSS safety trong log details

Mức ưu tiên: `P0`

Bước test:
1. Gửi log có `domain` hoặc `message` chứa `<script>alert(1)</script>`.
2. Mở `/logs`, view detail modal.

Kết quả mong đợi:
- Không execute script.
- Text được escape.
- Search/render không phá layout.

## 13. Test Audit

### TC-AUD-001 - Ghi audit cho thao tác quản trị

Mức ưu tiên: `P1`

Bước test:
1. Admin tạo user, đổi user, reset password.
2. GET `/api/admin/audit`.
3. GET `/api/admin/audit/user/<user_id>`.

Kết quả mong đợi:
- Audit có action/resource/user/timestamp.
- User activity trả log tương ứng.

### TC-AUD-002 - Teacher không đọc audit nếu không có permission

Mức ưu tiên: `P0`

Bước test:
1. Login teacher.
2. GET `/api/admin/audit`.

Kết quả mong đợi:
- Trả 403.

## 14. Test SocketIO realtime

### TC-RT-001 - Connect và ping/pong

Mức ưu tiên: `P1`

Bước test:
1. Dùng browser hoặc socket.io client connect Server.
2. Listen `server_message`.
3. Emit `ping` với payload mẫu.
4. Listen `pong`.

Kết quả mong đợi:
- Nhận welcome `server_message`.
- Nhận `pong` có timestamp và client_data.

### TC-RT-002 - Agent realtime events

Mức ưu tiên: `P1`

Bước test:
1. Socket client listen `agent_registered`, `agent_heartbeat`, `agent_group_updated`, `agent_policy_changed`, `agent_deleted`.
2. Thực hiện register/heartbeat/update group/update policy/delete.

Kết quả mong đợi:
- Event tương ứng được emit với payload có agent_id/status/group/policy.

### TC-RT-003 - Whitelist/log/user/API key events

Mức ưu tiên: `P1`

Bước test:
1. Listen `whitelist_added`, `whitelist_updated`, `whitelist_deleted`, `whitelist_bulk_added`, `new_log`, `logs_cleared`, `user_created`, `api_key_created`, `api_key_revoked`.
2. Thực hiện từng thao tác tương ứng.

Kết quả mong đợi:
- Event phát đúng một lần hoặc theo thiết kế hiện tại.
- Payload không chứa secret plaintext ngoài trường hợp tạo API key response HTTP.

## 15. Test Web Dashboard và frontend pages

### TC-WEB-001 - Login page và auth guard

Mức ưu tiên: `P0`

Bước test:
1. Mở `/login`.
2. Login sai.
3. Login đúng admin.
4. Reload `/`, `/agents`, `/groups`, `/whitelist`, `/logs`, `/api-keys`, `/admin/users`, `/admin/audit`, `/profile`.
5. Logout.

Kết quả mong đợi:
- Login sai hiển thị lỗi.
- Login đúng chuyển dashboard.
- Các page load data qua API.
- Logout xóa session, quay lại login hoặc API báo unauthorized.

### TC-WEB-002 - Dashboard stats và realtime

Mức ưu tiên: `P1`

Bước test:
1. Mở dashboard bằng admin.
2. Register/heartbeat agent.
3. Push logs.
4. Add whitelist.

Kết quả mong đợi:
- Stat cards agents/logs/allowed/blocked cập nhật sau API fetch hoặc realtime event.
- Không leak stats global trước khi JS áp RBAC cho teacher.

### TC-WEB-003 - Agents page

Mức ưu tiên: `P1`

Bước test:
1. Mở `/agents`.
2. Filter theo status/group/search.
3. Đổi display name.
4. Đổi position/layout nếu UI hỗ trợ.
5. Đổi group bằng admin.
6. Đổi policy.

Kết quả mong đợi:
- List đúng dữ liệu.
- Update thành công phản ánh ngay trên UI.
- Teacher không thấy hoặc không thao tác agent ngoài group.

### TC-WEB-004 - Groups và group detail

Mức ưu tiên: `P1`

Bước test:
1. Mở `/groups`.
2. Tạo/sửa/xóa group.
3. Mở `/groups/<id>`.
4. Assign teacher/agent nếu UI hỗ trợ.

Kết quả mong đợi:
- UI gọi đúng API.
- Detail page hiển thị group và agents.
- Xóa group xử lý agent chuyển pending.

### TC-WEB-005 - Whitelist page

Mức ưu tiên: `P1`

Bước test:
1. Mở `/whitelist`.
2. Add domain/IP/pattern.
3. Import danh sách.
4. Export JSON/TXT.
5. Bulk select/update/delete.
6. Search/filter/category.

Kết quả mong đợi:
- UI không lỗi, hiển thị count/stat đúng.
- Validation rõ ràng với input sai.
- RBAC teacher được áp dụng.

### TC-WEB-006 - Logs page

Mức ưu tiên: `P1`

Bước test:
1. Mở `/logs`.
2. Filter action/date/agent/search.
3. View detail log.
4. Export/clear bằng admin.
5. Thử export/clear bằng teacher.

Kết quả mong đợi:
- Detail text rõ ràng cho log placeholder.
- XSS escaped.
- Teacher bị chặn export/clear.

### TC-WEB-007 - Admin users, audit, profile

Mức ưu tiên: `P1`

Bước test:
1. Mở `/admin/users`, tạo/sửa/disable/reset password.
2. Mở `/admin/audit`, filter audit.
3. Mở `/profile`, đổi email, đổi password.

Kết quả mong đợi:
- Page admin chỉ thao tác được bằng admin.
- Profile update và password change đúng validation.

## 16. Test Agent GUI PySide6

### TC-GUI-001 - Launch GUI source mode

Mức ưu tiên: `P0`

Bước test:
1. Chạy `python agent/agent_gui.py`.
2. Quan sát cửa sổ SAINT.
3. Đổi qua các tab Dashboard, Firewall Rules, IP Whitelist, Logs, Settings.

Kết quả mong đợi:
- App không crash do import.
- Sidebar hiển thị đủ 5 view.
- Không còn dependency UI cũ dựa trên Tk.
- Icon app load nếu `miku.ico` tồn tại.

### TC-GUI-002 - Settings load/save encrypted config

Mức ưu tiên: `P0`

Bước test:
1. Mở Settings.
2. Nhập Server URL, API key, intervals/log level/firewall options.
3. Save.
4. Kiểm tra file config `.enc` được tạo/cập nhật.
5. Restart GUI, kiểm tra config được load lại.

Kết quả mong đợi:
- Save thành công.
- Plaintext secret không nằm trong file config plaintext nếu crypto path hoạt động.
- `server.urls` đồng bộ theo server URL đã nhập.

### TC-GUI-003 - Dashboard Start/Stop offline mode

Mức ưu tiên: `P0`

Điều kiện:
- Không cấu hình server URL hoặc server tắt.

Bước test:
1. Click Start.
2. Quan sát status.
3. Click Stop.

Kết quả mong đợi:
- Agent không crash.
- Status `degraded` hoặc thông báo offline/missing config.
- Issues hiện trong activity log.
- Stop chuyển về stopped và cleanup.

### TC-GUI-004 - Dashboard Start/Stop online mode

Mức ưu tiên: `P0`

Điều kiện:
- Server chạy, API key hợp lệ, Agent chạy Admin nếu test firewall.

Bước test:
1. Cấu hình Settings.
2. Click Start.
3. Chờ register/sync/firewall/sniffer/heartbeat.
4. Quan sát cards: status, registration, firewall, whitelist counts, logs queue, uptime.
5. Click Stop.

Kết quả mong đợi:
- Status running hoặc degraded nếu non-critical component lỗi.
- Server thấy agent online.
- Whitelist data xuất hiện.
- Stop flush log, stop heartbeat/sniffer, cleanup firewall.

### TC-GUI-005 - Double click Start/Stop race

Mức ưu tiên: `P0`

Bước test:
1. Click Start nhiều lần liên tiếp.
2. Click Stop rồi Start ngay.
3. Lặp 3 lần.

Kết quả mong đợi:
- Không spawn nhiều worker song song.
- UI hiển thị message chờ stop nếu cleanup chưa xong.
- Status cuối cùng đúng với thao tác cuối.

### TC-GUI-006 - Signal bridge không freeze UI

Mức ưu tiên: `P1`

Bước test:
1. Khi agent chạy, tạo nhiều events stats/log/packet.
2. Quan sát dashboard/logs trong 1-2 phút.
3. Thử kéo/resize window, đổi tab.

Kết quả mong đợi:
- UI vẫn phản hồi.
- Signal events vào đúng view.
- Không thấy exception do update widget từ worker thread.

### TC-GUI-007 - Whitelist view

Mức ưu tiên: `P1`

Bước test:
1. Start agent online.
2. Mở IP Whitelist.
3. Click Sync/Refresh.
4. Search domain/IP.
5. Toggle resolved IPs.

Kết quả mong đợi:
- Table hiển thị domains/patterns/IPs từ Server.
- Sync cập nhật dữ liệu mới.
- Search debounce không gọi controller mỗi keystroke.
- Resolved IPs hiển thị khi DNS resolve được, không crash khi resolve fail.

### TC-GUI-008 - Firewall view

Mức ưu tiên: `P1`

Bước test:
1. Mở Firewall view trước khi Start.
2. Quan sát fallback netsh.
3. Start agent.
4. Quay lại Firewall view.

Kết quả mong đợi:
- Trước Start không crash dù chưa có manager.
- Sau Start, view nhận live `FirewallManager`.
- Rule count/policy/mode cập nhật.
- Timer refresh dừng khi hide view.

### TC-GUI-009 - Logs view local handler

Mức ưu tiên: `P1`

Bước test:
1. Mở Logs view.
2. Start/Stop agent để tạo Python logs.
3. Filter level, search text.
4. Export CSV.
5. Clear logs.
6. Đóng app.

Kết quả mong đợi:
- Logs local xuất hiện.
- Filter/search đúng.
- Export tạo file hợp lệ.
- Clear xóa history UI.
- Khi đóng app, `GUILogHandler` được cleanup, không crash do dangling Qt object.

### TC-GUI-010 - Settings manual firewall restore

Mức ưu tiên: `P0`

Bước test:
1. Chạy GUI bằng quyền Admin.
2. Start agent để tạo snapshot/rules.
3. Vào Settings, click Restore firewall.
4. Kiểm tra Windows Firewall outbound policy và SAINT rules.

Kết quả mong đợi:
- Nếu agent đang chạy, ưu tiên `FirewallManager.restore_snapshot`.
- Nếu không có live manager, fallback netsh thủ công.
- Restore không re-enable whitelist mode.
- Không còn SAINT rules ngoài mong đợi.

## 17. Test Agent lifecycle, config, token

### TC-CORE-001 - Device identity ổn định

Mức ưu tiên: `P1`

Bước test:
1. Import `core.AGENT_DEVICE_ID`.
2. Restart agent process.
3. So sánh device_id.

Kết quả mong đợi:
- Cùng máy trả cùng device_id.
- Hostname fallback không rỗng.

### TC-CORE-002 - Config load, env override, validation

Mức ưu tiên: `P1`

Bước test:
1. Chạy với config mặc định.
2. Set env `FC_SERVER__URL=http://localhost:5000`.
3. Reload config.
4. Set firewall mode sai.
5. Reload config.

Kết quả mong đợi:
- Env override file/default.
- `server.urls` đồng bộ với `server.url`.
- Firewall mode bị coerce về `whitelist_only`.

### TC-CORE-003 - Token auto refresh

Mức ưu tiên: `P0`

Bước test:
1. Register agent lấy token.
2. Gán access token gần hết hạn hoặc test qua refresh endpoint.
3. Gọi `TokenManager.refresh_now()`.
4. Gọi heartbeat/log/sync sau refresh.

Kết quả mong đợi:
- Token mới lưu vào config.
- Auth header dùng JWT mới.
- Nếu refresh token invalid, `needs_reregistration` bật và lifecycle có thể re-register.

### TC-CORE-004 - Cleanup idempotent

Mức ưu tiên: `P0`

Bước test:
1. Start agent.
2. Stop agent.
3. Gọi stop/cleanup thêm lần nữa.
4. Start lại.

Kết quả mong đợi:
- Cleanup không throw fatal exception.
- Threads dừng.
- Start lại được.

## 18. Test Windows Firewall enforcement

Lưu ý: nhóm test này cần máy Windows test/VM và quyền Administrator. Trước khi test, ghi lại policy hiện tại:

```powershell
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all | findstr SAINT
```

### TC-FW-001 - Snapshot trước khi bật whitelist mode

Mức ưu tiên: `P0`

Bước test:
1. Start agent Admin.
2. Kiểm tra file `%LOCALAPPDATA%\SAINT\profiles\backup.saint-snapshot.json`.
3. Stop agent.

Kết quả mong đợi:
- Snapshot được tạo atomic.
- Stop/cleanup restore về baseline.
- Nếu snapshot đã có, không overwrite khi `force=False`.

### TC-FW-002 - Enable whitelist mode không tự khóa Server/DNS

Mức ưu tiên: `P0`

Bước test:
1. Cấu hình Server URL.
2. Whitelist có ít nhất một domain allowed.
3. Start agent Admin.
4. Kiểm tra netsh rules có self-allow, DNS, server IP, whitelist IP.
5. Ping/curl Server.
6. DNS resolve domain allowed.

Kết quả mong đợi:
- Default Deny bật sau khi allow rules được tạo.
- Agent vẫn heartbeat được.
- DNS vẫn hoạt động.

### TC-FW-003 - Update whitelist diff

Mức ưu tiên: `P0`

Bước test:
1. Start agent với whitelist A.
2. Trên Server thêm IP/domain B.
3. Trigger agent sync.
4. Xóa A.
5. Kiểm tra rules.

Kết quả mong đợi:
- Rule B được thêm.
- Rule A được xóa.
- Không recreate toàn bộ rules không cần thiết ngoài design.

### TC-FW-004 - Restore snapshot safety

Mức ưu tiên: `P0`

Bước test:
1. Bật whitelist mode.
2. Gọi restore snapshot.
3. Kiểm tra outbound policy.
4. Kiểm tra SAINT rules.

Kết quả mong đợi:
- Policy trở về baseline hoặc allowoutbound safety nếu snapshot nguy hiểm.
- SAINT rules được clear.
- Không re-enable whitelist mode sau restore.

### TC-FW-005 - Non-admin passive/degraded mode

Mức ưu tiên: `P1`

Bước test:
1. Chạy Agent không Administrator.
2. Click Start.
3. Kiểm tra Dashboard/Firewall view.

Kết quả mong đợi:
- Agent không cố áp firewall gây lỗi không kiểm soát.
- Status degraded/passive rõ ràng.
- Sniffer/logging vẫn có thể hoạt động nếu dependencies đủ.

## 19. Test DNS, packet capture và network log

### TC-NET-001 - DNS resolver single/parallel/cache

Mức ưu tiên: `P1`

Bước test:
1. Resolve `example.com`.
2. Resolve list nhiều domains.
3. Resolve domain invalid.
4. Kiểm tra cache TTL/expiring keys nếu qua WhitelistManager.

Kết quả mong đợi:
- Domain hợp lệ có IPv4.
- Domain invalid không crash.
- Parallel resolve nhanh hơn tuần tự với nhiều domain.

### TC-NET-002 - Domain extractor DNS/HTTP/TLS SNI

Mức ưu tiên: `P1`

Bước test:
1. Tạo traffic DNS query tới domain allowed/blocked.
2. Tạo HTTP request có Host header.
3. Tạo HTTPS request có SNI.
4. Quan sát Agent logs/Server logs.

Kết quả mong đợi:
- Extract đúng domain khi packet có dữ liệu.
- Không crash với packet không parse được.
- Log action theo whitelist state.

### TC-NET-003 - Allowed/Blocked/Observed action mapping

Mức ưu tiên: `P0`

Bước test:
1. Firewall enabled, truy cập domain whitelisted.
2. Firewall enabled, truy cập domain không whitelist.
3. Firewall disabled/non-admin, truy cập domain.
4. Trường hợp IP whitelisted nhưng domain không whitelist.

Kết quả mong đợi:
- Whitelisted: `ALLOWED`, level INFO.
- Không whitelist: `BLOCKED`, level BLOCKED.
- Passive: `OBSERVED`.
- IP allowed nhưng domain không: `ALLOWED_BY_IP`, level WARNING.

### TC-NET-004 - LogSender queue/batch/flush

Mức ưu tiên: `P1`

Bước test:
1. Tạo nhiều log records qua handler.
2. Kiểm tra queue size và batch send.
3. Stop agent khi queue còn log.

Kết quả mong đợi:
- Batch gửi `/api/logs`.
- Queue full trả false/drop có warning.
- Stop flush queue trước khi thread dừng.

## 20. Test end-to-end chính

### TC-E2E-001 - Admin cấu hình lab và Agent nhận whitelist

Mức ưu tiên: `P0`

Bước test:
1. Server chạy sạch DB.
2. Login admin.
3. Tạo teacher_a.
4. Tạo Lab A, assign teacher_a.
5. Tạo API key agent_register.
6. Chạy Agent A, cấu hình Server URL/API key.
7. Start Agent.
8. Admin chuyển Agent A vào Lab A.
9. Admin/teacher thêm whitelist `example.com`.
10. Agent sync.
11. Truy cập `example.com`.
12. Truy cập domain blocked.
13. Xem logs trên web.

Kết quả mong đợi:
- Agent register và online.
- Agent nằm trong Lab A.
- Whitelist sync về Agent.
- Allowed domain đi qua, blocked domain bị log/block tùy enforcement.
- Web logs có action đúng.
- Teacher_a thấy Agent/logs Lab A; teacher_b không thấy.

### TC-E2E-002 - Policy/profile realtime update

Mức ưu tiên: `P1`

Bước test:
1. Agent đang chạy trong Lab A.
2. Teacher tạo profile Lab A gồm domain set 1, activate.
3. Agent sync và kiểm tra whitelist set 1.
4. Teacher tạo profile set 2, activate.
5. Agent heartbeat/sync.

Kết quả mong đợi:
- Active profile thay đổi whitelist hiệu lực.
- Version bump làm Agent nhận update.
- Realtime event `whitelist_updated` phát cho web.

### TC-E2E-003 - Token expired và re-register

Mức ưu tiên: `P1`

Bước test:
1. Agent chạy online.
2. Revoke refresh token hoặc làm token invalid.
3. Chờ/gọi sync/heartbeat/log send.
4. Khôi phục API key hợp lệ để Agent re-register.

Kết quả mong đợi:
- Request JWT invalid bị 401.
- Agent không crash.
- TokenManager đánh dấu cần re-register.
- Sau re-register, heartbeat/sync hoạt động lại.

### TC-E2E-004 - Server down rồi lên lại

Mức ưu tiên: `P0`

Bước test:
1. Agent chạy online.
2. Tắt Server.
3. Quan sát Agent GUI/logs 2-3 heartbeat interval.
4. Bật Server lại.
5. Trigger sync hoặc chờ heartbeat.

Kết quả mong đợi:
- Agent chuyển degraded/offline warning, không crash.
- Queue/log behavior đúng.
- Khi Server lên, Agent gửi heartbeat/sync lại.

## 21. Test bảo mật và negative cases

### TC-SEC-001 - Unauthorized API

Mức ưu tiên: `P0`

Bước test:
1. Gọi các API login-required không cookie/token.
2. Gọi JWT-required endpoint bằng cookie admin.
3. Gọi admin endpoint bằng JWT agent.

Kết quả mong đợi:
- Đúng loại auth mới được phép.
- Không endpoint nào nhầm quyền agent/admin.

### TC-SEC-002 - ObjectId/path invalid

Mức ưu tiên: `P1`

Bước test:
1. Gọi `/api/agents/not-an-id`.
2. Gọi `/api/groups/not-an-id`.
3. Gọi delete whitelist với id sai.

Kết quả mong đợi:
- Trả 400/404 rõ ràng.
- Không 500 stack trace.

### TC-SEC-003 - Payload lớn và field lạ

Mức ưu tiên: `P1`

Bước test:
1. Gửi whitelist bulk max 1000 và 1001.
2. Gửi user update có field không allow như `password_hash`, `role=superadmin`.
3. Gửi log batch rất lớn.

Kết quả mong đợi:
- Limit được enforce.
- Field không allow bị bỏ qua hoặc reject.
- Không ghi field nhạy cảm ngoài schema.

### TC-SEC-004 - CORS và cookie flags

Mức ưu tiên: `P2`

Bước test:
1. Kiểm tra response preflight OPTIONS cho `/api/*`.
2. Kiểm tra cookie attributes sau login.

Kết quả mong đợi:
- CORS đúng theo config hiện tại.
- Cookie httpOnly, sameSite Lax.
- Ghi chú production: `secure=True` cần bật khi dùng HTTPS.

## 22. Test performance, tải và độ ổn định

### TC-PERF-001 - DataTable/GUI nhiều rows

Mức ưu tiên: `P1`

Bước test:
1. Tạo 5.000 whitelist/log rows mock hoặc server data.
2. Mở WhitelistView/LogsView.
3. Search/filter/scroll.

Kết quả mong đợi:
- PySide6 `QTableView` render mượt, không freeze dài.
- Search debounce hoạt động.

### TC-PERF-002 - Heartbeat nhiều agents

Mức ưu tiên: `P1`

Bước test:
1. Script giả lập 50-200 agents register.
2. Gửi heartbeat mỗi 20s.
3. Mở dashboard/agents page.

Kết quả mong đợi:
- Server không lỗi 500.
- Agent statistics đúng.
- SocketIO event không làm UI treo.

### TC-PERF-003 - Log volume burst

Mức ưu tiên: `P1`

Bước test:
1. Gửi batch logs lớn theo nhiều request.
2. Query logs/stats/export.
3. Mở Logs page.

Kết quả mong đợi:
- Batch insert ổn định.
- Pagination/filter không timeout bất thường.
- Logs page không render quá chậm.

## 23. Test deployment/build

### TC-DEP-001 - Server Docker build/run

Mức ưu tiên: `P1`

Bước test:
1. `cd server`.
2. `docker compose up -d --build`.
3. Gọi `/api/health`.
4. Xem logs container.

Kết quả mong đợi:
- Image build thành công.
- Server đọc env đúng.
- Health trả healthy.

### TC-DEP-002 - PyInstaller Agent build

Mức ưu tiên: `P1`

Bước test:
1. `cd agent`.
2. Chạy PyInstaller với `saint_agent.spec`.
3. Mở `dist/SAINT.exe`.
4. Kiểm tra UAC admin prompt.
5. Chạy smoke test GUI.

Kết quả mong đợi:
- Bundle build không thiếu PySide6 plugins, Scapy runtime data và runtime mạng cần thiết.
- Không có console window.
- App yêu cầu admin.
- GUI launch và Start/Stop được.

### TC-DEP-003 - Fresh machine install

Mức ưu tiên: `P2`

Bước test:
1. Dùng máy Windows sạch/VM sạch.
2. Cài agent dependencies hoặc chạy exe.
3. Cấu hình Server/API key.
4. Start/Stop agent.

Kết quả mong đợi:
- Không thiếu runtime DLL/plugin.
- Nếu thiếu WinPcap/Npcap/driver, Agent báo lỗi rõ hoặc degraded.

## 24. Test hồi quy tự động hiện có

### TC-AUTO-001 - Chạy toàn bộ pytest Server

Mức ưu tiên: `P0`

Bước test:
1. Đảm bảo MongoDB chạy.
2. `cd server`.
3. `python -m pytest tests/ -v`.

Kết quả mong đợi:
- 7 file tests pass:
  - `test_agents.py`
  - `test_agent_full.py`
  - `test_audit.py`
  - `test_groups.py`
  - `test_teacher_data_filtering.py`
  - `test_users_auth.py`
  - `test_whitelist_and_logs.py`

### TC-AUTO-002 - Chạy riêng test RBAC thường xuyên

Mức ưu tiên: `P0`

Bước test:
1. `python -m pytest tests/test_teacher_data_filtering.py -v`.

Kết quả mong đợi:
- Tất cả test Teacher filtering pass.
- Không regression về leak dữ liệu cross-group.

### TC-AUTO-003 - Chạy test theo module sau thay đổi

Mức ưu tiên: `P1`

| Khi sửa | Chạy tối thiểu |
|---|---|
| `server/controllers/agent_controller.py`, `agent_service.py` | `test_agents.py`, `test_agent_full.py` |
| `server/controllers/whitelist_controller.py`, `whitelist_service.py` | `test_whitelist_and_logs.py`, `test_teacher_data_filtering.py` |
| `server/controllers/log_controller.py`, `log_service.py` | `test_whitelist_and_logs.py`, `test_teacher_data_filtering.py` |
| `server/controllers/group_controller.py`, `group_service.py` | `test_groups.py`, `test_teacher_data_filtering.py` |
| `server/controllers/user_controller.py`, auth/RBAC | `test_users_auth.py`, `test_audit.py`, `test_teacher_data_filtering.py` |
| `agent/controllers`, `agent/gui_qt` | Manual GUI smoke + Start/Stop + Settings save + Logs cleanup |
| `agent/firewall`, `agent/whitelist`, `agent/network` | Manual Windows Admin firewall/sync test |

## 25. Checklist nghiệm thu cuối

| Mục | Pass/Fail | Ghi chú |
|---|---|---|
| Server khởi động, health/config OK |  |  |
| Admin login/logout/refresh OK |  |  |
| Teacher RBAC không leak group khác |  |  |
| User management OK |  |  |
| API key create/validate/revoke OK |  |  |
| Group CRUD/assign teacher OK |  |  |
| Agent register/heartbeat/status OK |  |  |
| Agent policy OK |  |  |
| Whitelist CRUD/import/export/bulk OK |  |  |
| Agent sync whitelist đúng version/group |  |  |
| Whitelist profile activate/deactivate OK |  |  |
| Logs receive/list/filter/export/clear OK |  |  |
| Audit OK |  |  |
| SocketIO connect/ping/realtime events OK |  |  |
| Web pages render và JS gọi API đúng |  |  |
| Agent GUI launch và 5 tabs OK |  |  |
| Agent Settings save encrypted config OK |  |  |
| Agent online/degraded/offline behavior OK |  |  |
| Windows Firewall enable/update/restore OK |  |  |
| DNS/sniffer/domain extraction/log sender OK |  |  |
| Server Docker build/run OK |  |  |
| Agent PyInstaller build/run OK |  |  |
| Pytest server pass |  |  |

## 26. Ghi chú rủi ro khi test thật

- Test firewall phải có kế hoạch restore mạng: giữ quyền admin, snapshot VM hoặc lệnh `netsh advfirewall reset` trong trường hợp khẩn cấp.
- Không chạy enforcement trên máy cá nhân đang cần mạng ổn định nếu chưa xác nhận whitelist có Server/DNS/self-allow.
- Test API key phải lưu plaintext key ngay sau khi tạo; list API key không hiển thị lại secret.
- Test Teacher RBAC là nhóm bắt buộc vì lỗi ở đây là lỗi bảo mật, không chỉ lỗi UI.
- Test SocketIO bằng browser thật hoặc socket client riêng vì pytest hiện tại chủ yếu assert service/controller, chưa cover client nhận event thật.
