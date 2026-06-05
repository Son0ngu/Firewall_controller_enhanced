# SAINT Server -  Tài Liệu Kỹ Thuật

## 1. Tổng quan

SAINT Server là thành phần quản lý tập trung của hệ thống, cung cấp:
-  **REST API** cho Agent giao tiếp (đăng ký, heartbeat, sync whitelist, gửi logs)
-  **Web Dashboard** cho Admin/Teacher quản lý (agents, whitelists, groups, users)
-  **WebSocket** (Flask- SocketIO) cho real- time notifications
-  **RBAC** phân quyền Admin/Teacher

### Công nghệ
-  **Framework:** Flask + Flask- SocketIO (Gevent async)
-  **Database:** MongoDB Atlas (PyMongo)
-  **Auth:** JWT (PyJWT) + API Key (HMAC- SHA256) + bcrypt
-  **Validation:** Pydantic

- - - 

## 2. Cấu trúc thư mục

```
server/
├── app.py                          # Khởi tạo Flask app, đăng ký routes
├── time_utils.py                   # Hàm thời gian (timezone Việt Nam)
├── requirements.txt                # Dependencies
├── .env                            # Biến môi trường
│
├── config/
│   └── rbac_config.py              # Cấu hình RBAC (roles, permissions)
│
├── database/
│   └── config.py                   # Kết nối MongoDB, khởi tạo indexes
│
├── models/                         # Tầng dữ liệu (MongoDB CRUD)
│   ├── agent_model.py              # Agent: đăng ký, heartbeat, trạng thái
│   ├── log_model.py                # Logs: hoạt động mạng từ agent
│   ├── whitelist_model.py          # Whitelist: domain/IP được phép
│   ├── group_model.py              # Group: nhóm agent + whitelist
│   ├── user_model.py               # User: tài khoản Admin/Teacher
│   ├── session_model.py            # Session: phiên đăng nhập
│   ├── api_key_model.py            # API Key: key đăng ký agent
│   ├── agent_policy_model.py       # Policy: chính sách riêng từng agent
│   ├── whitelist_profile_model.py  # Profile: whitelist mẫu của teacher
│   └── audit_model.py              # Audit: lịch sử hành động
│
├── services/                       # Tầng business logic
│   ├── agent_service.py            # Xử lý agent lifecycle
│   ├── log_service.py              # Xử lý logs
│   ├── whitelist_service.py        # CRUD whitelist + sync
│   ├── group_service.py            # Quản lý group
│   ├── jwt_service.py              # Tạo/verify JWT token
│   ├── api_key_service.py          # Quản lý API key
│   ├── admin_auth_service.py       # Đăng nhập Admin/Teacher
│   ├── user_service.py             # CRUD user
│   ├── rbac_service.py             # Kiểm tra quyền RBAC
│   ├── audit_service.py            # Ghi audit log
│   ├── agent_policy_service.py     # Quản lý policy
│   └── whitelist_profile_service.py# Quản lý profile
│
├── controllers/                    # Tầng API endpoints
│   ├── agent_controller.py         # /api/agents/*
│   ├── whitelist_controller.py     # /api/whitelist/*
│   ├── log_controller.py           # /api/logs/*
│   ├── group_controller.py         # /api/groups/*
│   ├── auth_controller.py          # /api/auth/* (agent token, AgentAuthController; alias AuthController)
│   ├── web_auth_controller.py      # /api/admin/auth/* (WebAuthController — đổi tên từ AdminAuthController)
│   ├── admin_auth_controller.py    # shim: re-export WebAuthController + alias AdminAuthController
│   ├── user_controller.py          # /api/admin/users/*
│   ├── api_key_controller.py       # /api/api- keys/*
│   ├── audit_controller.py         # /api/admin/audit/*
│   └── whitelist_profile_controller.py # /api/whitelist- profiles/*
│
├── middleware/
│   ├── auth.py                     # Xác thực API Key + JWT cho Agent
│   └── rbac.py                     # Xác thực JWT cookie + inject user cho Web
│
├── views/                          # HTML templates + static files
│   ├── templates/                  # Jinja2 templates
│   └── static/                     # CSS, JS, images
│
└── tests/                          # Unit tests (pytest)
    ├── test_agents.py
    ├── test_agent_full.py
    ├── test_users_auth.py
    ├── test_groups.py
    ├── test_whitelist_and_logs.py
    ├── test_audit.py
    └── test_teacher_data_filtering.py
```

- - - 

## 3. Database Schema (MongoDB)

### 3.1 Collection `agents`
Lưu thông tin các Agent đã đăng ký.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `_id` | ObjectId | ID tự động |
| `agent_id` | string | ID duy nhất của agent |
| `device_id` | string | ID phần cứng máy tính |
| `hostname` | string | Tên máy tính |
| `ip_address` | string | Địa chỉ IP |
| `group_id` | string | Nhóm agent thuộc về |
| `display_name` | string | Tên hiển thị (tùy chỉnh) |
| `last_heartbeat` | datetime | Thời điểm heartbeat cuối |
| `status` | string | Trạng thái (active/inactive/offline) |
| `agent_token` | string | Token xác thực (legacy) |
| `registered_at` | datetime | Thời điểm đăng ký |
| `platform` | string | Hệ điều hành |
| `metrics` | object | CPU, memory, uptime |
| `position` | object | Vị trí trên bản đồ (x, y) |

**Trạng thái Agent:**
-  `active`: heartbeat ≤ 5 phút trước
-  `inactive`: heartbeat 5- 30 phút trước
-  `offline`: heartbeat > 30 phút hoặc chưa heartbeat

### 3.2 Collection `groups`
Nhóm Agent (thường theo lớp học/phòng lab).

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `_id` | ObjectId | ID tự động |
| `name` | string | Tên nhóm |
| `description` | string | Mô tả |
| `whitelist` | array | Danh sách whitelist IDs |
| `teacher_ids` | array | IDs giáo viên được gán |
| `created_by` | string | User ID người tạo |
| `whitelist_version` | int | Version whitelist (tăng khi thay đổi) |
| `created_at` | datetime | Thời điểm tạo |
| `updated_at` | datetime | Thời điểm cập nhật |

### 3.3 Collection `whitelists`
Danh sách domain/IP được phép truy cập.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `_id` | ObjectId | ID tự động |
| `value` | string | Domain hoặc IP (vd: google.com) |
| `type` | string | Loại: domain, ip, pattern |
| `scope` | string | Phạm vi: global hoặc group |
| `group_id` | string | ID nhóm (nếu scope = group) |
| `is_active` | bool | Đang hoạt động hay không |
| `expiry_date` | datetime | Ngày hết hạn (nullable) |
| `added_by` | string | User ID người thêm |
| `added_date` | datetime | Thời điểm thêm |
| `description` | string | Ghi chú |

### 3.4 Collection `logs`
Logs hoạt động mạng từ Agent gửi về.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `_id` | ObjectId | ID tự động |
| `agent_id` | string | Agent gửi log |
| `action` | string | `ALLOWED` / `ALLOWED_BY_IP` / `BLOCKED` / `OBSERVED` |
| `level` | string | `INFO` / `WARNING` / `BLOCKED` / `ERROR` |
| `domain` | string | Domain được truy cập (từ DNS/HTTP Host/TLS SNI) |
| `destination` | string | Domain hoặc dest_ip nếu không có domain |
| `domain_allowed` | bool | Cờ: domain có trong whitelist? |
| `ip_allowed` | bool | Cờ: dest_ip có trong whitelist? |
| `timestamp` | datetime | Thời điểm (Asia/Ho_Chi_Minh) |
| `protocol` | string | HTTPS/HTTP/DNS/TCP |
| `port` | string | Port (80, 443, 53...) |
| `source_ip` | string | IP nguồn (local IP của máy) |
| `dest_ip` | string | IP đích (đã pass Layer 3 firewall) |
| `firewall_mode` | string | `whitelist_only` |
| `firewall_enabled` | bool | Firewall đang enforce? |
| `admin_privileges` | bool | Agent có quyền admin? |
| `agent_host` | string | Hostname của máy chạy agent |
| `server_received_at` | datetime | Thời điểm server nhận log |

**Compliance levels - Preventive + Detective model:**

`action` value được agent gán trong [agent/core/handlers.py](../agent/core/handlers.py)
dựa trên kết quả của 2 lớp kiểm tra song song:

| `action` | `level` | Khi nào xảy ra |
|- - - - - - - - - - |- - - - - - - - - |- - - - - - - - - - - - - - - - |
| `ALLOWED` | `INFO` | Domain match explicit whitelist - compliant access |
| `ALLOWED_BY_IP` | `WARNING` | IP whitelisted nhưng SNI/Host header chỉ tới domain **không** có trong whitelist → CDN shared IP bleed- through. **Detective signal** để admin review |
| `BLOCKED` | `BLOCKED` | Cả domain và IP đều không match - Windows Firewall đã chặn ở Layer 3 |
| `OBSERVED` | `INFO`/`WARNING` | Agent passive mode (không có admin để enforce) |

### 3.5 Collection `users`
Tài khoản Admin và Teacher.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `_id` | ObjectId | ID tự động |
| `username` | string | Tên đăng nhập |
| `email` | string | Email |
| `password_hash` | string | Mật khẩu (bcrypt) |
| `role` | string | admin hoặc teacher |
| `full_name` | string | Họ tên |
| `is_active` | bool | Tài khoản hoạt động |
| `failed_login_attempts` | int | Số lần đăng nhập sai |
| `locked_until` | datetime | Khóa đến thời điểm |
| `created_at` | datetime | Thời điểm tạo |

### 3.6 Collection `admin_sessions`
Phiên đăng nhập Admin/Teacher.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `user_id` | string | User ID |
| `access_token_jti` | string | JTI của access token |
| `refresh_token_jti` | string | JTI của refresh token |
| `expires_at` | datetime | Thời điểm hết hạn |
| `is_revoked` | bool | Đã thu hồi chưa |
| `created_at` | datetime | Thời điểm tạo |

### 3.7 Collection `api_keys`
API Key cho Agent đăng ký.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `key_hash` | string | Hash HMAC- SHA256 của key |
| `name` | string | Tên key |
| `is_active` | bool | Đang hoạt động |
| `permissions` | array | Quyền hạn |
| `expires_at` | datetime | Ngày hết hạn |
| `created_by` | string | Admin tạo key |
| `created_at` | datetime | Thời điểm tạo |
| `last_used_at` | datetime | Lần sử dụng cuối |

### 3.8 Collection `agent_policies`
Chính sách riêng cho từng Agent.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `agent_id` | string | Agent áp dụng |
| `override_mode` | string | none / isolate / custom_whitelist |
| `custom_whitelist` | array | Whitelist tùy chỉnh (nếu custom) |
| `expires_at` | datetime | Ngày hết hạn |
| `override_version` | int | Version (để detect thay đổi) |
| `created_by` | string | User tạo |

**Override modes:**
-  `none`: Sử dụng whitelist nhóm (mặc định)
-  `isolate`: Chặn tất cả truy cập mạng
-  `custom_whitelist`: Chỉ cho phép danh sách tùy chỉnh

### 3.9 Collection `whitelist_profiles`
Whitelist mẫu của Teacher (có thể kích hoạt/tắt).

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `group_id` | string | Nhóm áp dụng |
| `teacher_id` | string | Teacher sở hữu |
| `name` | string | Tên profile |
| `domains` | array | Danh sách domain |
| `is_active` | bool | Đang kích hoạt |
| `version` | int | Version |
| `created_at` | datetime | Thời điểm tạo |

### 3.10 Collection `audit_logs`
Lịch sử tất cả hành động Admin/Teacher.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `user_id` | string | Người thực hiện |
| `action` | string | Hành động (user.create, whitelist.update...) |
| `resource_type` | string | Loại tài nguyên |
| `resource_id` | string | ID tài nguyên |
| `details` | object | Chi tiết thay đổi |
| `timestamp` | datetime | Thời điểm |
| `ip_address` | string | IP người thực hiện |

### 3.11 Collection `whitelist_meta`
Theo dõi version whitelist toàn cục.

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `scope` | string | global / group:{id} |
| `version` | int | Version hiện tại |
| `updated_at` | datetime | Thời điểm cập nhật |

### 3.12 Collection `revoked_tokens`
Token đã thu hồi (TTL auto- delete).

| Field | Type | Mô tả |
|- - - - - - - |- - - - - - |- - - - - - - - |
| `jti` | string | Token ID |
| `expires_at` | datetime | Thời điểm hết hạn (TTL index) |

- - - 

## 4. API Endpoints

### 4.1 Agent Registration & Heartbeat

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `POST` | `/api/agents/register` | API Key | Đăng ký agent mới, nhận agent_token |
| `POST` | `/api/agents/heartbeat` | JWT | Gửi heartbeat + logs + metrics |

**POST /api/agents/register**
```json
// Request Headers
{ "X- API- Key": "your- api- key" }

// Request Body
{
  "hostname": "PC- LAB01",
  "device_id": "abc123- hardware- id",
  "ip_address": "192.168.1.100",
  "platform": "Windows 10",
  "is_admin": true
}

// Response 200
{
  "success": true,
  "agent_id": "agent_xxxx",
  "agent_token": "jwt- token- here",
  "message": "Agent registered successfully"
}
```

**POST /api/agents/heartbeat**
```json
// Request Headers
{ "Authorization": "Bearer <jwt- token>" }

// Request Body
{
  "agent_id": "agent_xxxx",
  "hostname": "PC- LAB01",
  "ip_address": "192.168.1.100",
  "status": "online",
  "metrics": { "cpu": 45.2, "memory": 62.1, "uptime": 3600 },
  "logs": [
    { "timestamp": "...", "action": "ALLOWED", "domain": "google.com", "port": 443 }
  ]
}

// Response 200
{
  "success": true,
  "whitelist_version": 5,
  "whitelist_version_changed": true,
  "force_sync": false,
  "policy_version": 2,
  "policy_changed": false
}
```

### 4.2 Agent Management (Admin/Teacher qua Web)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/agents` | Login | Danh sách agents (RBAC filter) |
| `GET` | `/api/agents/<id>` | Login | Chi tiết agent |
| `GET` | `/api/agents/statistics` | Login | Thống kê (active/inactive/offline) |
| `PATCH` | `/api/agents/<id>/display- name` | Login | Đổi tên hiển thị |
| `PATCH` | `/api/agents/<id>/position` | Login | Cập nhật vị trí bản đồ |
| `PATCH` | `/api/agents/<id>/group` | Login | Chuyển agent sang nhóm khác |
| `DELETE` | `/api/agents/<id>` | Admin | Xóa agent |

### 4.3 Agent Policies

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/agents/<id>/policy` | Login | Xem policy của agent |
| `PATCH` | `/api/agents/<id>/policy` | Login | Đặt isolate/custom_whitelist |

### 4.4 Whitelist Management

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/whitelist` | Login | Danh sách whitelist |
| `POST` | `/api/whitelist` | Login | Thêm entry mới |
| `DELETE` | `/api/whitelist/<id>` | Login | Xóa entry |
| `POST` | `/api/whitelist/bulk` | Login | Thêm hàng loạt |
| `POST` | `/api/whitelist/bulk- update` | Login | Cập nhật hàng loạt |
| `POST` | `/api/whitelist/bulk- delete` | Login | Xóa hàng loạt |
| `GET` | `/api/whitelist/agent- sync` | JWT | Agent sync whitelist |
| `GET` | `/api/whitelist/statistics` | Login | Thống kê whitelist |
| `POST` | `/api/whitelist/import` | Login | Import từ CSV |
| `GET` | `/api/whitelist/export` | Login | Export ra CSV |

**GET /api/whitelist/agent- sync** (Agent gọi)
```json
// Response 200
{
  "success": true,
  "whitelist": [
    { "value": "google.com", "type": "domain" },
    { "value": "*.microsoft.com", "type": "pattern" },
    { "value": "192.168.1.10", "type": "ip" }
  ],
  "whitelist_version": 5,
  "active_profile": {
    "name": "Bài thực hành Web",
    "domains": ["w3schools.com", "developer.mozilla.org"]
  },
  "policy": {
    "override_mode": "none",
    "custom_whitelist": [],
    "override_version": 1
  }
}
```

### 4.5 Group Management

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/groups` | Login | Danh sách nhóm |
| `POST` | `/api/groups` | Admin | Tạo nhóm mới |
| `GET` | `/api/groups/<id>` | Login | Chi tiết nhóm |
| `PATCH` | `/api/groups/<id>` | Login | Cập nhật nhóm |
| `DELETE` | `/api/groups/<id>` | Admin | Xóa nhóm |
| `POST` | `/api/groups/<id>/teachers` | Admin | Gán teacher vào nhóm |

### 4.6 Whitelist Profiles (Teacher)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/whitelist- profiles/my- profiles` | Login | Profile của teacher |
| `GET` | `/api/groups/<id>/profiles` | Login | Profile của nhóm |
| `POST` | `/api/groups/<id>/profiles` | Login | Tạo profile |
| `PATCH` | `/api/groups/<id>/profiles/<pid>` | Login | Sửa profile |
| `DELETE` | `/api/groups/<id>/profiles/<pid>` | Login | Xóa profile |
| `POST` | `/api/groups/<id>/profiles/<pid>/activate` | Login | Kích hoạt |
| `POST` | `/api/groups/<id>/profiles/<pid>/deactivate` | Login | Tắt kích hoạt |

### 4.7 Logs

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/logs` | Login | Danh sách logs (RBAC filter) |
| `POST` | `/api/logs` | JWT | Agent gửi logs |
| `GET` | `/api/logs/stats` | Login | Thống kê (allowed/allowed_by_ip/blocked/warnings) |
| `DELETE` | `/api/logs` | Admin | Xóa logs theo filter |
| `DELETE` | `/api/logs/clear` | Admin | Xóa tất cả logs |
| `GET` | `/api/logs/export` | Admin | Export CSV |

**`/api/logs/stats` response schema:**

```json
{
  "total": 12345,
  "allowed": 10200,
  "allowed_by_ip": 87,          // NEW: CDN bleed- through (compliance WARNING)
  "blocked": 1953,
  "warnings": 105,
  // When client applies filters, the same metrics with `filtered_` prefix
  "filtered_total": 200,
  "filtered_allowed": 150,
  "filtered_allowed_by_ip": 12,
  "filtered_blocked": 38,
  "filtered_warnings": 15,
  "has_filters": true,
  "success": true,
  "server_time": "2026- 05- 18T..."
}
```

`allowed_by_ip` là metric **detective** quan trọng: số event mà Layer 3
firewall đã cho qua bằng IP match nhưng Layer 7 sniffer thấy domain
(SNI/Host) không có trong whitelist - dấu hiệu CDN shared IP. Admin theo
dõi metric này để tinh chỉnh policy hoặc handle violations.

### 4.8 Authentication (Admin/Teacher)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `POST` | `/api/admin/auth/login` | None | Đăng nhập |
| `POST` | `/api/admin/auth/logout` | Login | Đăng xuất |
| `GET` | `/api/admin/auth/me` | Login | Thông tin user hiện tại |
| `POST` | `/api/admin/auth/refresh` | Login | Làm mới access token |
| `PATCH` | `/api/admin/auth/change- password` | Login | Đổi mật khẩu |
| `PATCH` | `/api/admin/auth/profile` | Login | Cập nhật profile |

### 4.9 User Management (Admin only)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/admin/users` | Admin | Danh sách users |
| `POST` | `/api/admin/users` | Admin | Tạo user mới |
| `GET` | `/api/admin/users/<id>` | Admin | Chi tiết user |
| `PATCH` | `/api/admin/users/<id>` | Admin | Cập nhật user |
| `DELETE` | `/api/admin/users/<id>` | Admin | Xóa user |
| `POST` | `/api/admin/users/<id>/reset- password` | Admin | Reset mật khẩu |
| `GET` | `/api/admin/users/statistics` | Admin | Thống kê users |

### 4.10 API Keys (Admin only)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/api- keys` | Login | Danh sách keys |
| `POST` | `/api/api- keys` | Admin | Tạo key mới |
| `GET` | `/api/api- keys/<id>` | Admin | Chi tiết key |
| `PATCH` | `/api/api- keys/<id>` | Admin | Cập nhật key |
| `DELETE` | `/api/api- keys/<id>` | Admin | Xóa key |
| `POST` | `/api/api- keys/<id>/revoke` | Admin | Thu hồi key |
| `GET` | `/api/api- keys/stats` | Admin | Thống kê keys |
| `GET` | `/api/api- keys/validate` | Any | Validate key |

### 4.11 Audit Logs (Admin only)

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/admin/audit` | Admin | Danh sách audit logs |
| `GET` | `/api/admin/audit/user/<uid>` | Admin | Lịch sử hành động của user |

### 4.12 Utility

| Method | Route | Auth | Mô tả |
|- - - - - - - - |- - - - - - - |- - - - - - |- - - - - - - - |
| `GET` | `/api/health` | None | Health check |
| `GET` | `/api/config` | None | Server config (version, SocketIO) |
| `GET` | `/api/auth/token- info` | JWT | Thông tin token |
| `GET` | `/api/auth/verify` | JWT | Xác thực token agent |

- - - 

## 5. Hệ thống xác thực

### 5.1 Xác thực Agent (API Key + JWT)

```
Bước 1: Đăng ký Agent
┌─────────┐                          ┌────────┐
│  Agent   │  POST /api/agents/register  │ Server │
│          │ ─────────────────────────▶ │        │
│          │  Header: X- API- Key: xxx   │        │
│          │  Body: {hostname, device_id}│       │
│          │                          │        │
│          │  ◀───────────────────────  │        │
│          │  {agent_id, agent_token}  │        │
└─────────┘                          └────────┘

Bước 2: Heartbeat với JWT
┌─────────┐                          ┌────────┐
│  Agent   │  POST /api/agents/heartbeat │ Server │
│          │ ─────────────────────────▶ │        │
│          │  Header: Authorization:    │        │
│          │  Bearer <jwt- token>        │        │
│          │                          │        │
│          │  ◀───────────────────────  │        │
│          │  {whitelist_version, ...}  │        │
└─────────┘                          └────────┘
```

### 5.2 Xác thực Admin/Teacher (Cookie JWT)

```
Bước 1: Đăng nhập
┌──────────┐                          ┌────────┐
│  Browser │  POST /api/admin/auth/login │ Server │
│          │ ─────────────────────────▶ │        │
│          │  Body: {username, password}│        │
│          │                          │        │
│          │  ◀───────────────────────  │        │
│          │  Set- Cookie: access_token  │        │
│          │  (httpOnly, secure)        │        │
└──────────┘                          └────────┘

Bước 2: Truy cập API
┌──────────┐                          ┌────────┐
│  Browser │  GET /api/agents          │ Server │
│          │ ─────────────────────────▶ │        │
│          │  Cookie: access_token=xxx │        │
│          │                          │        │
│          │  ◀───────────────────────  │        │
│          │  {agents: [...]}          │        │
└──────────┘                          └────────┘
```

### 5.3 JWT Token Claims

**Agent Token:**
```json
{
  "agent_id": "agent_xxxx",
  "user_id": "device_id_hash",
  "token_for": "agent",
  "jti": "unique- token- id",
  "exp": 1234567890
}
```

**Admin/Teacher Token:**
```json
{
  "user_id": "user_xxxx",
  "username": "admin",
  "role": "admin",
  "token_for": "admin_user",
  "jti": "unique- token- id",
  "exp": 1234567890
}
```

- - - 

## 6. RBAC -  Phân quyền chi tiết

### 6.1 Roles

| Role | Mô tả |
|- - - - - - |- - - - - - - - |
| `admin` | Toàn quyền hệ thống |
| `teacher` | Giới hạn theo nhóm được gán |

### 6.2 Permissions (format: `resource:action`)

**Teacher được phép:**

| Permission | Mô tả |
|- - - - - - - - - - - |- - - - - - - - |
| `profile:read` | Xem thông tin cá nhân |
| `profile:change_password` | Đổi mật khẩu |
| `groups:read` | Xem nhóm (chỉ nhóm mình tạo/được gán) |
| `groups:update` | Sửa nhóm mình |
| `groups:manage_agents` | Quản lý agent trong nhóm |
| `agents:read` | Xem agents (chỉ trong nhóm mình) |
| `agents:detail` | Xem chi tiết agent |
| `whitelist:read` | Xem whitelist nhóm mình |
| `whitelist:create` | Thêm whitelist |
| `whitelist:update` | Sửa whitelist |
| `whitelist:delete` | Xóa whitelist |
| `whitelist:sync` | Sync whitelist |
| `logs:read` | Xem logs (chỉ từ nhóm mình) |
| `profiles:create/update/delete/activate` | Quản lý whitelist profile |

**Admin thêm (ngoài tất cả quyền teacher):**

| Permission | Mô tả |
|- - - - - - - - - - - |- - - - - - - - |
| `users:create/read/update/delete` | Quản lý tài khoản |
| `users:reset_password` | Reset mật khẩu |
| `agents:delete/command` | Xóa agent, gửi lệnh |
| `api_keys:read/create/revoke` | Quản lý API keys |
| `logs:export/delete` | Export/xóa logs |
| `system:config` | Cấu hình hệ thống |
| `audit:read` | Xem audit logs |

### 6.3 Data Filtering (Teacher)

Teacher chỉ thấy dữ liệu thuộc nhóm mình:
-  **Groups**: `created_by == user_id` HOẶC `user_id IN teacher_ids`
-  **Agents**: agent thuộc nhóm mà teacher quản lý
-  **Whitelists**: whitelist thuộc nhóm teacher
-  **Logs**: logs từ agents trong nhóm teacher

Middleware `rbac.py` tự động inject `current_user` vào request, services filter data theo role.

- - - 

## 7. WebSocket Events (Real- time)

Server sử dụng Flask- SocketIO để push notifications đến Web Dashboard:

| Event | Khi nào | Dữ liệu |
|- - - - - - - |- - - - - - - - - |- - - - - - - - - - |
| `server_message` | Client kết nối | Welcome message |
| `agent_registered` | Agent mới đăng ký | Agent info |
| `agent_status_changed` | Agent thay đổi trạng thái | agent_id, new_status |
| `whitelist_updated` | Whitelist được cập nhật | group_id, version |
| `api_key_created` | API key mới được tạo | Key info |
| `api_key_revoked` | API key bị thu hồi | Key info |

- - - 

## 8. Cấu hình & Triển khai

### 8.1 Biến môi trường (.env)

| Biến | Mô tả | Mặc định |
|- - - - - - |- - - - - - - - |- - - - - - - - - - |
| `MONGO_URI` | MongoDB connection string | (bắt buộc) |
| `MONGO_DBNAME` | Tên database | Monitoring |
| `FLASK_ENV` | Môi trường | development |
| `DEBUG` | Debug mode | True |
| `HOST` | Server host | 0.0.0.0 |
| `PORT` | Server port | 5000 |
| `JWT_SECRET_KEY` | Secret key cho JWT | (bắt buộc) |
| `JWT_REFRESH_SECRET_KEY` | Secret key cho refresh token | (bắt buộc) |
| `API_KEY_HMAC_SECRET` | Secret cho hash API key | (bắt buộc) |

### 8.2 Chạy Server

```bash
# Cài đặt dependencies
cd server
pip install - r requirements.txt

# Cấu hình .env
cp .env.example .env
# Sửa các biến MONGO_URI, JWT_SECRET_KEY, ...

# Chạy server
python app.py
# Server chạy tại http://0.0.0.0:5000
```

### 8.3 Dependencies chính

| Package | Version | Mục đích |
|- - - - - - - - - |- - - - - - - - - |- - - - - - - - - - |
| flask | latest | Web framework |
| flask- socketio | latest | WebSocket support |
| flask- cors | latest | CORS handling |
| pymongo | latest | MongoDB driver |
| pydantic | latest | Data validation |
| pyjwt | latest | JWT tokens |
| bcrypt | latest | Password hashing |
| email_validator | latest | Email validation |
| gevent | latest | Async worker |
| gevent- websocket | latest | WebSocket transport |
| python- dotenv | latest | Environment config |

- - - 

## 9. Mô hình MVC

```
Request → Middleware (Auth/RBAC) → Controller → Service → Model → MongoDB
                                       ↓
                                   Response (JSON)
```

-  **Middleware**: Xác thực và phân quyền trước khi request đến controller
-  **Controller**: Nhận request, validate input, gọi service, trả response
-  **Service**: Business logic, xử lý nghiệp vụ, gọi model
-  **Model**: CRUD operations trực tiếp với MongoDB

Tất cả timestamps sử dụng timezone Việt Nam (Asia/Ho_Chi_Minh) thông qua `time_utils.py`.
