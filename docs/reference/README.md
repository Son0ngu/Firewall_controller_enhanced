# Reference - Index

Bộ tham chiếu API per-module cho agent và server. **Trước khi viết helper mới**, scan section ["Common utilities"](#common-utilities--check-tr%C6%B0%E1%BB%9Bc-khi-t%E1%BB%B1-vi%E1%BB%BFt) ở cuối file này - phần lớn thứ bạn cần đã có.

Khác biệt với các docs còn lại:
- [docs/SYSTEM_OVERVIEW.md](../SYSTEM_OVERVIEW.md) → **kiến trúc** (luồng, sơ đồ, vì sao).
- Thư mục này → **API surface** (class/function nào tồn tại, signature, vị trí, ai gọi).
- [current-flows.md](current-flows.md) → **flow runtime hiện tại**: whitelist CRUD/sync/merge, agent firewall apply, config/build.

---

## Agent

| Module | Trách nhiệm | Trạng thái |
|---|---|---|
| [agent/core](agent/core.md) | Singleton Agent, lifecycle, registry, handlers, JWT token manager | ✅ |
| [agent/firewall](agent/firewall.md) | Quản lý Windows Firewall (policy, rules, snapshot) | ✅ |
| [agent/whitelist](agent/whitelist.md) | Sync + state + monitor whitelist | ✅ |
| [agent/capture](agent/capture.md) | Packet capture (Scapy, domain extractor, WinPcap) | ✅ |
| [agent/network](agent/network.md) | DNS resolver (parallel) | ✅ |
| [agent/config](agent/config.md) | Loader, defaults, validator, crypto | ✅ |
| [agent/services](agent/services.md) | HeartbeatSender | ✅ |
| [agent/logging_module](agent/logging_module.md) | LogSender (batch) | ✅ |
| [agent/cache](agent/cache.md) | LRU cache + `DNSRecord` | ✅ |
| [agent/shared](agent/shared.md) | Time/timezone, OS info | ✅ |
| [agent/utils](agent/utils.md) | error_handler, ip_detector, validators | ✅ |
| [agent/controllers](agent/controllers.md) | Framework-agnostic GUI controllers, worker thread, AgentSignals, whitelist bridge | ✅ |
| [agent/gui_qt](agent/gui_qt.md) | PySide6 app/view layer, Qt signal bridge, views, components, QSS styles | ✅ |
| [agent/gui legacy](agent/gui.md) | Compatibility note for removed legacy GUI package | ⚠️ legacy |

## Server

| Module | Trách nhiệm | Trạng thái |
|---|---|---|
| [server/app](server/app.md) | Flask bootstrap (gevent), router wire, time_utils helpers | ✅ |
| [server/database](server/database.md) | MongoDB client + Config classes (Dev/Prod/Testing) | ✅ |
| [server/middleware](server/middleware.md) | auth (API key + JWT) + RBAC decorators | ✅ |
| [server/config](server/config.md) | RBAC role hierarchy + permissions table | ✅ |
| [server/models](server/models.md) | 10 MongoDB collections layer (no ORM, raw pymongo) | ✅ |
| [server/services](server/services.md) | 12 business logic services | ✅ |
| [server/controllers](server/controllers.md) | 10 Flask Blueprints + full endpoint map | ✅ |
| [server/scripts](server/scripts.md) | `seed_rbac.py` - bootstrap admin user | ✅ |
| [server/tests](server/tests.md) | Server regression suite (~545 cases, real MongoDB/mocks theo fixture) | ✅ |

---

## Common utilities - check trước khi tự viết

Những helper hay bị **viết lại** vì không biết đã có. Trước khi gõ `def foo(...)`, hỏi: "thứ này có lý do gì để không ở chỗ chung không?"

### Thời gian / Timezone
| Cần | Dùng | Đừng |
|---|---|---|
| ISO timestamp gửi server | `shared.time_utils.now_iso()` | `datetime.now().isoformat()` (mất tz VN) |
| Unix timestamp | `shared.time_utils.now()` | `time.time()` (OK nhưng không nhất quán) |
| `datetime` aware VN | `shared.time_utils.now_vietnam()` | `datetime.now(tz=...)` thủ công |
| TTL cache check | `shared.time_utils.is_cache_valid(ts, ttl)` | `time.time() - ts > ttl` rải rác |
| Convert Unix → ISO VN | `shared.time_utils.now_server_compatible(ts)` | format thủ công |
| Uptime đẹp `"2h 30m 15s"` | `shared.time_utils.uptime_string()` | tự tính lại |
| Server-side | `server/time_utils.py` (riêng) | - |

### IP / Mạng / Hệ điều hành
| Cần | Dùng |
|---|---|
| Local IP | `utils.ip_detector.get_local_ip()` |
| Check admin (Windows) | `utils.ip_detector.check_admin_privileges()` |
| Validate IPv4 | `firewall.utils.FirewallUtils.is_valid_ip(ip)` (agent), `ipaddress.ip_address(ip)` (server) |
| Essential IPs (DNS, localhost, gateway) | `firewall.utils.FirewallUtils.get_essential_ips()` |
| OS name + version (Win11 detect chuẩn) | `shared.os_info.get_os_details()` |
| Resolve domain → IP song song | `network.OptimizedDNSResolver` |
| Resolve domain → IP đơn lẻ | `socket.gethostbyname(host)` |

### Agent identity / Auth
| Cần | Dùng |
|---|---|
| Singleton agent | `core.get_agent()` |
| Hostname / device_id | `core.AGENT_HOSTNAME`, `core.AGENT_DEVICE_ID` |
| Auth header gửi server (JWT > legacy) | `core.token_manager.get_auth_headers(config)` |
| TokenManager | `core.token_manager.get_token_manager()` |
| Lifecycle log entry chuẩn | `core.lifecycle.build_lifecycle_log(config, event_type, action, message)` |

### Server-side
| Cần | Dùng |
|---|---|
| JWT issue/verify | `server.services.jwt_service` |
| RBAC permission check | `server.middleware.rbac` |
| Audit log | `server.services.audit_service.log_action(...)` |

### Error handling
| Cần | Dùng |
|---|---|
| Wrap operation đừng để crash | `utils.error_handler.CriticalErrorHandler.safe_execute(fn, *args, error_msg=..., return_on_error=...)` |
| Decorator cho critical op | `@CriticalErrorHandler.critical_operation("Op Name")` |

### Netsh / Windows Firewall
| Cần | Dùng |
|---|---|
| Chạy `netsh` (no console flash) | `firewall.utils.FirewallUtils.run_netsh_command(args, timeout=30)` |

---

## Quy ước trong các file reference

- **Vị trí** ghi dạng link tương đối tới source, ví dụ `file.py:line -> ../../../agent/module/file.py#Lline`.
- Cột **Signature** đã lược bớt `self` và type hint dài; xem source để chính xác.
- **Ai gọi module này** ghi theo *package*, không liệt từng file (grep nếu cần chi tiết).
- **Module này gọi ra**: bỏ qua khi chỉ stdlib.
- **Đã có sẵn - đừng viết lại**: phần quan trọng nhất; hãy thêm vào đây mỗi khi phát hiện duplication.
- Private (`_foo`) **bỏ** trừ khi quan trọng về design.
- Không copy docstring - đọc code, tóm 1 dòng. Docstring có thể lệch thực tế.
