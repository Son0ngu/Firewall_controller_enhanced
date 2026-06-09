# `agent/core` - Singleton, Lifecycle, Registry, Handlers, Token

## Mục đích
Trung tâm điều phối agent: identity (hostname + device_id), trạng thái runtime (Singleton), tuần tự khởi động/dọn dẹp components, đăng ký với server, xử lý packet → log, và quản lý JWT auto-refresh. Mọi component khác (firewall/whitelist/sniffer/heartbeat/log_sender) đều được **gắn vào `Agent` singleton** trong `lifecycle.initialize_components`.

## Public API

Cap nhat 2026-05-27: lifecycle da co contract `AgentComponent.start/stop/health`, `LifecycleContext`, `start_components(...)`, `stop_components(...)` va fake-component tests. Chi tiet xem [lifecycle_components.md](lifecycle_components.md).

### `agent/core/agent.py` - Singleton + identity

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `AGENT_HOSTNAME` | `str` (module const) | [agent.py:56](../../../agent/core/agent.py#L56) | `socket.gethostname()`, fallback `"Unknown Agent"` |
| `AGENT_DEVICE_ID` | `str` (module const) | [agent.py:57](../../../agent/core/agent.py#L57) | Hash 24-char SHA256 từ BIOS/Baseboard/Disk serial qua PowerShell. Fallback MAC. |
| `agent_state` | `Dict` (module global) | [agent.py:59](../../../agent/core/agent.py#L59) | State flags: `startup_completed`, `registration_completed`, `agent_id`, ... |
| `generate_device_id()` | `() -> str` | [agent.py:38](../../../agent/core/agent.py#L38) | Tính device_id lúc import (đã có sẵn ở `AGENT_DEVICE_ID`) |
| `Agent` | `class` (Singleton) | [agent.py:69](../../../agent/core/agent.py#L69) | Container component refs + config |
| `Agent.config` | `Optional[Dict]` | [agent.py:84](../../../agent/core/agent.py#L84) | Set bởi `lifecycle.initialize_components` |
| `Agent.firewall / .whitelist / .log_sender / .sniffer / .heartbeat` | `Optional[...]` | [agent.py:85-89](../../../agent/core/agent.py#L85) | Component refs (None trước init) |
| `Agent.hostname` | `@property -> str` | [agent.py:99](../../../agent/core/agent.py#L99) | Alias `AGENT_HOSTNAME` |
| `Agent.device_id` | `@property -> str` | [agent.py:103](../../../agent/core/agent.py#L103) | Alias `AGENT_DEVICE_ID` |
| `Agent.state` | `@property -> Dict` | [agent.py:107](../../../agent/core/agent.py#L107) | Trả `agent_state` |
| `Agent.update_state(**kw)` | `(**Any) -> None` | [agent.py:110](../../../agent/core/agent.py#L110) | Cập nhật state flags |
| `Agent.get_agent_id()` | `() -> Optional[str]` | [agent.py:113](../../../agent/core/agent.py#L113) | Ưu tiên `config['agent_id']` rồi tới state |
| `Agent.get_agent_token()` | `() -> Optional[str]` | [agent.py:118](../../../agent/core/agent.py#L118) | Legacy token. JWT lấy qua `TokenManager`. |
| `Agent.is_registered()` | `() -> bool` | [agent.py:123](../../../agent/core/agent.py#L123) | Trả `agent_state['registration_completed']` |
| `Agent.is_running()` | `() -> bool` | [agent.py:126](../../../agent/core/agent.py#L126) | `running and startup_completed` |
| `Agent.stop()` | `() -> None` | [agent.py:129](../../../agent/core/agent.py#L129) | Set `running=False` (cooperative shutdown) |
| `get_agent()` | `() -> Agent` | [agent.py:132](../../../agent/core/agent.py#L132) | Cách *duy nhất* nên dùng để lấy singleton |
| `AgentRuntime` | `class` | [agent.py](../../../agent/core/agent.py) | Runtime injectable cho tests/harness; `Agent` singleton kế thừa class này. |
| `make_runtime(state=None)` | `(Optional[Dict]) -> AgentRuntime` | [agent.py](../../../agent/core/agent.py) | Tạo runtime độc lập, không chạm singleton production. |
| `DeviceIdentityProvider` | `class` | [agent.py](../../../agent/core/agent.py) | Lazy/cached hostname và device_id; `reset()` hỗ trợ tests. |

### `agent/core/lifecycle.py` - Khởi tạo / Dọn dẹp

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `initialize_components(config)` | `(Dict) -> bool` | [lifecycle.py:17](../../../agent/core/lifecycle.py#L17) | 7 bước: register → TokenManager → WhitelistManager → sync **trước** → FirewallManager (nếu admin) → LogSender → HeartbeatSender → PacketSniffer. Lỗi giữa chừng vẫn cố chạy offline. |
| `cleanup(config=None)` | `(Optional[Dict]) -> None` | [lifecycle.py:288](../../../agent/core/lifecycle.py#L288) | Dừng theo thứ tự ngược: token → sniffer → whitelist → heartbeat → log_sender (flush shutdown log) → firewall.cleanup → winpcap nếu auto-installed |
| `build_lifecycle_log(config, event_type, action, message)` | `(Dict, str, str, str) -> Dict` | [lifecycle.py:371](../../../agent/core/lifecycle.py#L371) | Build log entry chuẩn cho lifecycle events. Có `source/dest = "agent"/"N/A"` để tương thích schema log thường. |
| `LifecycleContext` | `@dataclass` | [lifecycle.py](../../../agent/core/lifecycle.py) | Context runtime/config/result/started_components cho mỗi component. |
| `AgentComponent` | `class` | [lifecycle.py](../../../agent/core/lifecycle.py) | Contract `start(context)`, `stop(context)`, `health(context)`. |
| `build_default_components()` | `() -> List[AgentComponent]` | [lifecycle.py](../../../agent/core/lifecycle.py) | Production order: registration, token, whitelist, firewall, log sender, heartbeat, packet sniffer. |
| `start_components(context, components)` | `(LifecycleContext, Sequence[AgentComponent]) -> None` | [lifecycle.py](../../../agent/core/lifecycle.py) | Start theo thứ tự; cleanup các component đã start nếu có failure. |
| `stop_components(context)` | `(LifecycleContext) -> None` | [lifecycle.py](../../../agent/core/lifecycle.py) | Stop ngược thứ tự và clear runtime component stack. |

### `agent/core/registry.py` - Đăng ký với Server

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `register_agent(config)` | `(Dict) -> bool` | [registry.py:29](../../../agent/core/registry.py#L29) | Decorated `@CriticalErrorHandler.critical_operation`. Loop qua tất cả URL trong `server.urls + server.url`. Trả `False` khi không có URL nào - agent vào offline mode. |
| `try_register_with_server(server_url, agent_info, config)` | `(str, Dict, Dict) -> bool` | [registry.py:79](../../../agent/core/registry.py#L79) | POST `/api/agents/register` với `X-API-Key` header. Lưu vào `config`: `agent_id`, `agent_token`, `user_id`, `server_url`, `jwt` dict. |
| `_collect_server_urls(config)` | `(Dict) -> List[str]` | [registry.py:17](../../../agent/core/registry.py#L17) | Wrapper backwards-compat — delegate sang `shared.server_urls.collect_server_urls(config, allow_dev_default=False)`. Code mới nên import resolver chung trực tiếp (xem [shared.md](shared.md)). |

### `agent/core/handlers.py` - Xử lý packet → log

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `create_domain_handler(config, agent)` | `(Dict, Agent) -> Callable[[Dict], None]` | [handlers.py:13](../../../agent/core/handlers.py#L13) | Closure trả handler được `PacketSniffer` gọi. |
| `handle_domain_detection(record, config, whitelist, log_sender)` | `(Dict, Dict, WhitelistManager, LogSender) -> None` | [handlers.py:26](../../../agent/core/handlers.py#L26) | Map port→protocol (443→HTTPS, 80→HTTP, 53→DNS), check whitelist, gán action+level theo bảng compliance, queue log. |

**Bảng compliance levels** (handlers.py:83-92):

| Action | Khi nào | Level |
|---|---|---|
| `ALLOWED` | Firewall enabled, domain whitelisted | INFO |
| `ALLOWED_BY_IP` | IP allowed nhưng domain (SNI/Host) không - dấu hiệu CDN bleed-through | **WARNING** |
| `ALLOWED` (no domain) | IP allowed, packet không có SNI/Host | INFO |
| `BLOCKED` | Không match cả domain lẫn IP | BLOCKED |
| `OBSERVED` | Passive mode (không admin / firewall disabled) | INFO/WARNING tuỳ whitelisted |

### `agent/core/token_manager.py` - JWT auto-refresh

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `TokenManager` | `class` | [token_manager.py:10](../../../agent/core/token_manager.py#L10) | Quản lý access/refresh tokens, auto-refresh background thread |
| `TokenManager.__init__(config)` | `(Dict)` | [token_manager.py:11](../../../agent/core/token_manager.py#L11) | Load tokens từ `config['jwt']` nếu có. Margin refresh trước hạn = 5 phút. Max refresh failures = 3 → trigger re-register. |
| `TokenManager.access_token` | `@property -> Optional[str]` | [token_manager.py:111](../../../agent/core/token_manager.py#L111) | **Side effect**: auto refresh nếu sắp hết hạn |
| `TokenManager.has_valid_token` | `@property -> bool` | [token_manager.py:127](../../../agent/core/token_manager.py#L127) | Có token + chưa hết hạn |
| `TokenManager.is_expired` | `@property -> bool` | [token_manager.py:139](../../../agent/core/token_manager.py#L139) | |
| `TokenManager.get_auth_header()` | `() -> Dict[str, str]` | [token_manager.py:148](../../../agent/core/token_manager.py#L148) | `{"Authorization": "Bearer <token>"}` (rỗng nếu không có token) |
| `TokenManager.set_tokens(access, refresh, access_exp, refresh_exp)` | `(str, str, str=None, str=None) -> None` | [token_manager.py:68](../../../agent/core/token_manager.py#L68) | Update + ghi vào config |
| `TokenManager.refresh_now()` | `() -> bool` | [token_manager.py:335](../../../agent/core/token_manager.py#L335) | Force refresh (POST `/api/auth/refresh`, `timeout=10`). Giữ `_lock` suốt request → các call này nối tiếp nhau (theo thiết kế hiện tại) |
| `TokenManager.start_auto_refresh(on_refreshed=None, on_expired=None)` | `(Callable, Callable) -> None` | [token_manager.py:340](../../../agent/core/token_manager.py#L340) | Spawn daemon thread `TokenRefresh`, loop 60s |
| `TokenManager.stop_auto_refresh()` | `() -> None` | [token_manager.py:360](../../../agent/core/token_manager.py#L360) | Join với timeout 5s |
| `TokenManager.needs_reregistration` | `@property -> bool` | [token_manager.py:397](../../../agent/core/token_manager.py#L397) | |
| `TokenManager.reset_reregistration_flag()` | `() -> None` | [token_manager.py:402](../../../agent/core/token_manager.py#L402) | Sau khi re-register thành công |
| `TokenManager.get_token_status()` | `() -> Dict` | [token_manager.py:408](../../../agent/core/token_manager.py#L408) | Snapshot monitoring (has_access, expires_in, ...) |
| `init_token_manager(config)` | `(Dict) -> TokenManager` | [token_manager.py:448](../../../agent/core/token_manager.py#L448) | Tạo singleton global `_token_manager` |
| `get_token_manager()` | `() -> Optional[TokenManager]` | [token_manager.py:455](../../../agent/core/token_manager.py#L455) | Lấy singleton |
| `get_auth_headers(config)` | `(Dict) -> Dict[str, str]` | [token_manager.py:460](../../../agent/core/token_manager.py#L460) | **Cách đúng để lấy auth header**: JWT từ TokenManager → JWT từ config → legacy `X-Agent-Token`. Mọi nơi gửi request lên server nên dùng cái này. |

## Ai gọi module này
- `lifecycle` được gọi bởi `agent_gui.py` (entry point) và `controllers/agent_controller`.
- `get_agent()` / `Agent` được dùng bởi `controllers/agent_controller`, `whitelist/sync`, `services/heartbeat`, `logging_module/sender` để lấy state/config.
- `get_auth_headers` được dùng bởi mọi module gửi HTTP (heartbeat, log_sender, whitelist sync).
- `AGENT_HOSTNAME / AGENT_DEVICE_ID` được dùng trong logs (handlers, lifecycle), heartbeat, registry.

## Module này gọi ra
- `agent/shared` - time, OS info
- `agent/utils` - admin check, ip detector, error handler
- `agent/whitelist`, `agent/firewall`, `agent/capture`, `agent/logging_module`, `agent/services` - khởi tạo lazy import trong `lifecycle` (tránh circular)
- `requests` - registry + token refresh

## Đã có sẵn - đừng viết lại
- Cần auth header để gọi server? → `core.token_manager.get_auth_headers(config)` (đã handle JWT → legacy fallback)
- Cần singleton agent? → `core.get_agent()` - **đừng** `Agent()` trực tiếp
- Cần hostname/device id? → `core.AGENT_HOSTNAME / AGENT_DEVICE_ID` - **đừng** gọi lại `socket.gethostname()` / WMI
- Cần build lifecycle log? → `lifecycle.build_lifecycle_log(...)` - schema chuẩn để server parse
- Cần wrap operation chống crash? → `utils.error_handler.CriticalErrorHandler.safe_execute` (xem cách handlers.py:58 dùng)

## Gotchas
- **Singleton `Agent`**: `_initialized` flag (line 75, 79) đảm bảo `__init__` chỉ chạy 1 lần. Cẩn thận khi mock trong test - phải reset `Agent._instance = None`.
- **`AGENT_DEVICE_ID` tính ở import time** (line 57). Gọi PowerShell 3 lần, mỗi lần timeout 5s ⇒ delay up to 15s khi import `core.agent` lần đầu. Đang OK vì import sớm trong startup, nhưng test cần ý thức.
- **Lifecycle có 2 alias cho cùng component** (lifecycle.py xem `agent.sniffer` & `agent.packet_sniffer`, cleanup chỉ kiểm `agent.sniffer`). Khi tạo component mới, đặt cả 2 hoặc thống nhất tên.
- **Whitelist sync phải chạy TRƯỚC firewall init** (lifecycle Step 2.5 trước Step 3). Lý do: cần có whitelist data để `enable_whitelist_mode` tạo allow rules trước khi bật Default Deny. Đảo thứ tự = agent tự khoá mình.
- **`enable_whitelist_mode` rồi mới enable Default Deny**, không phải ngược lại. Xem [docs/reference/agent/firewall.md](firewall.md) cho chi tiết.
- **JWT refresh callback chain**: `on_token_expired` trong lifecycle.py:61 gọi lại `register_agent` → reset flag → reload tokens. Nếu sửa, đảm bảo `_load_tokens_from_config` chạy *sau* khi config đã có jwt mới.
- **`needs_reregistration` không tự reset**: phải gọi `reset_reregistration_flag()` sau khi re-register thành công (đã làm ở lifecycle.py:67).
- **`_handle_refresh_error` consume HTTP 401**: nếu server đổi error codes, update `('REFRESH_TOKEN_EXPIRED', 'TOKEN_REVOKED', 'INVALID_TOKEN')` ở token_manager.py:285.
- **`try_register_with_server` mutate config in-place** (registry.py:108-122) - caller phải share cùng dict reference, không copy.
