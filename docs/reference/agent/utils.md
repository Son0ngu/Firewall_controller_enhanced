# `agent/utils` - Error handler, IP detector, Config validators

## Mục đích
3 file riêng lẻ, không có hierarchy: `error_handler` (wrap operation), `ip_detector` (local IP + admin check, có cache), `validators` (config validation - gần trùng `config/validator.py`).

## Public API

### `agent/utils/error_handler.py` - Safe execute + decorators

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `CriticalErrorHandler` | `class` (chỉ chứa static methods) | [error_handler.py:8](../../../agent/utils/error_handler.py#L8) | Stateless. Dùng như namespace |
| `CriticalErrorHandler.safe_execute(func, *args, error_msg="Operation failed", return_on_error=None, log_traceback=True, **kwargs)` | | [error_handler.py:10](../../../agent/utils/error_handler.py#L10) | Try-except wrapper. Trả `return_on_error` nếu raise. **Cách chuẩn để guard external API call** |
| `CriticalErrorHandler.critical_operation(operation_name)` | decorator | [error_handler.py:42](../../../agent/utils/error_handler.py#L42) | Log start + complete + failure. **Vẫn re-raise** exception (khác `safe_execute`) |
| `CriticalErrorHandler.retry_operation(max_retries=3, delay=1.0, backoff=2.0, exceptions=(Exception,))` | decorator | [error_handler.py:70](../../../agent/utils/error_handler.py#L70) | Exponential backoff retry. Sleep dùng `shared.sleep` (import nội bộ) |

### `agent/utils/ip_detector.py` - Local IP + admin check (cached)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `IPDetector` | `class` | [ip_detector.py:13](../../../agent/utils/ip_detector.py#L13) | TTL 300s cho IP cache |
| `.get_local_ip(force_refresh=False)` | `(bool) -> str` | [ip_detector.py:21](../../../agent/utils/ip_detector.py#L21) | 3 methods: ① default IPv4 gateway/interface via `netifaces` ② `gethostname → gethostbyname` ③ `netifaces` iterate non-loopback/link-local. Fallback `127.0.0.1` |
| `.get_admin_status(force_refresh=False)` | `(bool) -> bool` | [ip_detector.py:92](../../../agent/utils/ip_detector.py#L92) | Windows: `ctypes.windll.shell32.IsUserAnAdmin`. Linux/Mac: `os.geteuid() == 0`. **Cached vĩnh viễn** (admin status không đổi runtime) |
| `.get_cache_debug_info()` | `() -> Dict` | [ip_detector.py:113](../../../agent/utils/ip_detector.py#L113) | cached_ip, last_check_iso, cache_age, ttl, cache_valid |
| `get_local_ip(force_refresh=False)` | `(bool) -> str` | [ip_detector.py:128](../../../agent/utils/ip_detector.py#L128) | **Module-level** wrapper qua singleton `_ip_detector`. **Dùng cái này** thay vì tạo `IPDetector()` mới |
| `check_admin_privileges(force_refresh=False)` | `(bool) -> bool` | [ip_detector.py:132](../../../agent/utils/ip_detector.py#L132) | Module-level wrapper |
| `get_ip_detector()` | `() -> IPDetector` | [ip_detector.py:136](../../../agent/utils/ip_detector.py#L136) | Lấy singleton - cho debug |
| `_ip_detector` | module global | [ip_detector.py:125](../../../agent/utils/ip_detector.py#L125) | Singleton instance |

### `agent/utils/validators.py` - Config validator (legacy duplicate)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `validate_configuration(config)` | `(Dict) -> bool` | [validators.py:9](../../../agent/utils/validators.py#L9) | Validate server/firewall/logging/whitelist/heartbeat sections. **KHÔNG coerce** giá trị, chỉ log. Trả `True/False`, mất errors detail |
| `_validate_*` | internal | [validators.py:58-135](../../../agent/utils/validators.py#L58) | Helper riêng - duplicate logic của `config/validator.py` |

## Ai gọi module này

`error_handler`:
- `agent/core/registry.py` - `@CriticalErrorHandler.critical_operation("Agent Registration")`
- `agent/core/handlers.py` - `safe_execute` wrap `whitelist.is_allowed` và `log_sender.queue_log`
- Theory: mọi external boundary

`ip_detector`:
- `agent/firewall/utils.py` - `get_essential_ips()`, `check_admin_privileges`
- `agent/firewall/manager.py` - admin guard
- `agent/core/registry.py` + `lifecycle.py` + `handlers.py` - gather agent info
- `agent/services/heartbeat.py` (indirectly via core)
- Mọi nơi cần local IP

`validators`:
- Export trong `utils/__init__.py` nhưng **không có file nào trong agent gọi `validate_configuration`** - duplicate dead-ish của `config/validator.py`

## Module này gọi ra
- `agent/shared/time_utils` - `is_cache_valid`, `cache_age`, `now`, `sleep`
- `socket`, `netifaces`, `platform` - IP detection
- `ctypes.windll.shell32` - admin check (Windows)
- `subprocess` - `netsh` fallback admin check (chỉ trong `config/validator`, không ở đây)

## Đã có sẵn - đừng viết lại
- Cần check admin? → `utils.check_admin_privileges()` - cached, cross-platform
- Cần local IP của máy? → `utils.get_local_ip()` - 3 fallback methods, cached 5 phút
- Cần wrap operation chống crash? → `CriticalErrorHandler.safe_execute(fn, *args, ...)` - đọng pattern, đã có log + return_on_error
- Cần retry với backoff? → `@CriticalErrorHandler.retry_operation(max_retries=3, ...)`
- Cần log "đang chạy critical op X"? → `@CriticalErrorHandler.critical_operation("X")` - sẽ re-raise nên đừng dùng cho non-critical

## Gotchas
- **Singleton `_ip_detector` ở module level** (ip_detector.py:125): không reset được giữa các test. Nếu cần test, gọi `get_ip_detector().get_local_ip(force_refresh=True)`.
- **Admin status cached VĨNH VIỄN** (ip_detector.py:93): nếu user mở agent không admin, sau đó relaunch as admin trong cùng process (hiếm), `_cached_admin_status` vẫn `False`. Process restart = fix. Hoặc `force_refresh=True`.
- **Method 1 (default gateway/interface)** không cần public DNS hay Internet; lấy IPv4 trên interface default của hệ thống. Nếu không có default gateway thì fall qua method 2/3.
- **`netifaces` cần build native** (ip_detector.py:6): trên CI/dev có thể fail import. Method 3 sẽ bị skip silently - fallback method 2 hoặc localhost.
- **`safe_execute` vs `critical_operation`**: hai pattern khác nhau. `safe_execute` swallow exception trả default. `critical_operation` re-raise. Đừng nhầm - dùng `safe_execute` khi caller có thể handle missing value, `critical_operation` khi caller MUỐN crash nếu fail.
- **`retry_operation` import `sleep` ngầm** trong wrapper (error_handler.py:92): import-on-call → tránh circular. Hậu quả: lần retry đầu tiên có thêm 1ms import overhead. Vô hại.
- **`exceptions` parameter của retry_operation** mặc định `(Exception,)` - catch tất. Cẩn thận khi wrap function raise `KeyboardInterrupt` (không kế thừa Exception, không catch).
- **`validate_configuration` ở utils dead-ish**: không ai gọi. Logic gần trùng `config/validator.py` nhưng KHÔNG coerce mode về `whitelist_only`, KHÔNG return errors/warnings list. Nên xoá hoặc đồng bộ rule với cái còn lại. Hiện coi như tech debt.
- **`get_local_ip` fallback `127.0.0.1`** (ip_detector.py:88-90): cache cả `127.0.0.1`. Nghĩa là máy mất Internet trong 5 phút đầu sẽ giữ `127.0.0.1` cached cho tới TTL. Lần sync sau đó vẫn báo localhost. Acceptable.
- **`force_refresh=True` không clear cache, chỉ skip cache check** - gọi lại không-force vẫn nhận giá trị mới (vừa lưu). OK.
- **No timeout cho method 2 (`gethostbyname`)** - có thể hang lâu nếu DNS local broken. Method 1 chạy trước, thường thành công ⇒ rare path.
