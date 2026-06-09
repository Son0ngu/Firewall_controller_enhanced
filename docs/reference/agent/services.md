# `agent/services` - Heartbeat Sender

## Mục đích
Gửi heartbeat định kỳ (mặc định 20s) lên server kèm metrics (CPU/disk/uptime), OS info, version. Nhận lại flag `force_sync` từ server (khi admin đổi whitelist) và `whitelist version` đang dùng của agent để server detect drift.

Module hiện chỉ có **1 thành viên**: `HeartbeatSender`. File `windows_service.py` đã bị xoá (xem git status); không còn Windows service mode - agent chạy như user-mode GUI process.

## Public API

### `agent/services/heartbeat.py`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `HeartbeatSender` | `class` | [heartbeat.py:16](../../../agent/services/heartbeat.py#L16) | Owns 1 daemon thread `HeartbeatSender` |
| `.__init__(config)` | `(Dict)` | [heartbeat.py:18](../../../agent/services/heartbeat.py#L18) | Đọc `heartbeat` section: enabled, interval=20, timeout=10, retry_interval=5, max_failures=3 |
| `.set_agent_credentials(agent_id, token)` | `(str, str) -> None` | [heartbeat.py:59](../../../agent/services/heartbeat.py#L59) | **Bắt buộc gọi trước start** - nếu thiếu, `start()` sẽ warn và skip |
| `.start()` | `() -> None` | [heartbeat.py:63](../../../agent/services/heartbeat.py#L63) | No-op nếu `enabled=False` hoặc credentials thiếu. Spawn thread |
| `.stop()` | `() -> None` | [heartbeat.py:85](../../../agent/services/heartbeat.py#L85) | Set `_running=False`, join 5s |
| `.get_status()` | `() -> Dict` | [heartbeat.py:218](../../../agent/services/heartbeat.py#L218) | enabled, running, consecutive_failures, last_successful_heartbeat |
| `.on_force_sync` | `Optional[Callable[[], None]]` | [heartbeat.py:42](../../../agent/services/heartbeat.py#L42) | **Caller wire vào**: được gọi khi server trả `force_sync=True`. Lifecycle wire `whitelist.sync_now` |
| `.get_whitelist_versions` | `Optional[Callable[[], Dict]]` | [heartbeat.py:44](../../../agent/services/heartbeat.py#L44) | **Caller wire vào**: lambda trả `{"global_version": ..., "group_version": ...}` - heartbeat sẽ merge vào payload. Lifecycle wire qua `whitelist._state._version/_group_version` |
| `._heartbeat_loop()` | `() -> None` | [heartbeat.py:91](../../../agent/services/heartbeat.py#L91) | success → sleep `interval`. fail → sleep `_backoff_seconds()`. Sleep qua `_interruptible_sleep` (cả 2 path) |
| `._interruptible_sleep(seconds)` | `(float) -> None` | [heartbeat.py:139](../../../agent/services/heartbeat.py#L139) | Ngủ từng giây có check `_running`, **rồi ngủ phần lẻ còn lại**. Fix busy-spin: trước đây `range(int(sleep_time))` cắt phần <1s → backoff <1s thành no-op → hammer server |
| `._send_heartbeat()` | `() -> bool` | [heartbeat.py:119](../../../agent/services/heartbeat.py#L119) | POST `/api/agents/heartbeat`. Body: agent_id, token, device_id, timestamp, metrics, status, platform, os_info, agent_version, whitelist versions. JWT auth via `get_auth_headers`. Loop qua các server URLs |
| `._collect_metrics()` | `() -> Dict` | [heartbeat.py:189](../../../agent/services/heartbeat.py#L189) | `psutil.virtual_memory().percent`, `disk_usage("C:\\")`, uptime từ `psutil.boot_time()` |
| `._get_server_urls()` | `() -> list` | [heartbeat.py:46](../../../agent/services/heartbeat.py#L46) | Delegate sang `shared.server_urls.collect_server_urls(config, allow_dev_default=False)`. Empty config ⇒ empty list ⇒ `_send_heartbeat` early-return `True` (skip silently, không counter failure). |

**Body heartbeat** (heartbeat.py:122-142):
```json
{
  "agent_id": "...",
  "token": "...",
  "device_id": "...",
  "timestamp": "2026-05-18T10:30:00+07:00",
  "metrics": {"memory_percent": 42.5, "disk_percent": 73.1, "uptime_seconds": 12345, "timestamp": "..."},
  "status": "active",
  "platform": "Windows",
  "os_info": "Windows 11 23H2 (Build 22631)",
  "agent_version": "1.0.0",
  "global_version": "...",       // nếu get_whitelist_versions wired
  "group_version": "..."
}
```

**Response format expected**:
```json
{ "success": true, "data": { "force_sync": true, "policy_mode": "..." } }
```

## Ai gọi module này
- `agent/core/lifecycle.py` - tạo `HeartbeatSender(config)`, gọi `set_agent_credentials`, wire `on_force_sync` → `whitelist.sync_now`, wire `get_whitelist_versions` → lambda đọc `_state._version/_group_version`, gọi `start()` + `stop()`
- GUI không gọi trực tiếp; status đọc qua `Agent.heartbeat.get_status()` nếu cần

## Module này gọi ra
- `agent/core/token_manager.get_auth_headers` - JWT header
- `agent/shared/time_utils` - `now`, `now_iso`, `sleep`
- `agent/shared/os_info.get_os_details` - platform/OS string
- `psutil` - system metrics
- `requests` - HTTP POST

## Đã có sẵn - đừng viết lại
- Cần gửi periodic ping lên server? → đã có `HeartbeatSender` - đừng viết loop POST riêng. Wire `on_force_sync` callback nếu muốn server trigger action
- Cần báo cáo whitelist version đang dùng? → wire `get_whitelist_versions` lambda - đừng nhúng `_version` field vào heartbeat payload thủ công
- Cần get auth headers? → `get_auth_headers(config)` (xem [core.md](core.md))

## Gotchas
- **Heartbeat OFFLINE-aware** (P0.5): khi `_get_server_urls()` trả empty (chưa cấu hình server URL), `_send_heartbeat` skip ngay (early return `True`) — không cố POST `localhost:5000` mỗi 20s nữa, không bump `_consecutive_failures`. Cùng resolver chung với whitelist/log sender (`shared/server_urls.py`).
- **`set_agent_credentials` BẮT BUỘC** trước `start`: nếu không, `start()` log warning và return mà không spawn thread. Symptom: heartbeat im lặng, không log gì sau warning đầu. Lifecycle.py đã đảm bảo gọi đúng thứ tự.
- **`agent_id` & `token` lưu cả ở instance var và trong body** (line 124-125). Body field `token` là **legacy** - server hiện đại verify qua JWT header. Vẫn gửi để tương thích server cũ.
- **`on_force_sync` được gọi đồng bộ trong `_send_heartbeat`** (heartbeat.py:169-171) - nếu callback chậm (vd `sync_now` mất 5s), heartbeat thread bị block, có thể trễ heartbeat tiếp theo. `whitelist.sync_now` thường < 1s nên OK.
- **`get_whitelist_versions` được gọi mỗi lần send** (heartbeat.py:138-142) - đảm bảo lambda đó nhẹ. Hiện chỉ đọc 2 string attribute, không vấn đề.
- **`max_failures` chỉ log error, không action**: heartbeat.py:102-106. Đạt 3 lần fail liên tiếp → log "Too many...", nhưng vẫn tiếp tục retry. Nếu muốn trigger re-register hay alert - phải wire thêm callback.
- **`_collect_metrics` swallow exception** (heartbeat.py:201,208,213): nếu `psutil.virtual_memory` raise, metric sẽ vẫn là `0`. Không crash, nhưng dashboard có thể hiển thị 0% nhầm lẫn.
- **Disk path hard-coded `"C:\\"`** (heartbeat.py:205): máy không có C: drive (ổ Linux, hoặc Windows custom layout) sẽ ra 0. Hiện agent Windows-only, có C: ⇒ OK.
- **`agent_version = "1.0.0"` hard-coded** (heartbeat.py:132) - không dynamic. Nhớ bump khi release.
- **Body field `agent_id` lấy từ instance var, không phải config** (heartbeat.py:124). Nếu re-register đổi `agent_id` trong config nhưng quên gọi lại `set_agent_credentials`, heartbeat sẽ gửi id cũ. Lifecycle.py không re-call sau token expiry - cần check nếu lifecycle thay đổi.
- **`token` field cũng từ instance var** (line 125) - không phải JWT. JWT mới qua `get_auth_headers`. Khi token rotation xảy ra, body field `token` lệch với header. Server thường chỉ check header.
- **No backoff khi failures cao** - vẫn dùng cố định `retry_interval=5s`. Server overload sẽ tiếp tục bị hammer. Acceptable cho hệ thống cỡ <100 agent.
