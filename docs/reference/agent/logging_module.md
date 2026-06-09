# `agent/logging_module` - Log Sender (batch upload tới server)

## Mục đích
Queue log records từ các component (chủ yếu là `handlers.handle_domain_detection`) và gửi theo batch lên server. Tách thread sender khỏi thread caller → caller không bị block bởi network. Auto-serialize datetime, ensure essential fields, JWT auth.

Module 1 file (`sender.py`). Tên module là `logging_module` (không phải `logging`) để tránh shadow stdlib.

## Public API

### `agent/logging_module/sender.py`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `LogSender` | `class` | [sender.py:17](../../../agent/logging_module/sender.py#L17) | Owns `queue.Queue` (default 1000) + daemon thread `LogSender` |
| `.__init__(config)` | `(Dict)` | [sender.py:19](../../../agent/logging_module/sender.py#L19) | Đọc `max_queue_size=1000`, `batch_size=100`, `send_interval=2`. Generate `agent_id` từ `config['agent_id']` hoặc fallback `hostname-mac` |
| `.start()` | `() -> None` | [sender.py:56](../../../agent/logging_module/sender.py#L56) | Spawn thread, idempotent |
| `.stop()` | `() -> None` | [sender.py:69](../../../agent/logging_module/sender.py#L69) | **Flush queue trước** rồi join thread 5s - đảm bảo logs còn lại được gửi |
| `.queue_log(log_data)` | `(Dict) -> bool` | [sender.py:86](../../../agent/logging_module/sender.py#L86) | **Public entry**. Serialize, đảm bảo có `agent_id` + `timestamp`, `put_nowait`. `False` nếu queue full (drop) |
| `.get_status()` | `() -> Dict` | [sender.py:286](../../../agent/logging_module/sender.py#L286) | running, queue_size, `logs_sent`, batch_size, last_send_time. `logs_sent` = counter `_logs_sent` cộng dồn số log gửi thành công (200/201/202) trong `_send_batch` |
| `._serialize_log(log_data)` | `(Dict) -> Dict` | [sender.py:106](../../../agent/logging_module/sender.py#L106) | Recursive serialize. Detect `is_lifecycle_event` → bỏ network defaults. None → `"unknown"` |
| `._sender_loop()` | `() -> None` | [sender.py:156](../../../agent/logging_module/sender.py#L156) | Wake mỗi 1s. Send khi `queue_size >= batch_size` OR `time_since_last_send >= send_interval` |
| `._flush_queue()` | `() -> None` | [sender.py:178](../../../agent/logging_module/sender.py#L178) | Empty toàn bộ queue rồi gửi 1 batch lớn (cho shutdown) |
| `._send_logs()` | `() -> None` | [sender.py:190](../../../agent/logging_module/sender.py#L190) | Lấy tối đa `batch_size` log từ queue |
| `._send_batch(logs)` | `(List[Dict]) -> bool` | [sender.py:205](../../../agent/logging_module/sender.py#L205) | POST `/api/logs` với body `{"logs": [...]}`. Status 200/201/202 = OK. 401 = auth fail (no retry). Timeout 15s |
| `._ensure_serializable(obj)` | `(Any) -> Any` | [sender.py:260](../../../agent/logging_module/sender.py#L260) | Recursive safety net trước khi `json.dumps` |
| `._generate_agent_id()` | `() -> str` | [sender.py:273](../../../agent/logging_module/sender.py#L273) | `f"{hostname}-{mac:xx:xx:...}"` - fallback nếu config không có `agent_id` |
| `._get_server_urls(config)` | `(Dict) -> List[str]` | [sender.py:43](../../../agent/logging_module/sender.py#L43) | Delegate sang `shared.server_urls.collect_server_urls(config, allow_dev_default=False)`. Empty config ⇒ empty list ⇒ sender vào OFFLINE mode. Không còn fallback Render production URL hay localhost. |

**Essential fields** (sender.py:130-148) - auto-fill nếu thiếu:
| Field | Default | Áp dụng |
|---|---|---|
| `timestamp` | `now_iso()` | luôn |
| `agent_id` | `self.agent_id` | luôn |
| `level` | `"INFO"` | luôn |
| `action` | `"UNKNOWN"` | luôn |
| `message` | `"Log entry"` | luôn |
| `domain`, `destination`, `source_ip`, `dest_ip`, `protocol`, `port` | `"unknown"` | **chỉ khi không phải lifecycle event** |

## Ai gọi module này
- `agent/core/lifecycle.py` - tạo `LogSender(config)`, gọi `start()`, queue shutdown log, gọi `stop()`
- `agent/core/handlers.py` - `log_sender.queue_log(enhanced_record)` qua `CriticalErrorHandler.safe_execute`
- `agent/gui_qt/components/log_console.py` (`GUILogHandler`) - bắt Python logging và **không** đẩy qua sender (chỉ hiển thị local). Sender chỉ nhận record từ handlers

## Module này gọi ra
- `agent/core/token_manager.get_auth_headers` - JWT
- `agent/shared/time_utils` - `now`, `now_iso`, `sleep`
- `requests` - HTTP
- stdlib: `queue`, `threading`, `socket`, `uuid`

## Đã có sẵn - đừng viết lại
- Cần queue log từ component? → `agent.log_sender.queue_log(record)` - đừng `requests.post` trực tiếp
- Cần ensure log có timestamp + agent_id? → `queue_log` đã auto fill
- Cần phân biệt lifecycle event vs network event? → set `record["is_lifecycle_event"] = True` ⇒ network fields sẽ KHÔNG bị inject `"unknown"`. Đã có helper `core.lifecycle.build_lifecycle_log(...)`
- Cần serialize datetime trong record? → đã có `_serialize_log` recursive, tự chuyển isoformat. **Đừng** `dt.isoformat()` thủ công trước khi queue

## Gotchas
- **Queue mặc định 1000** (sender.py:27): packet sniffer phát hiện hàng trăm domain/giây trong burst → có thể full. `queue_log` trả `False` và log warning, record bị drop. Nếu muốn lossless, tăng `logging.sender.max_queue_size` trong config.
- **`_send_batch` chỉ dùng `server_urls[0]`** (sender.py:225) - KHÔNG fallback sang URL khác như sync/heartbeat. Cứ POST tới URL đầu tiên. Lý do: log volume cao, fail nhanh dễ hơn fail qua 3 server.
- **Không còn hardcoded Render/localhost fallback** (P0.5): empty config ⇒ sender đăng log warning "OFFLINE mode" và `_send_batch` skip silently (`logger.debug` mỗi batch). Trước đây fallback `["https://firewall-controller.onrender.com", "http://localhost:5000"]` có thể leak log lên Render production của repo gốc — đã xoá.
- **401 KHÔNG retry** (sender.py:243-245): trả `False`, log warning. Batch logs đó **mất** - không re-queue. Khi token expired, một số log sẽ bị mất giữa thời điểm expire và thời điểm refresh.
- **Status 200/201/202 đều coi là OK** (sender.py:240). Server hiện trả 202 (accepted, queued). Đừng thay đổi expectation thành `== 200`.
- **Essential fields inject sau `_serialize_log` đệ quy** (sender.py:130-152): logic check `is_lifecycle_event` quyết định có inject network defaults hay không. Lifecycle log thiếu field `domain` sẽ KHÔNG bị fill `"unknown"`. Server side phải biết schema này.
- **None → `"unknown"`** (sender.py:121-122): mọi `None` value trong dict được convert thành string `"unknown"`. Hậu quả: server không phân biệt được "field missing" và "field is null". Hiện đồng thuận format này - server schema không có nullable field.
- **`_flush_queue` không có timeout total** - nếu queue 1000 item, send 1 batch lớn có thể fail timeout 15s ⇒ mất hết. Acceptable cho shutdown.
- **`_serialize_log` recursive depth không giới hạn** - record với cycle sẽ stack overflow. Hiện không ai tạo record có cycle, nhưng nếu future log structured event với object refs thì cần guard.
- **`_generate_agent_id` chỉ dùng khi config không có agent_id** - fallback `hostname-mac`. Sau register thành công, `config['agent_id']` được set với UUID từ server. Generate-fallback chỉ chạy ở edge case (config corrupted, register fail nhưng vẫn cố log).
- **`send_interval = 2s` nghĩa là time-since-last-send**, không phải fixed interval. Nếu queue luôn full (> batch_size) → gửi liên tục. Nếu queue rỗng → no-op cho tới khi có log + đủ 2s.
- **Wake interval `sleep(1)`** (sender.py:172) là minimum latency từ lúc queue log tới khi gửi. Test cần đợi ≥1s sau queue mới check server.
