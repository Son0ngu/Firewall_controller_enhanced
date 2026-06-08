# Bảo mật, rủi ro và giới hạn của Agent

## Cập nhật xác thực firewall 2026-05-28

Baseline mới nhất là Render full deep E2E run `20260528_141158`, chạy trên máy Windows Administrator với `-RunRealFirewallPolicy -WriteBackend powershell -Deep`. Kết quả PASS sạch: `24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0`, `cleanup_failures=0`, `CLEANUP_OK=43`. Phần firewall dùng backend ghi `powershell`/NetSecurity và xác nhận:

- Snapshot trước mutation có đủ `domain/private/public = allow`.
- Bật whitelist-only/Default Deny thành công, cả 3 profile outbound chuyển sang `block`.
- Self-allow rules đủ 3 rule: HTTPS TCP/443, DNS UDP/53, DNS TCP/53; không duplicate sau tạo lại.
- Packet allowed vẫn kết nối được trong khi Default Deny active.
- Packet blocked bị chặn đúng trong khi Default Deny active.
- Managed allow rule test add/remove đúng.
- Restore snapshot thành công, cả 3 profile quay về `allow`, residual SAINTE2E rules = 0, blocked candidate kết nối lại được sau restore.

Run firewall-only `20260527_235108` vẫn là smoke lịch sử hữu ích, nhưng kết luận hiện tại nên lấy từ full deep run `20260528_141158` vì nó cover thêm Agent/server contract, heartbeat policy force sync, GUI, Socket.IO, classroom scale và 30-minute soak.

Kết luận vận hành: PowerShell/NetSecurity write backend đã đạt packet-level smoke trên một máy Windows admin thật và đã pass trong full deep Render E2E. Tuy nhiên vẫn cần canary thêm máy lab trước khi đổi default rộng, vì rủi ro khóa mạng phụ thuộc driver/firewall policy/local security software từng máy. Những phần chưa test thật sự: multi-machine vật lý, reboot/service autostart sau reboot và soak dài hơn 30 phút.

## Cập nhật an toàn Default Deny 2026-06-08

Đã fix các đường bật whitelist firewall (`FirewallManager.setup_whitelist_firewall()` và `enable_whitelist_mode()`) để không bật Default Deny trước khi tạo allow rules. Thứ tự mới:

1. Tạo self-allow rules cho chương trình Agent.
2. Tạo toàn bộ allow rules cho whitelist IP + essential IP.
3. Chỉ khi hai bước trên thành công mới bật Windows Firewall Default Deny.

`RulesManager.create_allow_rules_batch()` cũng được đổi sang fail-closed: batch chỉ thành công khi tất cả IP trong batch tạo rule thành công, không còn coi "tạo được ít nhất một rule" là đủ. Unit test mới xác nhận Default Deny không được gọi nếu self-allow hoặc allow batch thất bại.

## Cơ chế bảo mật

| Cơ chế | Source | Ý nghĩa |
| --- | --- | --- |
| API Key khi đăng ký | `agent/core/registry.py` | Agent không tự đăng ký nếu thiếu credential hợp lệ. |
| JWT access/refresh | `agent/core/token_manager.py` | Gọi API sau đăng ký bằng token, có auto refresh. |
| Config encryption | `agent/config/crypto.py` | Mã hóa file config chứa thông tin nhạy cảm theo machine key. |
| Whitelist-only | `agent/firewall/manager.py` | Default Deny outbound, chỉ allow whitelist/server/DNS. |
| Snapshot/restore | `agent/firewall/manager.py`, `agent/gui_qt/views/settings.py` | Giảm rủi ro khi cần phục hồi policy. |

## Rủi ro ngắt mạng

`whitelist_only` có thể làm máy mất kết nối nếu:

- Chưa allow IP Server hoặc DNS trước khi bật Default Deny.
- Domain whitelist không resolve được.
- Agent chạy với quyền Administrator trên máy thật nhưng cấu hình sai.
- Cleanup/restore thất bại sau khi tạo rules.

## Giảm rủi ro đã có trong code

- `create_self_allow_rules()` allow chương trình Agent.
- `_resolve_server_urls()` resolve và allow Server URL trước khi bật policy.
- `setup_whitelist_firewall()` và `enable_whitelist_mode()` đều theo nguyên tắc allow-before-deny; nếu self-allow hoặc allow batch thất bại thì không bật Default Deny.
- `sync_whitelist_changes()` now keeps protected essential/server IPs, and `remove_ip_from_whitelist()` refuses to remove them.
- `shared/server_urls.py::collect_server_urls(config, allow_dev_default=False)` là resolver URL Server chung; khi chưa cấu hình Server, Agent ở first-run offline mode thay vì tự fallback về `http://localhost:5000`.
- `PolicyManager.backup_current_policy()` và restore policy.
- `RulesManager.clear_all_rules()` dọn rule theo prefix.
- Settings view có thao tác restore/clear rule thủ công.

## Giới hạn

- Tập trung Windows; dùng `netsh`, pywin32, Scapy/driver packet capture.
- Layer 7 chỉ quan sát DNS/HTTP/SNI, không decrypt HTTPS.
- Nếu CDN/shared IP làm IP được whitelist nhưng domain khác đi qua, hệ thống ghi warning thay vì luôn chặn chính xác ở domain-level.
