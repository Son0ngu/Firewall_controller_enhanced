# `agent/firewall` - Windows Firewall (Default Deny + Whitelist)

## Mục đích
Quản lý Windows Firewall qua `FirewallProvider` abstraction. Read side ưu tiên PowerShell NetSecurity khi khả dụng và fallback `netsh`; write side mặc định vẫn dùng `netsh` để giữ behavior cũ, có opt-in `FIREWALL_WRITE_BACKEND=powershell` cho NetSecurity sau Windows-admin smoke. Bật **Default Deny outbound** + tạo allow rules cho whitelist (IPs + domains resolved). Có snapshot/restore để hoàn nguyên về trạng thái pre-SAINT. IPv4-only.

Kiến trúc chính: `FirewallManager` (orchestrator) → `PolicyManager` (chính sách 3 profile) + `RulesManager` (CRUD rules) → `FirewallProvider` (`NetSecurityFirewallProvider` hoặc `NetshFirewallProvider`) + `FirewallUtils` (validate, essential IPs, legacy netsh runner).

## Public API

### `agent/firewall/manager.py` - Orchestrator

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `FirewallManager` | `class` | [manager.py:52](../../../agent/firewall/manager.py#L52) | Composes Policy + Rules + state |
| `FirewallManager.__init__(rule_prefix="FirewallController", provider=None, write_provider=None)` | `(str, Optional[FirewallProvider], Optional[FirewallProvider])` | [manager.py:53](../../../agent/firewall/manager.py#L53) | Wire read/write providers, load existing rules, backup current policy, detect mode đang chạy |
| `.allowed_ips` | `@property -> Set[str]` | [manager.py:273](../../../agent/firewall/manager.py#L273) | Delegate sang `rules_manager.allowed_ips` |
| `.default_deny_enabled` | `@property -> bool` | [manager.py:278](../../../agent/firewall/manager.py#L278) | Delegate sang `policy_manager` |
| `.enable_whitelist_mode(server_urls=None, whitelist_ips=None, whitelist_domains=None)` | `(List[str], Set[str], Set[str]) -> bool` | [manager.py:517](../../../agent/firewall/manager.py#L517) | **Entry point khi startup**. Tạo self-allow rules → essential IPs → resolve server URLs → whitelist IPs → resolve domains → tạo allow rules → **rồi mới** enable Default Deny |
| `.setup_whitelist_firewall(whitelisted_ips, essential_ips=None)` | `(Set[str], Set[str]) -> bool` | [manager.py:86](../../../agent/firewall/manager.py#L86) | Variant ngắn: gộp whitelisted + essential, self-allow, Default Deny, batch allow rules |
| `.update_whitelist(domains, ips)` | `(Set[str], Set[str]) -> bool` | [manager.py:403](../../../agent/firewall/manager.py#L403) | **Được `WhitelistManager` gọi sau sync**. Resolve domains, sync diff (add/remove) |
| `.add_ip_to_whitelist(ip, reason="dynamic_addition")` | `(str, str) -> bool` | [manager.py:138](../../../agent/firewall/manager.py#L138) | |
| `.remove_ip_from_whitelist(ip)` | `(str) -> bool` | [manager.py:162](../../../agent/firewall/manager.py#L162) | |
| `.sync_whitelist_changes(old_ips, new_ips)` | `(Set[str], Set[str]) -> bool` | [manager.py:181](../../../agent/firewall/manager.py#L181) | Diff-based add/remove |
| `.cleanup_whitelist_firewall()` | `() -> bool` | [manager.py:214](../../../agent/firewall/manager.py#L214) | Clear all rules + restore original policy (fallback default) |
| `.cleanup_all_rules()` | `() -> bool` | [manager.py:244](../../../agent/firewall/manager.py#L244) | Legacy alias - gần giống `cleanup_whitelist_firewall` |
| `.clear_all_rules()` | `() -> bool` | [manager.py:240](../../../agent/firewall/manager.py#L240) | Chỉ xoá rules, **không** đổi policy |
| `.get_whitelist_status()` | `() -> Dict` | [manager.py:283](../../../agent/firewall/manager.py#L283) | Snapshot status (cho heartbeat / GUI) |
| `.get_firewall_policy_status()` | `() -> Dict` | [manager.py:296](../../../agent/firewall/manager.py#L296) | Bao gồm `policies` cho từng profile |
| `.validate_firewall_state()` | `() -> Dict` | [manager.py:315](../../../agent/firewall/manager.py#L315) | Liệt `issues` nếu state lệch |
| `.test_whitelist_connectivity(sample_ips)` | `(List[str]) -> Dict[str, bool]` | [manager.py:348](../../../agent/firewall/manager.py#L348) | Test max 5 IP đầu |
| `.is_blocked(ip)` | `(str) -> bool` | [manager.py:367](../../../agent/firewall/manager.py#L367) | Legacy: trong Default Deny mode, không nằm trong whitelist = blocked |
| `.block_ip(ip, domain=None)` | `(str, Optional[str]) -> bool` | [manager.py:379](../../../agent/firewall/manager.py#L379) | Legacy: tương đương `remove_ip_from_whitelist` |
| `.unblock_ip(ip)` | `(str) -> bool` | [manager.py:386](../../../agent/firewall/manager.py#L386) | Legacy: tương đương `add_ip_to_whitelist` |
| `.save_snapshot(path=DEFAULT_SNAPSHOT_FILENAME, *, force=False)` | `(str, bool) -> bool` | [manager.py:629](../../../agent/firewall/manager.py#L629) | Atomic write (tempfile + `os.replace`). `force=False` → skip-if-exists để giữ baseline pre-SAINT |
| `.restore_snapshot(path=DEFAULT_SNAPSHOT_FILENAME)` | `(str) -> bool` | [manager.py:709](../../../agent/firewall/manager.py#L709) | Cần admin. Restore profiles, clear SAINT rules, **không** re-enable whitelist mode kể cả snapshot đã ở đó |
| `DEFAULT_SNAPSHOT_FILENAME` | `str` const | [manager.py:21](../../../agent/firewall/manager.py#L21) | `"profiles/backup.saint-snapshot.json"` dưới `%LOCALAPPDATA%\SAINT` khi dùng đường dẫn tương đối |
| `_resolve_snapshot_path(path)` | `(str) -> Path` | [manager.py:44](../../../agent/firewall/manager.py#L44) | Resolve tương đối → `%LOCALAPPDATA%\SAINT`, không ghi runtime state cạnh EXE |
| `_resolve_snapshot_read_path(path)` | `(str) -> Path` | [manager.py:58](../../../agent/firewall/manager.py#L58) | Đọc snapshot ở AppData trước, fallback legacy install/exe dir nếu backup cũ còn tồn tại |

### `agent/firewall/policy.py` - Default Deny policy

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `PolicyManager` | `class` | [policy.py:9](../../../agent/firewall/policy.py#L9) | Quản 3 profile: domain / private / public |
| `.get_current_policy()` | `() -> Dict[str, str]` | [policy.py:15](../../../agent/firewall/policy.py#L15) | Parse `netsh advfirewall show allprofiles`, trả `{profile: "allow"/"block"}` cho Outbound |
| `.backup_current_policy()` | `() -> None` | [policy.py:48](../../../agent/firewall/policy.py#L48) | Lưu vào `_original_policies` để restore sau |
| `.enable_default_deny()` | `() -> bool` | [policy.py:56](../../../agent/firewall/policy.py#L56) | Set `blockinbound,blockoutbound` cho 3 profile |
| `.verify_default_deny()` | `() -> bool` | [policy.py:100](../../../agent/firewall/policy.py#L100) | Re-parse và confirm ≥1 profile ở chế độ block |
| `.restore_original_policy()` | `() -> bool` | [policy.py:138](../../../agent/firewall/policy.py#L138) | Restore từ `_original_policies`; rỗng → fallback default |
| `.restore_default_policy()` | `() -> bool` | [policy.py:170](../../../agent/firewall/policy.py#L170) | Set tất cả profile về `blockinbound,allowoutbound` (mặc định Windows) |
| `.default_deny_enabled` | `bool` | [policy.py:13](../../../agent/firewall/policy.py#L13) | State flag |

### `agent/firewall/rules.py` - CRUD rules

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `RulesManager` | `class` | [rules.py:10](../../../agent/firewall/rules.py#L10) | Threadsafe (`_rule_lock` cho batch) |
| `.create_self_allow_rules(program_path)` | `(str) -> bool` | [rules.py:17](../../../agent/firewall/rules.py#L17) | Tạo 3 rule cho exe agent: TCP 443, UDP 53, TCP 53. **Idempotent** qua write provider (delete-then-add). Bằng `program=` không `remoteip=` ⇒ bền với DNS rotation. |
| `.create_allow_rule(ip)` | `(str) -> bool` | [rules.py:74](../../../agent/firewall/rules.py#L74) | Tên rule: `{prefix}_Allow_{ip_underscored}_{unix_ts}`. Skip nếu đã có. |
| `.remove_allow_rule(ip)` | `(str) -> bool` | [rules.py:112](../../../agent/firewall/rules.py#L112) | List all → match theo pattern `_<ip>_` → delete từng cái |
| `.create_allow_rules_batch(ips)` | `(Set[str]) -> bool` | [rules.py:162](../../../agent/firewall/rules.py#L162) | Sorted iteration với `sleep(0.02)` giữa các netsh để giữ stability |
| `.clear_all_rules()` | `() -> bool` | [rules.py:191](../../../agent/firewall/rules.py#L191) | Xoá mọi rule có prefix khớp `self.rule_prefix` |
| `.load_existing_rules()` | `() -> None` | [rules.py:240](../../../agent/firewall/rules.py#L240) | Đọc state hiện có vào `allowed_ips` lúc init (cho recovery sau crash) |
| `.get_rule_count()` | `() -> int` | [rules.py:291](../../../agent/firewall/rules.py#L291) | Đếm rules có prefix |
| `.allowed_ips` | `Set[str]` | [rules.py:14](../../../agent/firewall/rules.py#L14) | In-memory cache |

### `agent/firewall/provider.py` - Backend abstraction

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `FirewallProvider` | `ABC` | [provider.py](../../../agent/firewall/provider.py) | Contract chung cho read + write firewall operations. |
| `get_default_provider()` | `() -> FirewallProvider` | [provider.py](../../../agent/firewall/provider.py) | Read backend: env `SAINT_FIREWALL_PROVIDER`, rồi NetSecurity nếu available, fallback netsh. |
| `get_write_provider()` | `() -> FirewallProvider` | [provider.py](../../../agent/firewall/provider.py) | Write backend: default `netsh`; opt-in PowerShell/NetSecurity bằng `FIREWALL_WRITE_BACKEND=powershell` hoặc `netsecurity`. |
| `FirewallProvider.create_or_replace_rule(...)` | `(...) -> bool` | [provider.py](../../../agent/firewall/provider.py) | Create managed rule with exact-name replacement semantics. |
| `FirewallProvider.delete_rules_by_prefix(rule_prefix)` | `(str) -> int` | [provider.py](../../../agent/firewall/provider.py) | Clear all SAINT-managed rules for a prefix. |
| `FirewallProvider.set_profile_outbound_policy(profile, action)` | `(str, str) -> bool` | [provider.py](../../../agent/firewall/provider.py) | Set outbound policy to `allow` or `block`. |

### `agent/firewall/application_service.py` - GUI facade

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `FirewallApplicationService` | `class` | [application_service.py](../../../agent/firewall/application_service.py) | UI-safe facade for manual restore/clear operations. |
| `.restore_firewall_snapshot(path=DEFAULT_SNAPSHOT_FILENAME)` | `(str) -> bool` | [application_service.py](../../../agent/firewall/application_service.py) | Delegate to running `FirewallManager` when supplied, otherwise create one. |
| `.clear_saint_rules()` | `() -> bool` | [application_service.py](../../../agent/firewall/application_service.py) | Clear SAINT rules via manager/rules backend; GUI does not call netsh directly. |

### `agent/firewall/utils.py` - Helpers

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `FirewallUtils.is_valid_ipv4(ip)` | `(str) -> bool` | [utils.py:15](../../../agent/firewall/utils.py#L15) | Wrap `ipaddress.ip_address` |
| `FirewallUtils.is_valid_ip(ip)` | `(str) -> bool` | [utils.py:23](../../../agent/firewall/utils.py#L23) | **IPv4 only** - agent firewall không hỗ trợ IPv6 |
| `FirewallUtils.get_essential_ips()` | `() -> Set[str]` | [utils.py:30](../../../agent/firewall/utils.py#L30) | localhost + system DNS (dnspython resolver) + local IP + gateway (`x.x.x.1` heuristic). Không inject public DNS fallback khi không detect được DNS |
| `FirewallUtils.has_admin_privileges()` | `() -> bool` | [utils.py:67](../../../agent/firewall/utils.py#L67) | Wrap `utils.ip_detector.check_admin_privileges` |
| `FirewallUtils.run_netsh_command(args, timeout=30)` | `(list, int) -> CompletedProcess` | [utils.py:76](../../../agent/firewall/utils.py#L76) | `subprocess.run` với `CREATE_NO_WINDOW` (không nháy console). **Dùng cái này** cho mọi netsh call |
| `FirewallUtils.test_ip_connectivity(ip, ports=None, timeout=3)` | `(str, list, int) -> bool` | [utils.py:88](../../../agent/firewall/utils.py#L88) | TCP connect_ex tới 80/443/53 (default). Return True nếu ≥1 port OK |

## Ai gọi module này
- `agent/core/lifecycle.py` - khởi tạo `FirewallManager`, gọi `save_snapshot`, `enable_whitelist_mode`, `cleanup`
- `agent/whitelist/manager.py` - gọi `update_whitelist(domains, ips)` sau mỗi sync
- `agent/gui_qt/views/settings.py` - gọi `FirewallApplicationService.restore_firewall_snapshot` từ nút Restore

## Module này gọi ra
- `agent/shared/time_utils` - timestamp cho rule descriptions
- `agent/utils/ip_detector` - `check_admin_privileges`, `get_local_ip`
- `agent/network` - `OptimizedDNSResolver` (lazy import, fallback `socket.getaddrinfo`)
- `dns.resolver` - detect system DNS
- `subprocess` - chạy `netsh` hoặc PowerShell backend qua provider

## Đã có sẵn - đừng viết lại
- Cần thao tác firewall read/write? → đi qua `FirewallProvider` / `RulesManager` / `PolicyManager`. Chỉ dùng `FirewallUtils.run_netsh_command(args)` khi đang implement hoặc maintain `NetshFirewallProvider`.
- Cần validate IPv4? → `FirewallUtils.is_valid_ip(ip)`
- Cần list IP "phải allow để máy còn dùng được"? → `FirewallUtils.get_essential_ips()`
- Cần test TCP tới IP? → `FirewallUtils.test_ip_connectivity(ip)`
- Cần resolve path snapshot tương đối → absolute? → `manager._resolve_snapshot_path(path)` cho write path, `manager._resolve_snapshot_read_path(path)` cho restore fallback.

## Gotchas
- **IPv4 only** - `is_valid_ip` reject IPv6. Khi DNS trả AAAA, drop. Đừng "fix" bằng cách cho qua - `netsh advfirewall` với IPv6 có quirks (empty stderr on failure).
- **Thứ tự CRITICAL khi startup**: self-allow → tạo allow rules → **rồi mới** `enable_default_deny`. Đảo lại = self-lock. Xem `enable_whitelist_mode` (manager.py:517-593). `setup_whitelist_firewall` (manager.py:86) có thứ tự khác (deny trước, allow sau) - kế thừa logic cũ và chỉ nên dùng khi đã có self-allow rules từ trước.
- **`save_snapshot(force=False)` mặc định skip-if-exists**: nếu sau crash agent restart, snapshot có thể đã chứa state "post-SAINT-mutation". Ta CHỦ Ý không ghi đè để giữ baseline pre-SAINT thực sự. Muốn ghi mới phải `force=True` (chỉ admin tool hoặc rõ user intent).
- **`restore_snapshot` KHÔNG re-enable whitelist mode** kể cả khi snapshot ghi nhận đang ở whitelist mode (line 785). Lý do: user click Restore = muốn thoát khỏi SAINT control, ngược lại sẽ bất ngờ.
- **`restore_snapshot` cần admin** (line 726). Nếu không có admin, `netsh` silent fail mà returncode vẫn 0 ⇒ ta đã thêm guard explicit.
- **Snapshot lockout safety net** (manager.py:764): nếu mọi profile đều `block` trong snapshot, restore sẽ force về `allowoutbound` mặc định để không cô lập máy.
- **`remove_allow_rule` dùng pattern match `_<ip>_`** (rules.py:118): nếu một IP được tạo nhiều rule khác nhau (e.g. dynamic add nhiều lần), tất cả sẽ bị xoá - đó là design.
- **Write backend default vẫn là netsh**: `FIREWALL_WRITE_BACKEND=powershell` đã có nhưng là opt-in. Chỉ đổi default sau Windows-admin smoke vì rule write sai có thể làm agent không tạo allow rules hoặc khóa traffic.
- **`load_existing_rules`** không parse text trong `RulesManager` nữa; nó gọi `FirewallProvider.list_outbound_allow_ips`. Non-English Windows nên dùng NetSecurity read provider khi available.
- **`_resolve_domains_to_ips` lazy import `agent.network.OptimizedDNSResolver`** (manager.py:485). Nếu module bị rename/move, fallback sang `socket.getaddrinfo` - đừng vì thấy ImportError mà sửa ngay, có thể đúng đường fallback.
- **Rule prefix trùng = collision**: nếu chạy 2 instance agent (vd dev + prod) cùng `rule_prefix`, `clear_all_rules` sẽ xoá lẫn nhau. Config validator phải đảm bảo prefix unique nếu cần coexistence.
- **`get_essential_ips` cố detect gateway bằng heuristic `x.x.x.1`** (utils.py:58). Sai trong mạng có gateway custom (e.g. `192.168.0.254`). Hiện coi như edge case acceptable; nếu sửa, tránh `netsh interface ip show config` vì chậm.
