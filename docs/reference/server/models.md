# `server/models` - MongoDB collections layer

## Mục đích
Wrap mỗi MongoDB collection thành một class với CRUD methods + index setup ở `__init__`. **Không có ORM** - pymongo trực tiếp. Datetime → tz VN qua `time_utils`. Pattern chung: `_setup_indexes()` chạy lúc construct, mỗi method try-except + log.

11 model files. Group-scoped whitelist entries now have first-class storage in `whitelist_entries`; legacy `groups.whitelist[]` remains a one-release read fallback.

## Collections map

| Model | Collection | Mục đích | Key fields |
|---|---|---|---|
| `AgentModel` | `agents` | Thông tin agent (host, IP, status, heartbeat) | `agent_id` unique, `device_id` unique sparse |
| `WhitelistModel` | `whitelist` + `whitelist_meta` | Whitelist entries + global version metadata | `value` lower, `scope`, `group_id` |
| `WhitelistEntryModel` | `whitelist_entries` | First-class group whitelist entries during migration away from `groups.whitelist[]` | `_id`, `scope`, `group_id`, `type`, `value`, `legacy_embedded_id` |
| `LogModel` | `logs` | Network logs từ agent | `timestamp` DESC, `agent_id`, `action` |
| `GroupModel` | `groups` | Groups + per-group whitelist + assigned teachers | `name` unique, `teacher_ids` |
| `UserModel` | `users` | Admin/teacher accounts (bcrypt password) | `username` unique, `email` unique sparse |
| `SessionModel` | `admin_sessions` | Active admin/teacher login sessions với JTI | TTL on `expires_at`, `access_token_jti` unique |
| `AuditModel` | `audit_logs` | Append-only audit trail | `timestamp` DESC, `user_id`, `action` |
| `APIKeyModel` | `api_keys` | Agent registration API keys (HMAC-SHA256 hashed); no rate-limit fields/enforcement | `key_hash` unique |
| `AgentPolicyModel` | `agent_policies` | Per-agent override (isolate/custom_whitelist) | `agent_id` unique |
| `WhitelistProfileModel` | `whitelist_profiles` | Per-teacher whitelist profiles trong group | `group_id+teacher_id` compound |

## Public API

### `models/agent_model.py` - `AgentModel`

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [agent_model.py:19](../../../server/models/agent_model.py#L19) | Setup 7 index (agent_id unique, device_id unique sparse, hostname, ip, last_heartbeat DESC, status, group_id, compound hostname+ip) |
| `register_agent(agent_data)` | `(Dict) -> Dict` | [agent_model.py:44](../../../server/models/agent_model.py#L44) | Insert mới. Set `registered_date`, `updated_date`, `last_heartbeat` = now_vietnam, default `status="pending"` |
| `update_agent(agent_id, update_data)` | `(str, Dict) -> bool` | [agent_model.py:68](../../../server/models/agent_model.py#L68) | `$set` thêm `updated_date` |
| `update_agent_group(agent_id, group_id, status=None)` | | [agent_model.py:82](../../../server/models/agent_model.py#L82) | Chuyển agent sang group khác |
| `update_heartbeat(agent_id, update_data)` | | [agent_model.py:93](../../../server/models/agent_model.py#L93) | Parse `last_heartbeat` qua `parse_agent_timestamp` (handle agent timestamp lệch tz) |
| `find_by_agent_id(agent_id)` | `(str) -> Optional[Dict]` | [agent_model.py:116](../../../server/models/agent_model.py#L116) | |
| `find_by_device_id(device_id)` | | [agent_model.py:139](../../../server/models/agent_model.py#L139) | Dùng cho dedup khi register lại |
| `find_by_hostname(hostname)` | `(str) -> List[Dict]` | [agent_model.py:131](../../../server/models/agent_model.py#L131) | Regex case-insensitive |
| `count_by_group(group_id)` | `(str) -> int` | [agent_model.py:124](../../../server/models/agent_model.py#L124) | |
| `get_all_agents(query=None, limit=100, skip=0)` | | [agent_model.py:147](../../../server/models/agent_model.py#L147) | Sort by `last_heartbeat` DESC |
| `count_agents(query=None)` | `→ int` | [agent_model.py:157](../../../server/models/agent_model.py#L157) | |
| `get_active_agents(inactive_threshold_minutes=5)` | | [agent_model.py:167](../../../server/models/agent_model.py#L167) | `last_heartbeat >= now - 5min` |
| `get_inactive_agents(...)` | | [agent_model.py:180](../../../server/models/agent_model.py#L180) | |
| `delete_agent(agent_id)` | | [agent_model.py:193](../../../server/models/agent_model.py#L193) | |
| `get_agent_statistics(inactive_threshold_minutes=5)` | `→ Dict` | [agent_model.py:203](../../../server/models/agent_model.py#L203) | Aggregate by computed `actual_status` (active/inactive/offline) qua `$cond` so sánh `last_heartbeat` với threshold |

### `models/whitelist_model.py` - `WhitelistModel` (collections: `whitelist`, `whitelist_meta`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [whitelist_model.py:21](../../../server/models/whitelist_model.py#L21) | Setup 7 index + 1 compound `(value, type, is_active)`. Conflict-aware (check existing) |
| `get_global_version() / bump_global_version()` | `→ int` | [whitelist_model.py:44, 51](../../../server/models/whitelist_model.py#L44) | Version cho global scope, lưu ở `whitelist_meta` collection scope="global". Agent dùng để detect change |
| `insert_entry(entry_data)` | `(Dict) -> str` | [whitelist_model.py:168](../../../server/models/whitelist_model.py#L168) | Default `is_active=True, type="domain", scope="global"`. Auto-bump version nếu scope global |
| `find_all_entries(query, sort_field="added_date", sort_order=DESC)` | | [whitelist_model.py:207](../../../server/models/whitelist_model.py#L207) | Default `is_active=True`. Cleanup expired trước. Convert timezones cho display |
| `find_entry_by_value(value, active_only=False)` | | [whitelist_model.py:272](../../../server/models/whitelist_model.py#L272) | Lowercase + strip |
| `find_entry_by_id(entry_id, active_only=False)` | | [whitelist_model.py:433](../../../server/models/whitelist_model.py#L433) | |
| `cleanup_expired_entries()` | `→ int` | [whitelist_model.py:290](../../../server/models/whitelist_model.py#L290) | Xoá `expiry_date < now`. Bump version |
| `validate_entry_value(entry_type, value)` | `→ Dict` | [whitelist_model.py:314](../../../server/models/whitelist_model.py#L314) | Cho domain/ip/url. Regex domain, `socket.inet_aton` IP, `urlparse` URL |
| `delete_entry(entry_id)` | `→ bool` | [whitelist_model.py:364](../../../server/models/whitelist_model.py#L364) | Bump version nếu global |
| `update_entry(entry_id, update_data)` | `→ bool` | [whitelist_model.py:381](../../../server/models/whitelist_model.py#L381) | Bump version nếu global. **Đừng** dùng cho group entries - group entries đi qua `WhitelistEntryModel`/`WhitelistService`. |
| `bulk_insert_entries(entries)` | `→ List[str]` | [whitelist_model.py:488](../../../server/models/whitelist_model.py#L488) | Set timestamps, defaults |
| `get_entries_for_sync(since_date=None, scope="global", group_id=None)` | `→ List[Dict]` | [whitelist_model.py:451](../../../server/models/whitelist_model.py#L451) | Format sync: chỉ value/type/priority/category/added_date |
| `verify_dns(domain)` | `→ Dict` | [whitelist_model.py:542](../../../server/models/whitelist_model.py#L542) | `socket.getaddrinfo` |
| `get_statistics()` | | [whitelist_model.py:406](../../../server/models/whitelist_model.py#L406) | total/active/inactive + by_type aggregate |
| `build_query_from_filters(filters)` | | [whitelist_model.py:516](../../../server/models/whitelist_model.py#L516) | Build mongo query từ filters dict (type/category/added_by/search) |
| `_convert_entry_timezones(entry)` | | [whitelist_model.py:246](../../../server/models/whitelist_model.py#L246) | Inject `*_formatted`, `*_iso` fields |

### `models/whitelist_entry_model.py` - `WhitelistEntryModel` (collection: `whitelist_entries`)

First-class storage for group whitelist entries during migration away from `groups.whitelist[]`.

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Setup indexes for `scope`, `group_id`, `is_active`, `legacy_embedded_id`, and `(scope, group_id, type, value, is_active)`. |
| `insert_entry(entry_data)` | `(Dict) -> str` | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Normalize group entry and return real ObjectId string. |
| `bulk_insert_entries(entries)` | `(List[Dict]) -> List[str]` | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Bulk insert normalized entries. |
| `list_group_entries(group_id, include_inactive=True)` | `-> List[Dict]` | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | List collection rows for one group. |
| `find_entry_by_id(entry_id, active_only=False)` | `-> Optional[Dict]` | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Lookup by real ObjectId string. |
| `find_entry_access_info(entry_id)` | `-> Optional[Dict]` | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Minimal RBAC access lookup: `scope`, `group_id`. |
| `update_entry(entry_id, update_data)` / `delete_entry(entry_id)` | | [whitelist_entry_model.py](../../../server/models/whitelist_entry_model.py) | Mutate real collection rows; caller bumps group whitelist version. |

### `models/log_model.py` - `LogModel` (collection: `logs`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [log_model.py:28](../../../server/models/log_model.py#L28) | Setup 5 index incl compound `(action, timestamp)` |
| `insert_logs(logs)` | `(List[Dict]) -> List[str]` | [log_model.py:150](../../../server/models/log_model.py#L150) | Parse mỗi `timestamp` qua `_parse_timestamp` (tolerant). Set `server_received_at = now_vietnam()` |
| `find_all_logs(query, limit=100, offset=0)` | | [log_model.py:78](../../../server/models/log_model.py#L78) | Sort by `timestamp` DESC. Inject `display_time` (HH:MM:SS). Default essential fields |
| `find_logs(query, limit=100, skip=0, sort_field="timestamp", sort_order=DESC)` | | [log_model.py:226](../../../server/models/log_model.py#L226) | Variant với pagination skip |
| `count_logs(query=None)` | | [log_model.py:62](../../../server/models/log_model.py#L62) | |
| `delete_logs(query=None)` | `→ int` | [log_model.py:134](../../../server/models/log_model.py#L134) | Delete với query, return count |
| `get_total_count()` | | [log_model.py:182](../../../server/models/log_model.py#L182) | Wrapper `count_documents({})` |
| `get_count_by_action(action)` | | [log_model.py:190](../../../server/models/log_model.py#L190) | |
| `get_recent_logs(limit=10)` | | [log_model.py:198](../../../server/models/log_model.py#L198) | Include `time_ago` string |
| `get_logs_summary(since=None)` | `→ Dict` | [log_model.py:258](../../../server/models/log_model.py#L258) | Default last 24h. Count total/allowed/blocked/error |

### `models/group_model.py` - `GroupModel` (collection: `groups`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [group_model.py:14](../../../server/models/group_model.py#L14) | Setup 5 index (name unique, is_system, created_at, created_by, teacher_ids) |
| `ensure_pending_group()` | `→ Dict` | [group_model.py:30](../../../server/models/group_model.py#L30) | Atomic upsert system group `name=pending, is_system=True`. Goi từ AgentService.__init__ và app bootstrap |
| `create_group(name, description="", whitelist=None, is_system=False, created_by=None)` | | [group_model.py:59](../../../server/models/group_model.py#L59) | Initialize `whitelist_version=1`, `teacher_ids=[]` |
| `add_teacher(group_id, teacher_id)` | | [group_model.py:76](../../../server/models/group_model.py#L76) | `$addToSet` |
| `remove_teacher(group_id, teacher_id)` | | [group_model.py:84](../../../server/models/group_model.py#L84) | `$pull` |
| `set_teachers(group_id, teacher_ids)` | | [group_model.py:92](../../../server/models/group_model.py#L92) | Replace full list |
| `list_groups(query_filter=None)` | | [group_model.py:100](../../../server/models/group_model.py#L100) | |
| `find_by_id(group_id)` | | [group_model.py:104](../../../server/models/group_model.py#L104) | |
| `update_group(group_id, update_data)` | | [group_model.py:110](../../../server/models/group_model.py#L110) | Whitelist update auto-bump version (read-then-increment) |
| `delete_group(group_id)` | | [group_model.py:138](../../../server/models/group_model.py#L138) | |
| `bump_whitelist_version(group_id)` | | [group_model.py:142](../../../server/models/group_model.py#L142) | `$inc whitelist_version` |

### `models/user_model.py` - `UserModel` (collection: `users`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `MAX_FAILED_ATTEMPTS = 5` / `LOCK_DURATION_MINUTES = 15` | const | [user_model.py:19-20](../../../server/models/user_model.py#L19) | Brute-force protection |
| `__init__(db)` | | [user_model.py:26](../../../server/models/user_model.py#L26) | Setup 5 index (username unique, email unique sparse, role+is_active compound, created_by, created_at DESC) |
| `create(user_data)` | `(Dict) -> Dict` | [user_model.py:48](../../../server/models/user_model.py#L48) | Set defaults: `is_active=True`, `failed_login_attempts=0`, `locked_until=None` |
| `find_by_id(user_id)` | | [user_model.py:75](../../../server/models/user_model.py#L75) | |
| `find_by_username(username)` | | [user_model.py:83](../../../server/models/user_model.py#L83) | **Regex case-insensitive với `re.escape`** - safe |
| `find_by_email(email)` | | [user_model.py:94](../../../server/models/user_model.py#L94) | Tương tự |
| `get_all_users(query=None, limit=100, skip=0)` | | [user_model.py:105](../../../server/models/user_model.py#L105) | |
| `count_users(query=None)` | | [user_model.py:120](../../../server/models/user_model.py#L120) | |
| `update(user_id, update_data)` | | [user_model.py:134](../../../server/models/user_model.py#L134) | |
| `update_last_login(user_id)` | | [user_model.py:147](../../../server/models/user_model.py#L147) | |
| `increment_failed_attempts(user_id)` | `→ int` | [user_model.py:163](../../../server/models/user_model.py#L163) | Khi >= MAX, set `locked_until = now + 15min` |
| `reset_failed_attempts(user_id)` | | [user_model.py:188](../../../server/models/user_model.py#L188) | Sau login success |
| `is_locked(user)` | `(Dict) -> bool` | [user_model.py:204](../../../server/models/user_model.py#L204) | Compare `now < locked_until` |
| `lock_account(user_id, duration_minutes=15)` | | [user_model.py:211](../../../server/models/user_model.py#L211) | Manual lock |
| `delete(user_id)` | | [user_model.py:230](../../../server/models/user_model.py#L230) | |
| `get_user_statistics()` | `→ Dict` | [user_model.py:244](../../../server/models/user_model.py#L244) | total + by_role + active/inactive |

### `models/session_model.py` - `SessionModel` (collection: `admin_sessions`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [session_model.py:20](../../../server/models/session_model.py#L20) | Setup 4 index incl **TTL `expires_at` (expireAfterSeconds=0)** - MongoDB auto-delete expired |
| `create(session_data)` | | [session_model.py:49](../../../server/models/session_model.py#L49) | |
| `find_by_access_jti(jti) / find_by_refresh_jti(jti)` | | [session_model.py:64, 72](../../../server/models/session_model.py#L64) | |
| `get_user_sessions(user_id)` | `→ List[Dict]` | [session_model.py:80](../../../server/models/session_model.py#L80) | Active only |
| `revoke(jti)` | `→ bool` | [session_model.py:95](../../../server/models/session_model.py#L95) | Match access_jti hoặc refresh_jti. Set `is_revoked=True, revoked_at=now` |
| `revoke_all_user(user_id)` | `→ int` | [session_model.py:110](../../../server/models/session_model.py#L110) | |
| `is_session_revoked(jti)` | `→ bool` | [session_model.py:123](../../../server/models/session_model.py#L123) | **`False` nếu session không tồn tại** (allow - JWT có thể được tạo nhưng session chưa save) |
| `cleanup_expired()` | `→ int` | [session_model.py:139](../../../server/models/session_model.py#L139) | Manual cleanup. TTL index đã tự làm |

### `models/audit_model.py` - `AuditModel` (collection: `audit_logs`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [audit_model.py:20](../../../server/models/audit_model.py#L20) | Setup 6 index (timestamp DESC, user_id, action, resource_type, resource_id, compound user_id+timestamp) |
| `log(audit_data)` | `→ Dict` | [audit_model.py:44](../../../server/models/audit_model.py#L44) | Insert + timestamp. **Swallow exception** (return `{}`) - không block main op |
| `get_logs(query=None, limit=100, skip=0)` | | [audit_model.py:60](../../../server/models/audit_model.py#L60) | Sort by timestamp DESC |
| `get_user_activity(user_id, limit=50)` | | [audit_model.py:75](../../../server/models/audit_model.py#L75) | |
| `count_logs(query=None)` | | [audit_model.py:87](../../../server/models/audit_model.py#L87) | |

### `models/api_key_model.py` - `APIKeyModel` (collection: `api_keys`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `KEY_PREFIX = "fc_"` | const | [api_key_model.py:35](../../../server/models/api_key_model.py#L35) | "FirewallController prefix" |
| `API_KEY_HMAC_SECRET` | env var | [api_key_model.py:25](../../../server/models/api_key_model.py#L25) | Bắt buộc set ở production; thiếu env sẽ raise `RuntimeError` ngay khi import |
| `__init__(db)` | | [api_key_model.py:37](../../../server/models/api_key_model.py#L37) | Setup 5 index incl `key_hash` unique |
| `generate_api_key()` | `@staticmethod → str` | [api_key_model.py:57](../../../server/models/api_key_model.py#L57) | `fc_<token_hex(16)>` = 35 chars |
| `hash_api_key(key)` | `@staticmethod → str` | [api_key_model.py:69](../../../server/models/api_key_model.py#L69) | HMAC-SHA256 với secret |
| `_hash_api_key_legacy(key)` | `@staticmethod` | [api_key_model.py:86](../../../server/models/api_key_model.py#L86) | Legacy plain SHA-256 (cho backward compat) |
| `create_api_key(name, description="", expires_in_days=None, permissions=None, created_by="system")` | `→ Dict` | [api_key_model.py:91](../../../server/models/api_key_model.py#L91) | Trả **plaintext key 1 lần** - không lưu trừ hash. Default permissions=["register"] |
| `validate_api_key(api_key, required_permission="register")` | `→ Dict` | [api_key_model.py:164](../../../server/models/api_key_model.py#L164) | Try HMAC hash → fallback legacy → **auto-migrate** sang HMAC. Check active, expired, permission. Update `last_used_at`, `usage_count`. Permission aliases map old↔new. Không enforce rate limit/429 |
| `revoke_api_key(key_id, revoked_by="system")` | | [api_key_model.py:267](../../../server/models/api_key_model.py#L267) | Set `is_active=False, revoked_at, revoked_by` |
| `list_api_keys(include_revoked=False, page=1, limit=20)` | `→ Dict` | [api_key_model.py:299](../../../server/models/api_key_model.py#L299) | **Exclude `key_hash` field** từ result |
| `get_api_key_by_id(key_id)` | | [api_key_model.py:354](../../../server/models/api_key_model.py#L354) | |
| `update_api_key(key_id, name=None, description=None, permissions=None, is_active=None)` | | [api_key_model.py:379](../../../server/models/api_key_model.py#L379) | |
| `get_stats()` | `→ Dict` | [api_key_model.py:428](../../../server/models/api_key_model.py#L428) | total/active/expired/revoked |

### `models/whitelist_profile_model.py` - `WhitelistProfileModel` (collection: `whitelist_profiles`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `__init__(db)` | | [whitelist_profile_model.py:21](../../../server/models/whitelist_profile_model.py#L21) | Setup 4 index (compound group_id+teacher_id, compound group_id+is_active, teacher_id, created_at DESC) |
| `create_profile(group_id, teacher_id, teacher_username, name, domains=None)` | `→ Dict` | [whitelist_profile_model.py:36](../../../server/models/whitelist_profile_model.py#L36) | Init `is_active=False, version=1` |
| `find_by_id(profile_id)` | | [whitelist_profile_model.py:55](../../../server/models/whitelist_profile_model.py#L55) | |
| `list_by_group(group_id, teacher_id=None)` | | [whitelist_profile_model.py:61](../../../server/models/whitelist_profile_model.py#L61) | Optional filter by teacher |
| `update_profile(profile_id, update_data)` | | [whitelist_profile_model.py:68](../../../server/models/whitelist_profile_model.py#L68) | Auto-bump version khi `domains` thay đổi |
| `bump_version(profile_id)` | | [whitelist_profile_model.py:82](../../../server/models/whitelist_profile_model.py#L82) | `$inc version` |
| `delete_profile(profile_id)` | | [whitelist_profile_model.py:89](../../../server/models/whitelist_profile_model.py#L89) | |
| `activate(profile_id) / deactivate(profile_id)` | | [whitelist_profile_model.py:93, 101](../../../server/models/whitelist_profile_model.py#L93) | Set `is_active`, `activated_at` |
| `deactivate_all_in_group(group_id)` | `→ int` | [whitelist_profile_model.py:108](../../../server/models/whitelist_profile_model.py#L108) | Bulk deactivate. Caller phải đảm bảo chỉ 1 active per group |
| `get_active_profile(group_id)` | `→ Optional[Dict]` | [whitelist_profile_model.py:116](../../../server/models/whitelist_profile_model.py#L116) | Cho agent sync |

### `models/agent_policy_model.py` - `AgentPolicyModel` (collection: `agent_policies`)

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `VALID_MODES = ("none", "isolate", "custom_whitelist")` | const | [agent_policy_model.py:40](../../../server/models/agent_policy_model.py#L40) | |
| `__init__(db)` | | [agent_policy_model.py:42](../../../server/models/agent_policy_model.py#L42) | Setup 3 index (agent_id unique, override_mode, expires_at) - **TTL không dùng**, expire check runtime để giữ audit |
| `get_policy(agent_id)` | `→ Optional[Dict]` | [agent_policy_model.py:65](../../../server/models/agent_policy_model.py#L65) | None nếu chưa set (= mode "none") |
| `get_effective_mode(agent_id)` | `→ str` | [agent_policy_model.py:74](../../../server/models/agent_policy_model.py#L74) | **Auto-reset to "none" khi expired** (mutation side effect). Khác `get_policy` |
| `set_policy(agent_id, mode, applied_by_user, reason="", custom_whitelist=None, expires_at=None)` | `→ Dict` | [agent_policy_model.py:103](../../../server/models/agent_policy_model.py#L103) | Upsert. `$inc override_version`. Validate `mode in VALID_MODES` |
| `reset_policy(agent_id, applied_by_user)` | | [agent_policy_model.py:144](../../../server/models/agent_policy_model.py#L144) | Shortcut `set_policy(mode="none")` |
| `get_custom_whitelist(agent_id)` | `→ List[Dict]` | [agent_policy_model.py:148](../../../server/models/agent_policy_model.py#L148) | Chỉ meaningful khi mode=custom_whitelist |
| `list_isolated_agents()` | `→ List[str]` | [agent_policy_model.py:160](../../../server/models/agent_policy_model.py#L160) | Dashboard helper |
| `list_policies_by_agent_ids(agent_ids)` | `→ Dict` | [agent_policy_model.py:168](../../../server/models/agent_policy_model.py#L168) | Batch load |
| `count_by_mode()` | `→ Dict[str, int]` | [agent_policy_model.py:179](../../../server/models/agent_policy_model.py#L179) | Aggregate |

## Ai gọi module này
Mỗi model được khởi tạo 1 lần ở `app.register_controllers` rồi inject vào service tương ứng. Controllers KHÔNG gọi model trực tiếp (luôn qua service) - trừ vài edge case như `agent_controller._check_agent_ownership` đọc `agent_model.find_by_agent_id` cho ownership check trước khi delegate sang service.

| Model | Caller chính |
|---|---|
| `AgentModel` | `AgentService` + `AgentPolicyService` + `RBACService.can_teacher_access_agent` |
| `WhitelistModel` | `WhitelistService` |
| `WhitelistEntryModel` | `WhitelistService` |
| `LogModel` | `LogService` |
| `GroupModel` | `GroupService` + `WhitelistProfileService` + `AgentService` (init pending group) + `RBACService` |
| `UserModel` | `UserService` + `AdminAuthService` + `rbac middleware` (lookup user by jti) |
| `SessionModel` | `AdminAuthService` |
| `AuditModel` | `AuditService` |
| `APIKeyModel` | `APIKeyService` + `auth middleware` (validate) |
| `AgentPolicyModel` | `AgentPolicyService` |
| `WhitelistProfileModel` | `WhitelistProfileService` |

## Module này gọi ra
- `pymongo`, `bson.ObjectId`
- `time_utils.now_vietnam / parse_agent_timestamp / to_vietnam`
- `bcrypt` (gián tiếp qua service - model chỉ lưu hash)
- `hmac`, `hashlib`, `secrets` (api_key_model)

## Đã có sẵn - đừng viết lại
- Cần CRUD collection? → tạo `XModel(db)` mới + setup indexes. **Đừng** insert trực tiếp `db.x.insert_one` ở service
- Cần version cho whitelist? → `WhitelistModel.bump_global_version()` cho global, `GroupModel.bump_whitelist_version(gid)` cho group, `WhitelistProfileModel.bump_version(pid)` cho profile
- Cần hash API key? → `APIKeyModel.hash_api_key(key)` (HMAC-SHA256)
- Cần validate domain/IP/URL? → `WhitelistModel.validate_entry_value(type, value)`
- Cần ensure pending group? → `GroupModel.ensure_pending_group()` - idempotent atomic upsert
- Cần check user locked? → `UserModel.is_locked(user)`
- Cần `now_vietnam` aware datetime? → `time_utils.now_vietnam()` (xem [app.md](app.md))
- Cần TTL index để auto-cleanup? → ví dụ ở `SessionModel._setup_indexes` (line 37)

## Gotchas

### Indexes
- **Index creation idempotent** - `create_index` không raise nếu đã có. WhitelistModel có logic detect existing để tránh conflict (line 76-130).
- **TTL index `expireAfterSeconds=0`** cần `expires_at` là field aware datetime. Mongo native TTL chỉ chạy mỗi 60s nên có lag.
- **Compound `(value, type, is_active)` ở whitelist** không unique - cho phép trùng nếu khác `scope`. Nếu cần unique global value, phải compound thêm `scope`.

### Datetime
- **Mọi datetime lưu vào Mongo phải aware** (codec options strict). Naive → pymongo raise. Helpers `now_vietnam()` luôn aware.
- **`parse_agent_timestamp` rất khoan dung** (xem [app.md](app.md)) - fallback `now_vietnam()` cho bất kỳ input lỗi. Model dùng để parse `last_heartbeat` từ agent.

### Whitelist storage migration

Cap nhat 2026-05-27: group entries are collection-first through `WhitelistEntryModel` / `whitelist_entries`. New group writes go to `whitelist_entries`; reads merge collection rows with legacy embedded `groups.whitelist[]`; collection rows win on duplicate `type:value`. Details: [whitelist_entries.md](whitelist_entries.md).

### Whitelist storage 2 nơi
- **Global entries** lưu ở collection `whitelist` (mỗi entry 1 document)
- **Group entries mới** lưu trong `whitelist_entries`. `groups.whitelist[]` chỉ còn legacy read fallback/rollback trong compatibility window.
- **Profile entries** lưu inline trong `whitelist_profiles.domains` array
- `WhitelistModel` CHỈ thao tác trên collection `whitelist` (global). Group entries phải qua `WhitelistEntryModel`/`WhitelistService`; profile entries qua `WhitelistProfileModel`.
- WhitelistService chỉ giữ pseudo-ID `group::<gid>::<type>::<value>` cho legacy embedded fallback; new group entries trả `_id` thật từ `whitelist_entries`.

### API key migration
- **Lazy migration HMAC** (api_key_model.py:191-197): legacy keys hash bằng plain SHA-256. Khi validate fail HMAC, fallback legacy. Match → update hash sang HMAC. Sau migration full, có thể xoá `_hash_api_key_legacy`.
- **Không có API key rate limit thật**: collection `api_keys` không lưu `rate_limit`, `usage_window`, quota bucket hoặc reset timestamp. `usage_count` là counter trọn đời, chỉ tăng `$inc` mỗi lần validate thành công và không dùng để chặn request.
- **`API_KEY_HMAC_SECRET` không còn default fallback** - module import sẽ fail nếu env thiếu. Production phải set env; đổi secret vẫn invalidate các key HMAC cũ nên migration/re-issue keys phải làm cẩn thận.

### API key expiration

Cap nhat 2026-06-01: API key expiration co enforce that. `create_api_key(..., expires_in_days=N)` luu `expires_at`; `validate_api_key(...)` reject khi `expires_at < now_vietnam()` voi `{"valid": False, "error": "API key has expired"}`. Expired key khong cap nhat `last_used_at` va khong tang `usage_count`. `expires_in_days=0`/`None` la never expires.

### User/session
- **Brute-force lock 5 lần / 15 phút** (user_model.py:19-20). Reset sau login success. Acceptable cho web admin, hơi quá lỏng cho exposure cao.
- **`find_by_username` regex case-insensitive** (line 86-89) - dùng `re.escape` chống regex injection. Đừng đổi sang query thường (mất CI).
- **`is_session_revoked` return `False` khi không tìm thấy** (session_model.py:133): nghĩa là JWT mà không có session record (vd test gen token trực tiếp) sẽ được allow. Đảm bảo mọi login real tạo session.

### Agent policy
- **`get_effective_mode` mutate state** (line 89-99): nếu policy expired, set lại `override_mode="none"` ngay khi đọc. Side effect ẩn - nếu dashboard list nhiều agent, hàng loạt write. Acceptable vì lazy invalidation.
- **`override_version` được agent dùng để detect change** (line 137 `$inc`). Đừng tự reset.
- **Schema có sẵn ở docstring** (line 21-37) - đọc khi cần thêm field.

### Group
- **`ensure_pending_group` atomic upsert** (line 32-50): thread-safe. Default cho mọi agent mới register.
- **`update_group` auto-bump `whitelist_version`** khi `whitelist` field trong payload (line 122-129) - read-modify-write race nếu 2 admin sửa cùng lúc. Acceptable cho admin path low-traffic.
- **Legacy `created_by` field** - vẫn check trong RBAC. Migration kế hoạch chuyển sang `teacher_ids` list.

### Audit
- **`AuditModel.log` swallow exception** (line 47-54): nếu DB fail, action chính vẫn pass. Cố ý - audit không được block business logic. Hậu quả: có thể mất audit nếu Mongo lỗi. Acceptable trade-off.
- **Không có read API qua service** - controller gọi `audit_service.get_logs/get_user_activity/count_logs`.

### Indexes có thể bị stale
- Setup indexes ở `__init__` mỗi lần app boot. Đổi schema (vd thêm field unique) → restart đủ. Drop index thủ công nếu sửa direction/sparse: `db.<coll>.dropIndex(name)`.
