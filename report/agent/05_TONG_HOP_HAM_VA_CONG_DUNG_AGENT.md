# Tổng hợp hàm và công dụng - Agent



Tài liệu này được sinh từ phân tích AST source code, không import module và không chạy runtime.


## Package `agent`


### `agent/agent_gui.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `main()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/agent_gui.py:11` |


## Package `agent/cache`


### `agent/cache/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/cache/lru_cache.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `DNSRecord` | Cấu trúc dữ liệu lưu kết quả DNS gồm IP, TTL và metadata. | `agent/cache/lru_cache.py:13` |
| `CacheValue` | Generic cache value with metadata. | `agent/cache/lru_cache.py:20` |
| `LRUCache` | Cache LRU có TTL, dùng giảm số lần resolve DNS. | `agent/cache/lru_cache.py:26` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `LRUCache` | `__init__(self, max_size, default_ttl)` | Initialize LRU Cache. | `agent/cache/lru_cache.py:27` |
| `LRUCache` | `get(self, key)` | Get item from cache. | `agent/cache/lru_cache.py:43` |
| `LRUCache` | `set(self, key, value, ttl)` | Set item in cache. | `agent/cache/lru_cache.py:62` |
| `LRUCache` | `_remove(self, key)` | Remove item from cache. | `agent/cache/lru_cache.py:76` |
| `LRUCache` | `delete(self, key)` | Delete item from cache. | `agent/cache/lru_cache.py:82` |
| `LRUCache` | `clear(self)` | Clear all items from cache. | `agent/cache/lru_cache.py:90` |
| `LRUCache` | `cleanup_expired(self)` | Remove all expired items. | `agent/cache/lru_cache.py:97` |
| `LRUCache` | `get_expiring_keys(self, threshold_seconds)` | Get keys that will expire within the threshold. | `agent/cache/lru_cache.py:112` |
| `LRUCache` | `get_stats(self)` | Get cache statistics. | `agent/cache/lru_cache.py:134` |
| `LRUCache` | `__len__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/cache/lru_cache.py:147` |
| `LRUCache` | `__contains__(self, key)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/cache/lru_cache.py:150` |


## Package `agent/capture`


### `agent/capture/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/capture/extractors.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `DomainExtractor` | Extracts domain names from various packet types. | `agent/capture/extractors.py:24` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `DomainExtractor` | `extract_http_host(packet)` | Extract Host header from HTTP packet. | `agent/capture/extractors.py:28` |
| `DomainExtractor` | `extract_https_sni(packet)` | Extract SNI from TLS ClientHello. | `agent/capture/extractors.py:63` |
| `DomainExtractor` | `_extract_sni_manual(payload)` | Manual SNI extraction from TLS payload. | `agent/capture/extractors.py:99` |
| `DomainExtractor` | `extract_dns_query(packet)` | Extract domain from DNS query. | `agent/capture/extractors.py:183` |
| `DomainExtractor` | `_is_valid_hostname(hostname)` | Validate hostname format. | `agent/capture/extractors.py:209` |


### `agent/capture/scapy_config.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `configure_scapy()` | Configure Scapy cache directory to avoid permission errors. | `agent/capture/scapy_config.py:12` |
| `ensure_pcap_driver()` | Ensure Scapy can find WinPcap or Npcap on Windows. | `agent/capture/scapy_config.py:54` |
| `apply_scapy_config()` | Apply Scapy configuration after import. | `agent/capture/scapy_config.py:122` |


### `agent/capture/sniffer.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `PacketSniffer` | Thành phần bắt gói tin và chuyển packet sang domain/log record. | `agent/capture/sniffer.py:24` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `PacketSniffer` | `__init__(self, callback)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/sniffer.py:25` |
| `PacketSniffer` | `start(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/capture/sniffer.py:38` |
| `PacketSniffer` | `stop(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/capture/sniffer.py:56` |
| `PacketSniffer` | `_capture_loop(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/sniffer.py:75` |
| `PacketSniffer` | `_process_packet(self, packet)` | Process captured packet and extract domain info. | `agent/capture/sniffer.py:131` |


### `agent/capture/winpcap_installer.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `is_admin()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:30` |
| `is_winpcap_installed()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:37` |
| `download_winpcap(target_dir)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:88` |
| `install_winpcap_silent(installer_path)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:157` |
| `uninstall_winpcap_silent()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:203` |
| `cleanup_winpcap()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:268` |
| `ensure_winpcap_available()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/capture/winpcap_installer.py:292` |
| `was_installed_by_us()` | Check if WinPcap was installed by this agent session. | `agent/capture/winpcap_installer.py:319` |
| `init_winpcap_manager()` | Initialize the WinPcap manager - call this at startup. | `agent/capture/winpcap_installer.py:325` |


## Package `agent/config`


### `agent/config/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/config/crypto.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_get_machine_key()` | Derive a Fernet key from machine identity (hostname + MAC). | `agent/config/crypto.py:24` |
| `encrypt_config(config, path)` | Encrypt config dict and write to file. | `agent/config/crypto.py:34` |
| `decrypt_config(path)` | Read and decrypt config from encrypted file. | `agent/config/crypto.py:58` |
| `migrate_plaintext_to_encrypted(path)` | If plaintext config exists but encrypted does not, encrypt it. | `agent/config/crypto.py:80` |


### `agent/config/defaults.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/config/loader.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `load_config()` | Load configuration from multiple sources. | `agent/config/loader.py:30` |
| `get_config()` | Get cached configuration or load if not cached. | `agent/config/loader.py:98` |
| `reload_config()` | Force reload configuration from sources. | `agent/config/loader.py:115` |
| `_load_from_file()` | Load configuration from file (encrypted preferred, plaintext fallback). | `agent/config/loader.py:127` |
| `_load_from_env()` | Load configuration from environment variables. | `agent/config/loader.py:166` |
| `_convert_value(value)` | Convert string value to appropriate type. | `agent/config/loader.py:195` |
| `_deep_copy(d)` | Create a deep copy of a dictionary. | `agent/config/loader.py:213` |
| `_deep_update(base_dict, update_dict)` | Recursively update a dictionary with another dictionary. | `agent/config/loader.py:217` |
| `_get_config_source(file_config, env_config)` | Determine configuration source for metadata. | `agent/config/loader.py:228` |


### `agent/config/validator.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `validate_config(config)` | Validate configuration and return issues. | `agent/config/validator.py:9` |
| `_validate_server_config(config, errors, warnings)` | Validate server configuration. | `agent/config/validator.py:35` |
| `_validate_firewall_config(config, errors, warnings)` | Validate firewall configuration. | `agent/config/validator.py:56` |
| `_validate_logging_config(config, warnings)` | Validate logging configuration. | `agent/config/validator.py:87` |
| `_validate_whitelist_config(config, warnings)` | Validate whitelist configuration. | `agent/config/validator.py:98` |
| `_validate_heartbeat_config(config, warnings)` | Validate heartbeat configuration. | `agent/config/validator.py:109` |
| `_has_admin_privileges()` | Check if running with administrator privileges. | `agent/config/validator.py:120` |


## Package `agent/core`


### `agent/core/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/core/agent.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `Agent` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:69` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `Agent` | `__new__(cls)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:72` |
| `Agent` | `__init__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:78` |
| `Agent` | `hostname(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:99` |
| `Agent` | `device_id(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:103` |
| `Agent` | `state(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:107` |
| `Agent` | `update_state(self)` | Cập nhật trạng thái, cấu hình hoặc bản ghi. | `agent/core/agent.py:110` |
| `Agent` | `get_agent_id(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/core/agent.py:113` |
| `Agent` | `get_agent_token(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/core/agent.py:118` |
| `Agent` | `is_registered(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:123` |
| `Agent` | `is_running(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:126` |
| `Agent` | `stop(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/core/agent.py:129` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_hash_ids(ids)` | Xử lý bảo mật dữ liệu nhạy cảm bằng hash/mã hóa. | `agent/core/agent.py:11` |
| `_windows_hardware_ids()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:16` |
| `generate_device_id()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/agent.py:38` |
| `get_agent()` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/core/agent.py:132` |


### `agent/core/handlers.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `create_domain_handler(config, agent)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `agent/core/handlers.py:13` |
| `handle_domain_detection(record, config, whitelist, log_sender)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/handlers.py:26` |


### `agent/core/lifecycle.py`

| Function / Class | Công dụng | Vị trí |
| --- | --- | --- |
| `ComponentStatus` (dataclass) | Bản ghi 1 component sau khi init: `name`, `status` (ok/skipped/degraded/failed), `detail`. | `agent/core/lifecycle.py` |
| `InitResult` (dataclass) | Kết quả tổng hợp của `initialize_components`. Có `overall`, `issues`, `__bool__` (truthy nếu không có critical failure). | `agent/core/lifecycle.py` |
| `initialize_components(config, runtime=None)` | Khởi tạo các component theo thứ tự trên runtime được inject hoặc singleton mặc định, ghi `ComponentStatus` cho từng bước, in summary, trả về `InitResult`. Heartbeat lấy `device_id` từ runtime thay vì module-level identity. | `agent/core/lifecycle.py` |
| `_missing_server_creds(server_url, agent_id)` | Trả về danh sách thiếu (`server_url` / `agent_id`) để LogSender/Heartbeat biết lý do degrade. | `agent/core/lifecycle.py` |
| `_log_init_summary(result)` | In bảng tóm tắt sau init (headline theo `overall`, mỗi component 1 dòng với icon). | `agent/core/lifecycle.py` |
| `cleanup(config, runtime=None)` | Cleanup all agent resources trên runtime được inject hoặc singleton mặc định. | `agent/core/lifecycle.py` |
| `build_lifecycle_log(config, event_type, action, message)` | Build a lifecycle log entry with proper field values; device_id/hostname resolve lazy qua `DeviceIdentityProvider` khi build log, không khi import module. | `agent/core/lifecycle.py` |


### `agent/core/registry.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_collect_server_urls(config)` | Wrapper compatibility gọi `shared.server_urls.collect_server_urls(..., allow_dev_default=False)`; có thể trả list rỗng để Agent ở first-run offline mode. | `agent/core/registry.py:19` |
| `register_agent(config)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/registry.py:29` |
| `try_register_with_server(server_url, agent_info, config)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/registry.py:79` |


### `agent/core/token_manager.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `TokenManager` | Quản lý access/refresh token và auto refresh. | `agent/core/token_manager.py:10` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `TokenManager` | `__init__(self, config)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/core/token_manager.py:11` |
| `TokenManager` | `_load_tokens_from_config(self)` | Load tokens from config if available | `agent/core/token_manager.py:42` |
| `TokenManager` | `set_tokens(self, access_token, refresh_token, access_expires_at, refresh_expires_at)` | Set new tokens. | `agent/core/token_manager.py:68` |
| `TokenManager` | `access_token(self)` | Get current access token, refreshing if needed | `agent/core/token_manager.py:112` |
| `TokenManager` | `refresh_token(self)` | Get refresh token | `agent/core/token_manager.py:122` |
| `TokenManager` | `has_valid_token(self)` | Check if we have a valid access token | `agent/core/token_manager.py:128` |
| `TokenManager` | `is_expired(self)` | Check if access token is expired | `agent/core/token_manager.py:140` |
| `TokenManager` | `get_auth_header(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/core/token_manager.py:148` |
| `TokenManager` | `_should_refresh(self)` | Check if token should be refreshed | `agent/core/token_manager.py:155` |
| `TokenManager` | `_do_refresh(self, with_rotation)` | Perform token refresh. | `agent/core/token_manager.py:168` |
| `TokenManager` | `_handle_refresh_error(self, data)` | Handle refresh error response | `agent/core/token_manager.py:277` |
| `TokenManager` | `_trigger_reregistration(self, reason)` | Trigger agent re-registration | `agent/core/token_manager.py:298` |
| `TokenManager` | `_update_config_tokens(self, token_data)` | Update config with new tokens | `agent/core/token_manager.py:310` |
| `TokenManager` | `_clear_tokens(self)` | Clear all tokens | `agent/core/token_manager.py:323` |
| `TokenManager` | `refresh_now(self)` | Force token refresh | `agent/core/token_manager.py:335` |
| `TokenManager` | `start_auto_refresh(self, on_refreshed, on_expired)` | Start background thread for auto token refresh. | `agent/core/token_manager.py:340` |
| `TokenManager` | `stop_auto_refresh(self)` | Stop background refresh thread | `agent/core/token_manager.py:360` |
| `TokenManager` | `_refresh_loop(self)` | Background loop for token refresh | `agent/core/token_manager.py:367` |
| `TokenManager` | `on_token_refreshed(self, callback)` | Set callback for token refresh | `agent/core/token_manager.py:385` |
| `TokenManager` | `on_token_expired(self, callback)` | Set callback for token expiry | `agent/core/token_manager.py:389` |
| `TokenManager` | `on_reregistration_needed(self, callback)` | Set callback for when re-registration is required | `agent/core/token_manager.py:393` |
| `TokenManager` | `needs_reregistration(self)` | Check if agent needs to re-register | `agent/core/token_manager.py:398` |
| `TokenManager` | `reset_reregistration_flag(self)` | Reset the re-registration flag after successful registration | `agent/core/token_manager.py:402` |
| `TokenManager` | `get_token_status(self)` | Get current token status for monitoring. | `agent/core/token_manager.py:408` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `init_token_manager(config)` | Initialize global token manager | `agent/core/token_manager.py:448` |
| `get_token_manager()` | Get global token manager | `agent/core/token_manager.py:455` |
| `get_auth_headers(config)` | Get authentication headers for requests. | `agent/core/token_manager.py:460` |


## Package `agent/firewall`


### `agent/firewall/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/firewall/manager.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `FirewallManager` | Điều phối policy/rules Windows Firewall cho whitelist-only mode. | `agent/firewall/manager.py:52` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `FirewallManager` | `__init__(self, rule_prefix)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/manager.py:53` |
| `FirewallManager` | `setup_whitelist_firewall(self, whitelisted_ips, essential_ips)` | Setup whitelist-based firewall using Windows Default Deny policy. | `agent/firewall/manager.py:86` |
| `FirewallManager` | `add_ip_to_whitelist(self, ip, reason)` | Add IP to whitelist dynamically. | `agent/firewall/manager.py:138` |
| `FirewallManager` | `remove_ip_from_whitelist(self, ip)` | Xóa, dọn dẹp hoặc hủy dữ liệu liên quan. | `agent/firewall/manager.py:162` |
| `FirewallManager` | `sync_whitelist_changes(self, old_ips, new_ips)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/firewall/manager.py:181` |
| `FirewallManager` | `cleanup_whitelist_firewall(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/manager.py:214` |
| `FirewallManager` | `clear_all_rules(self)` | Remove all firewall rules created by this manager. | `agent/firewall/manager.py:240` |
| `FirewallManager` | `cleanup_all_rules(self)` | Complete cleanup for whitelist-only mode (legacy compatibility). | `agent/firewall/manager.py:244` |
| `FirewallManager` | `allowed_ips(self)` | Get allowed IPs from rules manager. | `agent/firewall/manager.py:273` |
| `FirewallManager` | `default_deny_enabled(self)` | Check if default deny is enabled. | `agent/firewall/manager.py:278` |
| `FirewallManager` | `get_whitelist_status(self)` | Get current status of whitelist-only firewall mode. | `agent/firewall/manager.py:283` |
| `FirewallManager` | `get_firewall_policy_status(self)` | Get current Windows Firewall policy status. | `agent/firewall/manager.py:296` |
| `FirewallManager` | `validate_firewall_state(self)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/firewall/manager.py:315` |
| `FirewallManager` | `test_whitelist_connectivity(self, sample_ips)` | Test connectivity to sample whitelisted IPs. | `agent/firewall/manager.py:348` |
| `FirewallManager` | `is_blocked(self, ip)` | Check if an IP is blocked (not in whitelist when Default Deny is active). | `agent/firewall/manager.py:367` |
| `FirewallManager` | `get_blocked_ips(self)` | Get blocked IPs (in Default Deny mode, all non-whitelisted IPs are blocked). | `agent/firewall/manager.py:373` |
| `FirewallManager` | `block_ip(self, ip, domain)` | Legacy: In Default Deny mode, blocking means removing from whitelist. | `agent/firewall/manager.py:379` |
| `FirewallManager` | `unblock_ip(self, ip)` | Legacy: In Default Deny mode, unblocking means adding to whitelist. | `agent/firewall/manager.py:386` |
| `FirewallManager` | `_restore_original_policy(self)` | Wrapper for policy manager. | `agent/firewall/manager.py:394` |
| `FirewallManager` | `_restore_default_policy(self)` | Wrapper for policy manager. | `agent/firewall/manager.py:398` |
| `FirewallManager` | `update_whitelist(self, domains, ips)` | Update firewall rules based on whitelist data. | `agent/firewall/manager.py:403` |
| `FirewallManager` | `_resolve_domains_to_ips(self, domains)` | Resolve domain names to IP addresses. | `agent/firewall/manager.py:451` |
| `FirewallManager` | `enable_whitelist_mode(self, server_urls, whitelist_ips, whitelist_domains)` | Enable whitelist-only mode with Default Deny policy. | `agent/firewall/manager.py:517` |
| `FirewallManager` | `_resolve_server_urls(self, urls)` | Resolve server URLs to IP addresses. | `agent/firewall/manager.py:599` |
| `FirewallManager` | `save_snapshot(self, path)` | Save current firewall state to a snapshot file. | `agent/firewall/manager.py:629` |
| `FirewallManager` | `restore_snapshot(self, path)` | Restore firewall to the state captured in the snapshot file. | `agent/firewall/manager.py:709` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_resolve_snapshot_path(path)` | Resolve a snapshot file path to an absolute, cwd-independent location. | `agent/firewall/manager.py:24` |


### `agent/firewall/policy.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `PolicyManager` | Đọc, backup, bật và restore firewall policy. | `agent/firewall/policy.py:9` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `PolicyManager` | `__init__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/policy.py:11` |
| `PolicyManager` | `get_current_policy(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/firewall/policy.py:15` |
| `PolicyManager` | `backup_current_policy(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/policy.py:48` |
| `PolicyManager` | `enable_default_deny(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/policy.py:56` |
| `PolicyManager` | `verify_default_deny(self)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/firewall/policy.py:100` |
| `PolicyManager` | `restore_original_policy(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/policy.py:138` |
| `PolicyManager` | `restore_default_policy(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/policy.py:170` |


### `agent/firewall/rules.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `RulesManager` | Tạo/xóa/đếm Windows Firewall rules theo prefix. | `agent/firewall/rules.py:10` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `RulesManager` | `__init__(self, rule_prefix)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/rules.py:12` |
| `RulesManager` | `create_self_allow_rules(self, program_path)` | Create allow rules for the agent's own exe. | `agent/firewall/rules.py:17` |
| `RulesManager` | `create_allow_rule(self, ip)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `agent/firewall/rules.py:74` |
| `RulesManager` | `remove_allow_rule(self, ip)` | Xóa, dọn dẹp hoặc hủy dữ liệu liên quan. | `agent/firewall/rules.py:112` |
| `RulesManager` | `create_allow_rules_batch(self, ips)` | Tạo mới hoặc thêm dữ liệu vào bộ nhớ/DB/cấu hình. | `agent/firewall/rules.py:162` |
| `RulesManager` | `clear_all_rules(self)` | Cache LRU có TTL, dùng giảm số lần resolve DNS. | `agent/firewall/rules.py:191` |
| `RulesManager` | `load_existing_rules(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/rules.py:240` |
| `RulesManager` | `get_rule_count(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/firewall/rules.py:291` |


### `agent/firewall/utils.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `FirewallUtils` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/utils.py:12` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `FirewallUtils` | `is_valid_ipv4(ip)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/utils.py:15` |
| `FirewallUtils` | `is_valid_ip(ip)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/utils.py:23` |
| `FirewallUtils` | `get_essential_ips()` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/firewall/utils.py:30` |
| `FirewallUtils` | `has_admin_privileges()` | Check if the application is running with administrator privileges. | `agent/firewall/utils.py:67` |
| `FirewallUtils` | `run_netsh_command(args, timeout)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/utils.py:76` |
| `FirewallApplicationService` | Facade cho GUI/manual restore: restore snapshot và clear SAINT rules qua `FirewallManager`/`RulesManager`, không để view gọi netsh trực tiếp. | `agent/firewall/application_service.py` |
| `FirewallProvider` | Contract backend cho read/write firewall operations; default read ưu tiên NetSecurity, write default `netsh`, opt-in PowerShell bằng `FIREWALL_WRITE_BACKEND=powershell`. | `agent/firewall/provider.py` |
| `FirewallUtils` | `test_ip_connectivity(ip, ports, timeout)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/firewall/utils.py:88` |


## Package `agent/controllers`

Package này chứa controller dùng chung cho GUI: không import PySide6, không phụ thuộc widget, chỉ quản lý lifecycle, worker thread, event queue và dữ liệu whitelist cho view layer.

### `agent/controllers/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.

### `agent/controllers/agent_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `AgentStatus` | Agent status enum (`STOPPED`, `STARTING`, `RUNNING`, **`DEGRADED`**, `STOPPING`, `ERROR`). `DEGRADED` được set khi `InitResult.overall == 'degraded'` - agent vẫn chạy, GUI hiện badge vàng + list issues. `is_running` truthy cho cả `RUNNING` và `DEGRADED`. | `agent/controllers/agent_controller.py` |
| `AgentEvent` | Event data from agent to GUI. | `agent/controllers/agent_controller.py:21` |
| `AgentSignals` | Event queue thread-safe giữa worker thread và GUI thread. Drain mỗi `DRAIN_INTERVAL_MS=50ms`, soft-cap `MAX_EVENTS_PER_TICK=100` để 1 burst event không block GUI. | `agent/controllers/agent_controller.py` |
| `AgentController` | Controller trung tâm nối GUI với Agent worker/lifecycle. | `agent/controllers/agent_controller.py:107` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `AgentSignals` | `__init__(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:30` |
| `AgentSignals` | `connect(self, signal_name, callback)` | Connect a callback to a signal. | `agent/controllers/agent_controller.py:42` |
| `AgentSignals` | `disconnect(self, signal_name, callback)` | Disconnect a callback from a signal. | `agent/controllers/agent_controller.py:50` |
| `AgentSignals` | `emit(self, signal_name, data)` | Queue an event to be processed by GUI thread. | `agent/controllers/agent_controller.py:58` |
| `AgentSignals` | `process_events(self, root)` | Drain queue trên GUI thread. Xử lý tối đa `MAX_EVENTS_PER_TICK=100` event/tick; nếu chạm cap thì reschedule ngay (`delay=0`), nếu không tick lại sau `DRAIN_INTERVAL_MS=50ms`. | `agent/controllers/agent_controller.py` |
| `AgentSignals` | `_dispatch_event(self, event)` | Dispatch event to registered callbacks. | `agent/controllers/agent_controller.py:86` |
| `AgentSignals` | `_get_timestamp(self)` | Get current timestamp. | `agent/controllers/agent_controller.py:97` |
| `AgentController` | `__new__(cls)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:111` |
| `AgentController` | `__init__(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:117` |
| `AgentController` | `status(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:148` |
| `AgentController` | `is_running(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:152` |
| `AgentController` | `stats(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:156` |
| `AgentController` | `set_root(self, root)` | *(Tkinter-era API; không còn dùng ở Qt port - Qt frontend dùng `QtSignalBridge` để drain queue thay thế.)* | `agent/controllers/agent_controller.py` |
| `AgentController` | `start_agent(self)` | Start agent in background thread. | `agent/controllers/agent_controller.py:165` |
| `AgentController` | `stop_agent(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/agent_controller.py:191` |
| `AgentController` | `_agent_worker(self)` | Worker thread: gắn `_on_whitelist_ready` callback lên runtime (để lifecycle wire GUI sớm — thêm 2026-06-05), gọi `initialize_components(InitResult)`, vào main loop 1s/tick. Mỗi tick gọi `_update_stats` rồi emit `stats_updated` **chỉ khi snapshot khác lần trước** (diff-emit). Payload kèm `is_registered` + `firewall_enabled` để dashboard không phải pull. | `agent/controllers/agent_controller.py` |
| `AgentController` | `_on_whitelist_ready(self, manager)` | Callback do `lifecycle._init_whitelist_sync` gọi ngay sau Step 2.5 — wire `WhitelistController().set_whitelist_manager(manager)` để GUI Whitelist tab populate sớm thay vì đợi đủ 7 step (~1-3 phút). Idempotent: controller là singleton, block fallback ở cuối `_agent_worker` vẫn chạy an toàn. | `agent/controllers/agent_controller.py:490` |
| `AgentController` | `_update_stats(self)` | Update internal statistics. | `agent/controllers/agent_controller.py:319` |
| `AgentController` | `get_agent_info(self)` | Get current agent information. | `agent/controllers/agent_controller.py:349` |
| `AgentController` | `get_stats(self)` | Get current agent statistics. | `agent/controllers/agent_controller.py:372` |
| `AgentController` | `force_whitelist_sync(self)` | Force immediate whitelist sync. | `agent/controllers/agent_controller.py:377` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `get_agent_controller()` | Get the global agent controller instance. | `agent/controllers/agent_controller.py:396` |


### `agent/controllers/whitelist_controller.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistController` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/whitelist_controller.py:8` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistController` | `__new__(cls)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/whitelist_controller.py:13` |
| `WhitelistController` | `__init__(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/whitelist_controller.py:20` |
| `WhitelistController` | `set_whitelist_manager(self, manager)` | Đồng bộ whitelist, DNS refresh và cập nhật firewall. | `agent/controllers/whitelist_controller.py:40` |
| `WhitelistController` | `_on_manager_sync_complete(self)` | Called when WhitelistManager completes a sync (including periodic syncs). | `agent/controllers/whitelist_controller.py:57` |
| `WhitelistController` | `_trigger_server_sync(self)` | Trigger immediate sync with server in background. | `agent/controllers/whitelist_controller.py:62` |
| `WhitelistController` | `_sync_from_manager(self)` | Sync local list from WhitelistManager (domains + IPs). | `agent/controllers/whitelist_controller.py:84` |
| `WhitelistController` | `on_data_changed(self, callback)` | Register callback for data changes. | `agent/controllers/whitelist_controller.py:140` |
| `WhitelistController` | `on_error(self, callback)` | Register callback for errors. | `agent/controllers/whitelist_controller.py:145` |
| `WhitelistController` | `on_success(self, callback)` | Register callback for success messages. | `agent/controllers/whitelist_controller.py:150` |
| `WhitelistController` | `_notify_data_changed(self)` | Notify all data changed listeners. | `agent/controllers/whitelist_controller.py:155` |
| `WhitelistController` | `_notify_error(self, message)` | Notify all error listeners. | `agent/controllers/whitelist_controller.py:164` |
| `WhitelistController` | `_notify_success(self, message)` | Notify all success listeners. | `agent/controllers/whitelist_controller.py:172` |
| `WhitelistController` | `remove_ip(self, ip)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/whitelist_controller.py:180` |
| `WhitelistController` | `get_all_ips(self)` | Xử lý request/UI action, validate input và điều phối service/component tương ứng. | `agent/controllers/whitelist_controller.py:220` |
| `WhitelistController` | `refresh(self)` | Refresh whitelist data from manager. | `agent/controllers/whitelist_controller.py:225` |
| `WhitelistController` | `get_stats(self)` | Get whitelist statistics. | `agent/controllers/whitelist_controller.py:249` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `get_whitelist_controller()` | Get WhitelistController singleton instance. | `agent/controllers/whitelist_controller.py:279` |


> **Lưu ý**: Package GUI cũ (`agent/gui/`) đã được xoá. Frontend hiện tại nằm ở `agent/gui_qt/` (PySide6), còn controller dùng chung đã được tách rõ sang `agent/controllers/`.


## Package `agent/gui_qt`

PySide6 frontend - toàn bộ widget, view, signal bridge.


### `agent/gui_qt/app.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `run()` | Entry function - khởi tạo `QApplication` (Fusion theme + global QSS), tạo `AgentController` singleton, instantiate `QtSignalBridge(controller.signals)`, show `MainWindow`. Trả về exit code của QApplication. | `agent/gui_qt/app.py` |


### `agent/gui_qt/signal_bridge.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `QtSignalBridge` | QObject với typed Qt signals (`status_changed`, `stats_updated`, `packet_captured`, `log_received`, `error_occurred`, `whitelist_synced`). `QTimer` 50ms drain queue của `AgentSignals` rồi re-emit thành Qt signals trên GUI thread. Soft-cap 100 event/tick + reschedule `singleShot(0)` khi burst để không block UI. | `agent/gui_qt/signal_bridge.py` |


### `agent/gui_qt/styles.py`

Hằng số palette (`ACCENT_BLUE`, `ACCENT_GREEN`, `ACCENT_RED`, `ACCENT_ORANGE`, `ACCENT_PURPLE`, `BG_CARD`, `BG_INPUT`, `FG_PRIMARY`, …) + `GLOBAL_QSS` áp dụng cho QApplication. Bao gồm: button object names (`#success`, `#danger`, `#primary`), card frame (`QFrame#card`), sidebar (`QFrame#sidebar`), table header padding, `QLabel { background: transparent; }` để label trong card không vẽ window bg đè lên.


### `agent/gui_qt/main_window.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `MainWindow` | `QMainWindow` chính: sidebar (brand + 5 nav buttons checkable) + `QStackedWidget` chứa 5 views. Wire `bridge.status_changed` → `firewall_view.set_firewall_manager()` khi agent chạy; wire `bridge.whitelist_synced { agent_ready: True }` → `whitelist_view.set_agent_ready(True)`. `closeEvent` cleanup `LogsView` handler + dừng signal bridge timer trước khi đóng. | `agent/gui_qt/main_window.py` |


### `agent/gui_qt/components/status_card.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `StatusCard` | Tile dashboard: icon + title (top), value lớn (center), subtitle (bottom). API: `set_value`, `set_color`, `set_icon`, `set_subtitle`, `set_title`, `get_value`. | `agent/gui_qt/components/status_card.py` |


### `agent/gui_qt/components/data_table.py`

Reusable bảng dữ liệu - `QTableView` virtualized natively (chỉ paint row đang scroll vào viewport), thay thế DataTable legacy tự destroy/recreate widget mỗi cell.

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `DictTableModel` | `QAbstractTableModel` nhận list-of-dicts + column config (`key`, `title`, `width`, `type?`). `data()` trả `DisplayRole` + `ForegroundRole` theo cột `status` (xanh active / đỏ blocked / cam pending). `set_rows(rows)` dùng `beginResetModel/endResetModel`. | `agent/gui_qt/components/data_table.py` |
| `DataTable` | QWidget bọc QTableView + model. Header left-aligned khớp với cell left-aligned. Last column auto-stretches (`setStretchLastSection(True)`); các cột khác fixed `width`. API giữ tương thích với DataTable cũ: `set_data`, `get_data`, `clear`, `row_count`. | `agent/gui_qt/components/data_table.py` |


### `agent/gui_qt/components/log_console.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `_LogSignals` | QObject carrier `entry_received = Signal(dict)` để `GUILogHandler.emit()` (chạy thread bất kỳ) deliver record sang GUI thread qua `Qt.QueuedConnection`. | `agent/gui_qt/components/log_console.py` |
| `LogConsole` | QFrame bọc `QPlainTextEdit` (read-only, monospace) + toolbar (line count, pause, level filter). `setMaximumBlockCount(N)` auto-trim O(1). `set_filter_level()` rebuild from `_history`. | `agent/gui_qt/components/log_console.py` |
| `GUILogHandler` | `logging.Handler` forward record sang `LogConsole.append_log()`. Thread-safe qua Qt queued connection. | `agent/gui_qt/components/log_console.py` |


### `agent/gui_qt/components/sparkline.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `Sparkline` | Line chart widget vẽ bằng `QPainter`. Ring buffer max N điểm; `push(value)` append + repaint; gridline mờ, fill area dưới line. Không phụ thuộc Qt Charts module. | `agent/gui_qt/components/sparkline.py` |


### `agent/gui_qt/views/dashboard.py`

Layout: Header (title + StatusPill + Sync Now + Start/Stop) → 8 status cards grid 4×2 → middle row (Activity Log 60% trái + Server Overview / Firewall Status 40% phải).

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `StatusPill` | Pill-shaped badge: dot + text, background tint theo accent colour. Header indicator (`Running` / `Stopped` / `Starting...` / `Degraded` / `Error`). | `agent/gui_qt/views/dashboard.py` |
| `_StackedField` | Helper layout: label nhỏ (top) + value lớn (below). Dùng trong Server Overview để URL dài có full panel width. | `agent/gui_qt/views/dashboard.py` |
| `_MetricCell` | Helper layout: centered label + large value. Dùng trong Firewall Status panel (Policy / Rules / Mode / Allowed IPs). | `agent/gui_qt/views/dashboard.py` |
| `DashboardView` | Qt main view. Signal-driven: subscribe `status_changed` / `stats_updated` / `packet_captured` / `error_occurred` / `whitelist_synced` từ bridge. Diff-skip cache `_last_card_values` skip `set_value`/`set_color` khi không đổi. Packet log throttle 20/sec (BLOCKED never drops), activity log cap 500 dòng qua `setMaximumBlockCount`. Activity log dùng `appendHtml` với inline span để render tag badge (INFO/STATUS/SYNC/WARN/ERROR/BLOCK/ALLOW) với color khác nhau. 1s `_tick_timer` refresh relative time strings (Heartbeat "10s ago", Last sync "Just now"). | `agent/gui_qt/views/dashboard.py` |


### `agent/gui_qt/views/firewall.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `_LoadSignals` | QObject carrier `finished = Signal(list, str, str)` để rule-load worker thread deliver kết quả về GUI thread. | `agent/gui_qt/views/firewall.py` |
| `FirewallView` | Header + Policy/Rules/Mode stats panel + DataTable rules + status bar. `showEvent`/`hideEvent` start/stop `_refresh_timer` (5s). `_load_rules` chạy trong threading.Thread; nếu `firewall_manager` chưa wire thì fallback qua `FirewallProvider` thay vì parse netsh trong view. `set_firewall_manager(mgr)` được MainWindow gọi khi agent running. | `agent/gui_qt/views/firewall.py` |


### `agent/gui_qt/views/whitelist.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `_ResolveSignals` | QObject carrier cho DNS resolve background thread (`finished = Signal(list)` của (ip, domain) pairs). | `agent/gui_qt/views/whitelist.py` |
| `WhitelistView` | Header + stats label + search + "Resolved IPs" toggle + DataTable + status bar. Search debounce 200ms qua `QTimer.singleShot`; in-memory filter `_last_loaded_data` không gọi lại controller mỗi keystroke. "Resolved IPs" toggle: background thread chạy `OptimizedDNSResolver.resolve_multiple_parallel`, deliver pairs về GUI thread qua Qt signal. Auto-sync 30s timer chỉ start khi `set_agent_ready(True)` được MainWindow gọi. | `agent/gui_qt/views/whitelist.py` |


### `agent/gui_qt/views/logs.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `LogsView` | Title + filter controls (level combo + search) + `LogConsole` + status bar. `_setup_logging` attach `GUILogHandler` vào root logger + named loggers (agent / core / firewall / whitelist / capture / heartbeat / controllers / gui_qt). Export CSV qua `QFileDialog`. Search là substring filter trên top của level filter. `cleanup()` detach handler khỏi loggers - gọi từ `MainWindow.closeEvent` để tránh dangling reference. | `agent/gui_qt/views/logs.py` |


### `agent/gui_qt/views/settings.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `SettingsView` | `QScrollArea` chứa form chia 4 section: 🔑 Authentication (API key + show/hide toggle 👁), 🌐 Server Connection (URL + heartbeat interval + sync interval với `QIntValidator`), 🤖 Agent Configuration (hostname read-only + log level combo), 🔥 Firewall Backup & Restore (snapshot path + ♻️ Restore button). Save dùng `config.crypto.encrypt_config` theo flow cấu hình mã hoá hiện tại. Restore: admin guard → confirm dialog → `FirewallApplicationService.restore_firewall_snapshot(...)`, ưu tiên running `FirewallManager` khi agent đang chạy và dùng backend firewall package khi không. | `agent/gui_qt/views/settings.py` |



## Package `agent/logging_module`


### `agent/logging_module/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/logging_module/sender.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `LogSender` | Queue log và gửi batch về Server. | `agent/logging_module/sender.py:17` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `LogSender` | `__init__(self, config)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/logging_module/sender.py:19` |
| `LogSender` | `_get_server_urls(self, config)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/logging_module/sender.py:43` |
| `LogSender` | `start(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/logging_module/sender.py:56` |
| `LogSender` | `stop(self)` | Stop sender and flush remaining logs. | `agent/logging_module/sender.py:69` |
| `LogSender` | `queue_log(self, log_data)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/logging_module/sender.py:86` |
| `LogSender` | `_serialize_log(self, log_data)` | Serialize log data for JSON transmission. | `agent/logging_module/sender.py:106` |
| `LogSender` | `_sender_loop(self)` | Main sender loop. | `agent/logging_module/sender.py:156` |
| `LogSender` | `_flush_queue(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/logging_module/sender.py:178` |
| `LogSender` | `_send_logs(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/logging_module/sender.py:190` |
| `LogSender` | `_send_batch(self, logs)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/logging_module/sender.py:205` |
| `LogSender` | `_ensure_serializable(self, obj)` | Ensure object is JSON serializable. | `agent/logging_module/sender.py:260` |
| `LogSender` | `_generate_agent_id(self)` | Generate unique agent identifier. | `agent/logging_module/sender.py:273` |
| `LogSender` | `get_status(self)` | Get sender status. | `agent/logging_module/sender.py:286` |


## Package `agent/network`


### `agent/network/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/network/dns_resolver.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `OptimizedDNSResolver` | DNS resolver with dnspython and aiodns fallback. | `agent/network/dns_resolver.py:48` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `OptimizedDNSResolver` | `__init__(self, max_workers, timeout)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/network/dns_resolver.py:51` |
| `OptimizedDNSResolver` | `resolve_domain_sync(self, domain)` | Synchronous DNS resolution with dnspython. | `agent/network/dns_resolver.py:72` |
| `OptimizedDNSResolver` | `resolve_domain_async(self, domain)` | Asynchronous DNS resolution with aiodns. | `agent/network/dns_resolver.py:120` |
| `OptimizedDNSResolver` | `_query_aiodns(self, domain, record_type)` | Safe async DNS query with timeout using running loop. | `agent/network/dns_resolver.py:169` |
| `OptimizedDNSResolver` | `resolve_multiple_parallel(self, domains)` | Resolve multiple domains in parallel using thread pool with chunking. | `agent/network/dns_resolver.py:187` |
| `OptimizedDNSResolver` | `resolve_multiple_async(self, domains)` | Resolve multiple domains asynchronously. | `agent/network/dns_resolver.py:236` |
| `OptimizedDNSResolver` | `_fallback_resolve(self, domain)` | Fallback to standard socket resolution. | `agent/network/dns_resolver.py:264` |
| `OptimizedDNSResolver` | `_async_fallback_resolve(self, domain)` | Fallback to socket resolution in executor for async context. | `agent/network/dns_resolver.py:296` |
| `OptimizedDNSResolver` | `_is_ip_address(self, address)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/network/dns_resolver.py:303` |
| `OptimizedDNSResolver` | `shutdown(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/network/dns_resolver.py:310` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_min_ttl_dnspython(answer)` | Extract minimum TTL from all RRsets in DNS response. | `agent/network/dns_resolver.py:23` |


## Package `agent/services`


### `agent/services/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/services/heartbeat.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `HeartbeatSender` | Gửi heartbeat định kỳ từ Agent về Server. | `agent/services/heartbeat.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `HeartbeatSender` | `__init__(self, config)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:18` |
| `HeartbeatSender` | `_get_server_urls(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:46` |
| `HeartbeatSender` | `set_agent_credentials(self, agent_id, token)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:59` |
| `HeartbeatSender` | `start(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:63` |
| `HeartbeatSender` | `stop(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:85` |
| `HeartbeatSender` | `_heartbeat_loop(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:91` |
| `HeartbeatSender` | `_send_heartbeat(self)` | Business logic chính, nối controller với model/component và phát event nếu cần. | `agent/services/heartbeat.py:119` |
| `HeartbeatSender` | `_collect_metrics(self)` | Collect system metrics | `agent/services/heartbeat.py:189` |
| `HeartbeatSender` | `get_status(self)` | Get heartbeat sender status. | `agent/services/heartbeat.py:218` |


## Package `agent/shared`


### `agent/shared/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/shared/os_info.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_detect_windows_info()` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/shared/os_info.py:12` |
| `get_os_details()` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/shared/os_info.py:55` |


### `agent/shared/server_urls.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `collect_server_urls(config, allow_dev_default=False)` | Resolver URL Server tập trung cho registration, whitelist sync, heartbeat và log sender; mặc định không fallback localhost khi chưa cấu hình. | `agent/shared/server_urls.py:18` |


### `agent/shared/time_utils.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `_load_vietnam_timezone()` | Return the Vietnam timezone, falling back to a fixed offset. | `agent/shared/time_utils.py:10` |
| `now()` | Get current Unix timestamp. | `agent/shared/time_utils.py:34` |
| `now_vietnam()` | Get current Vietnam datetime (Asia/Ho_Chi_Minh). | `agent/shared/time_utils.py:44` |
| `now_iso()` | Get current Vietnam time as ISO 8601 string. | `agent/shared/time_utils.py:54` |
| `now_server_compatible(ts)` | Return Vietnam ISO timestamp, optionally from Unix timestamp. | `agent/shared/time_utils.py:64` |
| `sleep(duration)` | Sleep for specified duration. | `agent/shared/time_utils.py:79` |
| `is_cache_valid(timestamp, ttl)` | Check if cache is still valid based on TTL. | `agent/shared/time_utils.py:94` |
| `cache_age(timestamp)` | Get cache age in seconds. | `agent/shared/time_utils.py:108` |
| `uptime()` | Get agent uptime in seconds. | `agent/shared/time_utils.py:125` |
| `uptime_string()` | Get agent uptime as readable string. | `agent/shared/time_utils.py:135` |
| `reset_uptime()` | Reset uptime counter (for testing). | `agent/shared/time_utils.py:149` |
| `debug_time_info()` | Get debug time information. | `agent/shared/time_utils.py:159` |


## Package `agent/utils`


### `agent/utils/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/utils/error_handler.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `CriticalErrorHandler` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/utils/error_handler.py:8` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `CriticalErrorHandler` | `safe_execute(func)` | Execute function safely with error handling. | `agent/utils/error_handler.py:11` |
| `CriticalErrorHandler` | `critical_operation(operation_name)` | Decorator for critical operations with logging. | `agent/utils/error_handler.py:43` |
| `CriticalErrorHandler` | `retry_operation(max_retries, delay, backoff, exceptions)` | Decorator for retrying operations on failure. | `agent/utils/error_handler.py:71` |


### `agent/utils/ip_detector.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `IPDetector` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/utils/ip_detector.py:13` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `IPDetector` | `__init__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/utils/ip_detector.py:15` |
| `IPDetector` | `get_local_ip(self, force_refresh)` | Get local IP address with caching. | `agent/utils/ip_detector.py:21` |
| `IPDetector` | `get_admin_status(self, force_refresh)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/utils/ip_detector.py:92` |
| `IPDetector` | `get_cache_debug_info(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/utils/ip_detector.py:113` |

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `get_local_ip(force_refresh)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/utils/ip_detector.py:128` |
| `check_admin_privileges(force_refresh)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/ip_detector.py:132` |
| `get_ip_detector()` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/utils/ip_detector.py:136` |


### `agent/utils/validators.py`

| Function | Công dụng | Vị trí |
| --- | --- | --- |
| `validate_configuration(config)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/validators.py:9` |
| `_validate_server_config(config)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/validators.py:58` |
| `_validate_firewall_config(config)` | Validate firewall configuration. Only `whitelist_only` is supported. | `agent/utils/validators.py:78` |
| `_validate_logging_config(config)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/validators.py:101` |
| `_validate_whitelist_config(config)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/validators.py:116` |
| `_validate_heartbeat_config(config)` | Kiểm tra hợp lệ, quyền truy cập hoặc trạng thái an toàn. | `agent/utils/validators.py:128` |


## Package `agent/whitelist`


### `agent/whitelist/__init__.py`

Module chỉ chứa khai báo package/import hoặc hằng số.


### `agent/whitelist/manager.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistManager` | Đồng bộ whitelist, DNS refresh và cập nhật firewall. | `agent/whitelist/manager.py:16` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistManager` | `__init__(self, config)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/manager.py:17` |
| `WhitelistManager` | `on_sync_complete(self, callback)` | Register callback to be called when sync completes. | `agent/whitelist/manager.py:70` |
| `WhitelistManager` | `_notify_sync_complete(self)` | Notify all registered callbacks that sync is complete. | `agent/whitelist/manager.py:75` |
| `WhitelistManager` | `_get_server_urls(self)` | Get list of server URLs. | `agent/whitelist/manager.py:83` |
| `WhitelistManager` | `set_firewall_manager(self, firewall_manager)` | Set firewall manager for rule updates. | `agent/whitelist/manager.py:97` |
| `WhitelistManager` | `start_sync(self)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/whitelist/manager.py:102` |
| `WhitelistManager` | `stop_sync(self)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/whitelist/manager.py:125` |
| `WhitelistManager` | `stop_periodic_updates(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/whitelist/manager.py:133` |
| `WhitelistManager` | `_sync_loop(self)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/whitelist/manager.py:136` |
| `WhitelistManager` | `_refresh_dns_loop(self)` | Background loop to refresh expiring DNS records. | `agent/whitelist/manager.py:153` |
| `WhitelistManager` | `sync_now(self)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/whitelist/manager.py:195` |
| `WhitelistManager` | `is_allowed(self, domain, ip)` | Check if domain/IP is allowed. | `agent/whitelist/manager.py:268` |
| `WhitelistManager` | `is_ip_allowed(self, ip)` | Check if IP is allowed (delegate to state). | `agent/whitelist/manager.py:286` |
| `WhitelistManager` | `remove_ip(self, ip)` | Remove IP from whitelist state. | `agent/whitelist/manager.py:290` |
| `WhitelistManager` | `_update_firewall_rules(self)` | Update firewall rules based on whitelist. | `agent/whitelist/manager.py:297` |
| `WhitelistManager` | `get_stats(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/manager.py:367` |
| `WhitelistManager` | `get_cache_info(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/manager.py:383` |
| `WhitelistManager` | `force_refresh(self)` | Force immediate refresh of whitelist. | `agent/whitelist/manager.py:394` |
| `WhitelistManager` | `cleanup(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/whitelist/manager.py:399` |


### `agent/whitelist/monitor.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistMonitor` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/monitor.py:10` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistMonitor` | `__init__(self, sync_callback, interval)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/monitor.py:11` |
| `WhitelistMonitor` | `start(self)` | Start the monitor. | `agent/whitelist/monitor.py:21` |
| `WhitelistMonitor` | `stop(self)` | Điều khiển vòng đời thành phần hoặc tiến trình nền. | `agent/whitelist/monitor.py:36` |
| `WhitelistMonitor` | `_monitor_loop(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/monitor.py:42` |
| `WhitelistMonitor` | `get_status(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/monitor.py:63` |


### `agent/whitelist/state.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistState` | Lưu trạng thái whitelist đã parse từ Server. | `agent/whitelist/state.py:12` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistState` | `__init__(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/state.py:13` |
| `WhitelistState` | `_parse_entries(self, data)` | Parse domains/ips from server response into sets. | `agent/whitelist/state.py:27` |
| `WhitelistState` | `update(self, data)` | Áp dụng response sync từ Server vào state. Short-circuit khi `up_to_date=true` hoặc khi parsed mới = current. **Anti-wipe guard** (thêm 2026-06-05): nếu `prev_total>0`, `new_total==0`, và `not group_changed` → giữ cache + log warning + cập nhật version bookkeeping, return False — tránh race condition giữa initial sync (Step 2.5) và periodic sync (Step 4) làm wipe state đã populated. | `agent/whitelist/state.py:65` |
| `WhitelistState` | `_calculate_checksum(self)` | Calculate checksum of current state. | `agent/whitelist/state.py:124` |
| `WhitelistState` | `is_domain_allowed(self, domain)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/state.py:133` |
| `WhitelistState` | `is_ip_allowed(self, ip)` | Check if IP is in whitelist. | `agent/whitelist/state.py:157` |
| `WhitelistState` | `get_stats(self)` | Get whitelist statistics. | `agent/whitelist/state.py:162` |
| `WhitelistState` | `get_all_domains(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/state.py:174` |
| `WhitelistState` | `get_all_patterns(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/state.py:178` |
| `WhitelistState` | `get_all_ips(self)` | Lấy/truy vấn dữ liệu theo tham số hoặc trạng thái hiện tại. | `agent/whitelist/state.py:182` |
| `WhitelistState` | `remove_ip(self, ip)` | Remove an IP from the state safely. | `agent/whitelist/state.py:186` |
| `WhitelistState` | `clear(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/state.py:194` |


### `agent/whitelist/sync.py`

| Class | Công dụng | Vị trí |
| --- | --- | --- |
| `WhitelistSyncer` | HTTP client kéo whitelist từ Server, có fallback URL. | `agent/whitelist/sync.py:12` |

| Class | Method | Công dụng | Vị trí |
| --- | --- | --- | --- |
| `WhitelistSyncer` | `__init__(self, server_urls, agent_id, config, connect_timeout, read_timeout, max_retries)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/sync.py:14` |
| `WhitelistSyncer` | `current_url(self)` | Hàm hỗ trợ nghiệp vụ trong module tương ứng. | `agent/whitelist/sync.py:32` |
| `WhitelistSyncer` | `_build_sync_url(self, base_url)` | Đồng bộ dữ liệu giữa Agent và Server hoặc giữa state và firewall. | `agent/whitelist/sync.py:37` |
| `WhitelistSyncer` | `_get_headers(self)` | Get request headers with authentication. | `agent/whitelist/sync.py:40` |
| `WhitelistSyncer` | `sync_with_server(self, params)` | Sync with server, trying fallback servers if needed. | `agent/whitelist/sync.py:47` |
| `WhitelistSyncer` | `extract_domain_value(self, domain_data)` | Extract domain value from server response. | `agent/whitelist/sync.py:138` |

## Cap nhat 2026-05-27 - Agent lifecycle component contract

`agent/core/lifecycle.py` da them cac public/internal symbols can ghi nho:

| Symbol | Cong dung | Vi tri |
| --- | --- | --- |
| `LifecycleContext` | Context runtime/config/result/started_components duoc truyen vao component. | `agent/core/lifecycle.py` |
| `AgentComponent` | Contract `start(context)`, `stop(context)`, `health(context)`. | `agent/core/lifecycle.py` |
| `build_default_components()` | Tao production component stack theo thu tu registration, token, whitelist, firewall, log sender, heartbeat, packet sniffer. | `agent/core/lifecycle.py` |
| `start_components(context, components)` | Start theo thu tu; neu component fail thi cleanup cac component da start. | `agent/core/lifecycle.py` |
| `stop_components(context)` | Stop nguoc thu tu va clear runtime stack. | `agent/core/lifecycle.py` |

Test moi: `agent/tests/test_lifecycle_components.py` cover start order, stop order, start failure cleanup va component-reported failure cleanup. Reference chi tiet: `docs/reference/agent/lifecycle_components.md`.

