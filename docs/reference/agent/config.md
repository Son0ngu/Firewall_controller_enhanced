# `agent/config` - Loader, Defaults, Validator, Encrypted Storage

## Mục đích
Load config từ nhiều nguồn (file → env → defaults), merge theo deep-merge, validate, **mã hoá ngầm** bằng Fernet với khoá derive từ hostname + MAC **+ salt ngẫu nhiên mỗi máy** (`.salt`, ACL-restricted) nên khoá không tái tạo được chỉ từ định danh máy công khai. Auto-migrate plaintext → encrypted, và `.enc` mã bằng khoá legacy (chưa salt) → re-encrypt khoá có salt khi đọc.

4 file: `defaults.py` (DEFAULT_CONFIG), `loader.py` (load + merge), `validator.py` (validate + coerce), `crypto.py` (Fernet encrypt/decrypt).

## Public API

### `agent/config/loader.py` - Load + merge + cache

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `CONFIG_PATHS` | `List[Path]` | [loader.py:19](../../../agent/config/loader.py#L19) | Thứ tự tìm: `<agent_dir>/agent_config.json`, cwd, `~/.firewall-controller/`, `C:/ProgramData/FirewallController/` |
| `DEFAULT_CONFIG_FILE` | `str` const | [loader.py:14](../../../agent/config/loader.py#L14) | `"agent_config.json"` |
| `load_config()` | `() -> Dict[str, Any]` | [loader.py:30](../../../agent/config/loader.py#L30) | Defaults → file → env. Inject `_metadata` (loaded_at, source, validation result) |
| `get_config()` | `() -> Dict[str, Any]` | [loader.py:98](../../../agent/config/loader.py#L98) | **Cached singleton**. Lần đầu gọi `load_config`, sau đó update `last_accessed` |
| `reload_config()` | `() -> Dict[str, Any]` | [loader.py:115](../../../agent/config/loader.py#L115) | Clear cache + reload. Dùng khi user save Settings |
| `_load_from_file()` | `() -> Optional[Dict]` | [loader.py:127](../../../agent/config/loader.py#L127) | Env `FIREWALL_CONTROLLER_CONFIG` override. Thử `.enc` trước → plaintext fallback → auto-migrate to encrypted |
| `_load_from_env()` | `() -> Dict[str, Any]` | [loader.py:166](../../../agent/config/loader.py#L166) | Prefix `FC_`. `__` (double underscore) = nested. Auto-convert true/false/null/int/float/JSON |
| `_convert_value(value)` | `(str) -> Any` | [loader.py:195](../../../agent/config/loader.py#L195) | bool/null/int/float/json/str |
| `_deep_update(base, update)` | `(Dict, Dict) -> None` | [loader.py:217](../../../agent/config/loader.py#L217) | Recursive merge - dict thì merge, scalar/list thì overwrite |
| `_deep_copy(d)` | `(Dict) -> Dict` | [loader.py:213](../../../agent/config/loader.py#L213) | JSON round-trip - không copy callable/non-serializable |

### `agent/config/defaults.py` - `DEFAULT_CONFIG` (giá trị mặc định)

| Section | Key | Default | Ý nghĩa |
|---|---|---|---|
| `server` | `urls` | `[]` | List URLs (ưu tiên thử lần lượt) |
| | `url` | `""` | URL chính. **Empty = offline mode**, không leak info |
| | `connect_timeout / read_timeout` | `15 / 45` | HTTP timeouts (giây) |
| | `retry_interval / max_retries` | `60 / 5` | |
| `auth` | `api_key` | `""` | X-API-Key cho `/api/agents/register` |
| | `auth_method / jwt_refresh_interval` | `"none" / 3600` | |
| `whitelist` | `auto_sync` | `True` | Bật sync loop |
| | `update_interval` | `60` | Giây |
| | `ip_cache_ttl / ip_refresh_interval` | `300 / 300` | DNS cache |
| `capture` | `engine` | `"scapy"` | (Hiện chỉ hỗ trợ scapy) |
| | `filter` | (string) | **KHÔNG được sniffer dùng - xem [capture.md](capture.md) Gotchas** |
| `logging` | `level` | `"INFO"` | |
| | `sender.batch_size / max_queue_size / send_interval` | `100 / 1000 / 2` | |
| `firewall` | `enabled` | `True` | |
| | `mode` | `"whitelist_only"` | **Mode duy nhất hỗ trợ** |
| | `rule_prefix` | `"FirewallController"` | |
| | `backup.path` | `"profiles/backup.saint-snapshot.json"` | Relative path resolve dưới `%LOCALAPPDATA%\SAINT` |
| `heartbeat` | `interval` | `20` | Giây |
| | `max_failures` | `3` | Sau ngần ấy fail → log error |

### `agent/config/validator.py` - Validate + coerce

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `validate_config(config)` | `(Dict) -> Tuple[bool, List[str], List[str]]` | [validator.py:9](../../../agent/config/validator.py#L9) | `(is_valid, errors, warnings)`. Errors → block; warnings → log nhưng tiếp tục |
| `_validate_server_config(config, errors, warnings)` | | [validator.py:35](../../../agent/config/validator.py#L35) | Thiếu URL là offline-first warning; scheme check là warning |
| `_validate_firewall_config(config, errors, warnings)` | | [validator.py:56](../../../agent/config/validator.py#L56) | **Coerces mode về `whitelist_only`** với warning (legacy configs). Warn nếu không admin |
| `_validate_logging_config(config, warnings)` | | [validator.py:87](../../../agent/config/validator.py#L87) | Level invalid → set INFO + warning |
| `_validate_whitelist_config(config, warnings)` | | [validator.py:98](../../../agent/config/validator.py#L98) | interval < 30s ⇒ warning |
| `_validate_heartbeat_config(config, warnings)` | | [validator.py:109](../../../agent/config/validator.py#L109) | interval < 10s ⇒ warning |
| `_has_admin_privileges()` | `() -> bool` | [validator.py:120](../../../agent/config/validator.py#L120) | Two-step: `IsUserAnAdmin` rồi fallback `netsh advfirewall show currentprofile` |

> Có một validator nữa ở [`utils/validators.py`](../../../agent/utils/validators.py) - gần trùng lặp. Xem [utils.md](utils.md) Gotchas.

### `agent/config/crypto.py` - Fernet encrypt/decrypt

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `ENCRYPTED_EXT` / `SALT_EXT` | `str` const | [crypto.py:25](../../../agent/config/crypto.py#L25) | `".enc"` / `".salt"`. File `agent_config.json.enc` + salt `agent_config.json.salt` |
| `encrypt_config(config, path)` | `(Dict, Path) -> bool` | [crypto.py:34](../../../agent/config/crypto.py#L34) | Ghi `.enc` (khoá có salt) + xoá plaintext gốc |
| `decrypt_config(path)` | `(Path) -> Optional[Dict]` | [crypto.py:58](../../../agent/config/crypto.py#L58) | Thử khoá-salt → fallback khoá legacy `_get_machine_key` → **re-encrypt** (migrate `.enc` cũ). Sai/hỏng → trả None |
| `migrate_plaintext_to_encrypted(path)` | `(Path) -> bool` | [crypto.py:80](../../../agent/config/crypto.py#L80) | Nếu thấy plaintext mà chưa có `.enc` → encrypt rồi xoá plaintext |
| `_load_or_create_salt(path)` / `_get_salted_key(path)` | `(Path) -> bytes` | [crypto.py:24](../../../agent/config/crypto.py#L24) | Salt ngẫu nhiên 32 byte (`secrets`) lưu `.salt` ACL qua `restrict_to_owner`; khoá hiện tại = `sha256(hostname+MAC+salt)` |
| `_get_machine_key()` | `() -> bytes` | [crypto.py:24](../../../agent/config/crypto.py#L24) | **LEGACY** (chỉ hostname+MAC) — chỉ dùng để migrate `.enc` cũ |

## Ai gọi module này
- `agent/agent_gui.py` (entry point) - `load_config()` lúc startup
- `agent/gui_qt/views/settings.py` - `reload_config()` sau khi user save settings
- `agent/core/lifecycle.py` - nhận `config` dict từ caller, không import config module trực tiếp

## Module này gọi ra
- `cryptography.fernet.Fernet` - encrypt/decrypt
- `agent/shared/time_utils` - metadata timestamps
- `ctypes.windll.shell32 / subprocess` - admin check
- stdlib: `json`, `pathlib`, `os.environ`

## Đã có sẵn - đừng viết lại
- Cần load config? → `get_config()` (cached) - **đừng** `json.load(open(...))` thẳng
- Cần reload sau khi user save settings? → `reload_config()`
- Cần build cấu hình test? → bắt đầu từ `DEFAULT_CONFIG` và `_deep_update` thay vì viết tay full dict
- Cần override config bằng env? → đặt biến `FC_<SECTION>__<KEY>` (vd `FC_SERVER__URL=https://...`)
- Cần encrypt/decrypt config? → đã auto khi load - không cần làm thủ công. Muốn force re-encrypt: `encrypt_config(config, path)`

## Gotchas
- **`server.url = ""` mặc định** (defaults.py:10) - agent vào **offline mode**, không gửi request nào tới server cho tới khi user nhập URL trong Settings. Lifecycle.py & registry.py đã handle case này. Đừng "fix" bằng cách set URL mặc định - sẽ leak hostname/MAC/OS ngay khi startup.
- **`firewall.mode` chỉ chấp nhận `"whitelist_only"`**: validator.py:70 sẽ coerce mode khác về whitelist_only với warning. Nếu sửa config thấy mode không apply, kiểm validator.
- **Env vars override file** (loader.py:55-57) - debug local dễ dùng (`set FC_SERVER__URL=http://localhost:5000`) nhưng cẩn thận: deploy nếu set env var sẽ override config user nhập trong GUI.
- **`_deep_update` không merge list** - list từ env/file sẽ REPLACE list từ default. Vd `server.urls=[]` default, user nhập `["a","b"]` ⇒ list final là `["a","b"]`, không phải `[] + ["a","b"]`.
- **`_deep_copy = JSON round-trip`** (loader.py:213): config có chứa `Path`, `datetime`, callable sẽ raise. Hiện DEFAULT_CONFIG chỉ scalar/dict/list nên OK.
- **Auto-migrate plaintext → encrypted** (loader.py:151-157): lần đầu thấy `agent_config.json` plaintext, sẽ tự encrypt thành `.enc` rồi xoá bản gốc. **Đừng** edit plaintext rồi expect nó sẽ load - sẽ bị xoá. Edit qua GUI Settings hoặc decrypt thủ công.
- **Machine key derive từ hostname + MAC**: đổi hostname HOẶC đổi network adapter chính ⇒ key đổi ⇒ `InvalidToken` ⇒ config không decrypt được ⇒ agent rơi về DEFAULT_CONFIG. Trên dev laptop dock đi dock lại, MAC có thể đổi tuỳ adapter. Hiện chấp nhận - coi như security tradeoff.
- **`FIREWALL_CONTROLLER_CONFIG` env var** override `CONFIG_PATHS` (loader.py:132-133). Khi set, sẽ KHÔNG fallback các path khác - file đó phải tồn tại.
- **`server_cfg["urls"] = [primary_url]` ở loader.py:73**: nếu user nhập `server.url` thì list urls bị overwrite về 1 phần tử. Cố ý - runtime modules đọc `urls` trước nên phải đồng nhất với chọn của user.
- **`_metadata` được inject vào config dict** (loader.py:60-66): không serialize lại lúc save. Nếu code khác `save_config` cần loại bỏ `_metadata` trước khi encrypt - hiện không có `save_config`, settings_view dùng đường khác.
- **`validate_config` mutate config** (validator.py:75, 95): set `firewall.mode="whitelist_only"`, `logging.level="INFO"` khi invalid. Khác với pure validator. Caller nhận dict đã được "fixed".
- **Hai validator gần trùng nhau**: `config/validator.py` và `utils/validators.py`. Cái thứ hai (utils) **không coerce**, chỉ log. Hiện loader chỉ dùng `config.validator`. Nếu sửa rule validate, đảm bảo cả 2 đồng bộ (hoặc xoá `utils/validators.py`).
