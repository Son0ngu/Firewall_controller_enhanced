# `server/database/config.py` - MongoDB connection + Config class

## Mục đích
Wrap `pymongo.MongoClient` thành singleton, đọc cấu hình từ env (`.env` qua `python-dotenv`). Định nghĩa 3 lớp Config (Dev/Prod/Testing) kế thừa `Config`. Tự gắn `tz_aware=True, tzinfo=VIETNAM_TZ` cho codec options → mọi datetime đọc từ Mongo đều aware-VN tự động.

## Public API

| Symbol | Signature | Vị trí | Mô tả |
|---|---|---|---|
| `Config` | `class` | [config.py:39](../../../server/database/config.py#L39) | Holds env-driven settings. Mọi attribute là class-level constant đọc qua `get_env(key, default)` |
| `DevelopmentConfig(Config)` | | [config.py:134](../../../server/database/config.py#L134) | `DEBUG=True`, `LOG_LEVEL=DEBUG` |
| `ProductionConfig(Config)` | | [config.py:139](../../../server/database/config.py#L139) | `DEBUG=False`, `LOG_LEVEL=WARNING`, pool size 25 |
| `TestingConfig(Config)` | | [config.py:148](../../../server/database/config.py#L148) | `MONGO_DBNAME='test_firewall_controller'` |
| `get_env(key, default)` | `(str, Any) -> Any` | [config.py:26](../../../server/database/config.py#L26) | Đọc env với type coercion: bool/int/float theo type của `default` |
| `get_config()` | `() -> Config` | [config.py:120](../../../server/database/config.py#L120) | Trả `Config()` (always new instance - không cache) |
| `get_config_by_name(name=None)` | `(Optional[str]) -> Config` | [config.py:154](../../../server/database/config.py#L154) | Pick by `FLASK_ENV` env var. Default → `Config` base |
| `get_mongo_client(config)` | `(Config) -> MongoClient` | [config.py:75](../../../server/database/config.py#L75) | **Singleton** `_mongo_client`. Connect với timeout 5s, pool 10, compression `snappy,zlib`, `appName="FirewallController"` |
| `close_mongo_client()` | `() -> None` | [config.py:112](../../../server/database/config.py#L112) | Reset singleton - gọi trong shutdown path |
| `get_database(config=None)` | `(Optional[Config]) -> Database` | [config.py:124](../../../server/database/config.py#L124) | `client.get_database(name, codec_options=_codec_options)` |
| `validate_config(config=None)` | `(Optional[Config]) -> bool` | [config.py:167](../../../server/database/config.py#L167) | Check required env (SECRET_KEY, MONGO_URI, MONGO_DBNAME) + ping Mongo. False → app refuses to start |
| `get_connection_info()` | `() -> dict` | [config.py:201](../../../server/database/config.py#L201) | `{connected, server_version, uptime, timestamp}` cho debug |
| `log_config_status(config=None)` | | [config.py:227](../../../server/database/config.py#L227) | Log database, debug mode, host:port, connection status |
| `_codec_options` | `CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)` | [config.py:24](../../../server/database/config.py#L24) | **Critical**: mọi `datetime` đọc từ Mongo sẽ auto-gắn tz VN |

## Settings table (mặc định từ env hoặc fallback)

| Env var | Default | Mục đích |
|---|---|---|
| `SECRET_KEY` | env bắt buộc | Flask session signing; thiếu env thì validate/startup fail |
| `DEBUG` | `True` | Flask debug mode |
| `MONGO_URI` | `mongodb://localhost:27017/` | Connection string |
| `MONGO_DBNAME` | `Monitoring` | DB name |
| `MONGO_MAX_POOL_SIZE` | `50` | pymongo max pool |
| `MONGO_MIN_POOL_SIZE` | `5` | pymongo min pool |
| `MONGO_MAX_IDLE_TIME_MS` | `30000` | Idle timeout 30s |
| `MONGO_SERVER_SELECTION_TIMEOUT_MS` | `5000` | Fail fast |
| `MONGO_CONNECT_TIMEOUT_MS` | `10000` | TCP connect |
| `MONGO_SOCKET_TIMEOUT_MS` | `20000` | Socket read |
| `LOG_LEVEL` | `INFO` | |
| `LOG_FILE` | `server.log` | |
| `SOCKETIO_ASYNC_MODE` | `gevent` | |
| `AGENT_WHITELIST_UPDATE_INTERVAL` | `300` (giây) | Sync interval suggestion |
| `HOST` | `0.0.0.0` | |
| `PORT` | `5000` | |
| `FLASK_ENV` | `development` | Picks config class |
| `JWT_SECRET_KEY` | random | Bắt buộc ở production (raise `RuntimeError`) - xem [services.md](services.md) |
| `JWT_REFRESH_SECRET_KEY` | random | Bắt buộc ở production |
| `API_KEY_HMAC_SECRET` | env bắt buộc | Set ở production - xem [models.md](models.md); thiếu env sẽ raise khi import |
| `ADMIN_COOKIE_SECURE` | `False` ở `Config`, `True` ở `ProductionConfig` | Cookie auth/refresh dùng `Secure` flag — chỉ gửi qua HTTPS. Đọc qua helper `_cookie_secure()` ở [web_auth_controller.py](../../../server/controllers/web_auth_controller.py) (đổi tên từ `admin_auth_controller.py`; shim cũ vẫn re-export cho backwards-compat). |
| `ENABLE_DEBUG_ENDPOINTS` | `False` | Cho phép register `/api/agents/debug/status` & `/api/agents/debug/direct` (xem [controllers.md](controllers.md)). Production để `False` → route trả 404. |
| `DEBUG_AUTH_QUERY_TOKEN` | `False` | Cho phép đọc `?api_key=` và `?access_token=` query string ở [middleware/auth.py](../../../server/middleware/auth.py). Default deny vì token leak qua proxy log/Referer. |

## Ai gọi module này
- `server/app.py` - bootstrap
- `server/scripts/seed_rbac.py` - connect Mongo cho seeder
- Tests - `get_database(config)` để có db instance test

Không có model/service nào import trực tiếp - chỉ `app.py` và `seed_rbac.py`.

## Module này gọi ra
- `pymongo` - `MongoClient`, `CodecOptions`
- `dotenv` - load `.env`
- `time_utils` - `now_iso`, `VIETNAM_TZ`

## Đã có sẵn - đừng viết lại
- Cần Mongo client? → `get_mongo_client(config)` - singleton, đừng `MongoClient(...)`
- Cần DB instance? → `get_database(config)` - đã set codec options
- Cần env vars có type coercion? → `get_env(key, default=True)` (auto bool), `get_env(key, default=5000)` (auto int)
- Cần check Mongo ready? → `validate_config()` (ping test)
- Cần connection info? → `get_connection_info()`

## Gotchas
- **`get_config()` không cache** (config.py:120): mỗi lần gọi tạo `Config()` mới → re-read env. Acceptable vì `Config` chỉ là namespace. Nếu cần cache, caller tự giữ ref (app.py:155 lưu `app.config_instance`).
- **`SECRET_KEY` thiếu env thì fail fast**: không còn random fallback. Production phải set `SECRET_KEY` cố định trong `.env`, nếu thiếu thì app không qua validation/startup.
- **`_mongo_client` là module-level singleton**: test phải `close_mongo_client()` giữa các test session để có connection mới (TestingConfig dùng db khác nhưng connection reuse).
- **Connection settings hardcode trong `get_mongo_client`** (config.py:84-99): override `MONGO_MAX_POOL_SIZE` env vẫn không có hiệu lực vì hàm dùng literal `maxPoolSize=10`. **Bug**: code đọc env vào `Config.MONGO_MAX_POOL_SIZE` nhưng không truyền vào client. Đáng sửa.
- **`compressors="snappy,zlib"`** (config.py:97): server Mongo phải hỗ trợ. Mongo Atlas free có sẵn. Self-hosted có thể thiếu snappy → fall back zlib.
- **`tz_aware=True` từ `_codec_options`** - đảm bảo aware datetimes. Nếu code save naive datetime vào Mongo, pymongo sẽ raise (CodecOptions strict). Đã có `to_vietnam(dt)` cho mọi place.
- **Validate config = ping Mongo** (config.py:191-198): nếu Mongo down lúc startup, app raise `RuntimeError("Database connection failed")`. Production cần ensure Mongo ready trước Flask start.
- **`MONGO_URI` mask trong log** (config.py:184): chỉ giữ phần sau `@` (host). User/pass không log. OK security.
- **`.env` path** (config.py:15-17): `os.path.dirname(os.path.dirname(...))` → parent của `database/` = `server/`. File `.env` PHẢI ở `server/.env`. Đặt ở repo root sẽ không load.
- **`override=True`** trong `load_dotenv` (config.py:17): env vars trong `.env` ghi đè system env. Production thường ngược lại (env > .env) - chú ý nếu deploy via systemd/Docker với env vars.
