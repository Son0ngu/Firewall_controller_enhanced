# `server/tests` - Integration test suite

## Mục đích
Integration tests dùng **real MongoDB** (test DB riêng cho mỗi file) - không mock DB, không spin up HTTP server. Test trực tiếp Model/Service/Controller bằng Python imports + Flask test context.

11 file test, ~535 test cases tong, ~7370 dong. Cap nhat 2026-06-01: them `test_api_key_expiration.py` de cover API key expiration khong can Mongo that.

## Tests theo file

| File | Lines | Test count | Test DB | Phạm vi |
|---|---:|---:|---|---|
| [test_agents.py](../../../server/tests/test_agents.py) | 847 | 58 | `test_saint_agents` | AgentModel + AgentService (register, heartbeat, status, group move). Cross-teacher isolation. Edge cases |
| [test_agent_full.py](../../../server/tests/test_agent_full.py) | 798 | 64 | `test_saint_agent_full` | Agent + AgentPolicy combined. Model/Service/Controller. RBAC teacher access |
| [test_api_key_expiration.py](../../../server/tests/test_api_key_expiration.py) | 142 | 4 | fake collection | API key `expires_at` enforcement: expired key invalid/401, no usage increment; live/never-expire keys valid |
| [test_audit.py](../../../server/tests/test_audit.py) | 391 | 29 | `test_saint_audit` | AuditModel + AuditService + AuditController (permission checks) |
| [test_groups.py](../../../server/tests/test_groups.py) | 881 | 70 | `test_saint_groups` | GroupModel + Service + Controller. RBAC filtering. Pending group integration |
| [test_users_auth.py](../../../server/tests/test_users_auth.py) | 857 | 84 | `test_saint_users_auth` | UserModel + SessionModel + AdminAuthService + UserService + Controllers. Brute-force, lock/unlock |
| [test_whitelist_and_logs.py](../../../server/tests/test_whitelist_and_logs.py) | 1193 | 109 | `test_saint_whitelist_logs` | Whitelist + Log Model/Service/Controller. RBAC. Pending group isolation |
| [test_teacher_data_filtering.py](../../../server/tests/test_teacher_data_filtering.py) | 1364 | 75 | (mock-based) | Toàn bộ RBAC filtering across 4 controllers. Mock-heavy (không cần real DB cho hầu hết) |

## Cấu trúc test class

Pattern lặp lại trong mọi file:

```
TestXModel        - DB CRUD tests trực tiếp
TestXService      - business logic, side effects
TestXController   - HTTP handlers via Flask test_client hoặc direct call
TestRBACX         - teacher isolation tests
TestXIntegration  - flow xuyên layers
TestXEdgeCases    - corner cases
```

Vd: [test_agents.py](../../../server/tests/test_agents.py) có 8 class:
- `TestAgentModel` - CRUD, find, heartbeat
- `TestAgentServiceRegistration` - register edge cases
- `TestAgentServiceHeartbeat` - heartbeat parse + status
- `TestAgentServiceStatus` - active/inactive/offline calc
- `TestAgentServiceGroupMove` - move pending ↔ normal
- `TestCrossTeacherIsolation` - RBAC
- `TestAgentEdgeCases` - undefined fields, device_id conflict
- `TestAgentPolicyInteraction` - policy + sync interaction

## Common fixtures

| Fixture | Scope | Mô tả |
|---|---|---|
| `mongo_client` | session | `MongoClient` với `MONGO_URI` từ `.env`. Ping ở setup, close ở teardown |
| `db` | function | `mongo_client.get_database(TEST_DB)` với codec aware-VN. **Drop DB ở teardown** - mỗi test isolated |
| `<x>_model` | function | Tạo model với `db` fixture |
| `<x>_service` | function | Tạo service với model deps |
| `app` | function | Minimal Flask app cho RBAC mock tests |
| `jwt_service` | function | `JWTService(db=db)` |
| `audit_service` | function | `AuditService(audit_model)` |

Helper makers (lặp lại):
```python
def make_admin():     return {"_id": ObjectId(), "username": "admin01", "role": "admin"}
def make_teacher(tid): return {"_id": tid or ObjectId(), "username": "teacher01", "role": "teacher"}

def _mock_auth(user):
    return patch.multiple('middleware.rbac',
        _extract_token=lambda: 'fake-token',
        _validate_admin_token=lambda token: (True, user, None))
```

## Cách chạy

```bash
cd server

# All
python -m pytest tests/ -v

# Specific file
python -m pytest tests/test_agents.py -v

# Specific class
python -m pytest tests/test_agents.py::TestAgentModel -v

# Specific test
python -m pytest tests/test_agents.py::TestAgentModel::test_register_agent -v

# By keyword
python -m pytest tests/test_agents.py -v -k "cross_teacher"

# With coverage
python -m pytest tests/ --cov=server --cov-report=term-missing
```

## Yêu cầu môi trường

- **MongoDB chạy local** (mặc định `mongodb://localhost:27017/`). Hoặc override `MONGO_URI` trong `.env`
- **`.env` ở `server/.env`** - fixtures load với `load_dotenv(env_path)` (xem `mongo_client` fixture pattern)
- **Python deps**: `pytest`, `pytest-mock`, `bcrypt`, `PyJWT`, `pymongo`, `dotenv`, `flask`, `flask_socketio`

## Ai gọi module này
- Developer chạy thủ công `pytest`
- CI/CD pipeline (chưa có config trong repo này)

## Module này gọi ra
- Toàn bộ `server/*` - model/service/controller imports
- `pytest`, `unittest.mock`
- `flask`, `bcrypt`, `pymongo`, `bson`, `dotenv`

## Đã có sẵn - đừng viết lại
- Cần fixture DB sạch? → copy `mongo_client` + `db` fixture từ `test_agents.py:43-65`. Đặt `TEST_DB` unique để không collide
- Cần mock auth admin/teacher? → copy `_mock_auth(user)` helper
- Cần factory user dict? → `make_admin() / make_teacher()`
- Cần parse Flask response? → `json.loads(resp.data)`, `resp.status_code`
- Cần codec options? → `CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)` (giống `database/config.py`)

## Gotchas

### Real DB, không mock
- **Cần Mongo running** trước khi pytest. Không có docker-compose included, CI cần spin Mongo container.
- **Drop DB ở teardown** (line `mongo_client.drop_database(TEST_DB)`) - test xong xoá sạch. Nếu pytest bị kill giữa chừng, DB còn lại → flush thủ công: `mongosh ... db.dropDatabase()`.
- **Mỗi file có TEST_DB riêng** (`test_saint_<scope>`): chạy song song nhiều file vẫn an toàn.

### Mock pattern không consistent
- `test_teacher_data_filtering.py` mock heavy (Flask test app + mock services) - nhanh, không cần Mongo
- Các file khác hybrid (real Mongo cho model/service, mock auth cho controller test)
- Đáng standardize sang 1 pattern. Hiện 2 pattern song song.

### Audit log testing
- `AuditModel.log` swallow exception → test thấy `{}` return có thể là OK hoặc error. `test_audit.py` chỉ check side effect (collection có entry) thay vì return value.

### Auth tests
- `test_users_auth.py::TestAdminAuthService` test bcrypt + tokens + sessions. Slow vì bcrypt rounds=12. Total ~10s cho 84 tests.
- Brute-force lock test: tạo user → fail 5 lần → assert locked → verify `is_locked()`. Restore bằng `reset_failed_attempts`.

### RBAC tests
- `test_teacher_data_filtering.py` 75 tests cover toàn bộ RBAC paths. Đáng giá để chạy thường xuyên - RBAC bug = security incident.
- Mock `flask.g.current_user` qua `with app.test_request_context(): g.current_user = make_teacher()`.

### Coverage gaps đáng để ý
- `services/agent_policy_service.apply_policy_to_sync` có test trong `test_agent_full.py::TestAgentPolicyService` - nhưng edge case "server_host=None" chưa cover
- `whitelist_service._update_group_entry` upgrade legacy string → dict: có 1 test happy path, edge case không
- Socket emit calls: assert qua `mock_socketio.emit.assert_called_with(...)` - không thực sự test client nhận event
- API key HMAC migration: chỉ test trong `test_agents.py` (sample), chưa có file riêng
- API key rate limit: không có test vì feature không tồn tại. Backend hiện không có `rate_limit` field/window counter/token bucket/429; UI giả đã bị gỡ ngày 2026-06-01.

Cap nhat 2026-06-01: API key expiration da co `test_api_key_expiration.py` cover expired key invalid/401, no usage increment, live key valid, never-expire key valid.

### Datetime drift
- `parse_agent_timestamp` (xem [app.md](app.md)) clamp future timestamps. Vài test fixture set heartbeat dù `now + 1 hour` → bị clamp. Đảm bảo test fixture < FUTURE_DRIFT_TOLERANCE (5 min).

### CI not configured
- Repo không có `.github/workflows/*.yml`. Manual test only. Nếu thêm CI, cần spin Mongo service + run pytest.

### Flask test context vs real request
- Test gọi handler trực tiếp `controller.handler()` trong `with app.test_request_context(...)`. KHÔNG đi qua Werkzeug routing. Vì vậy không test prefix `/api/`, không test 404 routing. Acceptable cho integration nhưng miss route conflict bugs.
