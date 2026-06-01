# Cap nhat kiem thu E2E, Firewall va ton dong - 2026-05-28

## Muc dich

File nay cap nhat trang thai moi nhat sau cac dot kiem thu tren Render production va may Windows Administrator. Pham vi gom Server API/RBAC, Agent contract, GUI, Socket.IO, whitelist conflict, Windows Firewall Default Deny va cac loi frontend da phat hien sau khi mo dashboard that.

## Ket qua chinh

| Hang muc | Ket qua | Bang chung |
| --- | --- | --- |
| Full system E2E deep tren Render | PASS sach: `24 PASS / 0 FAIL / 0 SKIP`, `exit_code=0` | `test-results/saint-full-system-e2e/20260528_141158/` |
| Cleanup sau full deep | `CLEANUP_OK=43`, `cleanup_failures=0`, `required_failures=0` | `20260528_141158` JSON |
| Public auth leak hotfix | `/api/groups`, `/api/logs?limit=1`, `/api/logs/stats` tra `401` khi chua dang nhap | Production smoke 2026-05-28 |
| Windows Firewall Default Deny | Bat that, ca 3 profile outbound ve `block`, restore ve `allow`, residual managed rules = 0 | `real_firewall_default_deny_contract` PASS |
| Packet allowed/blocked | Allowed packet OK khi Default Deny active; blocked packet bi chan dung ky vong; post-restore blocked target ket noi lai OK | `20260528_141158` JSON |
| Policy heartbeat force sync | Isolate heartbeat tra `force_sync=true`, `policy_mode=isolate`; custom/reset policy sync PASS | `deep_policy_matrix` PASS |
| Whitelist conflict/profile sync | Active profile domain sync dung, khong con `value: null`/pseudo-id `None` | `deep_whitelist_conflict_matrix` PASS |
| Long soak 30 phut | PASS, 28 samples healthy trong cua so 30 phut | `deep_long_soak_matrix` PASS |
| GUI click-by-click | PASS qua Playwright Node: login va dieu huong cac trang chinh, gom API Keys | `deep_gui_click_matrix` PASS |
| Socket.IO realtime | PASS: connect, ping/pong, `whitelist_added` event | `deep_websocket_realtime_matrix` PASS |
| Classroom synthetic scale | PASS voi 24 synthetic agents chia group A/B va RBAC teacher | `deep_classroom_scale_matrix` PASS |
| Chua test that su | Multi-machine vat ly, reboot cycle that, soak dai hon 30 phut | `coverage_not_tested` trong JSON |

## Cac loi da phat hien, da sua va da verify lai

### 1. `/api-keys` bi loi DOM null

Hien tuong tren production:

```text
api_keys.js:74 Error loading keys: TypeError: Cannot read properties of null (reading 'style')
```

Nguyen nhan: `server/views/static/js/pages/api_keys.js` tim `#keysList` va `#emptyState`, nhung template hien tai chi co `#keysContainer`. Khi co data API key, code goi `emptyState.style.display` va bi crash.

Trang thai fix:

- Da sua JS render truc tiep vao `#keysContainer`.
- Da them empty state bang HTML trong container.
- Da bo access DOM bat buoc voi filter/stat elements khi element khong ton tai.
- Da tach logic status API key thanh `active`, `expiring`, `expired`, `revoked`; filter Status co ca `Expiring Soon` va `Expired`.

File lien quan:

- `server/views/static/js/pages/api_keys.js`
- `server/views/templates/api_keys.html`

### 2. `favicon.ico` 404

Hien tuong:

```text
favicon.ico:1 Failed to load resource: the server responded with a status of 404
```

Trang thai fix:

- Da them route `/favicon.ico` tra SVG icon nhe.
- Da them `<link rel="icon">` vao base template.

File lien quan:

- `server/routes/pages.py`
- `server/views/templates/base.html`

### 2b. API Keys co truong Rate Limit gia

Hien tuong tren UI:

```text
Create New API Key co input Rate Limit 1000/hour va hint "0 for unlimited".
```

Ket luan audit source 2026-06-01: API key khong co rate limit that.

- `server/requirements.txt` khong co Flask-Limiter hay thu vien rate-limit tuong duong.
- `server/middleware/auth.py::require_api_key` chi extract key, goi validate, set `g.api_key_*`; khong dem request/window va khong tra `429`.
- `server/services/api_key_service.py::create_api_key` va `server/models/api_key_model.py::create_api_key` khong co parameter `rate_limit`; field frontend gui len bi drop silently.
- `server/models/api_key_model.py::validate_api_key` chi update `last_used_at` va `$inc usage_count`; counter nay la lifetime counter, khong reset theo gio.

Trang thai fix:

- Da xoa field Rate Limit khoi modal `/api-keys`.
- Da xoa payload `rate_limit` khoi `createApiKey()`.
- Da xoa hien thi `usage_count / rate_limit`, progress bar usage gia va CSS `.usage-bar`.

File lien quan:

- `server/views/static/js/pages/api_keys.js`
- `server/views/templates/api_keys.html`

### 2c. API Keys Expiration co enforce that

Ket luan audit source 2026-06-01: API key expiration khong phai UI gia.

- UI gui `expires_in_days` tu modal Create API Key.
- `APIKeyController.create_api_key()` validate `expires_in_days`; `0`/`null` duoc convert thanh never expires, so am bi reject.
- `APIKeyModel.create_api_key()` luu `expires_at = now_vietnam() + timedelta(days=expires_in_days)` neu co thoi han.
- `APIKeyModel.validate_api_key()` check `expires_at < now_vietnam()` truoc khi check permission va truoc khi tang usage. Neu expired, tra `{"valid": False, "error": "API key has expired"}`.
- Endpoint boc `require_api_key(...)` se tra HTTP `401` voi body `{"success": false, "error": "API key has expired"}`.
- Expired key khong cap nhat `last_used_at` va khong tang `usage_count`.
- UI `/api-keys` da tach status `expired` rieng thay vi goi chung la `revoked`; filter Status co them `Expired`, stat `Active` khong tinh expired key.

Regression moi:

- `server/tests/test_api_key_expiration.py`

### 2d. API Keys Expiration dropdown bi cat trong modal

Hien tuong tren UI:

```text
Expiration dropdown trong Create New API Key chi thay "Never expires" va "7 days".
Khong scroll/keo xuong duoc de chon "30 days", "90 days", "1 year".
```

Nguyen nhan: `keyExpiry` duoc boc bang custom select (`window.initCustomSelect('keyExpiry')`). Shared custom menu dung `position: absolute`, trong khi `.modal-content` co `overflow: hidden`; menu luon mo xuong va khong co `max-height/overflow-y`, nen options phia duoi bi cat va khong scroll duoc.

Trang thai fix:

- Giu `filterStatus`, `filterPermission` va `keyExpiry` dung shared custom select de UI dong bo.
- Cap nhat `window.initCustomSelect(...)` trong `base.js` de tinh boundary khi mo menu: neu khong du cho ben duoi thi them class `drop-up` va mo len tren.
- Cap nhat `custom_select.css` de `.custom-options` co `max-height`, `overflow-y: auto`, `overscroll-behavior: contain` va z-index phu hop voi Bootstrap modal.
- `Expiration` trong modal Create API Key hien thi du style custom select va chon duoc `Never expires`, `7 days`, `30 days`, `90 days`, `1 year`.

File lien quan:

- `server/views/static/js/base.js`
- `server/views/static/css/custom_select.css`
- `server/views/static/js/pages/api_keys.js`
- `server/views/templates/api_keys.html`

### 3. Agent policy heartbeat khong force sync

Hien tuong trong full deep run:

```text
Heartbeat did not request force sync for isolate
heartbeat.data.force_sync=false
heartbeat.data.policy_mode=none
```

Nguyen nhan local: `AgentService` co tham so `policy_model` de kiem tra override policy trong heartbeat, nhung container chua inject `agent_policy_model`.

Trang thai fix:

- Da sua `initialize_container()` de tao `AgentService(..., policy_model=agent_policy_model)`.
- Da deploy len Render va duoc xac nhan trong cac run sau. Run `20260528_123508` cho thay production da tra `heartbeat.data.force_sync=true`; run `20260528_141158` bang runner da sua heartbeat envelope PASS sach.

File lien quan:

- `server/bootstrap/container.py`

### 4. Firewall remove rule khong xoa ngay rule vua tao

Hien tuong trong firewall-only run truoc patch:

```text
Deep firewall remove rule did not restore managed allow rule count
```

Nguyen nhan: `RulesManager.remove_allow_rule()` dua vao read provider list rules. Trong mot lan chay, read provider tra rong/khong thay rule vua tao, nen khong goi delete rule. Cleanup cuoi van xoa sach theo prefix, nhung test add/remove bi fail.

Trang thai fix:

- `RulesManager` luu map IP -> rule name khi tao rule, de remove duoc ngay ca khi read provider khong hydrate kip.
- Sua `NetSecurityFirewallProvider` JSON field `remote_addresses` de khong bi output `{}`.
- Them regression test.

File lien quan:

- `agent/firewall/rules.py`
- `agent/firewall/netsecurity_provider.py`
- `agent/tests/test_firewall_provider_writes.py`

### 5. E2E runner false positive bulk duplicate whitelist

Hien tuong: full deep bao "Bulk duplicate inserted more than one row" trong khi server thuc te insert 1 row va reject duplicate row thu 2.

Nguyen nhan: runner doc whitelist scoped gom nhieu mang response va dem trung cung mot `_id`.

Trang thai fix:

- Da de-duplicate ID trong `find_whitelist_ids()`.

File lien quan:

- `tools/saint_full_system_e2e.py`

### 6. Hotfix bao mat: group/log API public sau deploy Render

Hien tuong tren production truoc hotfix:

```text
/api/groups tra 200 khi chua dang nhap va co danh sach group.
/api/logs?limit=1 tra 200 khi chua dang nhap va co log.
/api/logs/stats tra 200 khi chua dang nhap va co thong ke log.
```

Nguyen nhan: cac route web-facing dang chi dung `inject_current_user(...)`, decorator nay non-blocking nen request khong token van duoc vao controller.

Trang thai fix:

- Da thay bang `require_login(...)` cho `/api/groups`, `/api/groups/<id>` GET/PATCH/DELETE va `/api/groups/<id>/teachers`.
- Route gan teacher duoc boc `require_login(require_admin(...))`.
- Da thay bang `require_login(...)` cho `/api/logs/stats`, `/api/logs` GET, `/api/logs/clear`, legacy DELETE `/api/logs`, va `/api/logs/export`.
- Agent endpoint POST `/api/logs` giu `require_jwt(...)`, khong bi doi auth flow.
- Da them regression test dam bao request chua dang nhap nhan `401 Authentication required`.

File lien quan:

- `server/controllers/group_controller.py`
- `server/controllers/log_controller.py`
- `server/tests/test_groups.py`
- `server/tests/test_whitelist_and_logs.py`

Sau khi redeploy len Render, verify production phai tra 401:

```powershell
curl.exe -i "https://firewall-controller.onrender.com/api/groups"
curl.exe -i "https://firewall-controller.onrender.com/api/logs?limit=1"
curl.exe -i "https://firewall-controller.onrender.com/api/logs/stats"
```

Production smoke 2026-05-28 10:41 +07: all three unauthenticated endpoints returned `401 application/json` with `Authentication required`.

### 7. Hotfix log secret: khong ghi plaintext Mongo URI

Hien tuong: code boot MongoDB co log `MONGO_URI` day du. Neu Render logs da ghi connection string, can rotate credential sau khi deploy ban mask log.

Trang thai fix:

- Da them `_mask_connection_uri()` de mask credential thanh `***:***`.
- `get_mongo_client()` va `validate_config()` chi log Mongo URI da mask.
- Da them regression test cho MongoDB Atlas URI co username/password.

File lien quan:

- `server/database/config.py`
- `server/tests/test_app_factory.py`

### 8. Render full deep E2E run `20260528_104509`

Lenh da chay tren Render production voi `-RunRealFirewallPolicy -WriteBackend powershell -Deep`.

Ket qua:

- Summary: `PASS=22`, `FAIL=2`, `SKIP=0`.
- Cleanup: `CLEANUP_OK=45`, cleanup failures = none.
- PASS quan trong: public server surface, bootstrap login, CSRF negative, users, API keys, group RBAC, whitelist contract, profile contract, build Agent exe, agent registration/auth, agent heartbeat/sync/logs, agent policy RBAC, classroom scale, GUI, WebSocket, 30-minute soak, logs/audit, real Windows Firewall Default Deny.
- Real firewall packet matrix PASS; firewall restored ve allow, residual rules = 0.
- FAIL:
  - `deep_whitelist_conflict_matrix`: active profile domain missing from sync.
  - `deep_policy_matrix`: policy none did not preserve group conflict merge.

Nguyen nhan da xac dinh: active whitelist profile duoc tao voi payload `{"domain": "...", "category": "deep-profile"}`. Agent sync dung group-entry normalizer chi doc `value`, nen entry profile ra sync thanh `value: null` va pseudo-id `group::<group_id>::domain::None`. Loi `deep_policy_matrix` la loi day chuyen vi step truoc fail khi profile con active, lam conflict base bi profile override.

Trang thai fix sau run:

- Da normalize whitelist profile domains ve shape `value/type` khi create/update.
- Agent sync group-entry normalizer chap nhan ca legacy key `domain`, `ip`, `url`, `port`, `process`, va bo qua entry khong co value that.
- Da them regression test `test_agent_sync_active_profile_accepts_domain_key`.

Sau do da redeploy fix profile sync len Render. Run `20260528_123508` xac nhan `deep_whitelist_conflict_matrix` PASS, va run `20260528_141158` xac nhan full deep PASS sach.

Artifacts:

- `test-results/saint-full-system-e2e/20260528_104509/full_system_e2e_20260528_104509.txt`
- `test-results/saint-full-system-e2e/20260528_104509/full_system_e2e_20260528_104509.json`
- `test-results/saint-full-system-e2e/20260528_104509/full_system_e2e_20260528_104509_raw.json`

### 9. Render full deep E2E run `20260528_123508`

Lenh da chay tren Render production voi `-RunRealFirewallPolicy -WriteBackend powershell -Deep` sau khi deploy fix profile sync.

Ket qua:

- Summary: `PASS=23`, `FAIL=1`, `SKIP=0`, exit_code = 1.
- Cleanup: `CLEANUP_OK=43`, cleanup failures = none.
- PASS moi quan trong: `deep_whitelist_conflict_matrix` da PASS, xac nhan active profile domain sync da het loi `value: null`.
- PASS khac: public server surface, login, CSRF, users, API keys, group RBAC, whitelist/profile contract, build Agent exe, agent register/JWT, agent heartbeat/sync/logs, agent policy RBAC, classroom scale, GUI, WebSocket, 30-minute soak, logs/audit, real Windows Firewall Default Deny.
- Real firewall packet matrix PASS: blocked packet bi chan khi Default Deny active, firewall restored ve allow, residual rules = 0.
- FAIL duy nhat: `deep_policy_matrix` bao `Heartbeat did not request force sync for isolate`.

Phan tich JSON cho thay day la E2E runner false negative, khong phai server fail:

```json
{
  "success": true,
  "data": {
    "force_sync": true,
    "policy_mode": "isolate"
  }
}
```

Runner cu check `heartbeat.get("force_sync")` o root response, trong khi API tra envelope va field nam trong `heartbeat.data`. Trang thai fix:

- Da sua `tools/saint_full_system_e2e.py` de unwrap `heartbeat.get("data", heartbeat)` truoc khi assert.
- `.venv\Scripts\python.exe -m py_compile tools\saint_full_system_e2e.py` pass.

Ket luan: production da thuc su tra heartbeat force sync cho isolate. Sau khi runner duoc sua, run `20260528_141158` da tao artifact PASS sach.

Artifacts:

- `test-results/saint-full-system-e2e/20260528_123508/full_system_e2e_20260528_123508.txt`
- `test-results/saint-full-system-e2e/20260528_123508/full_system_e2e_20260528_123508.json`
- `test-results/saint-full-system-e2e/20260528_123508/full_system_e2e_20260528_123508_raw.json`

### 10. Render full deep E2E PASS sach `20260528_141158`

Lenh da chay tren Render production voi `-RunRealFirewallPolicy -WriteBackend powershell -Deep` bang runner da sua heartbeat envelope.

Ket qua chot:

- Summary: `PASS=24`, `FAIL=0`, `SKIP=0`, exit_code = 0.
- Cleanup: `CLEANUP_OK=43`, cleanup failures = none.
- Tat ca required steps PASS, gom: public server surface, bootstrap login, CSRF negative, temporary users/auth, user management, API key, group RBAC, whitelist/profile contracts, build Agent exe, agent registration/auth, heartbeat/sync/logs, agent policy RBAC, deep whitelist conflict, deep policy matrix, classroom scale, service/autostart readiness, GUI click matrix, WebSocket realtime, 30-minute soak, logs/audit, real Windows Firewall Default Deny.
- Tat ca deep matrices PASS: whitelist, policy, classroom, service/autostart, GUI, WebSocket, soak, firewall packet.
- Deep policy matrix xac nhan isolate heartbeat: `force_sync=true`, `policy_mode=isolate`; custom policy sync va reset policy sync cung PASS.
- Firewall packet matrix PASS: Default Deny active chan blocked packet, allowed packet van OK, add/remove managed rule OK.
- Firewall cleanup PASS: restored ve domain/private/public = `allow`, residual managed rules = 0, post-restore blocked test target ket noi lai OK.

Artifacts:

- `test-results/saint-full-system-e2e/20260528_141158/full_system_e2e_20260528_141158.txt`
- `test-results/saint-full-system-e2e/20260528_141158/full_system_e2e_20260528_141158.json`
- `test-results/saint-full-system-e2e/20260528_141158/full_system_e2e_20260528_141158_raw.json`

## Ket qua firewall-only deep run lich su

Run: `20260527_235108`

| Chi so | Ket qua |
| --- | --- |
| Steps | PASS=8, FAIL=0, SKIP=0 |
| Cleanup | CLEANUP_OK=5, cleanup_failures=0 |
| `deep_firewall_packet_matrix.passed` | true |
| Snapshot before mutation | domain/private/public = allow |
| Active Default Deny | domain/private/public = block |
| Allowed packet active | `1.1.1.1:443` OK |
| Blocked packet active | `151.101.1.69:443` blocked |
| Managed rule mutation | count `10 -> 11 -> 10` |
| Restore policy | domain/private/public = allow |
| Residual rules | 0 |
| Blocked packet after restore | `151.101.1.69:443` OK |

Ket luan: PowerShell/NetSecurity write backend da pass packet-level smoke tren mot may Windows Administrator thuc, bao gom Default Deny, self-allow, add/remove managed allow rule va restore.

## Kiem tra local da chay sau cac ban sua

| Lenh | Ket qua |
| --- | --- |
| `node --check server\views\static\js\pages\api_keys.js` | Pass |
| `.venv\Scripts\python.exe -m py_compile server\routes\pages.py` | Pass |
| `.venv\Scripts\python.exe -m py_compile server\controllers\group_controller.py server\controllers\log_controller.py` | Pass |
| `.venv\Scripts\python.exe -m py_compile server\database\config.py server\tests\test_app_factory.py` | Pass |
| `.venv\Scripts\python.exe -m py_compile tools\saint_full_system_e2e.py` | Pass |
| `.venv\Scripts\python.exe -m pytest server\tests\test_api_key_expiration.py -q --tb=short` | 4 passed |
| `node --check server\views\static\js\pages\api_keys.js` sau khi xoa Rate Limit UI gia | Pass |
| `rg -n "rate.?limit\|rate_limit\|keyRateLimit\|usage-bar\|/hour\|0 for unlimited" server\views\static\js\pages\api_keys.js server\views\templates\api_keys.html server\controllers\api_key_controller.py server\services\api_key_service.py server\models\api_key_model.py server\middleware\auth.py server\tests` | Khong con ket qua trong API key UI/backend/test lien quan |
| `node --check server\views\static\js\base.js` va `node --check server\views\static\js\pages\api_keys.js` sau khi sua shared custom select va bat lai `keyExpiry` | Pass |
| `rg -n "keyRateLimit\|usage-bar\|0 for unlimited\|/hour" server\views\static\js\pages\api_keys.js server\views\templates\api_keys.html` | Khong con ket qua |
| `rg -n "initCustomSelect\\('keyExpiry'\\)|drop-up|overflow-y: auto|overscroll-behavior" server\views\static\js\base.js server\views\static\css\custom_select.css server\views\static\js\pages\api_keys.js` | Co ket qua dung ky vong |
| Playwright smoke HTML toi gian voi `.modal-content { overflow:hidden }`, click `#keyExpiry` | Pass: dropdown `open=true`, `dropUp=true`, `optionCount=5`, `overflowY=auto`, menu nam trong modal boundary |
| `.venv\Scripts\python.exe -m pytest server\tests\test_app_factory.py -q --tb=short` | 4 passed |
| `.venv\Scripts\python.exe -m pytest server\tests\test_groups.py -q --tb=short` | 73 passed |
| `.venv\Scripts\python.exe -m pytest server\tests\test_whitelist_and_logs.py -q --tb=short` | 119 passed, 3 expected DeprecationWarning |
| `.venv\Scripts\python.exe -m pytest agent\tests -q --tb=short` | 8 passed |
| `.venv\Scripts\python.exe -m pytest server\tests\test_teacher_data_filtering.py -q --tb=short` | 81 passed |
| `.venv\Scripts\python.exe -m pytest server\tests\test_app_factory.py server\tests\test_agent_full.py server\tests\test_whitelist_and_logs.py -q --tb=short` | 184 passed, 3 expected DeprecationWarning |

## Ton dong con lai

### Da verify hotfix bao mat tren Render

Public smoke sau deploy Render 2026-05-28 da thay `/api-keys` DOM fix va `/favicon.ico` len production. Sau hotfix auth, public smoke luc 10:41 +07 xac nhan:

- `/api/groups` tra `401`.
- `/api/logs?limit=1` tra `401`.
- `/api/logs/stats` tra `401`.

Full deep E2E sach da PASS trong run `20260528_141158`. Tiep theo chi can kiem tra Render logs de xac nhan khong con plaintext Mongo URI/secret sau ban mask log va xu ly secret rotation neu can.

### Cach chay lai full deep khi can regression lai

Chi chay khi co admin password that cua Render. Khong thu credential mac dinh.

Lenh khuyen nghi trong PowerShell Administrator:

```powershell
$AdminPassword = Read-Host "Render admin password"
powershell -ExecutionPolicy Bypass -File .\tools\saint-full-system-e2e.ps1 -ServerUrl "https://firewall-controller.onrender.com" -BootstrapAdminUsername "admin" -BootstrapAdminPassword $AdminPassword -RunRealFirewallPolicy -WriteBackend powershell -Deep -TimeoutSeconds 60 -DeepPacketTimeoutSeconds 35
Remove-Variable AdminPassword -ErrorAction SilentlyContinue
```

Neu chi can packet firewall nhanh:

```powershell
$AdminPassword = Read-Host "Render admin password"
powershell -ExecutionPolicy Bypass -File .\tools\saint-full-system-e2e.ps1 -ServerUrl "https://firewall-controller.onrender.com" -BootstrapAdminUsername "admin" -BootstrapAdminPassword $AdminPassword -RunRealFirewallPolicy -WriteBackend powershell -Deep -FirewallOnly -SkipBuild -SkipAgentExeLaunch -TimeoutSeconds 60 -DeepPacketTimeoutSeconds 35
Remove-Variable AdminPassword -ErrorAction SilentlyContinue
```

Luu y: `-RunRealFirewallPolicy` co thay doi Windows Firewall that trong luc test va runner se cleanup/restore. Chi chay tren may canary co quyen Administrator va co duong khoi phuc mang.

### Kiem tra Render logs va secret rotation

Sau khi redeploy:

1. Mo Render Dashboard -> service `firewall-controller` -> `Logs`.
2. Trigger 3 lenh verify 401 o tren, roi tim trong Logs:
   - `path:/api/groups status_code:401`
   - `path:/api/logs status_code:401`
   - `path:/api/logs/stats status_code:401`
3. Tim cac chuoi nghi secret: `MONGO_URI`, `mongodb+srv://`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `SECRET_KEY`, `API_KEY_HMAC_SECRET`. Khong copy secret vao chat/report.
4. Neu thay plaintext secret trong log cu: rotate sau khi da deploy ban mask log.

Secret can uu tien rotate:

- MongoDB credential trong `MONGO_URI`: tao password/user moi ben MongoDB Atlas, cap nhat Render Environment, deploy lai, sau do disable/delete credential cu.
- `SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `API_KEY_HMAC_SECRET`: tao random secret moi, update trong Render Environment, chon deploy. Viec nay co the lam user/agent token hien tai het hieu luc, nen can dang nhap lai va cho agent refresh/re-register neu can.
- Admin password production: doi trong UI/admin flow neu credential tung bi log/chia se.

Tai lieu Render tham khao:

- Logs: https://render.com/docs/logging
- Environment variables/secrets: https://render.com/docs/configure-environment-variables
- Secret handling: https://render.com/articles/how-render-handles-secrets-and-environment-variables

### Chua test hoan toan trong 1 may nay

- Multi-machine vat ly: da test 24 synthetic agents, chua test 24 may Windows that trong cung lab.
- Reboot/service autostart: runner da tao script post-reboot check, chua tu reboot may.
- Soak dai hon 30 phut: da pass 30 phut, chua soak nhieu gio/ngay.
- Canary PowerShell backend tren nhieu may: moi pass mot may Windows Administrator.

### Van chua nen cat fallback whitelist ngay

Chua nen xoa fallback embedded whitelist/pseudo-ID tren production neu chua co:

- Backup DB production.
- Migration write da chay va verify.
- Log/metric xac nhan khong con request dung pseudo-ID `group::...`.
- It nhat mot release quan sat dual-path sau migration.

## Danh gia release readiness

| Hang muc | Trang thai |
| --- | --- |
| Server API/RBAC co ban | Tot, da duoc E2E va unit/integration test rong |
| GUI admin API Keys | Public smoke sau deploy OK, tiep tuc monitor |
| Agent/server contract | Register/JWT/heartbeat/sync/log pass; full deep run `20260528_141158` xac nhan isolate `force_sync=true`, custom policy va reset policy pass |
| Firewall Default Deny PowerShell backend | Pass tren 1 may Windows admin, can canary them |
| Cleanup/rollback firewall | Pass: restore allow, residual rules 0 |
| Whitelist final cutover | Chua san sang xoa fallback production |

Ket luan ngan: he thong da co full deep E2E PASS sach tren Render production trong run `20260528_141158`, public auth leak da duoc verify 401, profile sync pass, isolate heartbeat `force_sync=true`, firewall Default Deny pass va rollback sach. Truoc khi coi la release production final van can kiem tra/rotate secret neu log tung lo, canary firewall PowerShell tren them may lab va chua xoa whitelist fallback cho toi khi co bang chung production khong con pseudo-ID.
