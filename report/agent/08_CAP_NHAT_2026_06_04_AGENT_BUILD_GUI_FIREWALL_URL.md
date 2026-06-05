# Cap nhat 2026-06-04 - Agent build, GUI, firewall safety va URL handling

## Tom tat

Phien nay tap trung vao 8 nhom thay doi cua SAINT Agent:

1. Sua PyInstaller spec de build Agent thanh mot file `dist/SAINT.exe`.
2. Redesign GUI PySide6 theo style SaaS sang, it icon/emoji, card trang va sidebar sach.
3. Sua loi package/import `No module named 'agent'` trong ban EXE bang `pathex` + hidden imports.
4. Chan firewall apply rule khi Agent chua sync whitelist thanh cong, tranh truong hop sai URL/chua API key ma van tao allow rules.
5. Chuan hoa DNS va Server URL: chi dung System DNS, khong tu them public DNS fallback; Server URL tu dong strip route UI da biet nhung giu deployment subpath.
6. Chuyen config encrypted sang AppData de tranh loi Permission denied khi chay EXE.
7. Cai thien registration timeout/logging de Render/server cham khong lam agent roi vao degraded qua som.
8. Sua duplicate log GUI va sync interval key cua WhitelistManager.

Trang thai hien tai:

- Source da cap nhat.
- Test agent hien tai da pass: `31 passed`.
- Full server test hien tai da pass: `541 passed`, `25 warnings` cu.
- Ban EXE can build lai sau khi dong cac process `SAINT` dang chay; lan build sau cung bi Windows khoa file `dist/SAINT.exe`.

## 1. PyInstaller onefile EXE

Da chuyen spec chinh `agent/saint_agent.spec` tu output kieu onedir sang onefile.

Thay doi chinh:

- Them repo root vao path build de EXE import duoc ca namespace `agent.*` va top-level package.
- Mo rong hidden imports cho `firewall.*`, `agent.firewall.*`, `network.*`, `agent.network.*`, `config.*`, `agent.config.*`.
- `EXE(...)` nhan truc tiep binaries/zipfiles/datas va `exclude_binaries=False`.
- Giu `console=False`, `uac_admin=True`, icon `miku.ico`.
- Output ky vong: `dist/SAINT.exe`.

Reference:

| Noi dung | Reference |
| --- | --- |
| `REPO_ROOT = AGENT_ROOT.parent` | `agent/saint_agent.spec:14` |
| Hidden import top-level firewall provider | `agent/saint_agent.spec:52` |
| Hidden import namespace `agent.firewall.*` | `agent/saint_agent.spec:137` |
| `pathex=[str(REPO_ROOT), str(AGENT_ROOT)]` | `agent/saint_agent.spec:262` |
| Onefile `EXE(...)` block | `agent/saint_agent.spec:276` |
| `exclude_binaries=False` | `agent/saint_agent.spec:283` |
| `uac_admin=True` | `agent/saint_agent.spec:296` |

Ghi chu build:

- Da tung build thanh cong onefile sau khi sua spec/GUI, tao artifact `dist/SAINT.exe`.
- Sau cac fix firewall/DNS/URL cuoi phien, build lai bi chan vi Windows dang khoa file EXE: co 2 process `SAINT` dang chay (`17200`, `21572` tai thoi diem kiem tra).
- Can dong app hoac chay `Stop-Process -Name SAINT -Force` roi build lai.

## 2. Redesign GUI theo phong cach SaaS

Da doi presentation layer cua `agent/gui_qt` theo huong SaaS sang:

- Nen app `#F6F8FB`, card trang, border `#E2E8F0`, accent xanh SAINT `#0B78D0`.
- Sidebar text-only: `Dashboard`, `Firewall Rules`, `IP Whitelist`, `Logs`, `Settings`.
- Active state dung nen xanh nhat + left accent thay vi nut xanh dac.
- Bo emoji/icon loe loet khoi views/components.
- `StatusCard` doi sang title + status dot + value/subtitle; `set_icon()` giu de tuong thich nhung khong render emoji.
- `LogConsole`, `DataTable`, form Settings va buttons duoc lam sach theo style card/table SaaS.

Reference:

| Noi dung | Reference |
| --- | --- |
| Palette nen, card, accent | `agent/gui_qt/styles.py:8`, `agent/gui_qt/styles.py:19` |
| Sidebar active state | `agent/gui_qt/styles.py:104` |
| Primary button style | `agent/gui_qt/styles.py:108` |
| Form input style | `agent/gui_qt/styles.py:132` |
| Table style | `agent/gui_qt/styles.py:185` |
| Sidebar labels text-only | `agent/gui_qt/main_window.py:25` |
| Dashboard action buttons | `agent/gui_qt/views/dashboard.py:241`, `agent/gui_qt/views/dashboard.py:248` |
| Firewall Rules table view | `agent/gui_qt/views/firewall.py:68`, `agent/gui_qt/views/firewall.py:124` |
| IP Whitelist controls/table | `agent/gui_qt/views/whitelist.py:100`, `agent/gui_qt/views/whitelist.py:107`, `agent/gui_qt/views/whitelist.py:154` |
| Logs view buttons/console | `agent/gui_qt/views/logs.py:57`, `agent/gui_qt/views/logs.py:99`, `agent/gui_qt/views/logs.py:104` |
| Settings Save/Restore buttons | `agent/gui_qt/views/settings.py:237`, `agent/gui_qt/views/settings.py:262` |
| `StatusCard` compatibility/no emoji render | `agent/gui_qt/components/status_card.py:13`, `agent/gui_qt/components/status_card.py:81` |
| `LogConsole` Pause/Resume text | `agent/gui_qt/components/log_console.py:44`, `agent/gui_qt/components/log_console.py:116` |
| Shared `DataTable` | `agent/gui_qt/components/data_table.py:127` |

## 3. Firewall safety: khong apply rule khi whitelist sync fail

Loi nguoi dung thay:

- Moi chay Agent voi `localhost:5000` sai/chua API key nhung Firewall tab da hien cac rule allow:
  - local IP
  - gateway
  - localhost
  - system DNS

Nguyen nhan:

- Lifecycle cu sync whitelist fail nhung van di tiep sang `_init_firewall()`.
- `_init_firewall()` goi `enable_whitelist_mode()`.
- `enable_whitelist_mode()` tao essential allow rules truoc khi bat Default Deny.

Fix:

- Them helper lay status moi nhat cua lifecycle component.
- Firewall chi duoc enable khi component `whitelist_sync` co status `ok`.
- Neu URL sai, server unreachable, thieu/chua hop le API key/JWT thi firewall component duoc record `skipped`, Agent chay degraded/offline va khong ghi allow rules moi.

Reference:

| Noi dung | Reference |
| --- | --- |
| Helper `_latest_component_status(...)` | `agent/core/lifecycle.py:77` |
| Sync fail log moi: firewall stay disabled | `agent/core/lifecycle.py:467` |
| Gate firewall theo `whitelist_sync` | `agent/core/lifecycle.py:492` |
| Log skip firewall enforcement | `agent/core/lifecycle.py:496` |
| Detail `waiting for successful whitelist sync` | `agent/core/lifecycle.py:503` |
| Test guard khong instantiate firewall khi sync fail | `agent/tests/test_lifecycle_components.py:121` |

## 4. System DNS only, khong public DNS fallback

Nguoi dung hoi vi sao co `8.8.8.8` va `8.8.4.4`.

Ket qua kiem tra may hien tai:

- Windows `Wi-Fi` dang set System DNS la `{8.8.8.8, 8.8.4.4}`.
- Neu Windows dung DNS nay thi SAINT van co the allow chung vi do la System DNS that.

Fix trong code:

- Bo fallback cu tu them public DNS khi detect DNS fail.
- Neu khong doc duoc DNS he thong thi log warning va khong them `8.8.8.8`, `8.8.4.4`, `1.1.1.1`.
- Test moi xac nhan khong co public DNS fallback.

Reference:

| Noi dung | Reference |
| --- | --- |
| Detect IPv4 System DNS | `agent/firewall/utils.py:47` |
| No public DNS fallback warning | `agent/firewall/utils.py:50` |
| Test khong add public fallback khi DNS detect loi | `agent/tests/test_firewall_utils.py:12` |
| Test chi dung DNS detect tu he thong | `agent/tests/test_firewall_utils.py:30` |

## 5. Server URL normalization

Rui ro cu:

- Neu user paste `https://firewall-controller.onrender.com/api-keys?` vao o `Server URL`, runtime co the ghep endpoint thanh URL sai:
  - `/api-keys?/api/agents/register`
  - `/api-keys?/api/whitelist/agent-sync`

Design cuoi cung:

- Khong hard-code domain Render.
- `Server URL` la API base URL.
- Strip cac UI route da biet: `api-keys`, `login`, `dashboard`, `settings`.
- Giu deployment subpath la neu server duoc mount duoi path rieng.

Vi du:

| Input | Normalized |
| --- | --- |
| `https://firewall-controller.onrender.com/api-keys?` | `https://firewall-controller.onrender.com` |
| `http://localhost:5000/api-keys?` | `http://localhost:5000` |
| `https://school.example.edu/saint` | `https://school.example.edu/saint` |
| `https://school.example.edu/saint/api-keys?` | `https://school.example.edu/saint` |
| `https://school.example.edu/custom-controller` | `https://school.example.edu/custom-controller` |

Reference:

| Noi dung | Reference |
| --- | --- |
| Known UI route segments | `agent/shared/server_urls.py:20` |
| `normalize_server_url(...)` | `agent/shared/server_urls.py:23` |
| Strip UI route neu gap segment da biet | `agent/shared/server_urls.py:43` |
| `collect_server_urls(...)` goi normalize | `agent/shared/server_urls.py:82` |
| Config loader normalize config da luu | `agent/config/loader.py:74`, `agent/config/loader.py:80` |
| Settings Save normalize va update input | `agent/gui_qt/views/settings.py:298`, `agent/gui_qt/views/settings.py:300` |
| Settings success message khi URL duoc normalize | `agent/gui_qt/views/settings.py:347` |
| Tests cho URL normalize | `agent/tests/test_server_urls.py:12`, `agent/tests/test_server_urls.py:28`, `agent/tests/test_server_urls.py:35`, `agent/tests/test_server_urls.py:42` |

## 6. Log text cleanup

Da bo cac emoji/mojibake con sot trong log runtime:

- `WhitelistManager.sync_now()` log `Received ... entries from server`.
- `WhitelistManager` log `Updating firewall rules...`.
- WinPcap warning trong lifecycle bo emoji.

Reference:

| Noi dung | Reference |
| --- | --- |
| Whitelist received entries log | `agent/whitelist/manager.py:215` |
| Whitelist update firewall log | `agent/whitelist/manager.py:234` |
| WinPcap warning text | `agent/core/lifecycle.py:528` |

## 7. Verification da chay

Commands da chay:

```powershell
.\.venv\Scripts\python.exe -m pytest agent\tests\test_config_paths.py agent\tests\test_server_urls.py agent\tests\test_firewall_utils.py agent\tests\test_lifecycle_components.py agent\tests\test_firewall_provider_writes.py
```

Ket qua:

```text
20 passed
```

Compile smoke:

```powershell
.\.venv\Scripts\python.exe -m compileall -q agent\shared agent\config agent\gui_qt\views agent\tests
```

Ket qua: pass, khong co output loi.

Kiem tra build:

```powershell
.\.venv\Scripts\pyinstaller.exe .\agent\saint_agent.spec --clean --noconfirm
```

Ket qua cuoi phien:

- Build bi chan o buoc ghi de `dist\SAINT.exe`.
- Loi: `PermissionError: [WinError 5] Access is denied: ...\dist\SAINT.exe`.
- Nguyen nhan thuc te: con process `SAINT` dang chay, Windows khoa file EXE.

Lenh build lai sau khi dong app:

```powershell
Stop-Process -Name SAINT -Force
.\.venv\Scripts\pyinstaller.exe .\agent\saint_agent.spec --clean --noconfirm
```

## 8. Ghi chu van hanh sau phien sua

- Neu da co rule cu `FirewallController_*` trong Windows Firewall, can dung Settings -> Restore Firewall hoac PowerShell Admin de xoa rule cu.
- Source hien tai khong con tu apply firewall khi whitelist sync fail.
- Source hien tai khong tu them public DNS fallback.
- Source hien tai chap nhan Server URL o cac domain khac nhau va deployment subpath khac nhau.
- Ban `dist\SAINT.exe` can rebuild lai de chua cac fix firewall/DNS/URL cuoi phien.

## 9. Fix config permission denied - cap nhat them trong phien

Log nguoi dung gap:

```text
Failed to decrypt config: [Errno 13] Permission denied: 'agent_config.json.enc'
Failed to encrypt config: [Errno 13] Permission denied: 'agent_config.json.enc'
Config error: Server URL is required (either 'url' or 'urls')
```

Nguyen nhan:

- Settings GUI dang tu tim config bang relative path `agent_config.json`.
- Khi chay EXE, file encrypted cu nam canh executable trong `dist\agent_config.json.enc`.
- File nay da bi ACL siết qua chat/khac token, PowerShell thuong cung khong doc duoc ACL (`icacls`/`Get-Acl` bi Access denied).
- Vi Settings khong save duoc config, Agent runtime load default rong -> `Server URL is required` -> registration, whitelist sync, log sender, heartbeat deu degraded/skipped.

Fix:

- Them `config.paths` lam single source of truth cho config path.
- Config moi se ghi vao `%LOCALAPPDATA%\SAINT\agent_config.json.enc`, khong ghi canh EXE/current working directory.
- Loader runtime va Settings GUI cung dung chung write path/read path.
- Legacy paths van duoc read fallback de khong mat config cu neu file cu con doc duoc.
- ACL hardening dung `whoami` day du va grant lai current user, SYSTEM, Administrators bang SID.

Reference:

| Noi dung | Reference |
| --- | --- |
| Config path helper | `agent/config/paths.py:28`, `agent/config/paths.py:36` |
| Loader dung read path chung | `agent/config/loader.py:9`, `agent/config/loader.py:129` |
| Settings dung write path chung | `agent/gui_qt/views/settings.py:51`, `agent/gui_qt/views/settings.py:53` |
| ACL current user resolver | `agent/config/crypto.py:28` |
| ACL grant current user/SYSTEM/Admins | `agent/config/crypto.py:72` |
| Config path tests | `agent/tests/test_config_paths.py:11`, `agent/tests/test_config_paths.py:20`, `agent/tests/test_config_paths.py:28` |

Van hanh:

- Ban EXE cu van co the tiep tuc doc/ghi `dist\agent_config.json.enc`; can rebuild EXE de nhan fix.
- File `dist\agent_config.json.enc` cu dang bi Access denied nen nen bo qua/xoa bang Admin PowerShell sau khi dong SAINT, roi nhap lai Server URL + API key trong ban EXE moi.

## 10. Code audit sau loi "co URL/API key roi van degraded"

Log moi cho thay config da load duoc tu:

```text
C:\Users\sonbx\AppData\Local\SAINT\agent_config.json.enc
```

Config co Server URL va API key, nhung registration bi timeout o endpoint:

```text
https://firewall-controller.onrender.com/api/agents/register
```

Nguyen nhan trong code:

- `server.read_timeout` mac dinh la `45`, nhung `register_agent` chi dung mot timeout duy nhat `connect_timeout=15`.
- Neu server Render/Mongo cham luc register, request co the timeout sau 15s, nen khong nhan duoc `agent_id`, `agent_token`, JWT.
- Cac component sau do dung dung: whitelist sync bao thieu auth, firewall bi skip theo guard moi, log sender/heartbeat thieu `agent_id`.

Fix:

- Registration dung timeout tuple `(connect_timeout, read_timeout)`.
- Mac dinh moi cua registration la connect `15s`, read `45s`, dung voi default config.
- Log register hien ro URL, connect/read timeout, HTTP status/body excerpt, va phan biet `ConnectTimeout` voi `ReadTimeout`.
- Khong con truy cap `config['server']` truc tiep de tranh KeyError neu caller dua config thieu section server.

Reference:

| Noi dung | Reference |
| --- | --- |
| Default registration timeout | `agent/core/registry.py:26` |
| Helper `_registration_timeout(...)` | `agent/core/registry.py:49` |
| Registration log connect/read timeout | `agent/core/registry.py:124` |
| `requests.post(... timeout=timeout)` | `agent/core/registry.py:146` |
| HTTP/body excerpt khi register fail | `agent/core/registry.py:185` |
| Read timeout log rieng | `agent/core/registry.py:203` |
| Tests timeout/register credentials | `agent/tests/test_registry.py:21`, `agent/tests/test_registry.py:33` |

## 11. Fix duplicate log trong GUI Logs

Nguyen nhan duplicate log:

- `LogsView` gan cung mot `GUILogHandler` vao root logger va cac logger con.
- Python logging mac dinh propagate record tu logger con len root.
- Vi vay mot record tu `core.lifecycle`, `firewall`, `whitelist`, ... co the render 2 lan trong GUI.

Fix:

- Chi gan GUI handler vao root logger.
- Logger con chi set level va `propagate=True`.
- Them test offscreen de dam bao log tu `core.lifecycle` chi vao console 1 lan.

Reference:

| Noi dung | Reference |
| --- | --- |
| Handler chi add vao root | `agent/gui_qt/views/logs.py:118` |
| Logger con propagate len root, khong add handler lan hai | `agent/gui_qt/views/logs.py:127` |
| Test khong duplicate propagated records | `agent/tests/test_gui_logs.py:25` |

## 12. Fix Whitelist sync interval key

Nguyen nhan:

- Defaults, validator va Settings GUI dung key `whitelist.update_interval`.
- `WhitelistManager` lai doc `whitelist.sync_interval`.
- Neu user doi Sync Interval trong Settings, periodic sync co the van dung mac dinh `60s`.

Fix:

- `WhitelistManager` uu tien `update_interval`.
- Giu `sync_interval` lam legacy fallback.

Reference:

| Noi dung | Reference |
| --- | --- |
| `WhitelistManager` doc `update_interval` truoc | `agent/whitelist/manager.py:51` |
| Test `update_interval` | `agent/tests/test_whitelist_manager.py:11` |
| Test legacy `sync_interval` fallback | `agent/tests/test_whitelist_manager.py:20` |

## 13. Verification sau code audit

Commands da chay them:

```powershell
.\.venv\Scripts\python.exe -m compileall -q agent server tools
.\.venv\Scripts\python.exe -m pytest agent\tests -q --tb=short
```

Ket qua:

```text
31 passed
```

Server tests da chay tach theo nhom/file de tranh timeout tong:

```text
127 passed
118 passed
5 passed
78 passed
88 passed
119 passed, 3 warnings
```

Tong server tests da verify sau phien moi: `541 passed`.

Qt smoke test:

```text
DashboardView ok
FirewallView ok
WhitelistView ok
LogsView ok
SettingsView ok
qt smoke ok
```

## 14. Fix Whitelist URL normalization va DNS pattern handling

Bug nguoi dung report:

- URL OAuth co query string `?scope=...` bi agent coi la pattern vi `state.py` xem moi gia tri co `?` la wildcard.
- URL khong query nhu `https://login.microsoftonline.com` duoc luu nguyen vao `_domains`, nen hostname that `login.microsoftonline.com` khong match.
- Pattern URL nhu `https://login.microsoftonline.com/oauth?...` bi dua vao DNS resolver va fail `getaddrinfo`.

Quyet dinh:

- Whitelist URL duoc hieu theo host-only.
- `https://login.microsoftonline.com/oauth2/v2.0/authorize?scope=openid` canonical thanh `login.microsoftonline.com`.
- Wildcard chi hop le tren hostname voi `*`, vi du `*.microsoftonline.com`.
- Dau `?` khong con duoc dung lam wildcard.

Fix agent:

- Them helper canonicalize whitelist value trong `agent/shared/whitelist_values.py`.
- `WhitelistState` normalize `domain`, `url`, `pattern` truoc khi bucket.
- `is_domain_allowed()` normalize input truoc khi match.
- `WhitelistManager` va startup lifecycle chi resolve exact domains; patterns khong dua vao DNS resolver.
- `FirewallManager._resolve_domains_to_ips()` cung skip wildcard/pattern va strip URL/path/query neu caller dua du lieu cu.

Fix server:

- Them server helper canonicalize whitelist entry truoc khi validate/store/sync.
- Entry API van chap nhan `type=url`, nhung URL full se luu/sync thanh `type=domain`, `value=<hostname>`.
- Wildcard URL nhu `https://*.example.com/path?x=1` luu/sync thanh `type=pattern`, `value=*.example.com`.
- Duplicate check dung canonical value, nen `https://dup-login.example.com/oauth?x=1` va `dup-login.example.com` bi coi la trung.

Reference:

| Noi dung | Reference |
| --- | --- |
| Agent whitelist canonicalizer | `agent/shared/whitelist_values.py:12`, `agent/shared/whitelist_values.py:42` |
| State parser dung canonical type/value | `agent/whitelist/state.py:46` |
| `?` khong con tu thanh pattern | `agent/whitelist/state.py:52` |
| Domain check normalize input | `agent/whitelist/state.py:143` |
| WhitelistManager chi resolve exact domains | `agent/whitelist/manager.py:304`, `agent/whitelist/manager.py:330` |
| Lifecycle khong union patterns vao startup DNS | `agent/core/lifecycle.py:572` |
| Firewall DNS cleanup skip wildcard | `agent/firewall/manager.py:474` |
| Server canonicalizer | `server/services/whitelist_normalization.py:19`, `server/services/whitelist_normalization.py:47` |
| Server add/update/bulk canonicalize | `server/services/whitelist_service.py:239`, `server/services/whitelist_service.py:1095`, `server/services/whitelist_service.py:1256` |
| Pattern validation | `server/models/whitelist_model.py:387` |
| Agent URL normalization tests | `agent/tests/test_whitelist_url_normalization.py:13`, `agent/tests/test_whitelist_url_normalization.py:72` |
| Server URL canonicalization tests | `server/tests/test_whitelist_and_logs.py:380`, `server/tests/test_whitelist_and_logs.py:599` |

Verification moi:

```powershell
.\.venv\Scripts\python.exe -m pytest agent\tests -q --tb=short
.\.venv\Scripts\python.exe -m pytest server\tests -q --tb=short
.\.venv\Scripts\python.exe -m compileall -q agent server tools
```

Ket qua:

```text
31 passed
541 passed, 25 warnings
compileall pass
```

## 15. Audit cleanup: offline config, Npcap preflight, server policy DNS, onefile tooling

Nguoi dung yeu cau audit codebase va implement cleanup/fix sau audit.

Fix chinh:

- Config first-run offline khong con bi validate thanh error `Server URL is required`.
- `capture.sniffer` khong con check `wpcap.dll` ngay luc import module; lifecycle preflight truoc khi tao packet sniffer.
- Neu thieu Npcap/WinPcap, packet sniffer duoc mark `SKIPPED`, firewall/whitelist flow van tiep tuc.
- Server policy isolate/custom khong con inject public DNS `8.8.8.8`, `8.8.4.4`, `1.1.1.1`; agent tu them system DNS cua may khi apply firewall.
- Local IP detector khong con connect toi `8.8.8.8` de do interface; uu tien default IPv4 gateway/interface.
- Firewall snapshot mac dinh chuyen sang `%LOCALAPPDATA%\SAINT\profiles\backup.saint-snapshot.json`; restore van fallback duoc snapshot cu o install/exe dir.
- Smoke/full E2E tools dung onefile path `dist/SAINT.exe`.
- Xoa root spec cu `FirewallAgent.spec` de tranh build nham onedir/customtkinter.
- Don ignored artifacts: `build`, `test-results`, `playwright-report`, pytest cache, `__pycache__`. Khong xoa `dist/SAINT.exe`, `.venv`, `node_modules`, `server/.env`.

Reference:

| Noi dung | Reference |
| --- | --- |
| Offline Server URL la warning | `agent/config/validator.py:37`, `agent/utils/validators.py:54` |
| Packet sniffer import khong check pcap | `agent/capture/sniffer.py:6` |
| Lifecycle skip packet sniffer khi thieu driver | `agent/core/lifecycle.py:687` |
| Local IP dung default interface | `agent/utils/ip_detector.py:44` |
| Firewall snapshot AppData + legacy fallback | `agent/firewall/manager.py:44`, `agent/firewall/manager.py:58`, `agent/gui_qt/views/settings.py:223` |
| Server policy chi them server host | `server/services/agent_policy_service.py:121` |
| Server policy tests no public DNS | `server/tests/test_agent_full.py:539`, `server/tests/test_agent_full.py:557` |
| Smoke tool onefile path | `tools/agent_admin_smoke.py:41` |
| Full E2E onefile path va no public DNS check | `tools/saint_full_system_e2e.py:44`, `tools/saint_full_system_e2e.py:1719` |
| PowerShell E2E default allowed IP khong dung DNS public | `tools/saint-full-system-e2e.ps1:23` |
| Agent tests cho offline config/snapshot path/Npcap skip | `agent/tests/test_config_paths.py:36`, `agent/tests/test_config_paths.py:60`, `agent/tests/test_lifecycle_components.py:144` |

Verification target:

```powershell
.\.venv\Scripts\python.exe -m compileall -q agent server tools
.\.venv\Scripts\python.exe -m pytest agent\tests -q --tb=short
.\.venv\Scripts\python.exe -m pytest server\tests -q --tb=short
.\.venv\Scripts\python.exe -m PyInstaller agent\saint_agent.spec --clean --noconfirm
git diff --check
```

Verification da chay:

```text
targeted config/snapshot/lifecycle/policy tests: 22 passed
full regression: 576 passed, 25 warnings
compileall: pass
git diff --check: pass (chi LF/CRLF warning tren Windows)
pyinstaller onefile: pass, tao dist\SAINT.exe
```

Build note:

- PyInstaller van in warning Scapy/WinPcap trong luc collect dependency neu pcap service khong chay/quyen khong du; runtime da co lifecycle preflight de skip packet sniffer ro rang khi thieu Npcap/WinPcap.
- `dist\profiles\backup.saint-snapshot.json` neu con ton tai la snapshot legacy cu tu lan chay truoc, khong phai DLL/runtime folder cua PyInstaller. Ban moi ghi snapshot mac dinh vao `%LOCALAPPDATA%\SAINT\profiles\backup.saint-snapshot.json` va restore van fallback duoc file legacy.

## 16. Whitelist legacy domain service cleanup

Nguoi dung hoi co the xoa `WhitelistService.get_all_domains()` va
`WhitelistService.delete_domain()` khong. Ket qua trace:

- Frontend `server/views/static/js/whitelist.js` dang goi route
  `/api/whitelist` va `DELETE /api/whitelist/<id>`, khong goi truc tiep
  service method.
- Route `/api/whitelist` van can giu de tuong thich UI, nhung ben trong da
  migrate sang unified entry API.
- `WhitelistService.get_all_domains()` va `WhitelistService.delete_domain()`
  da duoc xoa.

Fix chinh:

- `server/controllers/whitelist_controller.py::list_domains` goi
  `service.get_all_entries(filters, limit, offset)`.
- `server/controllers/whitelist_controller.py::delete_domain` goi
  `service.bulk_delete_entries([domain_id])`.
- `server/services/whitelist_service.py::get_all_entries` them pagination va
  tra ca `items` lan `domains` de frontend cu van doc duoc.
- `server/models/whitelist_model.py::build_query_from_filters` search them
  `category`.
- Update tests khong mock/goi 2 method legacy nua.

Verification:

```text
targeted whitelist/controller tests: 50 passed
```
