# Cap nhat 2026-06-05 - Whitelist state anti-wipe va GUI wire-up som

## Tom tat

Phien nay sua 2 van de doc lap nhung lien quan cua flow whitelist sync giua agent va GUI, phat hien trong qua trinh chuan bi demo tren 4 VM Win10:

1. **State wipe bug (CRITICAL)** — `WhitelistState.update()` thay the vo dieu kien `_domains/_patterns/_ips` ngay ca khi server tra empty trong race condition giua `sync_now()` lan 1 (Step 2.5 lifecycle) va lan 2 (`start_sync()` thread bat dau o Step 4). Hau qua: state da co 39 domain bi wipe ve 0, GUI Whitelist tab va firewall manager mat data.

2. **Late GUI wire-up (HIGH UX)** — `WhitelistController.set_whitelist_manager()` chi duoc goi tai cuoi `_agent_worker` sau khi `initialize_components()` chay xong ca 7 step (registration, token, whitelist, firewall, log, heartbeat, sniffer). Trong khi state da san sang tu Step 2.5, GUI van thay `_whitelist_manager = None` cho den khi Step 7 xong → user nhin tab empty 1-3 phut khong hieu vi sao.

3. **Pylance Pylance reportInvalidTypeForm** — `server/services/whitelist_service.py` co pattern try/except import voi fallback `WhitelistEntryModel = None`, khien Pylance coi name la variable thay vi class, gay warning trong `Optional["WhitelistEntryModel"]`. Da chuyen sang pattern `if TYPE_CHECKING / else` chuan.

Trang thai hien tai:

- Source da cap nhat 3 file production + 1 file test moi (4 LOC count: state.py +20, agent_controller.py +32, lifecycle.py +14, test_whitelist_state.py NEW).
- Server-side: `whitelist_service.py` import pattern cleanup + reference doc trong `05_TONG_HOP_HAM_VA_CONG_DUNG_SERVER.md` da cap nhat signature `__init__` (them `entry_model`).
- Test agent: `40 passed` (gom 4 case anti-wipe moi).
- Test server whitelist: `128 passed in 4m 39s` — khong regression.
- Test server adjacent (`test_app_factory`, `test_groups`, `test_teacher_data_filtering`): `155 passed in 2m 07s`.
- Tong: **327 passed, 0 failed**.

---

## 1. Anti-wipe guard trong `WhitelistState.update()`

File: `agent/whitelist/state.py`.

### Bang chung bug

Log agent run truoc fix:

```
[23:31:20] Resolving 39 whitelist domains...           <- state HAS 39 domains
[23:31:22] Total IPs to allow: 54                       <- firewall used the state
[23:31:36] Synced from manager: 0 domains, 0 patterns, 0 IPs   <- state WIPED
```

Stats panel `Syncs: 9` trong 16 giay → nhieu lan `sync_now()` chong nhau. Server tra `{"domains": [], "up_to_date": false, "global_version": "vN+1"}` trong window race → state.update() thay the toan bo bang empty.

### Goc re trong code (truoc fix)

`state.py:97-109` co flow:
- Neu `up_to_date and not group_changed` → return False (an toan, da co)
- Neu new data **bang** current → return False (an toan)
- Con lai → **REPLACE** toan bo set (line 107-109)

Khong co buoc kiem tra "server tra empty trong khi cache dang co data". Trong race condition, `up_to_date=false` (server bao co thay doi) + parsed data rong + version moi → rot vao nhanh replace, wipe sach.

### Guard moi

Them ngay truoc dong replace:

```python
prev_total = len(self._domains) + len(self._patterns) + len(self._ips)
new_total = len(new_domains) + len(new_patterns) + len(new_ips)
if prev_total > 0 and new_total == 0 and not group_changed:
    logger.warning("Server returned empty whitelist while %d entries cached ...")
    self._version = str(data.get("global_version", ...))
    self._group_version = str(data.get("group_version", ...))
    self._group_id = new_group_id
    return False
```

Logic: chi giu cache khi (1) truoc do co data, (2) data moi hoan toan empty, (3) khong co tin hieu doi group. Van update version bookkeeping de khong loop hoi server lai cung delta.

### Cac case duoc cover

| Tinh huong | Guard hoat dong? | Hanh dong |
|---|---|---|
| Race: cache 39, server tra empty, `up_to_date=false` | **CO** | Giu cache, log warning |
| Agent thuc su chuyen group, group moi empty | **KHONG** (group_changed=true) | Wipe binh thuong |
| State rong + server tra empty | **KHONG** (prev_total=0) | No-op (existing path) |
| Server tra data moi != cache | **KHONG** (new_total>0) | Replace binh thuong |

### Test moi

File: `agent/tests/test_whitelist_state.py` (4 case):

| Test | Muc dich |
|---|---|
| `test_anti_wipe_preserves_cache_when_server_returns_empty` | Race-condition chinh — guard giu cache |
| `test_anti_wipe_does_not_block_legitimate_group_change` | Group change — guard bypass dung |
| `test_empty_to_empty_is_a_noop` | Fresh state — guard khong trigger sai |
| `test_normal_replace_path_still_works` | Real new data — replace binh thuong |

Tat ca 4 case PASS local.

---

## 2. GUI wire-up som qua callback hook tren `AgentRuntime`

Files: `agent/controllers/agent_controller.py`, `agent/core/lifecycle.py`.

### Goc re

Truoc fix, `agent_controller._agent_worker` co flow:

```python
init_result = initialize_components(self._config, runtime=self._runtime)   # blocks ~1-3 phut
...
if self._agent.whitelist:
    whitelist_ctrl = WhitelistController()
    whitelist_ctrl.set_whitelist_manager(self._agent.whitelist)   # ← chi chay sau khi init_components return
```

`initialize_components()` chay tuan tu 7 step: register → token → whitelist init → whitelist sync (Step 2.5) → firewall init (Step 3, gom auto-install Npcap 30-120s + snapshot netsh 5-30s + Default Deny) → log → heartbeat → packet sniffer.

State whitelist da san sang tu cuoi Step 2.5, nhung GUI controller chi nhan manager sau Step 7. User thay Whitelist tab empty cho den khi toan bo init xong.

### Cach giai

Dung **callback hook attached tren `AgentRuntime`** — co che attribute-on-runtime co san (giong cach `agent.config = config` o `lifecycle.py:313`). Tranh import controller vao lifecycle (vi pham phan tach moudule), tranh tao signal moi (qua nang cho mot wire-up local).

**`agent_controller.py`:**
- Them method `_on_whitelist_ready(self, manager)` — wire `WhitelistController().set_whitelist_manager(manager)` voi try/except.
- Truoc khi goi `initialize_components`, gan: `self._runtime._on_whitelist_ready_callback = self._on_whitelist_ready`.
- Giu block wire-up cuoi `_agent_worker` (line 362-365) lam fallback an toan — `WhitelistController` la singleton, goi nhieu lan idempotent.

**`lifecycle.py`:**
- Trong `_init_whitelist_sync`, sau khi sync_success xong va `result.record(...)` ghi nhan, lay callback ra qua `getattr(agent, "_on_whitelist_ready_callback", None)` va goi `callback(agent.whitelist)`.
- Bao tri/except — loi trong callback chi log warning, khong pha lifecycle.

### Hieu ung

| Mocc thoi gian | Truoc fix | Sau fix |
|---|---|---|
| Whitelist tab co data | Sau Step 7 (1-3 phut) | Sau Step 2.5 (10-60s phu thuoc network) |
| Log "WhitelistController wired early (via lifecycle callback)" | (khong co) | Xuat hien ngay sau "Whitelist synced" |
| Anti-wipe ket hop | — | State khong bi wipe ngay ca khi Step 4 race xay ra |

### Tai sao dat o Step 2.5 chu khong Step 2

- Step 2 (`_init_whitelist_manager`) chi tao `WhitelistManager`, state chua co data → controller `_sync_from_manager()` doc empty.
- Step 2.5 sync xong, state co N domains → controller doc duoc ngay.
- Cau hinh `whitelist.auto_sync=false` → Step 2.5 early-return, **callback khong fire** (do la dung — khong co data thi khong can wire som).

### Headless safe

Tests va headless callers khong gan attribute `_on_whitelist_ready_callback`. `getattr(... , None)` tra None → callback khong chay. Khong anh huong cac test hien co.

---

## 3. Pylance reportInvalidTypeForm trong `whitelist_service.py`

File: `server/services/whitelist_service.py`.

Truoc fix, dong 14-17:

```python
try:
    from models.whitelist_entry_model import WhitelistEntryModel
except Exception:
    WhitelistEntryModel = None
```

Pylance phan tich static thay binding cuoi cua `WhitelistEntryModel` la `None`, nen `Optional["WhitelistEntryModel"]` o dong 110 bi flag `Variable not allowed in type expression`.

Sau fix:

```python
if TYPE_CHECKING:
    from models.whitelist_entry_model import WhitelistEntryModel
else:
    try:
        from models.whitelist_entry_model import WhitelistEntryModel
    except Exception:
        WhitelistEntryModel = None
```

- Static analyzer (Pylance) chi vao nhanh `if` → thay class that, khong bao gio thay `None`.
- Runtime: `TYPE_CHECKING=False` → chi nhanh `else` chay, behavior 100% giong code cu.

Runtime test: `import services.whitelist_service` resolve `WhitelistEntryModel` ve `<class 'models.whitelist_entry_model.WhitelistEntryModel'>`.

### Reference doc dong bo

Cap nhat `report/server/05_TONG_HOP_HAM_VA_CONG_DUNG_SERVER.md`:

- Line 888: `WhitelistService` class line number `:22` → `:106` (line shift sau khi them TYPE_CHECKING block).
- Line 892: `__init__` signature them tham so `entry_model: Optional[WhitelistEntryModel] = None` (vốn da co trong code nhung doc lo).

---

## 4. Verify ket qua

### Static + unit

```powershell
.venv\Scripts\python.exe -m py_compile `
  agent\whitelist\state.py `
  agent\controllers\agent_controller.py `
  agent\core\lifecycle.py `
  agent\tests\test_whitelist_state.py
# OK: all 4 files compile

.venv\Scripts\python.exe -m pytest agent\tests\test_whitelist_state.py -v
# 4 passed in 1.18s
```

### Regression rong

```powershell
.venv\Scripts\python.exe -m pytest agent\tests -q
# 40 passed in 8.22s

.venv\Scripts\python.exe -m pytest server\tests\test_whitelist_and_logs.py -q
# 128 passed in 4m 39s (3 expected DeprecationWarning silenced by -q)

.venv\Scripts\python.exe -m pytest server\tests\test_app_factory.py server\tests\test_groups.py server\tests\test_teacher_data_filtering.py -q
# 155 passed in 2m 07s
```

Tong: **327 passed, 0 failed**.

### Smoke EXE tren VM (chua hoan thanh phia user)

Sau khi user rebuild qua `pyinstaller agent\saint_agent.spec --clean --noconfirm` va copy `dist\SAINT\` sang VM PC1:

- Cho launch ra GUI: bao ve quan sat khi Whitelist tab populate (muc tieu < 30s sau khi Step 2.5 xong).
- Log can co dong `WhitelistController wired early (via lifecycle callback)`.
- Sau ~60s neu thay log `WARNING ... Server returned empty whitelist while N entries cached` → guard catch race condition thanh cong.

User report luc 2026-06-05: van mat ~2m30s cho Whitelist tab co data. Phan tich tiep theo phai do bottleneck **truoc Step 2.5** (HTTP latency tu agent toi server, kha nang cao Render free tier cold start) — khong phai van de cua patch nay.

---

## 5. Cac han che con lai (out of scope phien nay)

### Whitelist state khong persist disk

`WhitelistState` chi luu trong RAM. Moi lan restart SAINT.exe phai sync lai tu server tu dau, khong tan dung duoc delta-sync co san (do version reset ve "").

Ket qua: launch thoi gian phu thuoc latency mang + co server. Khong giai quyet duoc bang patch wire-up som.

Phuong an tiem nang (chua trien khai trong phien nay):
- Them `WhitelistState.save_to_disk(path)` / `load_from_disk(path)` voi format JSON.
- Manager gọi `load_from_disk` luc khoi tao → state co data ngay → sync background refresh.

### Firewall tab van fallback netsh khi manager chua wired

`agent/gui_qt/views/firewall.py:201-209` co fallback shell out netsh khi `_firewall_manager is None`. Loop 5s/lan, moi lan 5-30s tren Win10 sach. Khong nguy hiem nhung gay lag UI 1-3 phut dau.

Phuong an tiem nang: them flag `_agent_status` listen `status_changed` signal, skip netsh khi `status != "running"`. Da mo ta trong plan file nhung chua trien khai vi out of scope cua "fix data wipe".

---

## 6. File da cham trong phien

| File | Loai | Quy mo |
|---|---|---|
| `agent/whitelist/state.py` | Production code | +20 LOC (anti-wipe guard) |
| `agent/controllers/agent_controller.py` | Production code | +32 LOC (`_on_whitelist_ready` + gan callback) |
| `agent/core/lifecycle.py` | Production code | +14 LOC (fire callback sau Step 2.5) |
| `agent/tests/test_whitelist_state.py` | Test file moi | 4 test case, ~110 LOC |
| `server/services/whitelist_service.py` | Server code | TYPE_CHECKING pattern (6 LOC delta) |
| `report/server/05_TONG_HOP_HAM_VA_CONG_DUNG_SERVER.md` | Reference doc | 2 row sua line number + signature |
| `report/agent/05_TONG_HOP_HAM_VA_CONG_DUNG_AGENT.md` | Reference doc | Cap nhat sau phien (turn nay) |
| `report/agent/09_CAP_NHAT_2026_06_05_*.md` | Report file moi | (file nay) |

Khong tao class moi, khong tao signal moi, khong tao utility module moi. Tat ca thay doi tai dung function/class/pattern co san trong codebase.
