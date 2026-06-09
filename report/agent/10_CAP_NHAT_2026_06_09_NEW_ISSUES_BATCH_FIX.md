# Cap nhat 2026-06-09 - Batch fix 6 NEW ISSUES phia Agent

## Tom tat

Phien nay fix 6 loi nho/khu tru phia agent, phat hien trong dot verify lai cac
review report truoc (cac loi nay nam ngoai danh sach goc, duoc dat ten "NEW
ISSUES"). Tat ca deu la loi logic/quality cuc bo, khong phai loi kien truc.

Nguyen tac: **tai dung toi da bien/ham/key da co**, chi them dung 1 thuoc tinh
moi `self._logs_sent` (da thong nhat voi user) + 1 helper `_interruptible_sleep`
+ vai bien local can thiet. Khong tao class/module/signal moi.

Trang thai:
- 5 file production agent da sua, tat ca `py_compile` PASS.
- Khong doi public API ngoai viec `LogSender.get_status()` them key `logs_sent`.
- 2 quyet dinh forks da chot voi user: logs_sent = them counter that;
  token lock = giu nguyen cau truc khoa, chi giam timeout.

---

## 1. `logs_sent` luon = 0 (dead stat)

File: `agent/logging_module/sender.py`, `agent/controllers/agent_controller.py`.

### Goc re

`agent_controller._update_stats()` doc `sender_status.get('logs_sent', 0)`
(agent_controller.py:537) nhung `LogSender.get_status()` KHONG tra key
`logs_sent` — LogSender khong co bat ky counter so log da gui nao (chi co
`_consecutive_send_failures`, `last_send_time`). Stat `logs_sent` tren dashboard
vi the luon = 0.

### Cach giai (them counter)

- `LogSender.__init__`: them `self._logs_sent = 0` ngay canh
  `self._consecutive_send_failures = 0`.
- `LogSender._send_batch`: o nhanh thanh cong (`response.status_code in
  (200, 201, 202)`), sau `self._record_send_success()` them
  `self._logs_sent += len(serialized_logs)` — **tai dung bien co san
  `serialized_logs`** (so log thuc su gui trong batch).
- `LogSender.get_status()`: them key `"logs_sent": self._logs_sent` vao dict
  tra ve (canh `queue_size`).
- `agent_controller.py:537` GIU NGUYEN — gio doc dung key that.

---

## 2. Heartbeat busy-spin khi backoff < 1s

File: `agent/services/heartbeat.py`.

### Goc re

Vong sleep ngat duoc trong `_heartbeat_loop` dung
`for _ in range(int(sleep_time)): sleep(1)`. `int(sleep_time)` cat het phan le:
backoff full-jitter o lan fail som thuong < 1s (vi du `random.uniform(0, 5)` ra
0.7) → `int(0.7) = 0` → `range(0)` → KHONG sleep → loop goi `_send_heartbeat()`
lien tuc → **hammer server**. Nhanh exception (`sleep(self._backoff_seconds())`)
lai block khong ngat duoc khi dung agent.

### Cach giai (helper ngat duoc + ngu ca phan le)

Them method private `_interruptible_sleep(self, seconds: float)`:

```python
def _interruptible_sleep(self, seconds: float) -> None:
    whole = int(seconds)
    for _ in range(whole):
        if not self._running:
            return
        sleep(1)
    remainder = seconds - whole
    if self._running and remainder > 0:
        sleep(remainder)
```

- Tai dung `self._running` (stop flag co san) + `sleep` (da import tu
  `shared.time_utils`).
- Vong chinh: thay khoi `for ... range(int(sleep_time))` bang
  `self._interruptible_sleep(sleep_time)`.
- Nhanh exception: thay `sleep(self._backoff_seconds())` bang
  `self._interruptible_sleep(self._backoff_seconds())` → vua het busy-spin vua
  ngat duoc trong ~1s khi stop.
- `_backoff_seconds()` giu nguyen (full-jitter van dung; phan le nay duoc ngu
  that thay vi bi cat).

---

## 3. Settings ghi de mat `server.urls` fallback

File: `agent/gui_qt/views/settings.py`.

### Goc re

`_save_config` set `self._config["server"]["urls"] = [normalized_url]` →
ghi de toan bo, xoa moi URL fallback nguoi dung tung cau hinh trong
`server.urls`.

### Cach giai (tai dung helper chuan)

Import them `collect_server_urls` (canh `normalize_server_url`), va thay dong
ghi de bang:

```python
prior_urls = list(self._config["server"].get("urls", []) or [])
self._config["server"]["urls"] = [normalized_url, *prior_urls]
self._config["server"]["urls"] = collect_server_urls(self._config)
```

- `collect_server_urls` (`shared/server_urls.py`) la nguon chan ly gop
  `url`+`urls`, chuan hoa + dedup giu thu tu.
- Dat `normalized_url` len dau list nen `server_urls[0]` (LogSender dung) luon
  tro toi URL vua nhap; cac fallback cu duoc giu lai phia sau.

---

## 4. Default heartbeat lech giua UI va DEFAULT_CONFIG

File: `agent/gui_qt/views/settings.py`.

UI dung fallback `.get("interval", 30)` (settings.py:181) trong khi
`DEFAULT_CONFIG["heartbeat"]["interval"] = 20` (config/defaults.py:91) va runtime
`HeartbeatSender.interval` default 20. Doi `30` → `20` cho khop. Sync/update
interval (fallback 60) da khop nen khong sua.

---

## 5. Tieu chi thanh cong restore khong nhat quan

File: `agent/firewall/policy.py`.

`restore_original_policy` tra `success_count > 0` (chi 1/N profile cung bao
thanh cong) trong khi `restore_default_policy` tra
`success_count == len(profiles)` (yeu cau du). Da dong bo theo ban chat:

- `restore_original_policy` return `success_count == len(self._original_policies)`
  (tai dung dict co san lam mau so).
- He qua mong muon: restore mot phan → tra False → caller `firewall/manager.py`
  (line ~261) roi xuong `restore_default_policy()` (ep allow ca 3 profile),
  khong de may bi block do dang. Giu nguyen `if success_count > 0:
  self.default_deny_enabled = False`.

---

## 6. Token manager giu khoa khi goi HTTP

File: `agent/core/token_manager.py`.

`self._lock` bi giu suot 15s trong khi `requests.post(..., timeout=15)` chay →
thread khac doc `.access_token` bi nghen. Day la van de latency/contention,
KHONG sai logic (token state van dung). Theo lua chon cua user: **giu nguyen
cau truc khoa**, chi giam `timeout=15` → `timeout=10` trong `_do_refresh` de
gioi han cua so nghen toi da (dong bo voi heartbeat/log cung dung 10/15s). Khong
dong vao logic refresh.

---

## 7. Verify

```bash
python -m py_compile \
  agent/logging_module/sender.py \
  agent/services/heartbeat.py \
  agent/gui_qt/views/settings.py \
  agent/firewall/policy.py \
  agent/core/token_manager.py
# ALL OK
```

Hoi quy de xuat (chua chay trong phien): `cd agent && python -m pytest tests/ -q`.
Smoke nen kiem:
- logs_sent: gui vai log → `LogSender.get_status()['logs_sent']` tang dan.
- heartbeat: ep server loi → khoang cach giua cac retry > 0 (khong spam);
  stop agent → thoat trong ~1s.
- settings: cau hinh 2 URL trong `server.urls`, doi Server URL roi Save → mo
  lai config thay URL moi dau list, fallback cu van con.
- policy: gia lap 1 profile restore fail → `restore_original_policy()` tra False
  va manager goi `restore_default_policy()`.

---

## 8. File da cham (phia agent)

| File | Loai | Quy mo |
|---|---|---|
| `agent/logging_module/sender.py` | Production | +3 LOC (counter `_logs_sent`) |
| `agent/services/heartbeat.py` | Production | +helper `_interruptible_sleep`, sua 2 sleep path |
| `agent/gui_qt/views/settings.py` | Production | merge urls + default 30→20 |
| `agent/firewall/policy.py` | Production | sua bieu thuc return restore_original_policy |
| `agent/core/token_manager.py` | Production | timeout 15→10 |

Phan server (import thua, bulk_delete count) ghi tai
`report/server/12_CAP_NHAT_2026_06_09_NEW_ISSUES_BATCH_FIX.md`.

Khong tao class/module/signal moi. Chi them counter `_logs_sent` (da thong nhat),
helper `_interruptible_sleep`, va vai bien local (`prior_urls`, `matched`).
