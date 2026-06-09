# Cap nhat 2026-06-09 - Batch fix NEW ISSUES phia Server

## Tom tat

Phan server cua dot batch-fix 2026-06-09 (phan agent ghi tai
`report/agent/10_CAP_NHAT_2026_06_09_NEW_ISSUES_BATCH_FIX.md`). Gom 2 muc:
import thua va sai semantics khi dem ket qua bulk delete. Ca 2 la quality fix,
khong doi response shape cua API.

Trang thai: 3 file server da sua, `py_compile` PASS, khong regression API.

---

## 1. Import thua `get_all_permissions`

Files: `server/services/admin_auth_service.py`, `server/services/user_service.py`.

`get_all_permissions` (tu `config.rbac_config`) duoc import o ca 2 file nhung
khong dung o dau (grep = 0 occurrence ngoai dong import). Ham van la export that
trong `config/rbac_config.py` (dung noi bo qua `check_permission`), nen xoa
import an toan.

- `admin_auth_service.py`: dong `from config.rbac_config import
  get_all_permissions` chi co mot ten → **xoa ca dong**.
- `user_service.py`: `from config.rbac_config import VALID_ROLES,
  get_all_permissions` → giu `VALID_ROLES` (con dung o dong 70, 151), bo
  `get_all_permissions`.

---

## 2. `bulk_delete_entries` dem sai semantics

File: `server/services/whitelist_service.py` (method `bulk_delete_entries`).

### Goc re

- Path global (collection) dem `deleted_count += 1` cho moi `item_id` xoa thanh
  cong (`delete_entry` tra bool).
- Path embedded group dem `deleted_count += (original_len - len(new_whitelist))`
  = so **phan tu mang** bi loai. Neu group co entry trung `(value, type)`, mot
  yeu cau xoa co the loai nhieu phan tu → `deleted_count` co the **vuot** so
  `item_ids` gui vao, va lech semantics so voi path global.

### Cach giai (dem theo request khop)

Trong vong loc entry, khi `should_delete` True thi them `(d_val, d_type)` vao
local set `matched`, roi doi:

```python
deleted_count += len(matched)   # thay vi (original_len - len(new_whitelist))
```

- Moi yeu cau khop chi dem 1 lan → khong vuot so id gui vao, dong nhat voi path
  global.
- Tai dung `items`, `should_delete`, vong lap co san; chi them 1 local `matched`.
- Response shape giu nguyen (`{success, deleted_count, error_count, errors,
  server_time}`). Caller (`whitelist_controller.delete_entry`,
  `bulk_delete_entries`) chi check `deleted_count > 0` hoac tra raw → khong vo.

---

## 3. Verify

```bash
python -m py_compile \
  server/services/admin_auth_service.py \
  server/services/user_service.py \
  server/services/whitelist_service.py
# ALL OK
```

- Grep xac nhan `get_all_permissions` khong con tham chieu trong 2 file → safe.
- De xuat: `cd server && python -m pytest tests/ -q`; goi API bulk delete voi
  danh sach id (gom group pseudo-id) → `deleted_count` <= so id gui.

---

## 4. File da cham (phia server)

| File | Loai | Quy mo |
|---|---|---|
| `server/services/admin_auth_service.py` | Production | -1 import |
| `server/services/user_service.py` | Production | bo 1 ten import |
| `server/services/whitelist_service.py` | Production | dem `len(matched)` thay so phan tu mang |
