# Cap nhat 2026-06-09 - High-priority: whitelist_service (phia Server)

## Tom tat

Phan server cua dot fix nhom uu tien cao (phan agent: Firewall-6 + Crypto-1 tai
`report/agent/11_CAP_NHAT_2026_06_09_HIGH_PRIORITY_FIREWALL_CRYPTO.md`).

**Phat hien quan trong khi kiem chung truc tiep code**: trong 4 muc server ban
dau, 3 muc KHONG phai bug chuc nang:

- **Server-4** (`get_agent_sync_data:966`) — `effective_mode != "none" or
  effective_mode != agent_policy_mode` chi False khi ca hai = "none". Khop dung y
  dinh "skip cache khi policy active HOAC vua doi" → **logic dung**, chi kho doc.
- **Server-5** (`_merge_whitelists`) — trace ca 4 to hop scope: group **luon
  thang bat ke thu tu** input → **da dung va order-independent**.
- **Server-10** (`rbac_service.get_group_query_filter`) — duong nay va
  `get_teacher_group_ids` dung **cung query** `{teacher_ids/created_by}` → tra
  cung tap group. Chi khac style. **De nguyen** (theo quyet dinh user, tranh them
  import).
- **Server-9** — BUG THAT (fail-open).

Nen batch nay chi: refactor do-ro Server-4/5 (giu nguyen hanh vi) + fix that
Server-9. Server suite **551 passed**, khong regression.

---

## 1. Server-4 — readability refactor (giu hanh vi)
File: `server/services/whitelist_service.py`, `get_agent_sync_data` (~963-967).

Tach dieu kien thanh 2 bien local ro nghia (tai dung `effective_mode`,
`agent_policy_mode`, `policy_changed`):

```python
policy_active = effective_mode != "none"
policy_mode_changed = effective_mode != agent_policy_mode
policy_changed = policy_active or policy_mode_changed
```
Xoa comment danh so gay hieu nham. **Ket qua y het code cu** (test sync van pass).

## 2. Server-5 — tie-break theo scope tuong minh (giu hanh vi)
File: `whitelist_service.py`, `_merge_whitelists` (~865-881).

Viet lai nhanh `if existing:` dung `incoming_is_group`/`existing_is_group` +
`winner`/`loser` cho tuong minh "group thang global bat ke thu tu". Da verify
tung case (group-first va global-first) khop code cu. Tai dung
`incoming_scope/existing_scope/entry_copy`.

## 3. Server-9 — fail-closed tren ObjectId loi (BUG THAT)
File: `whitelist_service.py`, `validate_teacher_entry_access` (~171-174).

Truoc: `ObjectId(item_id)` loi → `except: return True, None` = **cho phep**
(fail-open tren auth gate). Sau:

```python
except Exception:
    return False, "Invalid entry id"
```
- Chi sua nhanh exception (item_id malformed) → fail-closed.
- GIU `if not group: return True, None` (path khong-tim-thay, co chu dich defer
  404 cho operation, dung theo docstring).
- Return shape `(bool, Optional[str])` khong doi; tests da unpack `allowed,
  error` va xu ly `False`.

---

## Khong lam trong batch nay
- **Server-10**: de nguyen (ket qua dung).
- **Crypto-1**: da fix phia agent (xem report agent 11).

## Verify
```bash
.venv/Scripts/python.exe -m py_compile server/services/whitelist_service.py
.venv/Scripts/python.exe -m pytest server/tests -q
# 551 passed in 703.78s
```
Kiem rieng Server-9: `validate_teacher_entry_access("not-an-objectid", [...],
"delete")` → `(False, "Invalid entry id")`.

## File da cham (phia server)
| File | Loai | Quy mo |
|---|---|---|
| `server/services/whitelist_service.py` | Production | Server-4 refactor, Server-5 refactor, Server-9 fail-closed |
