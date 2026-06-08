# Whitelist entries migration reference

Cap nhat: 2026-05-27

## Muc tieu

Group whitelist dang duoc chuyen tu embedded array `groups.whitelist[]` sang collection rieng `whitelist_entries`.

Trang thai hien tai la **collection-first dual path**:

- Group whitelist write moi ghi vao `whitelist_entries`.
- Read path doc `whitelist_entries` truoc va merge legacy `groups.whitelist[]` trong mot release.
- Collection row co `_id` that va API/frontend uu tien `_id` that.
- Pseudo-ID `group::<group_id>::<type>::<value>` chi con la fallback cho legacy embedded row chua migrate/backfill.
- Embedded array chua bi xoa trong code/deploy nay de co rollback an toan.

Frontend note 2026-06-08:

- Group Detail page khong con doc count tu `group.whitelist[]` khi render banner.
- Inline editor lay entries tu `/api/whitelist?scope=group&group_id=...`.
- `GET /api/groups/<id>` chi giu metadata/version, khong phai source count that cua UI.

## Collection schema

Collection: `whitelist_entries`

| Field | Mo ta |
| --- | --- |
| `_id` | Mongo `ObjectId`, public id cho API/frontend. |
| `scope` | Hien tai group entries dung `group`; global entries van o collection `whitelist` trong compatibility window. |
| `group_id` | String id cua group. |
| `type` | `domain`, `ip`, hoac `url`. |
| `value` | Normalized lowercase/trimmed value. |
| `category` | Category hien thi/filter. |
| `priority` | Priority hien thi/sync. |
| `is_active` | Active flag. |
| `added_by`, `added_date` | Audit/display metadata. |
| `created_at`, `updated_at` | Timestamps. |
| `legacy_embedded_id` | String `_id` cua embedded row cu, dung de trace/rollback. |

Model: `server/models/whitelist_entry_model.py`

Indexes:

- `scope`
- `group_id`
- `is_active`
- sparse `legacy_embedded_id`
- compound `(scope, group_id, type, value, is_active)`

## Service behavior

`WhitelistService` nhan them `entry_model`.

Group-scope write path:

- `add_entry(... scope="group" ...)` ghi `whitelist_entries`.
- `bulk_add_entries(...)` ghi `whitelist_entries`.
- Sau write/delete/update group row, service goi `GroupModel.bump_whitelist_version(group_id)` de agent sync biet co thay doi.

Group-scope read path:

- `_get_group_entries(group, include_inactive=True)` lay collection rows.
- Legacy embedded entries van duoc normalize.
- Hai nguon duoc merge theo key `type:value`; collection row thang neu trung.
- Neu collection chua co row nao, embedded fallback van tra du lieu cu.

Update/delete path:

- `update_entry(entry_id, ...)` thu pseudo-ID cu, sau do thu real `_id` trong `whitelist_entries`, roi global legacy path.
- `delete_entry(entry_id)` thu global legacy collection, sau do `whitelist_entries`, sau do embedded ObjectId fallback.
- Teacher RBAC access check doc `whitelist_entries` truoc khi fallback embedded/global.

## Migration script

Script:

```powershell
.venv\Scripts\python.exe server\scripts\migrations\2026_migrate_group_whitelist_to_entries.py
.venv\Scripts\python.exe server\scripts\migrations\2026_migrate_group_whitelist_to_entries.py --json --fail-on-invalid
.venv\Scripts\python.exe server\scripts\migrations\2026_migrate_group_whitelist_to_entries.py --write
```

Default la dry-run. `--write` moi insert rows vao `whitelist_entries`.
`--json` in structured stats; `--fail-on-invalid` exit code 2 neu
`entries_skipped_invalid > 0`. Output JSON co `invalid_entries` sample gom
`group_id`, `group_name`, `entry_index`, va `entry_preview` de lap danh sach xu
ly thu cong.

Script copy moi entry trong `groups.whitelist[]` sang `whitelist_entries` va giu:

- `legacy_embedded_id`
- `group_id`
- `type`
- `value`
- `category`
- `priority`
- `notes`
- `added_by`
- `added_date`
- `is_active`

Script idempotent theo `legacy_embedded_id` neu co, fallback theo `(scope, group_id, type, value)`.

## Rollout sequence

1. Chay backfill embedded `_id` neu DB cu con row khong co id:
   `server/scripts/migrations/2026_backfill_group_whitelist_entry_ids.py --dry-run`, sau do `--write`.
2. Chay migration copy sang `whitelist_entries` dry-run tren staging/backup.
3. Chay `--write` tren staging, restart server, verify UI/API/sync dung `_id` that.
4. Chay regression + browser smoke.
5. Chay `--write` production trong maintenance window.
6. Theo doi server logs cho marker `legacy_group_pseudo_id_used`.
7. Sau mot release khong con legacy client/data, xoa fallback embedded va pseudo-ID generator.

## Test coverage

`server/tests/test_whitelist_and_logs.py` cover:

- group bulk add ghi vao `whitelist_entries` truoc, khong append embedded.
- read fallback tra embedded row khi group chua migrate.
- partial migration merge collection + embedded va collection row thang khi trung value.
- update/delete bang real `_id` cua `whitelist_entries`.
- legacy pseudo-ID usage logging qua marker `legacy_group_pseudo_id_used`.

Lenh regression chinh:

```powershell
.venv\Scripts\python.exe -m pytest server\tests\test_whitelist_and_logs.py -q
```

## Con chua nen xoa ngay

Chua xoa `groups.whitelist[]`, fallback embedded, va pseudo-ID fallback trong commit nay. Ly do: day la compatibility window de deploy migration an toan va co rollback. Xoa that su chi nen lam sau khi DB production da copy sang `whitelist_entries`, frontend/browser smoke pass, va server logs khong con marker `legacy_group_pseudo_id_used`.

Runbook van hanh chi tiet: [whitelist-firewall-cutover.md](../../runbooks/whitelist-firewall-cutover.md).
