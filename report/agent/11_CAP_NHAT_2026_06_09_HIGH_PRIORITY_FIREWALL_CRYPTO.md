# Cap nhat 2026-06-09 - High-priority: Firewall-6 + Crypto-1 (phia Agent)

## Tom tat

Phan agent cua dot fix nhom uu tien cao. Phan server (Server-4/5/9) ghi tai
`report/server/13_CAP_NHAT_2026_06_09_HIGH_PRIORITY_WHITELIST_FILTER.md`.

Gom 2 muc:
- **Firewall-6** — `enable_default_deny` fail-open (chap nhan 1/3 profile + verify
  fail van bao thanh cong).
- **Crypto-1** — khoa Fernet ma hoa config yeu (chi tu hostname+MAC, public).

Trang thai: 2 file production sua + 1 file test moi. Agent suite **51 passed**
(47 cu + 4 crypto moi), khong regression.

Nguyen tac: tai dung ham/bien co san; chi them khi that su can (salt + helper
crypto, da giai trinh).

---

## 1. Firewall-6 — Default Deny fail-open

File: `agent/firewall/policy.py`.

### Goc re
- `enable_default_deny`: `if success_count >= 1:` → chi can 1/3 profile dat
  block la coi thanh cong. Neu profile mang dang active nam trong 2 profile
  fail → outbound van mo nhung agent tuong da khoa.
- Khi `verify_default_deny()` fail van `self.default_deny_enabled = True;
  return True` ("proceeding anyway") → bao thanh cong gia.
- `verify_default_deny` dem `output.count('block') >= 2` tren raw netsh output
  → mong manh, khong kiem per-profile.

### Cach giai
- `enable_default_deny`: doi gate thanh `if success_count == len(profiles):`
  (du ca 3). Khi verify fail → `self.default_deny_enabled = False; return False`
  (khong bao thanh cong gia). Nhanh thieu profile cung set False + return False.
- `verify_default_deny`: viet lai dung `get_current_policy()` (co san, tra
  `{profile: 'block'/'allow'}` cho ca 3 profile) — `return all(policies.get(p)
  == "block" for p in ["domain","private","public"])`. Bo phu thuoc
  `FirewallUtils` string-count. (`get_current_policy` van dung `FirewallUtils`
  nen import khong thua.)

### He qua
Neu khong khoa duoc ca 3 profile → `enable_default_deny` tra False → caller
`firewall/manager.py` (`setup_whitelist_firewall` / `enable_whitelist_mode`)
KHONG set `whitelist_mode_active`. Fail-closed ve cuoc "bao da bat"; allow rules
da tao van vo hai khi default van allow. (User da chon huong "yeu cau du 3
profile".)

---

## 2. Crypto-1 — khoa ma hoa config yeu

File: `agent/config/crypto.py` (+ test `agent/tests/test_crypto.py`).

### Goc re
`_get_machine_key()` derive khoa Fernet chi tu `socket.gethostname()` +
`uuid.getnode()` (MAC). Ca hai deu public voi moi user/process local → ai lay
duoc `agent_config.json.enc` (backup, AV quarantine, share sai, ACL hong) deu
tu suy khoa va giai ma offline → lo API key / JWT.

### Cach giai (salt + migration, chi stdlib)
- Them salt ngau nhien 32 byte moi may (`secrets.token_bytes(32)`), luu file
  `agent_config.json.salt` canh `.enc`, ACL bang `restrict_to_owner` (co san).
- Khoa hien tai = `SHA256(hostname+MAC+salt)` → khong con tai tao tu dinh danh
  may cong khai. Chi lo `.enc` (khong co salt) thi khong du de giai.
- **Migration**: `decrypt_config` thu khoa-salt truoc; `InvalidToken` →
  fallback `_get_machine_key()` legacy; giai duoc → re-encrypt bang khoa salt.
  `.enc` cu tu nang cap, khong mat config.

### Ham/bien (tai dung + them toi thieu)
| Ten | Vai tro |
|---|---|
| `_machine_seed()` (moi) | Tach phan hostname+MAC dung chung |
| `_get_machine_key()` | GIU lam khoa **legacy** cho migration |
| `SALT_EXT = ".salt"` (moi) | Hang duoi extension salt |
| `_salt_path(path)` (moi) | `path + .salt` |
| `_load_or_create_salt(path)` (moi) | Sinh/doc salt, `restrict_to_owner` |
| `_get_salted_key(path)` (moi) | Khoa hien tai co salt |
| `_try_decrypt(ciphertext, key)` (moi) | Giai 1 khoa, None neu sai |
| `encrypt_config` | Doi sang `_get_salted_key(path)` |
| `decrypt_config` | Salt key → legacy fallback → re-encrypt |

Them `import secrets`. Tai dung `restrict_to_owner`, `ENCRYPTED_EXT`, `Fernet`,
`hashlib`, `base64`.

### Gioi han (trung thuc)
Admin local doc duoc CA `.enc` lan `.salt` van giai duoc — ban chat ma hoa doi
xung khong co TPM/DPAPI. Salt chan kich ban lo-moi-ciphertext (cai thien thuc).
Manh hon can DPAPI (`CryptProtectData` qua ctypes) rang theo tai khoan Windows —
de batch rieng.

### Test (`agent/tests/test_crypto.py`, 4 case)
| Test | Muc dich |
|---|---|
| `test_encrypt_decrypt_roundtrip` | Round-trip + salt file 32 byte |
| `test_salted_ciphertext_not_decryptable_by_legacy_key` | Salt thuc su tron vao khoa |
| `test_legacy_config_is_migrated_on_decrypt` | `.enc` cu → migrate, khong mat config |
| `test_decrypt_returns_none_when_no_file` | No-file → None |

---

## 3. Verify

```bash
.venv/Scripts/python.exe -m py_compile agent/firewall/policy.py agent/config/crypto.py
.venv/Scripts/python.exe -m pytest agent/tests -q
# 51 passed in 4.02s
```

Smoke firewall (chua chay default-deny that tren may dang dung): mock
`get_current_policy()` du 3 'block' → verify True; thieu 1 → False;
`set_profile_outbound_policy` fail 1 profile → `enable_default_deny` False +
`default_deny_enabled` False.

## 4. File da cham (phia agent)

| File | Loai | Quy mo |
|---|---|---|
| `agent/firewall/policy.py` | Production | gate `== len(profiles)`, verify per-profile qua get_current_policy |
| `agent/config/crypto.py` | Production | salt + migration; +1 import secrets |
| `agent/tests/test_crypto.py` | Test moi | 4 case round-trip/salt/migration |
