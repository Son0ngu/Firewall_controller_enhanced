"""
Encrypt/decrypt agent_config.json using Fernet (AES-128-CBC).

The Fernet key is derived from machine identity (hostname + MAC address)
combined with a per-install random salt persisted in an ACL-restricted
``.salt`` file. Mixing in the salt means the key is no longer reproducible
from public machine identifiers alone: an attacker who exfiltrates only the
``.enc`` ciphertext cannot derive the key without also reading the
ACL-restricted salt file. (A local admin able to read both files can still
decrypt — that is an inherent limit of local symmetric encryption.)

Configs encrypted before the salt was introduced are migrated transparently
on read via the legacy machine-only key (see ``decrypt_config``).
"""

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("config.crypto")

# Encrypted config uses .enc extension; per-install salt uses .salt
ENCRYPTED_EXT = ".enc"
SALT_EXT = ".salt"


def _current_windows_user() -> str:
    try:
        result = subprocess.run(
            ["whoami"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    username = os.environ.get("USERNAME") or os.environ.get("USER")
    domain = os.environ.get("USERDOMAIN")
    if username and domain:
        return f"{domain}\\{username}"
    return username or ""


def restrict_to_owner(path: Path) -> None:
    """Tighten ACL on ``path`` so only the current user (and SYSTEM/Admins
    on Windows) can read it.

    Defense in depth even though the file is Fernet-encrypted: an attacker
    on the same machine without the user's session shouldn't be able to
    exfiltrate the ciphertext + machine key (hostname + MAC are both
    derivable for any local user) and decrypt offline.

    Platform behaviour:
      - POSIX: ``chmod 0o600`` (owner read/write only).
      - Windows: ``icacls /inheritance:r`` to drop the inherited "Users"
        group, then ``/grant`` Full control to the current user. SYSTEM
        and Administrators retain access via their own explicit ACEs
        (icacls preserves them when ``/inheritance:r`` runs after the
        default ACL has SYSTEM + Administrators on it).

    Best-effort: never raise. If icacls is missing, antivirus blocks the
    subprocess, or the path was deleted between write and chmod, we log
    and move on — the encrypted file is still better than a plaintext
    one with world-readable permissions.
    """
    try:
        if sys.platform == "win32":
            user = _current_windows_user()
            if not user:
                logger.debug("restrict_to_owner: no current user, skipping icacls")
                return
            # /inheritance:r — remove inherited entries (e.g. "Users").
            # /grant:r "<user>:F" — replace/set Full control for current user.
            # We don't strip SYSTEM / Administrators; service managers and
            # admin recovery need them.
            result = subprocess.run(
                ["icacls", str(path), "/inheritance:r",
                 "/grant:r", f"{user}:F",
                 "/grant:r", "*S-1-5-18:F",
                 "/grant:r", "*S-1-5-32-544:F"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                logger.debug(
                    f"icacls failed for {path}: rc={result.returncode} "
                    f"stderr={result.stderr.strip()!r}"
                )
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except (FileNotFoundError, OSError) as e:
        logger.debug(f"restrict_to_owner({path}) skipped: {e}")
    except subprocess.TimeoutExpired:
        logger.debug(f"restrict_to_owner({path}) icacls timed out")


def _machine_seed() -> bytes:
    """Public machine identity (hostname + MAC). NOT secret on its own."""
    hostname = socket.gethostname()
    mac = hex(uuid.getnode())
    return f"SAINT:{hostname}:{mac}".encode()


def _get_machine_key() -> bytes:
    """LEGACY Fernet key derived from machine identity only (hostname + MAC).

    Kept solely so configs encrypted before the per-install salt was added can
    still be decrypted and migrated forward (see ``decrypt_config``). New writes
    use ``_get_salted_key``.
    """
    # SHA-256 → 32 bytes → url-safe base64 (Fernet key format)
    digest = hashlib.sha256(_machine_seed()).digest()
    return base64.urlsafe_b64encode(digest)


def _salt_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + SALT_EXT)


def _load_or_create_salt(path: Path) -> bytes:
    """Return the per-install random salt, creating + ACL-restricting it once.

    The salt is what makes the encryption key non-reproducible from public
    machine identifiers. Stored next to the ``.enc`` file and locked down with
    the same ``restrict_to_owner`` ACL.
    """
    salt_path = _salt_path(path)
    if salt_path.exists():
        try:
            data = salt_path.read_bytes()
            if data:
                return data
        except OSError as e:
            logger.warning(f"Cannot read salt {salt_path}: {e} - regenerating")

    salt = secrets.token_bytes(32)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(salt)
    restrict_to_owner(salt_path)
    return salt


def _get_salted_key(path: Path) -> bytes:
    """Current Fernet key: SHA-256(machine identity + per-install salt)."""
    digest = hashlib.sha256(_machine_seed() + b":" + _load_or_create_salt(path)).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_config(config: Dict[str, Any], path: Path) -> bool:
    """Encrypt config dict and write to file."""
    try:
        key = _get_salted_key(path)
        fernet = Fernet(key)

        plaintext = json.dumps(config, indent=4, ensure_ascii=False).encode("utf-8")
        encrypted = fernet.encrypt(plaintext)

        enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
        enc_path.parent.mkdir(parents=True, exist_ok=True)
        enc_path.write_bytes(encrypted)
        # Tighten ACL immediately after write. Belt-and-suspenders on top of the
        # salt: keep both the ciphertext and the salt file out of reach of other
        # local accounts.
        restrict_to_owner(enc_path)

        # Remove plaintext file if it exists
        if path.exists():
            path.unlink()

        logger.info(f"Config encrypted and saved to {enc_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to encrypt config: {e}")
        return False


def _try_decrypt(ciphertext: bytes, key: bytes) -> Optional[Dict[str, Any]]:
    """Decrypt + parse with one key. None if the key is wrong/data corrupt."""
    try:
        plaintext = Fernet(key).decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, ValueError):
        return None


def decrypt_config(path: Path) -> Optional[Dict[str, Any]]:
    """Read and decrypt config from encrypted file.

    Tries the current salted key first; falls back to the legacy machine-only
    key and, on success, re-encrypts with the salted key so old configs migrate
    forward transparently.
    """
    enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
    if not enc_path.exists():
        return None

    try:
        encrypted = enc_path.read_bytes()
    except OSError as e:
        logger.error(f"Failed to read {enc_path}: {e}")
        return None

    # 1) Current salted key.
    config = _try_decrypt(encrypted, _get_salted_key(path))
    if config is not None:
        return config

    # 2) Legacy machine-only key → migrate forward.
    config = _try_decrypt(encrypted, _get_machine_key())
    if config is not None:
        logger.info("Migrating config from legacy machine key to salted key")
        encrypt_config(config, path)
        return config

    logger.error(f"Cannot decrypt {enc_path} - wrong machine or corrupted file")
    return None


def migrate_plaintext_to_encrypted(path: Path) -> bool:
    """If plaintext config exists but encrypted does not, encrypt it."""
    enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
    if path.exists() and not enc_path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
            if encrypt_config(config, path):
                logger.info(f"Migrated plaintext config to encrypted: {enc_path}")
                return True
        except Exception as e:
            logger.error(f"Migration failed: {e}")
    return False
