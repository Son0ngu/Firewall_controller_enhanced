"""
Encrypt/decrypt agent_config.json using Fernet (AES-128-CBC).
Key is derived from machine identity (hostname + MAC address) so the
config file is only readable on the same machine.
"""

import base64
import hashlib
import json
import logging
import os
import socket
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("config.crypto")

# Encrypted config uses .enc extension
ENCRYPTED_EXT = ".enc"


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


def _get_machine_key() -> bytes:
    """Derive a Fernet key from machine identity (hostname + MAC)."""
    hostname = socket.gethostname()
    mac = hex(uuid.getnode())
    seed = f"SAINT:{hostname}:{mac}".encode()
    # SHA-256 → take first 32 bytes → base64-encode for Fernet (requires url-safe b64)
    digest = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_config(config: Dict[str, Any], path: Path) -> bool:
    """Encrypt config dict and write to file."""
    try:
        key = _get_machine_key()
        fernet = Fernet(key)

        plaintext = json.dumps(config, indent=4, ensure_ascii=False).encode("utf-8")
        encrypted = fernet.encrypt(plaintext)

        enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
        enc_path.parent.mkdir(parents=True, exist_ok=True)
        enc_path.write_bytes(encrypted)
        # Tighten ACL immediately after write. The ciphertext alone is fine
        # at rest, but the machine-key derivation (hostname + MAC) is
        # trivially reproducible by any local account, so we don't want a
        # world-readable .enc file lying around.
        restrict_to_owner(enc_path)

        # Remove plaintext file if it exists
        if path.exists():
            path.unlink()

        logger.info(f"Config encrypted and saved to {enc_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to encrypt config: {e}")
        return False


def decrypt_config(path: Path) -> Optional[Dict[str, Any]]:
    """Read and decrypt config from encrypted file."""
    enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
    if not enc_path.exists():
        return None

    try:
        key = _get_machine_key()
        fernet = Fernet(key)

        encrypted = enc_path.read_bytes()
        plaintext = fernet.decrypt(encrypted)

        return json.loads(plaintext.decode("utf-8"))
    except InvalidToken:
        logger.error(f"Cannot decrypt {enc_path} - wrong machine or corrupted file")
        return None
    except Exception as e:
        logger.error(f"Failed to decrypt config: {e}")
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
