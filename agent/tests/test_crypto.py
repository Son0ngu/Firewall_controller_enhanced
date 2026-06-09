import json
import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# Server tests also have a top-level ``config`` package. When pytest collects
# both trees in one process, drop any already-cached non-agent config package
# before importing the agent config modules below.
cached_config = sys.modules.get("config")
cached_path = getattr(cached_config, "__file__", "") if cached_config else ""
if cached_config and not os.path.abspath(cached_path).startswith(AGENT_DIR):
    for module_name in list(sys.modules):
        if module_name == "config" or module_name.startswith("config."):
            sys.modules.pop(module_name, None)

from cryptography.fernet import Fernet

from config import crypto


SAMPLE = {"auth": {"api_key": "fc_secret123"}, "server": {"url": "http://x:5000"}}


def _enc_path(path):
    return path.with_suffix(path.suffix + crypto.ENCRYPTED_EXT)


def _salt_path(path):
    return path.with_suffix(path.suffix + crypto.SALT_EXT)


def test_encrypt_decrypt_roundtrip(tmp_path):
    path = tmp_path / "agent_config.json"
    assert crypto.encrypt_config(SAMPLE, path) is True
    assert _enc_path(path).exists()
    # Salt file created and non-empty.
    assert _salt_path(path).exists()
    assert len(_salt_path(path).read_bytes()) == 32
    assert crypto.decrypt_config(path) == SAMPLE


def test_salted_ciphertext_not_decryptable_by_legacy_key(tmp_path):
    """The salt must actually be mixed in: a .enc written by encrypt_config
    cannot be opened with the legacy hostname+MAC-only key."""
    path = tmp_path / "agent_config.json"
    crypto.encrypt_config(SAMPLE, path)
    ciphertext = _enc_path(path).read_bytes()
    assert crypto._try_decrypt(ciphertext, crypto._get_machine_key()) is None
    assert crypto._try_decrypt(ciphertext, crypto._get_salted_key(path)) == SAMPLE


def test_legacy_config_is_migrated_on_decrypt(tmp_path):
    """A config encrypted with the old machine-only key (no salt file) is
    decrypted, then transparently re-encrypted with the salted key."""
    path = tmp_path / "agent_config.json"
    # Simulate a pre-salt .enc: encrypt with legacy key, no salt file present.
    legacy_cipher = Fernet(crypto._get_machine_key()).encrypt(
        json.dumps(SAMPLE).encode("utf-8")
    )
    _enc_path(path).write_bytes(legacy_cipher)
    assert not _salt_path(path).exists()

    # First decrypt triggers migration.
    assert crypto.decrypt_config(path) == SAMPLE
    assert _salt_path(path).exists()

    # After migration the ciphertext is the salted scheme: legacy key fails,
    # salted key works, and a second decrypt still returns the config.
    migrated = _enc_path(path).read_bytes()
    assert crypto._try_decrypt(migrated, crypto._get_machine_key()) is None
    assert crypto.decrypt_config(path) == SAMPLE


def test_decrypt_returns_none_when_no_file(tmp_path):
    path = tmp_path / "missing.json"
    assert crypto.decrypt_config(path) is None
