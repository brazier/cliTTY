"""Envelope encryption: DEK + KEK. Data encrypted with DEK; DEK stored encrypted by KEK (from master password)."""

from __future__ import annotations

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from src import database as db

_SALT_KEY = "encryption_salt"
_DEK_KEY = "encryption_dek"


def _derive_kek(master_password: str, salt: bytes) -> bytes:
    """Derive Key Encryption Key from master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


class Vault:
    """Holds the DEK for encrypting/decrypting data."""

    def __init__(self, dek: bytes) -> None:
        self._dek = dek
        self._fernet = Fernet(dek)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def get_raw_dek(self) -> bytes:
        """Return the raw DEK for change_master_password only."""
        return self._dek


def is_initialized() -> bool:
    """True if salt and DEK exist (vault already set up)."""
    return bool(db.get_setting(_SALT_KEY)) and bool(db.get_setting(_DEK_KEY))


def initialize(master_password: str) -> Vault:
    """First-run setup: generate salt and DEK, store DEK encrypted by KEK, return Vault."""
    salt = os.urandom(16)
    dek = Fernet.generate_key()
    kek = _derive_kek(master_password, salt)
    encrypted_dek = Fernet(kek).encrypt(dek)
    db.set_setting(_SALT_KEY, base64.urlsafe_b64encode(salt).decode())
    db.set_setting(_DEK_KEY, encrypted_dek.decode())
    return Vault(dek)


def unlock(master_password: str) -> Vault:
    """Derive KEK, decrypt DEK, return Vault. Raises ValueError if password is wrong."""
    salt_b64 = db.get_setting(_SALT_KEY)
    dek_enc = db.get_setting(_DEK_KEY)
    if not salt_b64 or not dek_enc:
        raise ValueError("Vault not initialized")
    salt = base64.urlsafe_b64decode(salt_b64)
    kek = _derive_kek(master_password, salt)
    try:
        dek = Fernet(kek).decrypt(dek_enc.encode())
    except InvalidToken:
        raise ValueError("Incorrect master password")
    return Vault(dek)


def change_master_password(current_password: str, new_password: str) -> Vault:
    """Re-wrap DEK with new KEK. Validates current password. Returns new Vault."""
    vault = unlock(current_password)
    dek = vault.get_raw_dek()
    salt_new = os.urandom(16)
    kek_new = _derive_kek(new_password, salt_new)
    encrypted_dek = Fernet(kek_new).encrypt(dek)
    db.set_setting(_SALT_KEY, base64.urlsafe_b64encode(salt_new).decode())
    db.set_setting(_DEK_KEY, encrypted_dek.decode())
    return Vault(dek)


# ---------------------------------------------------------------------------
# Profile encryption
# ---------------------------------------------------------------------------

_PROFILE_SENSITIVE_COLS = frozenset({
    "key_file", "proxy_command", "ciphers", "macs", "host_key_algorithms",
    "remote_command", "local_forwards", "remote_forwards", "dynamic_forwards",
    "extra_args",
})

def encrypt_profile_fields(data: dict, vault: Vault) -> dict:
    """Encrypt sensitive profile fields. Returns new dict with encrypted values."""
    out = dict(data)
    for col in _PROFILE_SENSITIVE_COLS:
        val = out.get(col)
        if val is None:
            continue
        if isinstance(val, list):
            val = json.dumps(val)
        else:
            val = str(val)
        out[col] = vault.encrypt(val) if val else ""
    return out


def decrypt_profile_row(row, vault: Vault) -> dict:
    """Convert profile row to dict with sensitive fields decrypted."""
    if row is None:
        return {}
    d = dict(row)
    for col in _PROFILE_SENSITIVE_COLS:
        val = d.get(col)
        if val is None or val == "":
            continue
        d[col] = vault.decrypt(val)
    return d
