"""Export and import for hosts, keys, and credentials."""

from __future__ import annotations

import base64
import csv
import json
import os
from pathlib import Path
from typing import Any, TYPE_CHECKING

from src import clitty_notify
from src import database as db
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if TYPE_CHECKING:
    from src.encryption import Vault

_EXPORT_ITERATIONS = 480_000


def _derive_export_key(password: str, salt: bytes) -> bytes:
    """Derive Fernet key from export password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_EXPORT_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_with_export_password(
    plaintext_json: str,
    password: str,
    *,
    export_type: str = "keys",
) -> str:
    """Encrypt JSON string with export password. Returns JSON with clitty_export envelope."""
    salt = os.urandom(16)
    key = _derive_export_key(password, salt)
    cipher = Fernet(key).encrypt(plaintext_json.encode())
    envelope = {
        "clitty_export": True,
        "version": 1,
        "type": export_type,
        "encrypted": True,
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "iterations": _EXPORT_ITERATIONS,
        "data": base64.urlsafe_b64encode(cipher).decode(),
    }
    return json.dumps(envelope)


def decrypt_with_export_password(ciphertext_json: str, password: str) -> str:
    """Decrypt clitty_export envelope with export password. Returns plaintext JSON."""
    envelope = json.loads(ciphertext_json)
    if not envelope.get("encrypted"):
        return ciphertext_json
    salt = base64.urlsafe_b64decode(envelope["salt"])
    data = base64.urlsafe_b64decode(envelope["data"])
    key = _derive_export_key(password, salt)
    try:
        return Fernet(key).decrypt(data).decode()
    except InvalidToken:
        raise ValueError("Incorrect export password")


def _detect_export_format(data: str) -> tuple[bool, str | None]:
    """Return (is_encrypted, export_type or None)."""
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return False, None
    if not isinstance(obj, dict) or not obj.get("clitty_export"):
        return False, None
    return bool(obj.get("encrypted")), obj.get("type")


# ---------------------------------------------------------------------------
# Hosts export (CSV, unencrypted)
# ---------------------------------------------------------------------------


def export_hosts_csv(path: str | Path) -> int:
    """Export hosts as CSV (unencrypted). Returns count written."""
    defs = db.get_column_defs()
    visible = [d["col_name"] for d in defs if d["visible"]]
    if not visible:
        visible = ["name", "ip_address"]
    if "name" not in visible:
        visible.insert(0, "name")
    if "ip_address" not in visible:
        visible.insert(1, "ip_address")
    headers = visible + ["proto"]
    rows = db.list_hosts()
    clitty_notify.clitty_notify(f"file created (export hosts csv): {path}", level="debug", log_only=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            r = dict(row)
            data = {}
            if r.get("data"):
                try:
                    data = json.loads(r["data"]) if isinstance(r["data"], str) else (r["data"] or {})
                except (json.JSONDecodeError, TypeError):
                    pass
            out: dict[str, str] = {"proto": r.get("proto") or "ssh"}
            for col in visible:
                if col == "name":
                    out["name"] = r.get("name") or ""
                elif col == "ip_address":
                    out["ip_address"] = r.get("ip_address") or ""
                else:
                    out[col] = str(data.get(col, ""))
            writer.writerow(out)
    return len(rows)


# ---------------------------------------------------------------------------
# Keys export/import
# ---------------------------------------------------------------------------


def export_keys(path: str | Path, vault: Vault, export_password: str) -> int:
    """Decrypt keys with vault, encrypt with export password, write JSON. Returns count."""
    keys = db.list_ssh_keys()
    items = []
    for k in keys:
        kd = dict(k)
        try:
            pk = vault.decrypt(kd["private_key_enc"])
            pp = vault.decrypt(kd["passphrase_enc"]) if kd.get("passphrase_enc") else ""
        except Exception:
            continue
        items.append({
            "label": kd.get("label") or "",
            "username": kd.get("username") or "",
            "private_key": pk,
            "passphrase": pp,
            "prompt_passphrase": int(kd.get("prompt_passphrase") or 0),
        })
    payload = {"items": items}
    plain = json.dumps(payload)
    encrypted = encrypt_with_export_password(plain, export_password, export_type="keys")
    clitty_notify.clitty_notify(f"file created (export keys): {path}", level="debug", log_only=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(encrypted)
    return len(items)


def _parse_export_file(raw: str, export_password: str | None) -> list[dict[str, Any]]:
    """Parse export file (encrypted or plain), return items list."""
    is_encrypted, _ = _detect_export_format(raw)
    if is_encrypted:
        if not export_password:
            raise ValueError("Export password required for encrypted file")
        raw = decrypt_with_export_password(raw, export_password)
    obj = json.loads(raw)
    if isinstance(obj, list):
        return obj
    return obj.get("items", [])


def import_keys(
    path: str | Path,
    vault: Vault,
    export_password: str | None = None,
) -> int:
    """Import keys from JSON (plain or encrypted). Returns count added."""
    raw = Path(path).read_text(encoding="utf-8")
    items = _parse_export_file(raw, export_password)
    added = 0
    for item in items:
        label = (item.get("label") or "").strip()
        username = (item.get("username") or "").strip()
        pk = (item.get("private_key") or "").strip()
        pp = (item.get("passphrase") or "").strip()
        prompt = int(item.get("prompt_passphrase") or 0)
        if not username or not pk or "-----BEGIN" not in pk:
            continue
        pk_enc = vault.encrypt(pk + "\n" if not pk.endswith("\n") else pk)
        pp_enc = vault.encrypt(pp) if pp else ""
        db.add_ssh_key(label, username, pk_enc, pp_enc, prompt_passphrase=prompt)
        added += 1
    return added


# ---------------------------------------------------------------------------
# Credentials export/import
# ---------------------------------------------------------------------------


def export_credentials(path: str | Path, vault: Vault, export_password: str) -> int:
    """Decrypt credentials with vault, encrypt with export password, write JSON. Returns count."""
    creds = db.list_credentials()
    items = []
    for c in creds:
        cd = dict(c)
        try:
            pw = vault.decrypt(cd["password"])
        except Exception:
            continue
        items.append({
            "label": cd.get("label") or "",
            "username": cd.get("username") or "",
            "password": pw,
        })
    payload = {"items": items}
    plain = json.dumps(payload)
    encrypted = encrypt_with_export_password(plain, export_password, export_type="credentials")
    clitty_notify.clitty_notify(f"file created (export credentials): {path}", level="debug", log_only=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(encrypted)
    return len(items)


def import_credentials(
    path: str | Path,
    vault: Vault,
    export_password: str | None = None,
) -> int:
    """Import credentials from JSON (plain or encrypted) or CSV (plain only). Returns count added."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    path_str = str(path).lower()

    if path_str.endswith(".csv"):
        return _import_credentials_csv(raw, vault)

    items = _parse_export_file(raw, export_password)
    added = 0
    for item in items:
        label = (item.get("label") or "").strip()
        username = (item.get("username") or "").strip()
        pw = item.get("password", "")
        if not username:
            continue
        pw_enc = vault.encrypt(pw)
        db.add_credential(username, pw_enc, label=label)
        added += 1
    return added


def _import_credentials_csv(raw: str, vault: Vault) -> int:
    """Import credentials from CSV (header: label,username,password or username,password)."""
    import io

    reader = csv.DictReader(io.StringIO(raw))
    fieldnames = reader.fieldnames or []
    headers_lower = [h.strip().lower() for h in fieldnames]
    header_map = {h: fn for h, fn in zip(headers_lower, fieldnames)}
    label_col = header_map.get("label")
    user_col = header_map.get("username") or header_map.get("user") or (fieldnames[0] if fieldnames else "")
    pw_col = header_map.get("password") or header_map.get("pass") or (fieldnames[-1] if len(fieldnames) >= 2 else "")

    added = 0
    for row in reader:
        username = (row.get(user_col, "") if user_col else "").strip()
        pw = (row.get(pw_col, "") if pw_col else "").strip()
        label = (row.get(label_col, "") if label_col else "").strip()
        if not username:
            continue
        pw_enc = vault.encrypt(pw)
        db.add_credential(username, pw_enc, label=label)
        added += 1
    return added
