"""SQLite database layer for Clitty – 5 tables: credentials, hosts, ssh_keys, connection_profiles, system_settings."""

from __future__ import annotations

import json
import os
import sqlite3

from cryptography.fernet import InvalidToken

from src import clitty_notify
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from src.encryption import Vault

DB_DIR = Path.home() / ".clitty"
DB_PATH = DB_DIR / "clitty.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL,
    password    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_column_defs (
    col_name  TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    visible   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (col_name)
);

CREATE TABLE IF NOT EXISTS hosts (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT NOT NULL DEFAULT '',
    ip_address              TEXT NOT NULL DEFAULT '',
    credential_id           INTEGER,
    key_id                  INTEGER,
    connect_through_host_id INTEGER,
    proto                   TEXT NOT NULL DEFAULT 'ssh',
    data                    TEXT NOT NULL DEFAULT '{}',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL,
    FOREIGN KEY (key_id) REFERENCES ssh_keys(id) ON DELETE SET NULL,
    FOREIGN KEY (connect_through_host_id) REFERENCES hosts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS connection_profiles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL UNIQUE,
    port                INTEGER NOT NULL DEFAULT 22,
    key_file            TEXT NOT NULL DEFAULT '',
    timeout             INTEGER NOT NULL DEFAULT 30,
    compression         INTEGER NOT NULL DEFAULT 0,
    forward_agent       INTEGER NOT NULL DEFAULT 0,
    proxy_command       TEXT NOT NULL DEFAULT '',
    ciphers             TEXT NOT NULL DEFAULT '',
    macs                TEXT NOT NULL DEFAULT '',
    host_key_algorithms TEXT NOT NULL DEFAULT '',
    remote_command      TEXT NOT NULL DEFAULT '',
    local_forwards      TEXT NOT NULL DEFAULT '[]',
    remote_forwards     TEXT NOT NULL DEFAULT '[]',
    dynamic_forwards    TEXT NOT NULL DEFAULT '[]',
    extra_args          TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    label            TEXT NOT NULL DEFAULT '',
    username         TEXT NOT NULL,
    private_key_enc  TEXT NOT NULL,
    passphrase_enc   TEXT NOT NULL DEFAULT '',
    prompt_passphrase INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS host_keys (
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22,
    key_type    TEXT NOT NULL,
    key_data    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (host, port, key_type)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dir() -> None:
    if not DB_DIR.exists():
        clitty_notify.clitty_notify(f"creating db dir: {DB_DIR}", level="debug", log_only=True)
    DB_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DB_DIR, 0o700)
    except OSError:
        pass


def get_connection() -> sqlite3.Connection:
    _ensure_dir()
    clitty_notify.clitty_notify(f"db connection opened: {DB_PATH}", level="debug", log_only=True)
    conn = sqlite3.connect(str(DB_PATH))
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


_HOST_KEYS_MIGRATIONS = [
    ("updated_at", "TEXT NOT NULL DEFAULT ''"),
    ("via_host_id", "INTEGER DEFAULT -1"),
]  # -1 = direct connection; positive = via that host id

_PROFILE_MIGRATIONS = [
    ("compression", "INTEGER NOT NULL DEFAULT 0"),
    ("forward_agent", "INTEGER NOT NULL DEFAULT 0"),
    ("proxy_command", "TEXT NOT NULL DEFAULT ''"),
    ("ciphers", "TEXT NOT NULL DEFAULT ''"),
    ("macs", "TEXT NOT NULL DEFAULT ''"),
    ("host_key_algorithms", "TEXT NOT NULL DEFAULT ''"),
    ("remote_command", "TEXT NOT NULL DEFAULT ''"),
    ("local_forwards", "TEXT NOT NULL DEFAULT '[]'"),
    ("remote_forwards", "TEXT NOT NULL DEFAULT '[]'"),
    ("dynamic_forwards", "TEXT NOT NULL DEFAULT '[]'"),
    ("no_execute", "INTEGER NOT NULL DEFAULT 0"),
]


def init_db() -> None:
    clitty_notify.clitty_notify("db init", level="debug", log_only=True)
    with get_connection() as conn:
        conn.executescript(_SCHEMA)
        host_cols = {row[1] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()}
        if "data" not in host_cols:
            conn.execute("DROP TABLE IF EXISTS hosts")
            conn.execute("""
                CREATE TABLE hosts (
                    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                    name                    TEXT NOT NULL DEFAULT '',
                    ip_address              TEXT NOT NULL DEFAULT '',
                    credential_id           INTEGER,
                    key_id                  INTEGER,
                    connect_through_host_id INTEGER,
                    proto                   TEXT NOT NULL DEFAULT 'ssh',
                    data                    TEXT NOT NULL DEFAULT '{}',
                    created_at              TEXT NOT NULL,
                    updated_at              TEXT NOT NULL,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL,
                    FOREIGN KEY (key_id) REFERENCES ssh_keys(id) ON DELETE SET NULL,
                    FOREIGN KEY (connect_through_host_id) REFERENCES hosts(id) ON DELETE SET NULL
                )
            """)
        profile_cols = {row[1] for row in conn.execute("PRAGMA table_info(connection_profiles)").fetchall()}
        for col_name, col_def in _PROFILE_MIGRATIONS:
            if col_name not in profile_cols:
                conn.execute(f"ALTER TABLE connection_profiles ADD COLUMN {col_name} {col_def}")
        try:
            host_keys_cols = {row[1] for row in conn.execute("PRAGMA table_info(host_keys)").fetchall()}
            for col_name, col_def in _HOST_KEYS_MIGRATIONS:
                if col_name not in host_keys_cols:
                    conn.execute(f"ALTER TABLE host_keys ADD COLUMN {col_name} {col_def}")
                    if col_name == "updated_at":
                        conn.execute(
                            "UPDATE host_keys SET updated_at = created_at WHERE updated_at = '' OR updated_at IS NULL"
                        )
            host_keys_cols = {row[1] for row in conn.execute("PRAGMA table_info(host_keys)").fetchall()}
            migrated = conn.execute(
                "SELECT value FROM system_settings WHERE key = 'host_keys_v2_migrated'"
            ).fetchone()
            if "via_host_id" in host_keys_cols and not migrated:
                conn.execute(
                    """CREATE TABLE host_keys_new (
                            host TEXT NOT NULL,
                            port INTEGER NOT NULL DEFAULT 22,
                            key_type TEXT NOT NULL,
                            via_host_id INTEGER NOT NULL DEFAULT -1,
                            key_data TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY (host, port, key_type, via_host_id)
                    )"""
                )
                conn.execute(
                    """INSERT INTO host_keys_new (host, port, key_type, via_host_id, key_data, created_at, updated_at)
                       SELECT host, port, key_type, COALESCE(via_host_id, -1), key_data, created_at, updated_at FROM host_keys"""
                )
                conn.execute("DROP TABLE host_keys")
                conn.execute("ALTER TABLE host_keys_new RENAME TO host_keys")
                conn.execute(
                    "INSERT INTO system_settings (key, value) VALUES ('host_keys_v2_migrated', '1')"
                )
        except sqlite3.OperationalError:
            pass


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def add_credential(username: str, password_enc: str, label: str = "") -> int:
    now = _now()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO credentials (label, username, password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (label, username, password_enc, now, now),
        )
        rid = cur.lastrowid  # type: ignore[return-value]
    clitty_notify.clitty_notify(f"db add credential: id={rid} username={username}", level="debug", log_only=True)
    return rid


def update_credential(cred_id: int, *, username: str | None = None, password_enc: str | None = None, label: str | None = None) -> None:
    fields: list[str] = []
    values: list[Any] = []
    if username is not None:
        fields.append("username = ?")
        values.append(username)
    if password_enc is not None:
        fields.append("password = ?")
        values.append(password_enc)
    if label is not None:
        fields.append("label = ?")
        values.append(label)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(cred_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE credentials SET {', '.join(fields)} WHERE id = ?", values)


def delete_credential(cred_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    clitty_notify.clitty_notify(f"db delete credential: id={cred_id}", level="debug", log_only=True)


def get_credential(cred_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,)).fetchone()


def list_credentials() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM credentials ORDER BY id").fetchall()


# ---------------------------------------------------------------------------
# SSH Keys
# ---------------------------------------------------------------------------

def add_ssh_key(
    label: str,
    username: str,
    private_key_enc: str,
    passphrase_enc: str = "",
    prompt_passphrase: int = 0,
) -> int:
    now = _now()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO ssh_keys (label, username, private_key_enc, passphrase_enc, prompt_passphrase, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (label, username, private_key_enc, passphrase_enc, prompt_passphrase, now, now),
        )
        rid = cur.lastrowid  # type: ignore[return-value]
    clitty_notify.clitty_notify(f"db add ssh_key: id={rid} username={username}", level="debug", log_only=True)
    return rid


def update_ssh_key(
    key_id: int,
    *,
    label: str | None = None,
    username: str | None = None,
    private_key_enc: str | None = None,
    passphrase_enc: str | None = None,
    prompt_passphrase: int | None = None,
) -> None:
    fields: list[str] = []
    values: list[Any] = []
    if label is not None:
        fields.append("label = ?")
        values.append(label)
    if username is not None:
        fields.append("username = ?")
        values.append(username)
    if private_key_enc is not None:
        fields.append("private_key_enc = ?")
        values.append(private_key_enc)
    if passphrase_enc is not None:
        fields.append("passphrase_enc = ?")
        values.append(passphrase_enc)
    if prompt_passphrase is not None:
        fields.append("prompt_passphrase = ?")
        values.append(prompt_passphrase)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(key_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE ssh_keys SET {', '.join(fields)} WHERE id = ?", values)
    clitty_notify.clitty_notify(f"db update ssh_key: id={key_id}", level="debug", log_only=True)


def delete_ssh_key(key_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM ssh_keys WHERE id = ?", (key_id,))
    clitty_notify.clitty_notify(f"db delete ssh_key: id={key_id}", level="debug", log_only=True)


def get_ssh_key(key_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM ssh_keys WHERE id = ?", (key_id,)).fetchone()


def list_ssh_keys() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM ssh_keys ORDER BY id").fetchall()


# ---------------------------------------------------------------------------
# Host Column Definitions
# ---------------------------------------------------------------------------

def save_column_defs(defs: list[dict[str, Any]]) -> None:
    """Replace all column definitions. Each def: {col_name, seq, visible}."""
    with get_connection() as conn:
        conn.execute("DELETE FROM host_column_defs")
        now_defs = [
            (d["col_name"], d["seq"], d.get("visible", 1))
            for d in defs
        ]
        conn.executemany(
            "INSERT INTO host_column_defs (col_name, seq, visible) VALUES (?, ?, ?)",
            now_defs,
        )
    clitty_notify.clitty_notify(f"db save_column_defs: {len(defs)} columns", level="debug", log_only=True)


def get_column_defs() -> list[sqlite3.Row]:
    """Return column definitions ordered by seq."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT col_name, seq, visible FROM host_column_defs ORDER BY seq"
        ).fetchall()


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

def add_host(
    name: str = "",
    ip_address: str = "",
    credential_id: int | None = None,
    key_id: int | None = None,
    connect_through_host_id: int | None = None,
    proto: str = "ssh",
    data: dict[str, Any] | None = None,
) -> int:
    now = _now()
    data_json = json.dumps(data or {})
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO hosts (name, ip_address, credential_id, key_id, connect_through_host_id, proto, data, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, ip_address, credential_id, key_id, connect_through_host_id, proto, data_json, now, now),
        )
        rid = cur.lastrowid  # type: ignore[return-value]
    clitty_notify.clitty_notify(f"db add host: id={rid} ip={ip_address}", level="debug", log_only=True)
    return rid


def update_host(host_id: int, **kwargs: Any) -> None:
    allowed = {"name", "ip_address", "credential_id", "key_id", "connect_through_host_id", "proto", "data"}
    fields: list[str] = []
    values: list[Any] = []
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k == "data" and isinstance(v, dict):
            v = json.dumps(v)
        fields.append(f"{k} = ?")
        values.append(v)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(host_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE hosts SET {', '.join(fields)} WHERE id = ?", values)
    clitty_notify.clitty_notify(f"db update host: id={host_id}", level="debug", log_only=True)


def update_host_by_ip(ip_address: str, credential_id: int) -> None:
    """Set the credential_id for the host matching the given IP."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE hosts SET credential_id = ?, key_id = NULL, updated_at = ? WHERE ip_address = ?",
            (credential_id, _now(), ip_address),
        )
    clitty_notify.clitty_notify(f"db update_host_by_ip: ip={ip_address} credential_id={credential_id}", level="debug", log_only=True)


def update_host_by_ip_key(ip_address: str, key_id: int) -> None:
    """Set the key_id for the host matching the given IP (clears credential_id)."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE hosts SET key_id = ?, credential_id = NULL, updated_at = ? WHERE ip_address = ?",
            (key_id, _now(), ip_address),
        )
    clitty_notify.clitty_notify(f"db update_host_by_ip_key: ip={ip_address} key_id={key_id}", level="debug", log_only=True)


def delete_host(host_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    clitty_notify.clitty_notify(f"db delete host: id={host_id}", level="debug", log_only=True)


def get_host(host_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()


def get_host_by_ip(ip_address: str) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM hosts WHERE ip_address = ?", (ip_address,)).fetchone()


def get_host_by_name(name: str) -> Optional[sqlite3.Row]:
    """Return the first host with exact name match, or None."""
    with get_connection() as conn:
        return conn.execute("SELECT * FROM hosts WHERE name = ?", (name.strip(),)).fetchone()


def list_hosts_ssh_only(search: str = "") -> list[sqlite3.Row]:
    """Return hosts with proto=ssh only (for use as via/jump hosts)."""
    with get_connection() as conn:
        if search:
            like = f"%{search}%"
            return conn.execute(
                "SELECT * FROM hosts WHERE (name LIKE ? OR ip_address LIKE ? OR data LIKE ?) AND (proto = 'ssh' OR proto IS NULL) ORDER BY name",
                (like, like, like),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM hosts WHERE proto = 'ssh' OR proto IS NULL ORDER BY name"
        ).fetchall()


def list_hosts(search: str = "") -> list[sqlite3.Row]:
    with get_connection() as conn:
        if search:
            like = f"%{search}%"
            return conn.execute(
                "SELECT * FROM hosts WHERE name LIKE ? OR ip_address LIKE ? OR data LIKE ? ORDER BY name",
                (like, like, like),
            ).fetchall()
        return conn.execute("SELECT * FROM hosts ORDER BY name").fetchall()


def get_jump_chain(host_id: int) -> list[sqlite3.Row]:
    """Return jump chain [first_hop, ..., last_hop, target_host].
    Walks connect_through_host_id until a host with none is reached.
    Returns [] on cycle or missing host."""
    seen: set[int] = set()
    chain: list[sqlite3.Row] = []
    current_id: int | None = host_id
    while current_id is not None:
        if current_id in seen:
            return []  # cycle
        seen.add(current_id)
        host = get_host(current_id)
        if not host:
            return []
        chain.append(host)
        cth = host["connect_through_host_id"] if "connect_through_host_id" in host.keys() else None
        current_id = cth if cth else None
    # chain is [target, last_hop, ..., first_hop]; reverse to [first_hop, ..., target]
    return list(reversed(chain))


def bulk_insert_hosts(rows: list[dict[str, Any]]) -> int:
    """Legacy: Insert hosts with old schema. Use bulk_insert_hosts_v2 for new schema."""
    return bulk_insert_hosts_v2(rows)


def bulk_insert_hosts_v2(rows: list[dict[str, Any]]) -> int:
    """Insert multiple hosts, skipping duplicates (matched on name + ip_address).
    Each row: name, ip_address, data (dict for custom columns), credential_id, key_id, connect_through_host_id, proto."""
    now = _now()
    inserted = 0
    with get_connection() as conn:
        for row in rows:
            existing = conn.execute(
                "SELECT id FROM hosts WHERE name = ? AND ip_address = ?",
                (row.get("name", ""), row.get("ip_address", "")),
            ).fetchone()
            if existing:
                continue
            proto = row.get("proto", "ssh") if "proto" in row else "ssh"
            data = row.get("data")
            if isinstance(data, dict):
                data_json = json.dumps(data)
            else:
                data_json = json.dumps(data or {})
            conn.execute(
                "INSERT INTO hosts (name, ip_address, credential_id, key_id, connect_through_host_id, proto, data, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row.get("name", ""),
                    row.get("ip_address", ""),
                    row.get("credential_id"),
                    row.get("key_id"),
                    row.get("connect_through_host_id"),
                    proto,
                    data_json,
                    now,
                    now,
                ),
            )
            inserted += 1
    return inserted


# ---------------------------------------------------------------------------
# Connection Profiles
# ---------------------------------------------------------------------------

def _profile_json_val(val: list[str] | str | None) -> str:
    """Serialize forwards for storage; accept pre-serialized (e.g. encrypted) string."""
    if isinstance(val, str):
        return val
    return json.dumps(val or [])


def add_profile(
    name: str,
    port: int = 22,
    key_file: str = "",
    timeout: int = 30,
    compression: int = 0,
    forward_agent: int = 0,
    proxy_command: str = "",
    ciphers: str = "",
    macs: str = "",
    host_key_algorithms: str = "",
    remote_command: str = "",
    local_forwards: list[str] | str | None = None,
    remote_forwards: list[str] | str | None = None,
    dynamic_forwards: list[str] | str | None = None,
    extra_args: str = "",
    no_execute: int = 0,
) -> int:
    now = _now()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO connection_profiles "
            "(name, port, key_file, timeout, compression, forward_agent, proxy_command, "
            "ciphers, macs, host_key_algorithms, remote_command, "
            "local_forwards, remote_forwards, dynamic_forwards, extra_args, no_execute, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name, port, key_file, timeout, compression, forward_agent, proxy_command,
                ciphers, macs, host_key_algorithms, remote_command,
                _profile_json_val(local_forwards),
                _profile_json_val(remote_forwards),
                _profile_json_val(dynamic_forwards),
                extra_args, no_execute, now, now,
            ),
        )
        rid = cur.lastrowid  # type: ignore[return-value]
    clitty_notify.clitty_notify(f"db add profile: id={rid} name={name}", level="debug", log_only=True)
    return rid


def update_profile(profile_id: int, **kwargs: Any) -> None:
    _json_cols = {"local_forwards", "remote_forwards", "dynamic_forwards"}
    fields: list[str] = []
    values: list[Any] = []
    for k, v in kwargs.items():
        if k in _json_cols and not isinstance(v, str):
            v = json.dumps(v or [])
        fields.append(f"{k} = ?")
        values.append(v)
    if not fields:
        return
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(profile_id)
    with get_connection() as conn:
        conn.execute(f"UPDATE connection_profiles SET {', '.join(fields)} WHERE id = ?", values)


def delete_profile(profile_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM connection_profiles WHERE id = ?", (profile_id,))
    clitty_notify.clitty_notify(f"db delete profile: id={profile_id}", level="debug", log_only=True)


def get_profile(profile_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM connection_profiles WHERE id = ?", (profile_id,)).fetchone()


def list_profiles() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM connection_profiles ORDER BY name").fetchall()


# ---------------------------------------------------------------------------
# System Settings (encrypted except bootstrap keys)
# ---------------------------------------------------------------------------

# Keys that must stay plain: they bootstrap the vault
_PLAIN_SETTING_KEYS = frozenset({"encryption_salt", "encryption_dek"})

_settings_vault: "Vault | None" = None


def set_settings_vault(vault: "Vault | None") -> None:
    """Set the vault used for encrypting/decrypting settings. Call after unlock."""
    global _settings_vault
    _settings_vault = vault


def get_setting(
    key: str, default: str = "", vault: "Vault | None" = None
) -> str:
    v = vault if vault is not None else _settings_vault
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
        raw = row["value"] if row else ""
    if key in _PLAIN_SETTING_KEYS:
        return raw or default
    if v and raw:
        try:
            return v.decrypt(raw)
        except InvalidToken:
            pass  # Migration: plaintext, use as-is
    return raw or default


def set_setting(
    key: str, value: str, vault: "Vault | None" = None
) -> None:
    v = vault if vault is not None else _settings_vault
    if key in _PLAIN_SETTING_KEYS:
        to_store = value
    elif v:
        to_store = v.encrypt(value)
    else:
        to_store = value
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, to_store),
        )


def delete_setting(key: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM system_settings WHERE key = ?", (key,))
    clitty_notify.clitty_notify(f"db delete_setting: key={key}", level="debug", log_only=True)


def list_settings() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM system_settings ORDER BY key").fetchall()


# ---------------------------------------------------------------------------
# Host Keys (for SSH host key verification)
# ---------------------------------------------------------------------------

def _via_host_id_db(via_host_id: int | None) -> int:
    """Map via_host_id=None to -1 for direct connection."""
    return -1 if via_host_id is None else via_host_id


def get_host_keys(
    host: str, port: int = 22, via_host_id: int | None = None
) -> list[tuple[str, str]]:
    """Return list of (key_type, key_data) for the given host:port.
    via_host_id: None = direct connection; int = reached via that jump host."""
    vid = _via_host_id_db(via_host_id)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT key_type, key_data FROM host_keys WHERE host = ? AND port = ? AND via_host_id = ?",
            (host, port, vid),
        ).fetchall()
        return [(row["key_type"], row["key_data"]) for row in rows]


def set_host_key(
    host: str,
    port: int,
    key_type: str,
    key_data: str,
    via_host_id: int | None = None,
) -> None:
    """Insert or replace a host key. via_host_id: None = direct, int = via that jump host."""
    vid = _via_host_id_db(via_host_id)
    now = _now()
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO host_keys (host, port, key_type, via_host_id, key_data, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host, port, key_type, via_host_id) DO UPDATE SET key_data = excluded.key_data, updated_at = excluded.updated_at""",
            (host, port, key_type, vid, key_data, now, now),
        )


def delete_host_key(
    host: str, port: int, key_type: str, via_host_id: int | None = None
) -> None:
    """Remove a host key (e.g. after server key rotation)."""
    vid = _via_host_id_db(via_host_id)
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM host_keys WHERE host = ? AND port = ? AND key_type = ? AND via_host_id = ?",
            (host, port, key_type, vid),
        )
    clitty_notify.clitty_notify(f"db delete_host_key: host={host} port={port} key_type={key_type}", level="debug", log_only=True)


def list_host_keys() -> list[sqlite3.Row]:
    """Return all host keys, ordered by host, port, key_type."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT host, port, key_type, via_host_id, key_data, created_at, updated_at FROM host_keys ORDER BY host, port, key_type"
        ).fetchall()
