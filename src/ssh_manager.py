"""SSH connection logic: credential probing via Paramiko and interactive sessions.

All key-based auth uses ssh-agent: keys are added to the agent at startup or
on demand, and both Paramiko and subprocess SSH use the agent for key selection.
"""

from __future__ import annotations

import json
import os
import select
import shlex
import shutil
import socket
import subprocess
import sqlite3
import sys
import tempfile
import threading
from base64 import decodebytes
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import paramiko
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import BadHostKeyException

from src import database as db
from src.encryption import Vault, decrypt_profile_row
from src import clitty_notify

_host_key_notify_callbacks: list = []


def register_host_key_warning_callback(callback) -> None:
    """Register a callback(message: str, severity: str) for host key notifications.
    Severity: 'information', 'warning', 'error'. Used by UI for notifications."""
    _host_key_notify_callbacks.append(callback)


def unregister_host_key_warning_callback(callback) -> None:
    """Remove a previously registered callback."""
    if callback in _host_key_notify_callbacks:
        _host_key_notify_callbacks.remove(callback)


def _emit_host_key_notify(msg: str, severity: str = "information") -> None:
    """Emit host key notification via clitty_notify (log + terminal/toast)."""
    level = "warn" if severity == "warning" else ("error" if severity == "error" else "info")
    clitty_notify.clitty_notify(msg, level=level, context=None)


# ---------------------------------------------------------------------------
# Temp file scanning (known issues)
# ---------------------------------------------------------------------------


def scan_temp_files() -> list[Path]:
    """Scan system temp directory for leftover cliTTY temp files.

    Returns list of paths to matching files. Also logs details for each file
    at info level (log_only) so users can see exactly which files are safe
    to delete.
    """
    tmpdir = Path(tempfile.gettempdir())
    patterns = [
        "clitty-kh-*.txt",   # known_hosts temp files
        "clitty-pw-*.tmp",   # password wrapper files
        "clitty-session-*",  # session data files
        "clitty-agent-*.pem",
        "clitty-askpass-*.py",
    ]
    seen: set[Path] = set()
    for pattern in patterns:
        for path in tmpdir.glob(pattern):
            if path.exists():
                seen.add(path.resolve())

    files = sorted(seen)
    if not files:
        return []

    clitty_notify.clitty_notify(
        f"Found {len(files)} leftover cliTTY temp file(s) in {tmpdir}. They can be safely deleted when no cliTTY sessions are running.",
        level="info",
        log_only=True,
    )
    for path in files:
        clitty_notify.clitty_notify(
            f"Leftover cliTTY temp file: {path} (safe to delete when not used by an active cliTTY session).",
            level="info",
            log_only=True,
        )
    return files


def _emit_host_key_added(host: str, port: int, key_count: int = 1) -> None:
    """Emit info notification when host key(s) are added."""
    s = "s" if key_count > 1 else ""
    msg = f"Host key{s} added for {host}:{port}"
    _emit_host_key_notify(msg, "information")


def _emit_host_key_change_warning(host: str, port: int) -> None:
    """Emit host key change warning: log, stderr, and UI callbacks."""
    msg = f"Host key changed for {host}:{port} (possible MITM). Stored key updated."
    _emit_host_key_notify(msg, "warning")


def _emit_host_key_rejected(host: str, port: int, reason: str) -> None:
    """Emit error notification when host key is rejected (strict mode, unknown host)."""
    msg = f"Host key rejected for {host}:{port}: {reason}"
    _emit_host_key_notify(msg, "error")

# ---------------------------------------------------------------------------
# ssh-agent helpers
# ---------------------------------------------------------------------------

_agent_loaded_key_ids: set[int] = set()

NEEDS_PASSPHRASE = "NEEDS_PASSPHRASE"


def _is_auto_probe_enabled() -> bool:
    """Return True if automatic credential/key probing is enabled in settings."""
    val = (db.get_setting("auto_probe_credentials", "true") or "true").lower()
    return val in ("true", "1", "yes")


def ensure_agent() -> bool:
    """Ensure ssh-agent is running. Returns True if agent is available.
    Checks env first, then saved socket from DB; if neither works, starts a new agent.
    Agent is not closed on app exit—only when user explicitly presses k (close_agent)."""
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if sock and os.path.exists(sock):
        return True
    saved = db.get_setting("ssh_auth_sock", "")
    if saved and os.path.exists(saved):
        os.environ["SSH_AUTH_SOCK"] = saved
        saved_pid = db.get_setting("ssh_agent_pid", "")
        if saved_pid:
            os.environ["SSH_AGENT_PID"] = saved_pid
        return True
    return start_agent()


def start_agent() -> bool:
    """Start ssh-agent and set SSH_AUTH_SOCK/SSH_AGENT_PID in environment.
    Returns True if agent was started successfully."""
    ssh_agent_bin = shutil.which("ssh-agent")
    if not ssh_agent_bin:
        clitty_notify.clitty_notify("ssh-agent could not be started: binary not found", level="error")
        clitty_notify.clitty_notify("ssh-agent start failed: binary not found", level="error", log_only=True)
        return False
    try:
        result = subprocess.run(
            [ssh_agent_bin, "-s"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            clitty_notify.clitty_notify("ssh-agent could not be started", level="error")
            clitty_notify.clitty_notify(f"ssh-agent start failed: returncode={result.returncode}", level="error", log_only=True)
            return False
        for line in result.stdout.splitlines():
            if "SSH_AUTH_SOCK" in line and "=" in line:
                val = line.split("=", 1)[1].split(";", 1)[0]
                os.environ["SSH_AUTH_SOCK"] = val
            elif "SSH_AGENT_PID" in line and "=" in line:
                val = line.split("=", 1)[1].split(";", 1)[0]
                os.environ["SSH_AGENT_PID"] = val
        sock = os.environ.get("SSH_AUTH_SOCK", "")
        pid = os.environ.get("SSH_AGENT_PID", "")
        if sock:
            db.set_setting("ssh_auth_sock", sock)
        if pid:
            db.set_setting("ssh_agent_pid", pid)
        clitty_notify.clitty_notify(f"ssh-agent started: sock={sock}", level="debug", log_only=True)
        return bool(sock)
    except (subprocess.TimeoutExpired, OSError) as e:
        clitty_notify.clitty_notify("ssh-agent could not be started", level="error")
        clitty_notify.clitty_notify(f"ssh-agent start failed: {e}", level="error", log_only=True)
        return False


def close_agent() -> bool:
    """Kill the ssh-agent process if we own it (SSH_AGENT_PID set).
    Clears SSH_AUTH_SOCK and SSH_AGENT_PID from environment.
    Returns True if agent was closed, False if none was running or not killable."""
    pid_str = os.environ.pop("SSH_AGENT_PID", None)
    os.environ.pop("SSH_AUTH_SOCK", None)
    if not pid_str:
        return False
    try:
        pid = int(pid_str)
    except ValueError:
        return False
    ssh_agent_bin = shutil.which("ssh-agent")
    if ssh_agent_bin:
        try:
            subprocess.run(
                [ssh_agent_bin, "-k"],
                env={**os.environ, "SSH_AGENT_PID": pid_str},
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            try:
                os.kill(pid, 9)
            except OSError:
                pass
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    _agent_loaded_key_ids.clear()
    db.delete_setting("ssh_auth_sock")
    db.delete_setting("ssh_agent_pid")
    clitty_notify.clitty_notify("ssh-agent closed", level="info", log_only=True)
    clitty_notify.clitty_notify("ssh-agent closed: cleared sock, pid, loaded keys", level="debug", log_only=True)
    return True


def is_agent_running() -> bool:
    """Check if ssh-agent socket is available (from env or saved DB). Does NOT start agent."""
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if sock and os.path.exists(sock):
        return True
    saved = db.get_setting("ssh_auth_sock", "")
    if saved and os.path.exists(saved):
        os.environ["SSH_AUTH_SOCK"] = saved
        saved_pid = db.get_setting("ssh_agent_pid", "")
        if saved_pid:
            os.environ["SSH_AGENT_PID"] = saved_pid
        return True
    return False


def _ssh_add_key(key_pem: str, passphrase: Optional[str] = None) -> tuple[bool, str | None]:
    """Add a PEM key string to the running ssh-agent via ssh-add.
    Uses SSH_ASKPASS with a helper script to provide the passphrase
    non-interactively (passphrase is passed via env var, never written to disk).
    Returns (success, error_message)."""
    ssh_add_bin = shutil.which("ssh-add")
    if not ssh_add_bin:
        return False, "ssh-add not found"
    if not ensure_agent():
        return False, "ssh-agent not available"

    fd, key_path = tempfile.mkstemp(prefix="clitty-agent-", suffix=".pem")
    clitty_notify.clitty_notify(f"temp file created: {key_path}", level="debug", log_only=True)
    askpass_path: Optional[str] = None
    try:
        if not key_pem.endswith("\n"):
            key_pem = key_pem + "\n"
        os.write(fd, key_pem.encode())
        os.close(fd)
        os.chmod(key_path, 0o600)

        env = os.environ.copy()
        if passphrase:
            afd, askpass_path = tempfile.mkstemp(prefix="clitty-askpass-", suffix=".py")
            clitty_notify.clitty_notify(f"temp file created: {askpass_path}", level="debug", log_only=True)
            script = (
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "sys.stdout.write(os.environ.get('_CLITTY_PP', '') + '\\n')\n"
            )
            os.write(afd, script.encode())
            os.close(afd)
            os.chmod(askpass_path, 0o700)
            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["_CLITTY_PP"] = passphrase

        result = subprocess.run(
            [ssh_add_bin, "-t", "8h", key_path],
            env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr.strip() or "ssh-add failed"
    except subprocess.TimeoutExpired:
        return False, "ssh-add timed out"
    except OSError as e:
        return False, str(e)
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass
        if askpass_path:
            try:
                os.unlink(askpass_path)
            except OSError:
                pass


def add_key_to_agent(key_id: int, vault: Vault) -> tuple[bool, str | None]:
    """Decrypt a stored key and add it to ssh-agent. Skips prompt_passphrase keys
    (returns NEEDS_PASSPHRASE). Returns (success, error_message)."""
    if key_id in _agent_loaded_key_ids:
        return True, None
    key_row = db.get_ssh_key(key_id)
    if not key_row:
        return False, "Key not found"
    if key_row["prompt_passphrase"]:
        return False, NEEDS_PASSPHRASE
    try:
        key_pem = vault.decrypt(key_row["private_key_enc"])
        passphrase = vault.decrypt(key_row["passphrase_enc"]) if key_row["passphrase_enc"] else None
    except Exception:
        return False, "Failed to decrypt key"
    ok, err = _ssh_add_key(key_pem, passphrase)
    if ok:
        _agent_loaded_key_ids.add(key_id)
        clitty_notify.clitty_notify(f"key added to agent: key_id={key_id}", level="debug", log_only=True)
    return ok, err


def add_key_to_agent_with_passphrase(
    key_id: int, vault: Vault, passphrase: str,
) -> tuple[bool, str | None]:
    """Add a prompt_passphrase key to ssh-agent using a user-supplied passphrase.
    Returns (success, error_message)."""
    if key_id in _agent_loaded_key_ids:
        return True, None
    key_row = db.get_ssh_key(key_id)
    if not key_row:
        return False, "Key not found"
    try:
        key_pem = vault.decrypt(key_row["private_key_enc"])
    except Exception:
        return False, "Failed to decrypt key"
    ok, err = _ssh_add_key(key_pem, passphrase)
    if ok:
        _agent_loaded_key_ids.add(key_id)
        clitty_notify.clitty_notify(f"key added to agent (with passphrase): key_id={key_id}", level="debug", log_only=True)
    return ok, err


def preload_agent_keys(vault: Vault) -> int:
    """Add all non-prompt keys to ssh-agent. Returns count of keys added."""
    if not ensure_agent():
        return 0
    count = 0
    for key_row in db.list_ssh_keys():
        if key_row["prompt_passphrase"]:
            continue
        ok, _ = add_key_to_agent(key_row["id"], vault)
        if ok:
            count += 1
    return count


def load_unloaded_keys_to_agent(vault: Vault) -> tuple[int, list[int]]:
    """Load all unloaded keys that don't require a passphrase prompt.
    Returns (count_added, list of key_ids that need passphrase to be loaded)."""
    if not ensure_agent():
        return 0, []
    added = 0
    need_passphrase: list[int] = []
    for key_row in db.list_ssh_keys():
        if key_row["id"] in _agent_loaded_key_ids:
            continue
        if key_row["prompt_passphrase"]:
            need_passphrase.append(key_row["id"])
            continue
        ok, _ = add_key_to_agent(key_row["id"], vault)
        if ok:
            added += 1
    return added, need_passphrase


def is_key_loaded(key_id: int) -> bool:
    """Check if a key has been added to the agent in this session."""
    return key_id in _agent_loaded_key_ids


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    """Resolved authentication for SSH: password or agent-based key auth."""
    username: str
    password: Optional[str] = None
    use_agent: bool = False


@dataclass
class ProfileOpts:
    """Resolved options from a connection_profiles row."""
    port: int = 22
    timeout: int = 30
    key_file: str = ""
    compression: bool = False
    forward_agent: bool = False
    no_execute: bool = False
    proxy_command: str = ""
    ciphers: str = ""
    macs: str = ""
    host_key_algorithms: str = ""
    remote_command: str = ""
    local_forwards: list[str] = field(default_factory=list)
    remote_forwards: list[str] = field(default_factory=list)
    dynamic_forwards: list[str] = field(default_factory=list)
    extra_args: str = ""


# ---------------------------------------------------------------------------
# Auth resolution
# ---------------------------------------------------------------------------

def _resolve_auth(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    key_id: Optional[int],
    port: int = 22,
    timeout: int = 10,
    allow_probe: bool = True,
    credential_storage_ip: Optional[str] = None,
) -> tuple[Optional[AuthResult], Optional[str]]:
    """Resolve auth from credential_id or key_id. Returns (AuthResult, error_msg).

    Key auth uses ssh-agent. Returns NEEDS_PASSPHRASE error for prompt_passphrase
    keys not yet loaded -- caller should prompt the user and call
    add_key_to_agent_with_passphrase, then retry.
    Probes credentials and agent keys when both IDs are None and allow_probe=True.
    credential_storage_ip: when set (e.g. target IP when connecting via forward), use for
    update_host_by_ip so the credential is saved to the correct host."""
    if key_id:
        key_row = db.get_ssh_key(key_id)
        if not key_row:
            return None, "Key not found"
        if is_key_loaded(key_id):
            return AuthResult(username=key_row["username"], use_agent=True), None
        ok, err = add_key_to_agent(key_id, vault)
        if not ok:
            if err == NEEDS_PASSPHRASE:
                return None, NEEDS_PASSPHRASE
            return None, err or "Failed to add key to agent"
        return AuthResult(username=key_row["username"], use_agent=True), None

    if credential_id:
        cred = db.get_credential(credential_id)
        if not cred:
            return None, "Credential not found"
        try:
            password = vault.decrypt(cred["password"])
        except Exception:
            return None, "Failed to decrypt credential"
        return AuthResult(username=cred["username"], password=password), None

    if allow_probe:
        probed_id = probe_credentials(ip, vault, port=port, timeout=timeout)
        if probed_id is not None:
            storage_ip = credential_storage_ip if credential_storage_ip is not None else ip
            db.update_host_by_ip(storage_ip, probed_id)
            clitty_notify.clitty_notify(f"Host {storage_ip} credential probed, updated to cred_id={probed_id}", level="debug", log_only=True)
            cred = db.get_credential(probed_id)
            if cred:
                try:
                    password = vault.decrypt(cred["password"])
                    return AuthResult(username=cred["username"], password=password), None
                except Exception:
                    pass
        probed_key_id = probe_keys(ip, vault, port=port, timeout=timeout)
        if probed_key_id is not None:
            storage_ip = credential_storage_ip if credential_storage_ip is not None else ip
            db.update_host_by_ip_key(storage_ip, probed_key_id)
            clitty_notify.clitty_notify(f"Host {storage_ip} key probed, updated to key_id={probed_key_id}", level="debug", log_only=True)
            key_row = db.get_ssh_key(probed_key_id)
            if key_row:
                return AuthResult(username=key_row["username"], use_agent=True), None
        return None, "No valid credential or key found"

    return None, "No credential or key specified"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_json_list(raw: str) -> list[str]:
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _get_profile_decrypted(profile_id: Optional[int], vault: Optional[Vault]) -> dict:
    """Fetch profile and decrypt sensitive fields. Returns dict or {}."""
    if not profile_id:
        return {}
    row = db.get_profile(profile_id)
    if not row:
        return {}
    if not vault:
        return dict(row)
    return decrypt_profile_row(row, vault)


def _resolve_profile(profile: Optional[sqlite3.Row | dict]) -> ProfileOpts:
    if profile is None or (isinstance(profile, dict) and not profile):
        return ProfileOpts()
    return ProfileOpts(
        port=profile["port"],
        timeout=profile["timeout"],
        key_file=profile["key_file"] or "",
        compression=bool(profile["compression"]),
        forward_agent=bool(profile["forward_agent"]),
        no_execute=bool(profile.get("no_execute", 0) or 0),
        proxy_command=profile["proxy_command"] or "",
        ciphers=profile["ciphers"] or "",
        macs=profile["macs"] or "",
        host_key_algorithms=profile["host_key_algorithms"] or "",
        remote_command=profile["remote_command"] or "",
        local_forwards=_parse_json_list(profile["local_forwards"]),
        remote_forwards=_parse_json_list(profile["remote_forwards"]),
        dynamic_forwards=_parse_json_list(profile["dynamic_forwards"]),
        extra_args=profile["extra_args"] or "",
    )


def _apply_host_proxy_override(opts: ProfileOpts, host_id: Optional[int]) -> ProfileOpts:
    """Apply per-host override: when host has use_proxy_and_extra_args=False,
    clear proxy_command and extra_args so they are not run (profile keeps them stored)."""
    if host_id is None:
        return opts
    host = db.get_host(host_id)
    if not host or not host.get("data"):
        return opts
    try:
        raw = host["data"]
        data = json.loads(raw) if isinstance(raw, str) else (raw or {})
        if not isinstance(data, dict):
            return opts
        use_proxy = data.get("use_proxy_and_extra_args", True)
        if use_proxy in (True, "true", "1", 1, "yes"):
            return opts
    except (json.JSONDecodeError, TypeError):
        return opts
    return ProfileOpts(
        port=opts.port,
        timeout=opts.timeout,
        key_file=opts.key_file,
        compression=opts.compression,
        forward_agent=opts.forward_agent,
        no_execute=opts.no_execute,
        proxy_command="",
        ciphers=opts.ciphers,
        macs=opts.macs,
        host_key_algorithms=opts.host_key_algorithms,
        remote_command=opts.remote_command,
        local_forwards=opts.local_forwards,
        remote_forwards=opts.remote_forwards,
        dynamic_forwards=opts.dynamic_forwards,
        extra_args="",
    )


def _build_paramiko_connect_kwargs(
    ip: str,
    username: str,
    opts: ProfileOpts,
    password: Optional[str] = None,
    use_agent: bool = False,
) -> dict:
    """Build the kwargs dict for paramiko SSHClient.connect().
    allow_agent (agent auth) is independent of forward_agent (SSH -A flag)."""
    kw: dict = dict(
        hostname=ip,
        port=opts.port,
        username=username,
        timeout=opts.timeout,
        compress=opts.compression,
    )
    if password:
        kw["password"] = password
        kw["look_for_keys"] = False
        kw["allow_agent"] = False
    elif use_agent:
        kw["look_for_keys"] = False
        kw["allow_agent"] = True
    elif opts.key_file:
        kw["key_filename"] = opts.key_file
        kw["look_for_keys"] = False
        kw["allow_agent"] = False
    else:
        kw["look_for_keys"] = True
        kw["allow_agent"] = True
    return kw


# ---------------------------------------------------------------------------
# Host key verification (DB-backed)
# ---------------------------------------------------------------------------

def _pkey_from_base64(key_type: str, key_data: str) -> paramiko.PKey:
    """Construct a Paramiko PKey from (key_type, base64_key_data)."""
    data = decodebytes(key_data.encode("ascii"))
    if key_type == "ssh-rsa":
        return RSAKey(data=data)
    if key_type == "ssh-ed25519":
        return Ed25519Key(data=data)
    if key_type.startswith("ecdsa-sha2-"):
        return ECDSAKey(data=data)
    if key_type == "ssh-dss":
        from paramiko.dsskey import DSSKey
        return DSSKey(data=data)
    raise ValueError(f"Unknown host key type: {key_type}")


def _get_host_key_settings() -> tuple[str, str]:
    """Return (host_key_verification, host_key_policy)."""
    verification = (db.get_setting("host_key_verification", "on") or "on").lower()
    policy = db.get_setting("host_key_policy", "accept_new") or "accept_new"
    return verification, policy


def _host_key_identity(
    host: str, port: int,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> tuple[str, int, Optional[int]]:
    """Resolve (host, port, via_host_id) for host key DB ops."""
    if host_key_host is not None and host_key_port is not None:
        return (host_key_host, host_key_port, host_key_via_host_id)
    return (host, port, None)


class _ClittyAcceptNewPolicy(paramiko.MissingHostKeyPolicy):
    """Accept on first connect: add to DB; subsequent connects verified via preloaded keys."""

    def __init__(
        self,
        port: int,
        host_key_host: Optional[str] = None,
        host_key_port: Optional[int] = None,
        host_key_via_host_id: Optional[int] = None,
    ):
        self._port = port
        self._hk_host = host_key_host
        self._hk_port = host_key_port
        self._hk_via = host_key_via_host_id

    def _storage_identity(self, hostname: str) -> tuple[str, int, Optional[int]]:
        h, p, v = _host_key_identity(hostname, self._port, self._hk_host, self._hk_port, self._hk_via)
        return (h, p, v)

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        h, p, v = self._storage_identity(hostname)
        db.set_host_key(h, p, key.get_name(), key.get_base64(), via_host_id=v)
        client.get_host_keys().add(hostname, key.get_name(), key)
        _emit_host_key_added(h, p, 1)


class _ClittyStrictPolicy(paramiko.MissingHostKeyPolicy):
    """Strict: only allow if key already in DB. Reject unknown hosts."""

    def __init__(self, port: int) -> None:
        self._port = port

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        reason = "Host key not in known hosts. Add manually or use 'Accept on first connect'."
        _emit_host_key_rejected(hostname, self._port, reason)
        raise BadHostKeyException(hostname, key, reason)


class _ClittyWarnPolicy(paramiko.MissingHostKeyPolicy):
    """Warn on change: add on first; on mismatch warn, update DB, allow."""

    def __init__(
        self,
        port: int,
        host_key_host: Optional[str] = None,
        host_key_port: Optional[int] = None,
        host_key_via_host_id: Optional[int] = None,
    ):
        self._port = port
        self._hk_host = host_key_host
        self._hk_port = host_key_port
        self._hk_via = host_key_via_host_id

    def _storage_identity(self, hostname: str) -> tuple[str, int, Optional[int]]:
        return _host_key_identity(hostname, self._port, self._hk_host, self._hk_port, self._hk_via)

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        h, p, v = self._storage_identity(hostname)
        stored = db.get_host_keys(h, p, via_host_id=v)
        if stored:
            _emit_host_key_change_warning(h, p)
        else:
            _emit_host_key_added(h, p, 1)
        db.set_host_key(h, p, key.get_name(), key.get_base64(), via_host_id=v)
        client.get_host_keys().add(hostname, key.get_name(), key)


def _apply_paramiko_host_key_policy(
    client: paramiko.SSHClient,
    host: str,
    port: int,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> None:
    """Load host keys from DB into client and set the appropriate policy based on settings."""
    verification, policy = _get_host_key_settings()
    h, p, v = _host_key_identity(host, port, host_key_host, host_key_port, host_key_via_host_id)
    if verification != "on":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return

    for key_type, key_data in db.get_host_keys(h, p, via_host_id=v):
        try:
            pkey = _pkey_from_base64(key_type, key_data)
            client.get_host_keys().add(host, key_type, pkey)
        except (ValueError, Exception) as e:
            clitty_notify.clitty_notify(
                f"Could not load host key {key_type} for {h}:{p}: {e}",
                level="debug", log_only=True
            )

    if policy == "accept_new":
        client.set_missing_host_key_policy(
            _ClittyAcceptNewPolicy(port, host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id)
        )
    elif policy == "strict":
        client.set_missing_host_key_policy(_ClittyStrictPolicy(port))
    else:
        client.set_missing_host_key_policy(
            _ClittyWarnPolicy(port, host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id)
        )


def fetch_host_keys_from_server(host: str, port: int = 22, timeout: int = 10) -> list[tuple[str, str]]:
    """Fetch host keys via ssh-keyscan. Returns list of (key_type, key_data). Raises OSError on failure."""
    return _ssh_keyscan(host, port, timeout)


def _ssh_keyscan(host: str, port: int, timeout: int = 10) -> list[tuple[str, str]]:
    """Run ssh-keyscan and parse output. Returns list of (key_type, key_data). Raises on failure."""
    keyscan = shutil.which("ssh-keyscan")
    if not keyscan:
        raise OSError("ssh-keyscan not found (required for host key verification)")
    result = subprocess.run(
        [keyscan, "-p", str(port), host],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise OSError(f"ssh-keyscan failed: {result.stderr or result.stdout}")
    keys: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 3:
            host_part, key_type, key_data = parts[0], parts[1], parts[2]
            if key_type.startswith("ssh-") or key_type.startswith("ecdsa-"):
                keys.append((key_type, key_data))
    return keys


def _ensure_host_key(
    host: str,
    port: int,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> list[tuple[str, str]]:
    """Ensure we have host key(s) for host:port. Returns list of (key_type, key_data).
    host_key_* override the DB lookup identity (for forwarded connections)."""
    verification, policy = _get_host_key_settings()
    h, p, v = _host_key_identity(host, port, host_key_host, host_key_port, host_key_via_host_id)
    stored = db.get_host_keys(h, p, via_host_id=v)
    if verification != "on":
        return []

    if policy == "strict":
        if not stored:
            reason = "Host key not in known hosts. Add manually or use 'Accept on first connect'."
            _emit_host_key_rejected(h, p, reason)
            raise OSError(f"Host key for {h}:{p} not in known hosts. Add manually or use 'Accept on first connect'.")
        return stored

    if policy == "warn":
        try:
            current = _ssh_keyscan(host, port)
        except OSError as e:
            if stored:
                return stored
            raise
        added_count = 0
        for key_type, key_data in current:
            existing = [(kt, kd) for kt, kd in stored if kt == key_type]
            if existing and existing[0][1] != key_data:
                _emit_host_key_change_warning(h, p)
            elif not existing:
                added_count += 1
            db.set_host_key(h, p, key_type, key_data, via_host_id=v)
        if added_count > 0:
            _emit_host_key_added(h, p, added_count)
        return current if current else stored

    # accept_new
    if stored:
        return stored
    keys = _ssh_keyscan(host, port)
    if not keys:
        raise OSError(f"ssh-keyscan returned no keys for {host}:{port}")
    for key_type, key_data in keys:
        db.set_host_key(h, p, key_type, key_data, via_host_id=v)
    _emit_host_key_added(h, p, len(keys))
    return keys


def _write_known_hosts_file(
    host: str,
    port: int,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> str:
    """Write known_hosts file for host:port. host_key_* override DB lookup (for forwarded connections)."""
    verification, _ = _get_host_key_settings()
    if verification != "on":
        fd, path = tempfile.mkstemp(prefix="clitty-kh-", suffix=".txt")
        clitty_notify.clitty_notify(f"temp file created (empty known_hosts): {path}", level="debug", log_only=True)
        os.close(fd)
        return path
    keys = _ensure_host_key(host, port, host_key_host, host_key_port, host_key_via_host_id)
    fd, path = tempfile.mkstemp(prefix="clitty-kh-", suffix=".txt")
    clitty_notify.clitty_notify(f"temp file created (known_hosts): {path}", level="debug", log_only=True)
    try:
        with os.fdopen(fd, "w") as f:
            host_spec = f"[{host}]:{port}" if port != 22 else host
            for key_type, key_data in keys:
                f.write(f"{host_spec} {key_type} {key_data}\n")
    except Exception:
        os.unlink(path)
        raise
    return path


def _get_subprocess_host_key_args(
    host: str,
    port: int,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> list[str]:
    """Return -o args for host key handling. host_key_* override DB lookup (for forwarded connections)."""
    verification, policy = _get_host_key_settings()
    if verification != "on":
        return ["-o", "StrictHostKeyChecking=no"]
    if policy == "warn":
        try:
            _ensure_host_key(host, port, host_key_host, host_key_port, host_key_via_host_id)
        except OSError:
            pass
        return ["-o", "StrictHostKeyChecking=no"]
    path = _write_known_hosts_file(host, port, host_key_host, host_key_port, host_key_via_host_id)
    return ["-o", f"UserKnownHostsFile={path}", "-o", "StrictHostKeyChecking=yes"]


# ---------------------------------------------------------------------------
# Port forwarding
# ---------------------------------------------------------------------------

def _run_local_forward(
    transport: paramiko.Transport,
    local_port: int,
    remote_host: str,
    remote_port: int,
    bind_addr: str = "",
) -> None:
    """Run local port forward (-L): listen locally, tunnel to remote via direct-tcpip."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_addr, local_port))
    except OSError:
        sock.close()
        return
    sock.listen(5)

    while transport.active:
        r, _, _ = select.select([sock], [], [], 0.5)
        if not r:
            continue
        try:
            client_sock, _ = sock.accept()
        except OSError:
            break

        def handle(cs: socket.socket) -> None:
            try:
                chan = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    cs.getpeername(),
                )
            except Exception:
                cs.close()
                return
            if chan is None:
                cs.close()
                return
            try:
                while True:
                    rfd, _, _ = select.select([cs, chan], [], [])
                    if cs in rfd:
                        data = cs.recv(4096)
                        if not data:
                            break
                        chan.send(data)
                    if chan in rfd:
                        data = chan.recv(4096)
                        if not data:
                            break
                        cs.sendall(data)
            except (EOFError, OSError):
                pass
            finally:
                try:
                    chan.close()
                except Exception:
                    pass
                try:
                    cs.close()
                except Exception:
                    pass

        th = threading.Thread(target=handle, args=(client_sock,), daemon=True)
        th.start()

    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# SSH / SFTP command builders
# ---------------------------------------------------------------------------

def _build_ssh_argv(
    ip: str,
    username: str,
    opts: ProfileOpts,
    *,
    use_agent: bool = False,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> list[str]:
    """Build argv for the ssh command. Agent handles stored-key auth;
    opts.key_file is only used when set in the connection profile.
    host_key_* override DB lookup for forwarded connections."""
    ssh_bin = shutil.which("ssh") or "ssh"
    host_key_args = _get_subprocess_host_key_args(
        ip, opts.port, host_key_host, host_key_port, host_key_via_host_id
    )
    cmd = [ssh_bin] + host_key_args + ["-p", str(opts.port)]
    if use_agent:
        sock = os.environ.get("SSH_AUTH_SOCK", "")
        if sock:
            cmd.extend(["-o", f"IdentityAgent={sock}"])
    if opts.key_file:
        cmd.extend(["-i", opts.key_file])
    if opts.compression:
        cmd.append("-C")
    if opts.forward_agent:
        cmd.append("-A")
    if opts.no_execute:
        cmd.append("-N")
    if opts.proxy_command:
        cmd.extend(["-o", f"ProxyCommand={opts.proxy_command}"])
    if opts.ciphers:
        cmd.extend(["-c", opts.ciphers])
    if opts.macs:
        cmd.extend(["-m", opts.macs])
    if opts.host_key_algorithms:
        cmd.extend(["-o", f"HostKeyAlgorithms={opts.host_key_algorithms}"])
    for fwd in opts.local_forwards:
        cmd.extend(["-L", fwd])
    for fwd in opts.remote_forwards:
        cmd.extend(["-R", fwd])
    for fwd in opts.dynamic_forwards:
        cmd.extend(["-D", fwd])
    if opts.extra_args:
        cmd.extend(shlex.split(opts.extra_args))
    cmd.append(f"{username}@{ip}")
    if opts.remote_command:
        cmd.append(opts.remote_command)
    return cmd


def _build_sftp_argv(
    ip: str,
    username: str,
    opts: ProfileOpts,
    *,
    use_agent: bool = False,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> list[str]:
    """Build argv for the sftp command. Agent handles stored-key auth."""
    sftp_bin = shutil.which("sftp") or "sftp"
    host_key_args = _get_subprocess_host_key_args(
        ip, opts.port, host_key_host, host_key_port, host_key_via_host_id
    )
    cmd = [sftp_bin] + host_key_args + ["-P", str(opts.port)]
    if use_agent:
        sock = os.environ.get("SSH_AUTH_SOCK", "")
        if sock:
            cmd.extend(["-o", f"IdentityAgent={sock}"])
    if opts.key_file:
        cmd.extend(["-i", opts.key_file])
    if opts.proxy_command:
        cmd.extend(["-o", f"ProxyCommand={opts.proxy_command}"])
    if opts.compression:
        cmd.extend(["-o", "Compression=yes"])
    if opts.forward_agent:
        cmd.extend(["-o", "ForwardAgent=yes"])
    if opts.ciphers:
        cmd.extend(["-o", f"Ciphers={opts.ciphers}"])
    if opts.macs:
        cmd.extend(["-o", f"MACs={opts.macs}"])
    if opts.host_key_algorithms:
        cmd.extend(["-o", f"HostKeyAlgorithms={opts.host_key_algorithms}"])
    if opts.extra_args:
        cmd.extend(shlex.split(opts.extra_args))
    cmd.append(f"{username}@{ip}")
    return cmd


# ---------------------------------------------------------------------------
# Terminal spawning helpers
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return sys.platform == "win32"


def _is_wsl() -> bool:
    """True when running Linux under WSL."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError):
        return "WSL_DISTRO_NAME" in os.environ


_TERMINALS_USE_DOUBLE_DASH = ("gnome-terminal", "mate-terminal")
_TERMINALS_USE_E_ARGS = ("alacritty", "wezterm", "kitty", "foot")
_TERMINALS_WINDOWS_WT = ("wt", "wt.exe")
_TERMINALS_WINDOWS_CMD = ("cmd", "cmd.exe")


def _is_wt_path(path: str, name: str) -> bool:
    """True if this is Windows Terminal (wt.exe)."""
    base = os.path.basename(path).lower()
    return name in _TERMINALS_WINDOWS_WT or base == "wt.exe" or base == "wt"


def _is_cmd_path(path: str, name: str) -> bool:
    """True if this is Windows cmd.exe."""
    base = os.path.basename(path).lower()
    return name in _TERMINALS_WINDOWS_CMD or base == "cmd.exe"


def _is_powershell_path(path: str, name: str) -> bool:
    """True if this is PowerShell."""
    base = os.path.basename(path).lower()
    return name == "powershell" or "powershell" in base


def _try_spawn_terminal(
    path: str, name: str, cmd: list[str], cmd_str: str, env: dict, cwd: Optional[str] = None
) -> bool:
    """Try to spawn a terminal. Returns True on success."""
    try:
        _wsl_windows_terminals = ("wt", "cmd", "powershell", "wt.exe", "cmd.exe")
        use_windows_logic = _is_windows() or (
            _is_wsl() and (name in _wsl_windows_terminals or "powershell" in name.lower())
        )
        if use_windows_logic:
            if _is_wt_path(path, name):
                args = [path, "new-tab"]
                if cwd:
                    args.extend(["-d", cwd])
                args.extend(cmd)
            elif _is_cmd_path(path, name):
                args = [path, "/c", "start", "Clitty SSH"] + cmd
            elif _is_powershell_path(path, name):
                args = [path, "-NoExit", "-Command", cmd_str]
            else:
                if "wt" in path.lower().replace("\\", "/").split("/")[-1]:
                    args = [path, "new-tab"]
                    if cwd:
                        args.extend(["-d", cwd])
                    args.extend(cmd)
                else:
                    args = [path, "/c", "start", "Clitty SSH"] + cmd
        elif name in _TERMINALS_USE_DOUBLE_DASH:
            args = [path, "--"] + cmd
        elif name in _TERMINALS_USE_E_ARGS:
            args = [path, "-e"] + cmd
        else:
            args = [path, "-e", cmd_str]
        subprocess.Popen(args, start_new_session=True, env=env, cwd=cwd)
        return True
    except OSError:
        return False


def _spawn_terminal_with_command(
    cmd: list[str],
    env: Optional[dict] = None,
    terminal: str = "auto",
    cwd: Optional[str] = None,
) -> bool:
    """Spawn a new terminal window running the given command. Returns True on success."""
    if env is None:
        env = os.environ.copy()
    cmd_str = shlex.join(cmd)
    if _is_windows():
        known_terminals = ["wt", "cmd", "powershell"]
    elif _is_wsl():
        known_terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal", "xterm", "alacritty", "wezterm", "kitty", "foot", "wt", "cmd", "powershell"]
    else:
        known_terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal", "xterm", "alacritty", "wezterm", "kitty", "foot"]

    terminal = (terminal or "auto").strip() or "auto"

    if terminal == "auto":
        for name in known_terminals:
            path = shutil.which(name)
            if path and _try_spawn_terminal(path, name, cmd, cmd_str, env, cwd=cwd):
                return True
        return False

    if terminal in known_terminals:
        path = shutil.which(terminal)
        if path:
            return _try_spawn_terminal(path, terminal, cmd, cmd_str, env, cwd=cwd)
        return False

    if "/" in terminal or "\\" in terminal:
        path = terminal
    else:
        path = shutil.which(terminal)
    if not path:
        return False
    name = (
        os.path.basename(path).lower()
        if _is_windows() or (_is_wsl() and path.lower().endswith(".exe"))
        else "alacritty"
    )
    return _try_spawn_terminal(path, name, cmd, cmd_str, env, cwd=cwd)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def check_host_alive(ip: str, port: int = 22, timeout: int = 3) -> bool:
    """Quick TCP connect to check if the host is reachable on the SSH port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return True
        except (OSError, socket.timeout):
            return False


# ---------------------------------------------------------------------------
# Credential / key probing
# ---------------------------------------------------------------------------

def probe_credentials(
    ip: str,
    vault: Vault,
    port: int = 22,
    timeout: int = 10,
    max_tries: Optional[int] = None,
) -> Optional[int]:
    """Try stored credentials against *ip* up to max_tries. Returns the credential id on success, or None."""
    if max_tries is None:
        limit = (db.get_setting("limit_auth_tries", "true") or "true").lower() in ("true", "1", "yes")
        if not limit:
            max_tries = 999999
        else:
            try:
                max_tries = int((db.get_setting("max_auth_tries", "3") or "3").strip())
            except (ValueError, TypeError):
                max_tries = 3
            max_tries = max(1, min(20, max_tries))
    creds = db.list_credentials()[:max_tries]
    for cred in creds:
        username = cred["username"]
        try:
            password = vault.decrypt(cred["password"])
        except Exception:
            continue
        client = paramiko.SSHClient()
        _apply_paramiko_host_key_policy(client, ip, port)
        try:
            client.connect(ip, port=port, username=username, password=password,
                           timeout=timeout, look_for_keys=False, allow_agent=False)
            client.close()
            return cred["id"]
        except (paramiko.AuthenticationException, paramiko.SSHException, OSError):
            client.close()
            continue
    return None


def probe_keys(
    ip: str,
    vault: Vault,
    port: int = 22,
    timeout: int = 10,
    max_tries: Optional[int] = None,
) -> Optional[int]:
    """Ensure all non-prompt keys are in the agent, then try unique usernames
    with allow_agent=True up to max_tries. Returns the key id on success, or None.
    Much faster than the old approach of trying each key individually."""
    if max_tries is None:
        limit = (db.get_setting("limit_auth_tries", "true") or "true").lower() in ("true", "1", "yes")
        if not limit:
            max_tries = 999999
        else:
            try:
                max_tries = int((db.get_setting("max_auth_tries", "3") or "3").strip())
            except (ValueError, TypeError):
                max_tries = 3
            max_tries = max(1, min(20, max_tries))
    preload_agent_keys(vault)

    keys = db.list_ssh_keys()
    seen_usernames: dict[str, int] = {}
    for key_row in keys:
        if key_row["prompt_passphrase"]:
            continue
        if key_row["username"] not in seen_usernames:
            seen_usernames[key_row["username"]] = key_row["id"]

    for i, (username, first_key_id) in enumerate(seen_usernames.items()):
        if i >= max_tries:
            break
        client = paramiko.SSHClient()
        _apply_paramiko_host_key_policy(client, ip, port)
        try:
            client.connect(ip, port=port, username=username, timeout=timeout,
                           look_for_keys=False, allow_agent=True)
            client.close()
            return first_key_id
        except (paramiko.AuthenticationException, paramiko.SSHException, OSError):
            client.close()
            continue
    return None


# ---------------------------------------------------------------------------
# sshpass helpers (password auth for subprocess)
# ---------------------------------------------------------------------------

def _build_wrapper_command(cmd: list[str], env: dict) -> tuple[str, Optional[str]]:
    """Build a command that runs cmd with SSHPASS from a temp password file.

    Uses permanent ssh_wrapper.py (no user data) and a temp file for the
    password only. The wrapper reads the password, unlinks the file, sets
    SSHPASS, and runs the ssh command."""
    pass_val = env.get("SSHPASS", "")
    fd, pw_path = tempfile.mkstemp(prefix="clitty-pw-", suffix=".tmp")
    clitty_notify.clitty_notify(f"temp file created (password): {pw_path}", level="debug", log_only=True)
    try:
        os.write(fd, pass_val.encode("utf-8"))
        os.close(fd)
        os.chmod(pw_path, 0o600)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(pw_path)
        except OSError:
            pass
        return ("", "Failed to create password temp file")

    wrapper_path = Path(__file__).resolve().parent / "ssh_wrapper.py"
    if not wrapper_path.is_file():
        try:
            os.unlink(pw_path)
        except OSError:
            pass
        return ("", "ssh_wrapper.py not found")

    full_cmd = [sys.executable, str(wrapper_path), pw_path] + cmd
    return (shlex.join(full_cmd), None)


def _wrap_with_sshpass(cmd: list[str], password: str) -> tuple[list[str], dict]:
    """Wrap ssh command with sshpass for password auth. Returns (cmd, env)."""
    sshpass_path = shutil.which("sshpass")
    if not sshpass_path:
        return (cmd, os.environ.copy())
    return (
        [sshpass_path, "-e"] + cmd,
        {**os.environ, "SSHPASS": password},
    )


# ---------------------------------------------------------------------------
# Paramiko connection functions
# ---------------------------------------------------------------------------

def connect_paramiko_interactive(
    ip: str,
    username: str,
    password: Optional[str] = None,
    opts: ProfileOpts | None = None,
    use_agent: bool = False,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> None:
    """Open a Paramiko interactive shell session."""
    import termios
    import tty

    if opts is None:
        opts = ProfileOpts()

    client = paramiko.SSHClient()
    _apply_paramiko_host_key_policy(
        client, ip, opts.port,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )
    connect_kwargs = _build_paramiko_connect_kwargs(ip, username, opts, password, use_agent)
    clitty_notify.clitty_notify(f"Paramiko connecting to {ip}:{opts.port} user={username}", level="debug", log_only=True)
    client.connect(**connect_kwargs)

    transport = client.get_transport()
    if transport:
        for fwd in opts.local_forwards:
            parts = fwd.split(":")
            if len(parts) == 3:
                try:
                    local_port, remote_host, remote_port = int(parts[0]), parts[1], int(parts[2])
                    bind_addr = ""
                except (ValueError, IndexError):
                    continue
            elif len(parts) == 4:
                try:
                    bind_addr, local_port, remote_host, remote_port = parts[0], int(parts[1]), parts[2], int(parts[3])
                except (ValueError, IndexError):
                    continue
            else:
                continue
            t = threading.Thread(
                target=_run_local_forward,
                args=(transport, local_port, remote_host, remote_port, bind_addr),
                daemon=True,
            )
            t.start()

    chan = client.invoke_shell()

    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
                except EOFError:
                    break
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                chan.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
        chan.close()
        client.close()


def open_paramiko_from_creds(
    ip: str,
    username: str,
    password: Optional[str] = None,
    profile_id: Optional[int] = None,
    use_agent: bool = False,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
    port: Optional[int] = None,
    vault: Optional[Vault] = None,
    opts: Optional[ProfileOpts] = None,
) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    """Open Paramiko SSH+SFTP using pre-resolved credentials. Caller must close both.
    Pass opts for session mode (no vault); or profile_id + vault to fetch and decrypt."""
    if opts is None:
        profile = _get_profile_decrypted(profile_id, vault)
        opts = _resolve_profile(profile)
    if port is not None:
        opts = ProfileOpts(**{**vars(opts), "port": port})
    client = paramiko.SSHClient()
    _apply_paramiko_host_key_policy(
        client, ip, opts.port,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )
    connect_kwargs = _build_paramiko_connect_kwargs(ip, username, opts, password, use_agent)
    clitty_notify.clitty_notify(f"Paramiko connecting to {ip}:{opts.port} user={username}", level="debug", log_only=True)
    client.connect(**connect_kwargs)
    sftp = paramiko.SFTPClient.from_transport(client.get_transport())
    clitty_notify.clitty_notify(f"Paramiko connected: {ip}:{opts.port}", level="debug", log_only=True)
    return (client, sftp)


# ---------------------------------------------------------------------------
# Build SSH command strings (for embedded terminal / textual-terminal)
# ---------------------------------------------------------------------------

def build_ssh_command_string(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_id: Optional[int] = None,
) -> tuple[str, Optional[str]]:
    """Build ssh command string for embedded terminal (textual-terminal).
    Returns (command_string, error_message)."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)

    if not check_host_alive(ip, port=opts.port):
        return ("", "Host is not reachable")

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
    )
    if auth is None:
        return ("", err or "Auth failed")

    cmd = _build_ssh_argv(
        ip, auth.username, opts, use_agent=auth.use_agent,
        host_key_host=None, host_key_port=None, host_key_via_host_id=None,
    )
    if auth.password:
        if not shutil.which("sshpass"):
            return ("", "Password auth requires sshpass (install it for embedded mode)")
        cmd, run_env = _wrap_with_sshpass(cmd, auth.password)
        return _build_wrapper_command(cmd, run_env)
    return (shlex.join(cmd), None)


def build_ssh_command_string_from_creds(
    ip: str,
    username: str,
    password: Optional[str],
    profile_id: Optional[int] = None,
    use_agent: bool = False,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
    port: Optional[int] = None,
    vault: Optional[Vault] = None,
    opts: Optional[ProfileOpts] = None,
    host_id: Optional[int] = None,
) -> tuple[str, Optional[str]]:
    """Build ssh command string using pre-resolved credentials (no vault).
    Pass opts for session mode; or profile_id + vault to fetch and decrypt."""
    if opts is None:
        profile = _get_profile_decrypted(profile_id, vault)
        opts = _resolve_profile(profile)
    opts = _apply_host_proxy_override(opts, host_id)
    if port is not None:
        opts = ProfileOpts(**{**vars(opts), "port": port})

    if not check_host_alive(ip, port=opts.port):
        return ("", "Host is not reachable")

    cmd = _build_ssh_argv(
        ip, username, opts, use_agent=use_agent,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )
    if password:
        if not shutil.which("sshpass"):
            return ("", "Password auth requires sshpass (install it for embedded mode)")
        cmd, run_env = _wrap_with_sshpass(cmd, password)
        return _build_wrapper_command(cmd, run_env)
    return (shlex.join(cmd), None)


# ---------------------------------------------------------------------------
# Subprocess connections
# ---------------------------------------------------------------------------

def connect_subprocess(
    ip: str,
    username: str,
    opts: ProfileOpts | None = None,
    password: Optional[str] = None,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
) -> int:
    """Spawn system ``ssh`` and wait for it to finish. Returns exit code."""
    if opts is None:
        opts = ProfileOpts()
    clitty_notify.clitty_notify(f"subprocess SSH connecting to {ip}:{opts.port} user={username}", level="debug", log_only=True)
    cmd = _build_ssh_argv(
        ip, username, opts,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )
    if password and shutil.which("sshpass"):
        cmd, run_env = _wrap_with_sshpass(cmd, password)
        result = subprocess.run(cmd, env=run_env)
    else:
        result = subprocess.run(cmd)
    return result.returncode


def connect_sftp_subprocess(
    ip: str,
    username: str,
    opts: ProfileOpts | None = None,
    password: Optional[str] = None,
) -> int:
    """Spawn system ``sftp`` and wait for it to finish. Returns exit code."""
    if opts is None:
        opts = ProfileOpts()
    cmd = _build_sftp_argv(ip, username, opts)
    if password and shutil.which("sshpass"):
        cmd, run_env = _wrap_with_sshpass(cmd, password)
        result = subprocess.run(cmd, env=run_env)
    else:
        result = subprocess.run(cmd)
    return result.returncode


# ---------------------------------------------------------------------------
# Spawn in new terminal
# ---------------------------------------------------------------------------

def spawn_ssh_in_new_terminal(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
    port: Optional[int] = None,
    credential_storage_ip: Optional[str] = None,
    host_id: Optional[int] = None,
) -> int:
    """Prepare SSH connection and spawn it in a new terminal window.
    Returns 0 on success, 1 for credential/profile errors, 2 for host unreachable, 3 if no terminal found."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)
    if port is not None:
        opts = ProfileOpts(**{**vars(opts), "port": port})

    if not check_host_alive(ip, port=opts.port):
        return 2

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
        credential_storage_ip=credential_storage_ip,
    )
    if auth is None:
        return 1

    cmd = _build_ssh_argv(
        ip, auth.username, opts,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )
    terminal = (db.get_setting("terminal_emulator", "auto") or "auto").strip() or "auto"
    if auth.password and shutil.which("sshpass"):
        cmd, run_env = _wrap_with_sshpass(cmd, auth.password)
        ok = _spawn_terminal_with_command(cmd, env=run_env, terminal=terminal)
    else:
        ok = _spawn_terminal_with_command(cmd, terminal=terminal)
    return 0 if ok else 3


def spawn_session_in_new_terminal(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
    port: Optional[int] = None,
    credential_storage_ip: Optional[str] = None,
    host_id: Optional[int] = None,
) -> int:
    """Spawn embedded SSH + status bar in a new terminal.
    Returns 0 on success, 1 for credential/profile errors, 2 for host unreachable, 3 if no terminal found.
    Agent keys are inherited by the child process via SSH_AUTH_SOCK."""
    from src import status_bar_config as sb

    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)
    if port is not None:
        opts = ProfileOpts(**{**vars(opts), "port": port})

    if not check_host_alive(ip, port=opts.port):
        return 2

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
        credential_storage_ip=credential_storage_ip,
    )
    if auth is None:
        return 1

    status_bar_config = sb.get_status_bar_config(vault=vault)

    project_root = str(Path(__file__).resolve().parent)
    session_py = str(Path(project_root) / "session.py")
    terminal = (db.get_setting("terminal_emulator", "auto") or "auto").strip() or "auto"

    session_data = {
        "password": auth.password if auth.password else None,
        "use_agent": auth.use_agent,
        "status_bar_config": status_bar_config,
        "host_key_host": host_key_host,
        "host_key_port": host_key_port,
        "host_key_via_host_id": host_key_via_host_id,
        "port": port,
        "profile_opts": dataclasses.asdict(opts) if profile_id else None,
    }
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="clitty-session-")
    session_data_path = tmp.name
    clitty_notify.clitty_notify(f"temp file created (session data): {session_data_path}", level="debug", log_only=True)
    try:
        tmp.write(json.dumps(session_data))
        tmp.close()
        os.chmod(session_data_path, 0o600)
    except Exception:
        if os.path.exists(session_data_path):
            try:
                os.unlink(session_data_path)
            except OSError:
                pass
        return 1

    cmd = [
        sys.executable, session_py, "--session-data-file", session_data_path,
        "--ip", ip, "--username", auth.username, "--profile-id", str(profile_id or 0),
    ]
    env = os.environ.copy()

    ok = _spawn_terminal_with_command(cmd, env=env, terminal=terminal, cwd=project_root)
    if ok:
        return 0
    if os.path.isfile(session_data_path):
        try:
            os.unlink(session_data_path)
        except OSError:
            pass
    return 3


def spawn_forward_only(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] | None,
    key_id: Optional[int],
    forward_target_ip: str,
    remote_port: int = 22,
    local_port: int = 2222,
    connect_port: Optional[int] = None,
    host_id: Optional[int] = None,
) -> tuple[subprocess.Popen | None, int]:
    """Spawn ssh -L local_port:forward_target_ip:remote_port in background.
    connect_port: port to connect to (default from profile). Use for chained forwards (e.g. 127.0.0.1:2222).
    Returns (Popen, 0) on success, (None, 1) credential error, (None, 2) host unreachable, (None, 3) other error.
    Caller must terminate the Popen when the session ends."""
    from src import clitty_notify
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)
    fwd_spec = f"{local_port}:{forward_target_ip}:{remote_port}"
    conn_port = connect_port if connect_port is not None else opts.port
    opts = ProfileOpts(
        port=conn_port,
        timeout=opts.timeout,
        key_file=opts.key_file,
        compression=opts.compression,
        forward_agent=opts.forward_agent,
        proxy_command=opts.proxy_command,
        local_forwards=[fwd_spec] + opts.local_forwards,
        remote_forwards=opts.remote_forwards,
        dynamic_forwards=opts.dynamic_forwards,
        extra_args=opts.extra_args,
    )
    if not check_host_alive(ip, port=conn_port):
        clitty_notify.clitty_notify("Port forward: host not reachable", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward: host {ip}:{conn_port} not reachable", level="error", log_only=True)
        return None, 2
    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=conn_port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
    )
    if auth is None:
        clitty_notify.clitty_notify(f"Port forward: {err}", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward auth failed for {ip}: {err}", level="error", log_only=True)
        return None, 1
    cmd = _build_ssh_argv(ip, auth.username, opts)
    try:
        if auth.password and shutil.which("sshpass"):
            cmd, run_env = _wrap_with_sshpass(cmd, auth.password)
            proc = subprocess.Popen(
                cmd, env=run_env, start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        else:
            proc = subprocess.Popen(
                cmd, start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        import time
        time.sleep(0.5)
        if proc.poll() is not None:
            clitty_notify.clitty_notify("Port forward failed", level="error", context=clitty_notify.CTX_UI)
            clitty_notify.clitty_notify(f"Port forward proc died early for {ip}:{conn_port} -> {forward_target_ip}:{remote_port}, poll={proc.poll()}", level="error", log_only=True)
            return None, 3
        clitty_notify.clitty_notify("Port forward started ({} -> {}:{})".format(local_port, forward_target_ip, remote_port), level="info", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward started {local_port} -> {forward_target_ip}:{remote_port}", level="info", log_only=True)
        return proc, 0
    except Exception as exc:
        clitty_notify.clitty_notify(f"Port forward error: {exc}", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward exception for {ip}:{conn_port}: {exc}", level="error", log_only=True)
        return None, 3


def spawn_forward_in_new_terminal(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] | None,
    key_id: Optional[int],
    forward_target_ip: str,
    remote_port: int = 22,
    local_port: int = 2222,
    host_id: Optional[int] = None,
) -> int:
    """Spawn ssh -L local_port:forward_target_ip:remote_port in a new terminal. Returns 0 on success, 1/2/3 on error."""
    from src import clitty_notify
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)
    fwd_spec = f"{local_port}:{forward_target_ip}:{remote_port}"
    opts = ProfileOpts(
        port=opts.port,
        timeout=opts.timeout,
        key_file=opts.key_file,
        compression=opts.compression,
        forward_agent=opts.forward_agent,
        proxy_command=opts.proxy_command,
        local_forwards=[fwd_spec] + opts.local_forwards,
        remote_forwards=opts.remote_forwards,
        dynamic_forwards=opts.dynamic_forwards,
        extra_args=opts.extra_args,
    )
    if not check_host_alive(ip, port=opts.port):
        clitty_notify.clitty_notify("Port forward: host not reachable", level="error", context=clitty_notify.CTX_UI)
        return 2
    auth, err = _resolve_auth(ip, vault, credential_id, key_id, port=opts.port, timeout=min(opts.timeout, 10))
    if auth is None:
        clitty_notify.clitty_notify(f"Port forward: {err}", level="error", context=clitty_notify.CTX_UI)
        return 1
    cmd = _build_ssh_argv(ip, auth.username, opts)
    terminal = (db.get_setting("terminal_emulator", "auto") or "auto").strip() or "auto"
    if auth.password and shutil.which("sshpass"):
        cmd, run_env = _wrap_with_sshpass(cmd, auth.password)
        ok = _spawn_terminal_with_command(cmd, env=run_env, terminal=terminal)
    else:
        ok = _spawn_terminal_with_command(cmd, terminal=terminal)
    if ok:
        clitty_notify.clitty_notify("Port forward started in new terminal ({} -> {}:{})".format(local_port, forward_target_ip, remote_port), level="info", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward in new terminal: {local_port} -> {forward_target_ip}:{remote_port}", level="info", log_only=True)
    else:
        clitty_notify.clitty_notify("Port forward: could not spawn terminal", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"Port forward spawn failed for {ip}:{opts.port} -> {forward_target_ip}:{remote_port}", level="error", log_only=True)
    return 0 if ok else 3


def spawn_sftp_in_new_terminal(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_id: Optional[int] = None,
) -> int:
    """Prepare SFTP connection and spawn it in a new terminal window.
    Returns 0 on success, 1 for credential/profile errors, 2 for host unreachable, 3 if no terminal found."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)

    if not check_host_alive(ip, port=opts.port):
        clitty_notify.clitty_notify("SFTP: host not reachable", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"SFTP spawn failed: host {ip}:{opts.port} not reachable", level="error", log_only=True)
        return 2

    auth, err = _resolve_auth(ip, vault, credential_id, key_id, port=opts.port, timeout=min(opts.timeout, 10))
    if auth is None:
        clitty_notify.clitty_notify(f"SFTP: {err or 'no valid credential'}", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"SFTP spawn failed for {ip}:{opts.port}: {err}", level="error", log_only=True)
        return 1

    cmd = _build_sftp_argv(ip, auth.username, opts)
    terminal = (db.get_setting("terminal_emulator", "auto") or "auto").strip() or "auto"
    if auth.password and shutil.which("sshpass"):
        cmd, run_env = _wrap_with_sshpass(cmd, auth.password)
        ok = _spawn_terminal_with_command(cmd, env=run_env, terminal=terminal)
    else:
        ok = _spawn_terminal_with_command(cmd, terminal=terminal)
    if ok:
        clitty_notify.clitty_notify(f"SFTP started in new terminal for {ip}", level="info", log_only=True)
    else:
        clitty_notify.clitty_notify("SFTP: could not spawn terminal", level="error", context=clitty_notify.CTX_UI)
        clitty_notify.clitty_notify(f"SFTP spawn failed for {ip}:{opts.port}: no terminal found", level="error", log_only=True)
    return 0 if ok else 3


# ---------------------------------------------------------------------------
# High-level connect
# ---------------------------------------------------------------------------

def connect(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    method: str = "subprocess",
    key_id: Optional[int] = None,
    host_key_host: Optional[str] = None,
    host_key_port: Optional[int] = None,
    host_key_via_host_id: Optional[int] = None,
    port: Optional[int] = None,
    credential_storage_ip: Optional[str] = None,
    host_id: Optional[int] = None,
) -> int:
    """High-level connect: resolve credential or key, pick method, launch session. Returns exit code (0 = ok).
    host_key_* override DB lookup for forwarded connections. port overrides profile port (e.g. 2222 for localhost)."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)
    if port is not None:
        opts = ProfileOpts(**{**vars(opts), "port": port})

    if not check_host_alive(ip, port=opts.port):
        return 2

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
        credential_storage_ip=credential_storage_ip,
    )
    if auth is None:
        return 1

    if method == "paramiko":
        connect_paramiko_interactive(
            ip, auth.username, password=auth.password, opts=opts, use_agent=auth.use_agent,
            host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
        )
        return 0
    return connect_subprocess(
        ip, auth.username, opts=opts, password=auth.password,
        host_key_host=host_key_host, host_key_port=host_key_port, host_key_via_host_id=host_key_via_host_id,
    )


def connect_sftp(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_id: Optional[int] = None,
) -> int:
    """High-level SFTP connect: resolve credential or key, launch sftp session. Returns exit code (0 = ok)."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)

    if not check_host_alive(ip, port=opts.port):
        return 2

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
    )
    if auth is None:
        return 1

    return connect_sftp_subprocess(ip, auth.username, opts=opts, password=auth.password)


def open_paramiko_sftp(
    ip: str,
    vault: Vault,
    credential_id: Optional[int],
    profile_id: Optional[int] = None,
    key_id: Optional[int] = None,
    host_id: Optional[int] = None,
) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    """Open a Paramiko SSH+SFTP connection. Caller must close both when done.
    Returns (ssh_client, sftp_client). Raises on connection/auth failure."""
    profile = _get_profile_decrypted(profile_id, vault)
    opts = _apply_host_proxy_override(_resolve_profile(profile), host_id)

    if not check_host_alive(ip, port=opts.port):
        raise ConnectionError(f"Host {ip} is not reachable on port {opts.port}")

    auth, err = _resolve_auth(
        ip,
        vault,
        credential_id,
        key_id,
        port=opts.port,
        timeout=min(opts.timeout, 10),
        allow_probe=_is_auto_probe_enabled(),
    )
    if auth is None:
        raise ConnectionError(err or "Auth failed")

    return open_paramiko_from_creds(
        ip, auth.username, password=auth.password, opts=opts,
        use_agent=auth.use_agent, vault=vault,
    )
