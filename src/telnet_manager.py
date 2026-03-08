"""Telnet connection manager – spawns system telnet client (subprocess)."""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from src import clitty_notify
from src import database as db
from src.encryption import Vault


def connect_telnet(
    host: str,
    port: int,
    vault: Vault,
    credential_id: Optional[int],
) -> int:
    """Run telnet in same terminal. Returns process exit code.
    Username/password are entered at the telnet prompt (try empty first, then stored password)."""
    telnet_bin = shutil.which("telnet")
    if not telnet_bin:
        clitty_notify.clitty_notify("Telnet: binary not found", level="error")
        clitty_notify.clitty_notify("Telnet: binary not found", level="error", log_only=True)
        return 3
    clitty_notify.clitty_notify(f"Telnet connection to {host}:{port} started", level="info", log_only=True)
    cmd = [telnet_bin, host, str(port)]
    proc = subprocess.run(cmd)
    return proc.returncode if proc.returncode is not None else 1


def spawn_telnet_in_new_terminal(
    host: str,
    port: int,
    vault: Vault,
    credential_id: Optional[int],
) -> int:
    """Spawn telnet in a new terminal window. Returns 0 on success, 3 if no terminal found."""
    from src import ssh_manager
    telnet_bin = shutil.which("telnet")
    if not telnet_bin:
        clitty_notify.clitty_notify("Telnet: binary not found", level="error")
        clitty_notify.clitty_notify("Telnet spawn: binary not found", level="error", log_only=True)
        return 3
    cmd = [telnet_bin, host, str(port)]
    terminal = (db.get_setting("terminal_emulator", "auto") or "auto").strip() or "auto"
    ok = ssh_manager._spawn_terminal_with_command(cmd, terminal=terminal)
    if ok:
        clitty_notify.clitty_notify(f"Telnet spawn to {host}:{port} in new terminal", level="info", log_only=True)
    else:
        clitty_notify.clitty_notify("Telnet: could not spawn terminal", level="error")
        clitty_notify.clitty_notify(f"Telnet spawn failed for {host}:{port}: no terminal found", level="error", log_only=True)
    return 0 if ok else 3
