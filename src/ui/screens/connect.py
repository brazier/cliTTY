"""Connection-related modal screens: profile selection, manual connect, host form, CSV import."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Literal

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DirectoryTree,
    Input,
    Label,
    ListItem,
    ListView,
    OptionList,
    RadioButton,
    RadioSet,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from src import database as db
from src import ssh_manager
from src.clitty_notify import CTX_TERMINAL, CTX_UI, clitty_notify


def _is_wsl() -> bool:
    """True when running Linux under WSL."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError):
        return "WSL_DISTRO_NAME" in os.environ
from src.encryption import Vault


# ---------------------------------------------------------------------------
# Passphrase prompt for ssh-agent registration
# ---------------------------------------------------------------------------

class AgentPassphraseScreen(ModalScreen[tuple[bool, str] | None]):
    """Prompt for a key passphrase to register the key with ssh-agent.
    Dismisses with (success, passphrase) or None on cancel."""

    DEFAULT_CSS = """
    AgentPassphraseScreen {
        align: center middle;
    }
    #passphrase-status {
        text-style: bold;
        margin-top: 1;
    }
    #passphrase-status.success {
        color: $success;
    }
    #passphrase-status.error {
        color: $error;
    }
    """

    def __init__(self, key_id: int, key_label: str = "", vault: Vault | None = None, **kwargs):
        super().__init__(**kwargs)
        self.key_id = key_id
        self.key_label = key_label
        self.vault = vault

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container"):
            yield Label("[b]Key Passphrase Required[/b]")
            if self.key_label:
                yield Label(f"Key: {self.key_label}")
            yield Label("Enter passphrase to register key with ssh-agent:")
            yield Input(id="key-passphrase", placeholder="passphrase (empty if none)", password=True)
            yield Static("", id="passphrase-status")
            yield Button("OK", variant="primary", id="btn-ok")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-ok":
            passphrase = self.query_one("#key-passphrase", Input).value
            if self.vault is None:
                self.dismiss((True, passphrase))
                return
            ok, err = ssh_manager.add_key_to_agent_with_passphrase(self.key_id, self.vault, passphrase)
            status_widget = self.query_one("#passphrase-status", Static)
            if ok:
                status_widget.update("[b]Success![/b] Key added to agent.")
                status_widget.set_class(True, "success")
                status_widget.set_class(False, "error")
                clitty_notify("Key added to agent", context=CTX_UI)
                self.dismiss((True, passphrase))
            else:
                status_widget.update(f"[b]Failed:[/b] {err}")
                status_widget.set_class(True, "error")
                status_widget.set_class(False, "success")


class CredentialSelectScreen(ModalScreen[int | None]):
    """Modal to select a stored credential for connecting."""

    DEFAULT_CSS = """
    CredentialSelectScreen {
        align: center middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container"):
            yield Label("[b]Select Credential[/b]")
            yield Label("Choose a stored credential to use for this connection.")
            yield ListView(id="cred-list")
            yield Button("Use Selected", variant="primary", id="btn-use")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        lv = self.query_one("#cred-list", ListView)
        for cred in db.list_credentials():
            label = cred["label"] or f"Cred #{cred['id']}"
            display = f"{label}  ({cred['username']})"
            lv.append(ListItem(Label(display), id=f"cred-{cred['id']}"))
        if lv.children:
            lv.index = 0

    def _get_selected_id(self) -> int | None:
        lv = self.query_one("#cred-list", ListView)
        if not lv.children:
            return None
        item = lv.highlighted_child
        if not item or not item.id:
            return None
        item_id = str(item.id)
        if not item_id.startswith("cred-"):
            return None
        try:
            return int(item_id.split("-", 1)[1])
        except (ValueError, IndexError):
            return None

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if not item_id.startswith("cred-"):
            return
        try:
            _ = int(item_id.split("-", 1)[1])
        except (ValueError, IndexError):
            return

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        if event.button.id == "btn-use":
            cid = self._get_selected_id()
            if cid is None:
                clitty_notify("No credential selected", level="warn", context=CTX_UI)
                return
            self.dismiss(cid)


# ---------------------------------------------------------------------------
# Profile selection before connecting
# ---------------------------------------------------------------------------

class ProfileSelectScreen(ModalScreen):
    """Let the user pick a connection profile (or none), then initiate the SSH or SFTP connection."""

    DEFAULT_CSS = """
    ProfileSelectScreen {
        align: center middle;
    }
    """

    def __init__(
        self,
        host_id: int,
        action: Literal["ssh", "sftp", "telnet"] = "ssh",
        ssh_forward_prefill: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.host_id = host_id
        self.action = action
        self.ssh_forward_prefill = ssh_forward_prefill or ""
        self._selected_profile_id: int | None = None

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container"):
            yield Label("[b]Select Connection Profile[/b]")
            yield Label("Select a profile in the list (or leave unselected for defaults).")
            yield ListView(id="profile-list")
            yield Label("SSH Forward (IP behind jump host)")
            yield Input(id="ssh-forward", placeholder="10.0.0.1")
            yield Checkbox("Connect in background", id="connect-background", value=True)
            yield Button("Connect", variant="primary", id="btn-connect")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        lv = self.query_one("#profile-list", ListView)
        for prof in db.list_profiles():
            lv.append(ListItem(Label(f"{prof['name']}  (port {prof['port']})"), id=f"prof-{prof['id']}"))
        if self.ssh_forward_prefill:
            self.query_one("#ssh-forward", Input).value = self.ssh_forward_prefill
        connection_window = db.get_setting("connection_window", "same")
        cb = self.query_one("#connect-background", Checkbox)
        if connection_window != "new":
            cb.disabled = True
            cb.value = True

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("prof-"):
            self._selected_profile_id = int(item_id.split("-", 1)[1])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss()
            return
        if event.button.id == "btn-connect":
            self._do_connect(self._selected_profile_id)

    def _do_connect(self, profile_id: int | None) -> None:
        host = db.get_host(self.host_id)
        if not host:
            clitty_notify("Host not found", level="error", context=CTX_UI)
            self.dismiss()
            return

        vault: Vault = self.app.vault  # type: ignore[attr-defined]
        connection_window = db.get_setting("connection_window", "same")
        ssh_forward_ip = self.query_one("#ssh-forward", Input).value.strip()
        connect_in_background = self.query_one("#connect-background", Checkbox).value
        chain = db.get_jump_chain(self.host_id)
        if len(chain) >= 2:
            first_hop = chain[0]
            ip = first_hop["ip_address"]
            credential_id = first_hop["credential_id"] if "credential_id" in first_hop.keys() else None
            key_id = first_hop["key_id"] if "key_id" in first_hop.keys() and first_hop["key_id"] else None
            ssh_forward_ip = host["ip_address"]
        else:
            ip = host["ip_address"]
            credential_id = host["credential_id"]
            key_id = host["key_id"] if "key_id" in host.keys() else None
        action = self.action
        app = self.app

        if action != "telnet" and key_id and not ssh_manager.is_key_loaded(key_id):
            key_row = db.get_ssh_key(key_id)
            if key_row and key_row["prompt_passphrase"]:
                def on_passphrase_result(result: tuple[bool, str] | None) -> None:
                    self.dismiss()
                    if result is None:
                        return
                    success, _passphrase = result
                    if not success:
                        return
                    if action == "sftp":
                        self._do_sftp(app, ip, vault, credential_id, profile_id, connection_window, key_id,
                                      ssh_forward_ip=ssh_forward_ip, connect_in_background=connect_in_background)
                    elif action == "telnet":
                        self._do_telnet(app, ip, vault, credential_id, profile_id, ssh_forward_ip, connect_in_background)
                    else:
                        self._do_ssh(app, ip, vault, credential_id, profile_id, connection_window, key_id,
                                     ssh_forward_ip=ssh_forward_ip, connect_in_background=connect_in_background)

                app.push_screen(
                    AgentPassphraseScreen(key_id=key_id, key_label=key_row["label"] or key_row["username"], vault=vault),
                    callback=on_passphrase_result,
                )
                return

        self.dismiss()

        if action == "sftp":
            self._do_sftp(app, ip, vault, credential_id, profile_id, connection_window, key_id,
                          ssh_forward_ip=ssh_forward_ip, connect_in_background=connect_in_background)
        elif action == "telnet":
            self._do_telnet(app, ip, vault, credential_id, profile_id, ssh_forward_ip, connect_in_background)
        else:
            self._do_ssh(app, ip, vault, credential_id, profile_id, connection_window, key_id,
                         ssh_forward_ip=ssh_forward_ip, connect_in_background=connect_in_background)

    def _do_ssh(
        self,
        app,
        ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        connection_window: str,
        key_id: int | None = None,
        ssh_forward_ip: str = "",
        connect_in_background: bool = True,
    ) -> None:
        host_key_host = ssh_forward_ip.strip() if ssh_forward_ip else None
        host_key_port = 22 if host_key_host else None
        host_key_via_host_id = self.host_id if host_key_host else None

        if ssh_forward_ip.strip():
            self._do_ssh_via_forward(
                app, ip, vault, credential_id, profile_id, connection_window, key_id,
                ssh_forward_ip.strip(), connect_in_background,
                host_key_host, host_key_port, host_key_via_host_id,
            )
            return

        self._do_ssh_direct(
            app, ip, vault, credential_id, profile_id, connection_window, key_id,
        )

    def _do_ssh_via_forward(
        self,
        app,
        jump_ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        connection_window: str,
        key_id: int | None,
        ssh_forward_ip: str,
        connect_in_background: bool,
        host_key_host: str,
        host_key_port: int,
        host_key_via_host_id: int,
    ) -> None:
        import time
        host = db.get_host(self.host_id)
        if not host:
            clitty_notify("Host not found", level="error", context=CTX_UI)
            return

        chain = db.get_jump_chain(self.host_id)
        run_forward_background = connect_in_background or (connection_window != "new")
        procs: list = []
        localhost_ip = "127.0.0.1"

        if len(chain) >= 3:
            for i in range(len(chain) - 1):
                hop = chain[i]
                next_hop = chain[i + 1]
                next_ip = next_hop["ip_address"]
                local_port = 2222 + i
                cred_id = hop["credential_id"] if "credential_id" in hop.keys() else None
                k_id = hop["key_id"] if "key_id" in hop.keys() and hop["key_id"] else None
                conn_host = hop["ip_address"] if i == 0 else localhost_ip
                conn_port = 22 if i == 0 else (2222 + i - 1)
                proc, rc = ssh_manager.spawn_forward_only(
                    conn_host, vault, cred_id, profile_id, k_id,
                    next_ip, remote_port=22, local_port=local_port,
                    connect_port=conn_port if i > 0 else None,
                    host_id=self.host_id,
                )
                if rc != 0:
                    for p in procs:
                        if p and p.poll() is None:
                            p.terminate()
                    return
                procs.append(proc)
                time.sleep(0.5 if i == 0 else 0.3)
            localhost_port = 2222 + len(chain) - 2
            forward_proc = procs
        else:
            localhost_port = 2222
            if run_forward_background:
                proc, rc = ssh_manager.spawn_forward_only(
                    jump_ip, vault, credential_id, profile_id, key_id, ssh_forward_ip,
                    host_id=self.host_id,
                )
                if rc != 0:
                    return
                time.sleep(0.8)
                forward_proc = proc
            else:
                rc = ssh_manager.spawn_forward_in_new_terminal(
                    jump_ip, vault, credential_id, profile_id, key_id, ssh_forward_ip,
                    host_id=self.host_id,
                )
                if rc != 0:
                    return
                time.sleep(1.5)
                forward_proc = None

        ran_blocking_connect = False
        try:
            hk_host, hk_port, hk_via = host_key_host, host_key_port, host_key_via_host_id

            method = db.get_setting("ssh_method", "subprocess")
            if method == "embedded" and connection_window == "same":
                from src.ui.screens.embedded_ssh import EmbeddedSSHScreen, TERMINAL_AVAILABLE
                if not TERMINAL_AVAILABLE:
                    clitty_notify("Embedded terminal unavailable. Use subprocess or new window.", level="error", context=CTX_UI)
                    return
                auth, err = ssh_manager._resolve_auth(
                    localhost_ip,
                    vault,
                    None,
                    None,
                    port=localhost_port,
                    timeout=10,
                    allow_probe=ssh_manager._is_auto_probe_enabled(),
                    credential_storage_ip=ssh_forward_ip,
                )
                if auth is None:
                    clitty_notify(err or "No credential found for target", level="error", context=CTX_UI)
                    return
                def on_disconnect() -> None:
                    if isinstance(forward_proc, list):
                        for p in forward_proc:
                            if p and p.poll() is None:
                                p.terminate()
                    elif forward_proc and forward_proc.poll() is None:
                        forward_proc.terminate()

                app.push_screen(EmbeddedSSHScreen(
                    ip=localhost_ip,
                    username=auth.username,
                    password=auth.password,
                    use_agent=auth.use_agent,
                    profile_id=profile_id,
                    host_key_host=hk_host,
                    host_key_port=hk_port,
                    host_key_via_host_id=hk_via,
                    port=localhost_port,
                    on_disconnect=on_disconnect,
                ))
            elif connection_window == "new":
                use_status_bar = (db.get_setting("new_window_status_bar", "true") or "true").lower() in ("true", "1", "yes")
                from src.ui.screens.embedded_ssh import TERMINAL_AVAILABLE
                if use_status_bar and not TERMINAL_AVAILABLE:
                    use_status_bar = False
                spawn_fn = ssh_manager.spawn_session_in_new_terminal if use_status_bar else ssh_manager.spawn_ssh_in_new_terminal
                rc = spawn_fn(
                    localhost_ip, vault, None, profile_id=profile_id, key_id=None,
                    host_key_host=hk_host, host_key_port=hk_port, host_key_via_host_id=hk_via,
                    port=localhost_port, credential_storage_ip=ssh_forward_ip,
                    host_id=self.host_id,
                )
                if rc == 0:
                    clitty_notify("SSH opened in new terminal" + (" (status bar)" if use_status_bar else ""), context=CTX_UI)
                    clitty_notify(f"SSH via forward started: target {ssh_forward_ip}", level="info", log_only=True)
                elif rc == 2:
                    clitty_notify("Target not reachable via forward", level="error", context=CTX_UI)
                    clitty_notify(f"SSH via forward failed: target {ssh_forward_ip} not reachable", level="error", log_only=True)
                elif rc == 1:
                    clitty_notify("No valid credential for target", level="error", context=CTX_UI)
                    clitty_notify(f"SSH via forward failed: no valid credential for {ssh_forward_ip}", level="error", log_only=True)
                elif rc == 3:
                    hint = "install wt, cmd, or powershell" if sys.platform == "win32" else ("gnome-terminal, xterm, wt, cmd, or powershell" if _is_wsl() else "gnome-terminal, xterm, etc.")
                    clitty_notify(f"No terminal emulator found ({hint})", level="error", context=CTX_UI)
            else:
                ran_blocking_connect = True
                with app.suspend():
                    try:
                        rc = ssh_manager.connect(
                            localhost_ip, vault, None, profile_id=profile_id, method=method, key_id=None,
                            host_key_host=hk_host, host_key_port=hk_port, host_key_via_host_id=hk_via,
                            port=localhost_port, credential_storage_ip=ssh_forward_ip,
                        )
                        if rc == 2:
                            clitty_notify(f"Target {ssh_forward_ip} not reachable via forward", level="error", context=CTX_TERMINAL)
                            clitty_notify(f"SSH via forward failed: {ssh_forward_ip} not reachable", level="error", log_only=True)
                        elif rc != 0:
                            clitty_notify(f"SSH exited with code {rc}", level="error", context=CTX_TERMINAL)
                            clitty_notify(f"SSH via forward exited: rc={rc}", level="error", log_only=True)
                        clitty_notify("Press Enter to return to cliTTY...", context=CTX_TERMINAL)
                        input()
                    except Exception as exc:
                        clitty_notify(f"Connection error: {exc}", level="error", context=CTX_TERMINAL)
                        input()
        finally:
            if ran_blocking_connect:
                if isinstance(forward_proc, list):
                    for p in forward_proc:
                        if p and p.poll() is None:
                            p.terminate()
                elif forward_proc and forward_proc.poll() is None:
                    forward_proc.terminate()

        self._maybe_update_jump_host(host, ssh_forward_ip)

    def _maybe_update_jump_host(self, host, ssh_forward_ip: str) -> None:
        host = dict(host) if not isinstance(host, dict) else host
        role = host.get("role") or ""
        if not role and host.get("data"):
            try:
                d = json.loads(host["data"]) if isinstance(host["data"], str) else host["data"]
                role = (d.get("Role") or d.get("role") or "") if isinstance(d, dict) else ""
            except (json.JSONDecodeError, TypeError):
                pass
        base = host["name"].strip().rstrip((role or "").strip()).strip()
        suffix = db.get_setting("jump_host_add", "[JUMP]")
        jump_name = f"{base}{suffix}" if base else (suffix or "[JUMP]")
        jump_host = db.get_host_by_name(jump_name)
        if jump_host:
            if (jump_host["ip_address"] or "").strip():
                clitty_notify(f"Jump host {jump_name} already has IP; not updated", level="warn", context=CTX_UI)
                return
            db.update_host(jump_host["id"], ip_address=ssh_forward_ip, connect_through_host_id=self.host_id)
            clitty_notify(f"Jump host {jump_name} updated with IP {ssh_forward_ip}", level="info", context=CTX_UI)
        else:
            data: dict[str, str] = {}
            try:
                raw = host.get("data")
                parsed = json.loads(raw) if isinstance(raw, str) else (raw or {})
                if isinstance(parsed, dict):
                    data = {k: str(v) for k, v in parsed.items() if v}
            except (json.JSONDecodeError, TypeError):
                pass
            for k in ("tenant", "Tenant", "site", "Site", "status", "Status"):
                if k in host.keys() and host[k]:
                    key = "Tenant" if k.lower() == "tenant" else "Site" if k.lower() == "site" else "Status"
                    data[key] = str(host[k])
            db.add_host(
                name=jump_name,
                ip_address=ssh_forward_ip,
                connect_through_host_id=self.host_id,
                data=data,
            )
            clitty_notify(f"Jump host {jump_name} created with IP {ssh_forward_ip}", level="info", context=CTX_UI)

    def _do_ssh_direct(
        self,
        app,
        ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        connection_window: str,
        key_id: int | None = None,
    ) -> None:
        method = db.get_setting("ssh_method", "subprocess")
        if method == "embedded" and connection_window == "same":
            from src.ui.screens.embedded_ssh import EmbeddedSSHScreen, TERMINAL_AVAILABLE
            if not TERMINAL_AVAILABLE:
                clitty_notify("Embedded terminal unavailable (e.g. on Windows). Use subprocess or new window.", level="error", context=CTX_UI)
                return
            app.push_screen(EmbeddedSSHScreen(
                host_id=self.host_id,
                profile_id=profile_id,
                vault=vault,
            ))
            return

        if connection_window == "new":
            try:
                use_status_bar = (db.get_setting("new_window_status_bar", "true") or "true").lower() in ("true", "1", "yes")
                from src.ui.screens.embedded_ssh import TERMINAL_AVAILABLE
                if use_status_bar and not TERMINAL_AVAILABLE:
                    use_status_bar = False
                spawn_fn = ssh_manager.spawn_session_in_new_terminal if use_status_bar else ssh_manager.spawn_ssh_in_new_terminal
                rc = spawn_fn(ip, vault, credential_id, profile_id=profile_id, key_id=key_id)
                if rc == 0:
                    clitty_notify("SSH opened in new terminal" + (" (status bar)" if use_status_bar else ""), context=CTX_UI)
                elif rc == 2:
                    clitty_notify("Host is not reachable", level="error", context=CTX_UI)
                elif rc == 1:
                    clitty_notify("No valid credential or key found", level="error", context=CTX_UI)
                elif rc == 3:
                    hint = "install wt, cmd, or powershell" if sys.platform == "win32" else ("install gnome-terminal, xterm, wt, cmd, or powershell" if _is_wsl() else "install gnome-terminal, xterm, etc.")
                    clitty_notify(f"No terminal emulator found ({hint})", level="error", context=CTX_UI)
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_UI)
            return

        method = db.get_setting("ssh_method", "subprocess")
        with app.suspend():
            try:
                rc = ssh_manager.connect(ip, vault, credential_id, profile_id=profile_id, method=method, key_id=key_id, host_id=self.host_id)
                if rc == 2:
                    clitty_notify(f"Host {ip} is not reachable (connection timed out on port)", level="error", context=CTX_TERMINAL)
                elif rc != 0 and credential_id is None:
                    clitty_notify(f"No valid credential or key found for {ip}", level="error", context=CTX_TERMINAL)
                elif rc != 0:
                    clitty_notify(f"SSH exited with code {rc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return to cliTTY...", context=CTX_TERMINAL)
                input()
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                input()

    def _do_telnet(
        self,
        app,
        ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        ssh_forward_ip: str,
        connect_in_background: bool,
    ) -> None:
        if ssh_forward_ip.strip():
            self._do_telnet_via_forward(app, ip, vault, credential_id, profile_id, ssh_forward_ip.strip(), connect_in_background)
        else:
            self._do_telnet_direct(app, ip, vault, credential_id, profile_id)

    def _do_telnet_direct(
        self,
        app,
        ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
    ) -> None:
        from src import telnet_manager
        method = db.get_setting("telnet_method", "subprocess")
        if method == "subprocess_new_window":
            rc = telnet_manager.spawn_telnet_in_new_terminal(ip, 23, vault, credential_id)
        else:
            with app.suspend():
                rc = telnet_manager.connect_telnet(ip, 23, vault, credential_id)
        if rc != 0:
            clitty_notify("Telnet connection failed", level="error", context=CTX_UI)

    def _do_telnet_via_forward(
        self,
        app,
        jump_ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        target_ip: str,
        connect_in_background: bool,
    ) -> None:
        from src import telnet_manager
        from src import ssh_manager
        import time
        TELNET_FWD_LOCAL = 2323
        target = db.get_host(self.host_id)
        target_credential_id = target["credential_id"] if target and "credential_id" in target.keys() and target["credential_id"] else credential_id
        chain = db.get_jump_chain(self.host_id)
        procs = []
        try:
            if len(chain) >= 3:
                for i in range(len(chain) - 1):
                    hop = chain[i]
                    next_hop = chain[i + 1]
                    next_ip = next_hop["ip_address"]
                    local_port = 2323 if i == len(chain) - 2 else 2222 + i
                    remote_port = 23 if i == len(chain) - 2 else 22
                    cred_id = hop["credential_id"] if "credential_id" in hop.keys() else None
                    conn_host = hop["ip_address"] if i == 0 else "127.0.0.1"
                    conn_port = 22 if i == 0 else (2222 + i - 1)
                    proc, rc = ssh_manager.spawn_forward_only(
                        conn_host, vault, cred_id, profile_id, None,
                        next_ip, remote_port=remote_port, local_port=local_port,
                        connect_port=conn_port if i > 0 else None,
                    )
                    if rc != 0:
                        for p in procs:
                            if p and p.poll() is None:
                                p.terminate()
                        return
                    procs.append(proc)
                    time.sleep(0.5 if i == 0 else 0.3)
                local_port = TELNET_FWD_LOCAL
            else:
                proc, rc = ssh_manager.spawn_forward_only(
                    jump_ip, vault, credential_id, profile_id, None,
                    target_ip, remote_port=23, local_port=TELNET_FWD_LOCAL,
                    host_id=self.host_id,
                )
                if rc != 0:
                    return
                time.sleep(0.8)
                procs = [proc]
                local_port = TELNET_FWD_LOCAL
            method = db.get_setting("telnet_method", "subprocess")
            if method == "subprocess_new_window":
                rc = telnet_manager.spawn_telnet_in_new_terminal("127.0.0.1", local_port, vault, target_credential_id)
            else:
                with app.suspend():
                    rc = telnet_manager.connect_telnet("127.0.0.1", local_port, vault, target_credential_id)
        finally:
            for p in procs:
                if p and p.poll() is None:
                    p.terminate()
        if rc != 0:
            clitty_notify("Telnet connection failed", level="error", context=CTX_UI)

    def _do_sftp(
        self,
        app,
        ip: str,
        vault: Vault,
        credential_id: int | None,
        profile_id: int | None,
        connection_window: str,
        key_id: int | None = None,
        ssh_forward_ip: str = "",
        connect_in_background: bool = True,
    ) -> None:
        if ssh_forward_ip.strip():
            clitty_notify("SSH Forward not yet supported for SFTP", level="warn", context=CTX_UI)
            return
        sftp_method = db.get_setting("sftp_method", "subprocess")
        if sftp_method == "paramiko":
            from src.ui.screens.sftp_browser import SFTPBrowserScreen
            app.push_screen(SFTPBrowserScreen(
                host_id=self.host_id,
                profile_id=profile_id,
                vault=vault,
            ))
            return

        if connection_window == "new":
            try:
                rc = ssh_manager.spawn_sftp_in_new_terminal(ip, vault, credential_id, profile_id=profile_id, key_id=key_id)
                if rc == 0:
                    clitty_notify("SFTP opened in new terminal", context=CTX_UI)
                elif rc == 2:
                    clitty_notify("Host is not reachable", level="error", context=CTX_UI)
                elif rc == 1:
                    clitty_notify("No valid credential or key found", level="error", context=CTX_UI)
                elif rc == 3:
                    hint = "install wt, cmd, or powershell" if sys.platform == "win32" else ("install gnome-terminal, xterm, wt, cmd, or powershell" if _is_wsl() else "install gnome-terminal, xterm, etc.")
                    clitty_notify(f"No terminal emulator found ({hint})", level="error", context=CTX_UI)
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_UI)
            return

        with app.suspend():
            try:
                rc = ssh_manager.connect_sftp(ip, vault, credential_id, profile_id=profile_id, key_id=key_id, host_id=self.host_id)
                if rc == 2:
                    clitty_notify(f"Host {ip} is not reachable (connection timed out on port)", level="error", context=CTX_TERMINAL)
                elif rc != 0 and credential_id is None:
                    clitty_notify(f"No valid credential or key found for {ip}", level="error", context=CTX_TERMINAL)
                elif rc != 0:
                    clitty_notify(f"SFTP exited with code {rc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return to cliTTY...", context=CTX_TERMINAL)
                input()
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                input()


# ---------------------------------------------------------------------------
# Manual connect by IP
# ---------------------------------------------------------------------------

class ManualConnectScreen(ModalScreen):
    """Prompt for an IP and connect. If the host doesn't exist, probe creds and add it."""

    DEFAULT_CSS = """
    ManualConnectScreen {
        align: center middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container"):
            yield Label("[b]Manual Connect[/b]")
            yield Label("IP Address")
            yield Input(id="mc-ip", placeholder="10.0.0.1")
            yield Button("Connect", variant="primary", id="btn-mc-connect")
            yield Button("Cancel", id="btn-mc-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-mc-cancel":
            self.dismiss()
            return

        ip = self.query_one("#mc-ip", Input).value.strip()
        if not ip:
            clitty_notify("IP address required", level="error", context=CTX_UI)
            return

        existing = db.get_host_by_ip(ip)
        vault: Vault = self.app.vault  # type: ignore[attr-defined]
        connection_window = db.get_setting("connection_window", "same")
        method = db.get_setting("ssh_method", "subprocess")
        app = self.app

        if existing:
            credential_id = existing["credential_id"]
            key_id = existing["key_id"] if "key_id" in existing.keys() else None
            host_id = existing["id"]
        else:
            credential_id = None
            key_id = None
            host_id = None

        if key_id and not ssh_manager.is_key_loaded(key_id):
            key_row = db.get_ssh_key(key_id)
            if key_row and key_row["prompt_passphrase"]:
                def on_passphrase_result(result: tuple[bool, str] | None) -> None:
                    self.dismiss()
                    if result is None:
                        return
                    success, _passphrase = result
                    if not success:
                        return
                    self._finish_manual_connect(
                        app,
                        ip,
                        vault,
                        connection_window,
                        method,
                        credential_id,
                        key_id,
                        host_id,
                        existing,
                        probe_enabled=True,
                    )

                app.push_screen(
                    AgentPassphraseScreen(key_id=key_id, key_label=key_row["label"] or key_row["username"], vault=vault),
                    callback=on_passphrase_result,
                )
                return

        probe_enabled = (db.get_setting("auto_probe_credentials", "true") or "true").lower() in ("true", "1", "yes")

        if (not probe_enabled) and credential_id is None and key_id is None and db.list_credentials():
            def on_cred_selected(cid: int | None) -> None:
                if cid is None:
                    return
                self._finish_manual_connect(
                    app,
                    ip,
                    vault,
                    connection_window,
                    method,
                    cid,
                    key_id,
                    host_id,
                    existing,
                    probe_enabled=False,
                )

            self.dismiss()
            app.push_screen(CredentialSelectScreen(), callback=on_cred_selected)
            return

        self.dismiss()
        self._finish_manual_connect(
            app,
            ip,
            vault,
            connection_window,
            method,
            credential_id,
            key_id,
            host_id,
            existing,
            probe_enabled=probe_enabled,
        )

    def _finish_manual_connect(
        self,
        app,
        ip,
        vault,
        connection_window,
        method,
        credential_id,
        key_id,
        host_id,
        existing,
        *,
        probe_enabled: bool = True,
    ) -> None:
        if connection_window == "new":
            try:
                if not ssh_manager.check_host_alive(ip):
                    clitty_notify("Host is not reachable", level="error", context=CTX_UI)
                    return
                if credential_id is None and key_id is None:
                    if probe_enabled:
                        credential_id = ssh_manager.probe_credentials(ip, vault)
                        if credential_id is None:
                            clitty_notify("No valid credential or key found", level="error", context=CTX_UI)
                            return
                    else:
                        clitty_notify("No credential or key selected for this host", level="error", context=CTX_UI)
                        return
                if host_id is None:
                    host_id = db.add_host(name=ip, ip_address=ip, credential_id=credential_id)
                if existing and existing["credential_id"] is None and credential_id:
                    db.update_host(host_id, credential_id=credential_id)
                use_status_bar = (db.get_setting("new_window_status_bar", "true") or "true").lower() in ("true", "1", "yes")
                from src.ui.screens.embedded_ssh import TERMINAL_AVAILABLE
                if use_status_bar and not TERMINAL_AVAILABLE:
                    use_status_bar = False
                spawn_fn = ssh_manager.spawn_session_in_new_terminal if use_status_bar else ssh_manager.spawn_ssh_in_new_terminal
                rc = spawn_fn(ip, vault, credential_id, profile_id=None, key_id=key_id, host_id=host_id)
                if rc == 0:
                    clitty_notify("SSH opened in new terminal" + (" (status bar)" if use_status_bar else ""), context=CTX_UI)
                elif rc == 2:
                    clitty_notify("Host is not reachable", level="error", context=CTX_UI)
                elif rc == 1:
                    clitty_notify("No valid credential or key found", level="error", context=CTX_UI)
                elif rc == 3:
                    hint = "install wt, cmd, or powershell" if sys.platform == "win32" else ("install gnome-terminal, xterm, wt, cmd, or powershell" if _is_wsl() else "install gnome-terminal, xterm, etc.")
                    clitty_notify(f"No terminal emulator found ({hint})", level="error", context=CTX_UI)
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_UI)
            return

        with app.suspend():
            try:
                if not ssh_manager.check_host_alive(ip):
                    clitty_notify(f"Host {ip} is not reachable (connection timed out)", level="error", context=CTX_TERMINAL)
                    clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                    input()
                    return

                if credential_id is None and key_id is None:
                    if probe_enabled:
                        clitty_notify(f"Probing credentials for {ip}...", context=CTX_TERMINAL)
                        credential_id = ssh_manager.probe_credentials(ip, vault)
                        if credential_id is None:
                            clitty_notify(f"No valid credential or key found for {ip}", level="error", context=CTX_TERMINAL)
                            clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                            input()
                            return
                        clitty_notify(f"Found working credential (id={credential_id})", context=CTX_TERMINAL)
                    else:
                        clitty_notify("No credential or key selected for this host", level="error", context=CTX_TERMINAL)
                        clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                        input()
                        return

                if host_id is None:
                    name = input("[cliTTY] Enter a name for this host: ").strip()
                    host_id = db.add_host(name=name, ip_address=ip, credential_id=credential_id)
                    clitty_notify(f"Saved host {name} (id={host_id})", context=CTX_TERMINAL)

                if existing and existing["credential_id"] is None and credential_id:
                    db.update_host(host_id, credential_id=credential_id)

                rc = ssh_manager.connect(ip, vault, credential_id, method=method, key_id=key_id, host_id=host_id)
                if rc == 2:
                    clitty_notify(f"Host {ip} is not reachable (connection timed out on port)", level="error", context=CTX_TERMINAL)
                elif rc != 0:
                    clitty_notify(f"SSH exited with code {rc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return to cliTTY...", context=CTX_TERMINAL)
                input()
            except Exception as exc:
                clitty_notify(f"Connection error: {exc}", level="error", context=CTX_TERMINAL)
                clitty_notify("Press Enter to return...", context=CTX_TERMINAL)
                input()


# ---------------------------------------------------------------------------
# Host add / edit form
# ---------------------------------------------------------------------------

class HostFormScreen(ModalScreen[bool]):
    """Modal for adding or editing a host."""

    DEFAULT_CSS = """
    HostFormScreen {
        align: center middle;
    }
    HostFormScreen #host-connect-through-list {
        max-height: 10;
    }
    """

    def __init__(self, host_id: int | None = None, **kwargs):
        super().__init__(**kwargs)
        self.host_id = host_id
        self._connect_through_host_id: int | None = None

    def _auth_options(self) -> list[tuple[str, str]]:
        """Build dropdown options: (None), credentials label (pass), keys label (key). Values: "", "cred:1", "key:2"."""
        opts: list[tuple[str, str]] = [("(None)", "")]
        for cred in db.list_credentials():
            label = cred["label"] or f"Cred #{cred['id']}"
            opts.append((f"{label} (pass)", f"cred:{cred['id']}"))
        for key in db.list_ssh_keys():
            label = key["label"] or f"Key #{key['id']}"
            opts.append((f"{label} (key)", f"key:{key['id']}"))
        return opts

    def _via_host_options(self) -> list[tuple[str, str]]:
        """Build dropdown options for via host: (Direct) and SSH-only hosts."""
        opts: list[tuple[str, str]] = [("(Direct)", "")]
        for h in db.list_hosts_ssh_only():
            label = f"{h['name']} ({h['ip_address']})"
            opts.append((label, str(h["id"])))
        return opts

    def _filter_via_host_options(self, search: str) -> list[tuple[str, str]]:
        """Filter via-host options by search string (case-insensitive)."""
        opts = self._via_host_options()
        if not search.strip():
            return opts
        q = search.strip().lower()
        return [(label, val) for label, val in opts if q in label.lower()]

    def _refresh_via_host_list(self, search: str = "") -> None:
        """Update the OptionList with filtered via-host options."""
        opts = self._filter_via_host_options(search)
        ol = self.query_one("#host-connect-through-list", OptionList)
        ol.clear_options()
        if opts:
            ol.add_options([Option(label, id=val) for label, val in opts])

    def _get_visible_columns(self) -> list[tuple[str, str]]:
        """Return [(col_name, input_id), ...] for visible columns, ordered by seq."""
        defs = db.get_column_defs()
        if not defs:
            return [
                ("name", "host-name"),
                ("ip_address", "host-ip"),
            ]
        result: list[tuple[str, str]] = []
        for d in defs:
            if not d["visible"]:
                continue
            c = d["col_name"]
            inp_id = "host-name" if c == "name" else ("host-ip" if c == "ip_address" else f"host-{c}")
            result.append((c, inp_id))
        return result

    def compose(self) -> ComposeResult:
        title = "Edit Host" if self.host_id else "Add Host"
        cols = self._get_visible_columns()
        with Vertical(classes="form-container"):
            yield Label(f"[b]{title}[/b]")
            for col_name, inp_id in cols:
                label = "IP Address" if col_name == "ip_address" else ("Name" if col_name == "name" else col_name)
                yield Label(label)
                yield Input(id=inp_id, placeholder=label)
            yield Label("Protocol")
            yield Select(
                [("SSH", "ssh"), ("Telnet", "telnet")],
                id="host-proto",
                value="ssh",
            )
            yield Label("Credential / Key")
            yield Select(
                self._auth_options(),
                id="host-auth-cred",
                value="",
            )
            yield Label("Connect via host (SSH only)")
            yield Input(
                id="host-connect-through-input",
                placeholder="Type to search...",
            )
            yield OptionList(id="host-connect-through-list")
            yield Checkbox(
                "Use proxy command & extra args (from profile)",
                id="host-use-proxy-extra",
                value=True,
            )
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        self._refresh_via_host_list("")
        if not self.host_id:
            self.query_one("#host-connect-through-input", Input).value = "(Direct)"
        if self.host_id:
            host = db.get_host(self.host_id)
            if host:
                data: dict[str, str] = {}
                if "data" in host.keys() and host["data"]:
                    try:
                        raw = host["data"]
                        data = json.loads(raw) if isinstance(raw, str) else (raw or {})
                    except (json.JSONDecodeError, TypeError):
                        pass
                for col_name, inp_id in self._get_visible_columns():
                    if col_name == "name":
                        self.query_one(f"#{inp_id}", Input).value = host["name"] or ""
                    elif col_name == "ip_address":
                        self.query_one(f"#{inp_id}", Input).value = host["ip_address"] or ""
                    else:
                        self.query_one(f"#{inp_id}", Input).value = data.get(col_name, "")
                proto = host["proto"] if "proto" in host.keys() else "ssh"
                self.query_one("#host-proto", Select).value = proto
                key_id = host["key_id"] if "key_id" in host.keys() else None
                cred_select = self.query_one("#host-auth-cred", Select)
                if host["credential_id"]:
                    cred_select.value = f"cred:{host['credential_id']}"
                elif key_id:
                    cred_select.value = f"key:{key_id}"
                else:
                    cred_select.value = ""
                cth = host["connect_through_host_id"] if "connect_through_host_id" in host.keys() else None
                self._connect_through_host_id = cth
                inp = self.query_one("#host-connect-through-input", Input)
                if cth:
                    for label, val in self._via_host_options():
                        if val == str(cth):
                            inp.value = label
                            break
                else:
                    inp.value = "(Direct)"
                use_proxy = data.get("use_proxy_and_extra_args", "true")
                self.query_one("#host-use-proxy-extra", Checkbox).value = use_proxy in (
                    True, "true", "1", 1, "yes"
                )
                self._refresh_via_host_list("")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "host-connect-through-input":
            self._refresh_via_host_list(event.value)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "host-connect-through-list":
            opt = event.option
            label = opt.prompt if isinstance(opt.prompt, str) else str(opt.prompt)
            self.query_one("#host-connect-through-input", Input).value = label
            opt_id = opt.id or ""
            self._connect_through_host_id = int(opt_id) if opt_id and opt_id.isdigit() else None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return

        name = ""
        ip = ""
        data: dict[str, str] = {}
        for col_name, inp_id in self._get_visible_columns():
            try:
                inp = self.query_one(f"#{inp_id}", Input)
                val = (inp.value or "").strip()
            except Exception:
                val = ""
            if col_name == "name":
                name = val
            elif col_name == "ip_address":
                ip = val
            else:
                data[col_name] = val
        use_proxy_cb = self.query_one("#host-use-proxy-extra", Checkbox)
        data["use_proxy_and_extra_args"] = "true" if use_proxy_cb.value else "false"

        credential_id = None
        key_id = None
        connect_through_host_id = None
        auth_val = self.query_one("#host-auth-cred", Select).value
        if isinstance(auth_val, str) and auth_val:
            if auth_val.startswith("cred:"):
                try:
                    credential_id = int(auth_val[5:])
                except ValueError:
                    pass
            elif auth_val.startswith("key:"):
                try:
                    key_id = int(auth_val[4:])
                except ValueError:
                    pass
        connect_through_host_id = self._connect_through_host_id

        proto_val = self.query_one("#host-proto", Select).value
        proto = str(proto_val) if proto_val else "ssh"
        if self.host_id:
            db.update_host(
                self.host_id,
                name=name,
                ip_address=ip,
                data=data,
                credential_id=credential_id,
                key_id=key_id,
                connect_through_host_id=connect_through_host_id,
                proto=proto,
            )
            clitty_notify(f"Updated host {name}", context=CTX_UI)
            clitty_notify(f"Host updated: id={self.host_id}, name={name}, ip={ip}", level="debug", log_only=True)
        else:
            host_id = db.add_host(
                name=name,
                ip_address=ip,
                data=data,
                credential_id=credential_id,
                key_id=key_id,
                connect_through_host_id=connect_through_host_id,
                proto=proto,
            )
            clitty_notify(f"Added host {name}", context=CTX_UI)
            clitty_notify(f"Host added: id={host_id}, name={name}, ip={ip}", level="debug", log_only=True)
        self.dismiss(True)


# ---------------------------------------------------------------------------
# CSV Import
# ---------------------------------------------------------------------------

def _default_col_name(header: str) -> str:
    h = (header or "").strip()
    return h[:1].upper() + h[1:].lower() if h else ""


class CSVImportScreen(ModalScreen[bool]):
    """Step 1: Browse and select a CSV file."""

    DEFAULT_CSS = """
    CSVImportScreen {
        align: center middle;
    }
    #csv-import-container {
        width: 70;
        height: 28;
        border: solid $primary;
        padding: 1 2;
    }
    #csv-import-tree {
        height: 1fr;
        min-height: 10;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="csv-import-container"):
            yield Label("[b]Import Hosts from CSV[/b]")
            yield Label("Browse to a CSV file, select it, then press Select File")
            yield DirectoryTree(str(Path.home()), id="csv-import-tree")
            with Vertical():
                yield Button("Select File", variant="primary", id="btn-select")
                yield Button("Cancel", id="btn-cancel")

    def _get_selected_path(self) -> Path | None:
        tree = self.query_one("#csv-import-tree", DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return None
        return node.data.path

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return
        if event.button.id != "btn-select":
            return

        path = self._get_selected_path()
        if path is None:
            clitty_notify("Select a file", level="warn", context=CTX_UI)
            return
        if path.is_dir():
            clitty_notify("Select a file, not a directory", level="warn", context=CTX_UI)
            return

        from src.importer import get_csv_headers

        try:
            headers = get_csv_headers(path)
        except Exception as exc:
            clitty_notify(f"Could not read CSV: {exc}", level="error", context=CTX_UI)
            return
        if not headers:
            clitty_notify("CSV has no headers", level="warn", context=CTX_UI)
            return

        self.app.push_screen(CSVMappingScreen(csv_path=path, headers=headers), self._on_mapping_done)

    def _on_mapping_done(self, result: bool) -> None:
        self.dismiss(result)


class CSVMappingScreen(ModalScreen[bool]):
    """Step 2: Map CSV headers to columns, then import."""

    DEFAULT_CSS = """
    CSVMappingScreen {
        align: center middle;
    }
    #csv-mapping-container {
        /* Reuse generic form container sizing & scrolling semantics, but ensure
           the mapping grid and buttons get dedicated space. */
        width: 80%;
        max-width: 120;
        min-width: 70;
        height: auto;
        max-height: 90%;
        overflow: hidden;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    .csv-mapping-row {
        height: auto;
        min-height: 1;
    }
    /* Make header + col name inputs a bit wider to use container space */
    .csv-mapping-row Input { width: 24; }
    .csv-mapping-row Input:disabled { width: 24; }
    /* Column widths; applied via shared classes on both header labels
       and row widgets so that everything lines up. */
    .csv-header-cell { width: 24; }
    .csv-col-cell { width: 24; }
    .csv-imp-cell { width: 4; }
    .csv-vis-cell { width: 4; }
    .csv-seq-cell { width: 7; }
    .csv-ip-cell { width: 5; text-align: center; }
    .csv-name-cell { width: 7; text-align: center; }
    /* Ensure the scrollable body takes remaining height above the fixed buttons */
    #csv-mapping-scroll {
        height: 1fr;
        min-height: 8;
    }
    #csv-buttons {
        padding-top: 1;
        dock: bottom;
        height: 3;
    }
    """

    def __init__(self, csv_path: Path, headers: list[str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.csv_path = csv_path
        self.headers = headers
        self.n = len(headers)

    def compose(self) -> ComposeResult:
        # Container uses scrolling via CSS (overflow-y: auto) instead of extra nested scrollables
        with Vertical(id="csv-mapping-container"):
            yield Label("[b]Map CSV Headers to Columns[/b]")
            # Column headers row – order matches body:
            # CSV Header | Col name | Imp | Vis | Seq | IP | Name
            with Horizontal(classes="csv-mapping-row"):
                yield Static("CSV Header", classes="csv-header-cell")
                yield Static("Col name", classes="csv-col-cell")
                yield Static("Imp", classes="csv-imp-cell")
                yield Static("Vis", classes="csv-vis-cell")
                yield Static("Seq", classes="csv-seq-cell")
                yield Static("IP", classes="csv-ip-cell")
                yield Static("Name", classes="csv-name-cell")
            # Body: mapping rows + radio selectors in a single scrollable column
            with ScrollableContainer(id="csv-mapping-scroll"):
                with Vertical():
                    for i, h in enumerate(self.headers):
                        default_col = "ip_address" if i == 0 else ("name" if i == 1 else _default_col_name(h))
                        with Horizontal(classes="csv-mapping-row"):
                            # CSV header text (read-only)
                            yield Input(value=h, id=f"header-{i}", disabled=True, classes="csv-header-cell")
                            # Target column name
                            inp = Input(value=default_col, id=f"col-{i}", placeholder="col name", classes="csv-col-cell")
                            if i == 0:
                                inp.value = "ip_address"
                                inp.disabled = True
                            elif i == 1:
                                inp.value = "name"
                                inp.disabled = True
                            yield inp
                            # Import / Visible flags
                            yield Checkbox(value=True, id=f"import-{i}")
                            yield Checkbox(value=True, id=f"visible-{i}")
                            # Seq dropdown: show 1..N and default to row number (1-based)
                            yield Select(
                                options=[(str(k), str(k)) for k in range(1, self.n + 1)],
                                value=str(i + 1),
                                id=f"seq-{i}",
                                classes="csv-seq-cell",
                            )
                            # IP / Name radio selectors as part of the same row
                            yield RadioButton(value=(i == 0), id=f"ip-{i}")
                            yield RadioButton(value=(i == 1), id=f"name-{i}")
            with Horizontal(id="csv-buttons"):
                yield Button("Import (skip empty IP)", variant="primary", id="btn-import-skip")
                yield Button("Import (include all)", id="btn-import-all")
                yield Button("Cancel", id="btn-cancel")

    def _update_col_inputs_from_radios(self) -> None:
        """Update col_name inputs based on IP/Name radio selection."""
        for j in range(self.n):
            col_inp = self.query_one(f"#col-{j}", Input)
            ip_selected = self.query_one(f"#ip-{j}", RadioButton).value
            name_selected = self.query_one(f"#name-{j}", RadioButton).value
            if ip_selected:
                col_inp.value = "ip_address"
                col_inp.disabled = True
            elif name_selected:
                col_inp.value = "name"
                col_inp.disabled = True
            else:
                col_inp.disabled = False
                col_inp.value = _default_col_name(self.headers[j])

    def on_radio_button_changed(self, event: RadioButton.Changed) -> None:
        """Keep exactly one IP and one Name radio selected, and sync inputs."""
        rb = event.radio_button
        if not rb.id:
            return
        rb_id = str(rb.id)
        try:
            idx = int(rb_id.split("-", 1)[1])
        except (ValueError, IndexError):
            idx = None

        # Enforce exclusivity within each logical group
        if rb_id.startswith("ip-") and rb.value:
            for j in range(self.n):
                if j != idx:
                    self.query_one(f"#ip-{j}", RadioButton).value = False
        elif rb_id.startswith("name-") and rb.value:
            for j in range(self.n):
                if j != idx:
                    self.query_one(f"#name-{j}", RadioButton).value = False

        self._update_col_inputs_from_radios()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        cb = event.control
        if not cb.id or not str(cb.id).startswith("import-"):
            return
        try:
            i = int(str(cb.id).split("-")[-1])
        except (ValueError, IndexError):
            return
        vis_cb = self.query_one(f"#visible-{i}", Checkbox)
        if not cb.value:
            vis_cb.disabled = True
            vis_cb.value = False
        else:
            vis_cb.disabled = False

    def _get_mapping(self) -> list[dict[str, Any]] | None:
        mapping: list[dict[str, Any]] = []
        ip_selected: int | None = None
        name_selected: int | None = None
        for i in range(self.n):
            col_inp = self.query_one(f"#col-{i}", Input)
            seq_sel = self.query_one(f"#seq-{i}", Select)
            imp_cb = self.query_one(f"#import-{i}", Checkbox)
            vis_cb = self.query_one(f"#visible-{i}", Checkbox)
            ip_rb = self.query_one(f"#ip-{i}", RadioButton)
            name_rb = self.query_one(f"#name-{i}", RadioButton)
            col_name = (col_inp.value or "").strip() or _default_col_name(self.headers[i])
            if ip_rb.value:
                ip_selected = i
                col_name = "ip_address"
            if name_rb.value:
                name_selected = i
                col_name = "name"
            try:
                sv = seq_sel.value
                seq_val = int(sv) if sv is not None and sv != "" else (i + 1)
            except (ValueError, TypeError):
                seq_val = i + 1
            mapping.append({
                "csv_header": self.headers[i],
                "col_name": col_name,
                "seq": seq_val,
                "import_": imp_cb.value,
                "visible": vis_cb.value,
            })
        if ip_selected is None:
            clitty_notify("Select one column for IP", level="warn", context=CTX_UI)
            return None
        if name_selected is None:
            clitty_notify("Select one column for Name", level="warn", context=CTX_UI)
            return None
        if ip_selected == name_selected:
            clitty_notify("IP and Name must be different columns", level="warn", context=CTX_UI)
            return None
        return mapping

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return
        if event.button.id not in ("btn-import-skip", "btn-import-all"):
            return

        mapping = self._get_mapping()
        if mapping is None:
            return

        from src.importer import import_csv_with_mapping

        skip = event.button.id == "btn-import-skip"
        try:
            count = import_csv_with_mapping(self.csv_path, mapping, skip_empty_ip=skip)
            clitty_notify(f"Imported {count} new hosts", context=CTX_UI)
        except Exception as exc:
            clitty_notify(f"Import error: {exc}", level="error", context=CTX_UI)
            return
        self.dismiss(True)
