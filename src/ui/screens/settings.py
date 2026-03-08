"""System settings screen."""

from __future__ import annotations

import os
import sys

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalGroup
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label, Select, Static

from src import database as db
from src import encryption
from src import status_bar_config as sb
from src.clitty_notify import CTX_UI, clitty_notify, refresh_logging_from_db


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


def _get_ssh_methods() -> list[tuple[str, str]]:
    from src.ui.screens.embedded_ssh import TERMINAL_AVAILABLE

    methods: list[tuple[str, str]] = [
        ("subprocess", "subprocess"),
        ("subprocess in new window (plain)", "subprocess_new_window"),
        ("embedded (in-app terminal + status bar)", "embedded"),
        ("paramiko", "paramiko"),
        ("auto", "auto"),
    ]
    if TERMINAL_AVAILABLE:
        # Insert embed variant after plain new window
        methods.insert(2, ("subprocess in new window (embed SSH + status bar)", "subprocess_new_window_embed"))
    return methods


def _get_terminal_options() -> list[tuple[str, str]]:
    if _is_windows():
        return [
            ("Auto (first found)", "auto"),
            ("Windows Terminal (wt)", "wt"),
            ("Command Prompt (cmd)", "cmd"),
            ("PowerShell", "powershell"),
            ("Other", "other"),
        ]
    options = [
        ("Auto (first found)", "auto"),
        ("gnome-terminal", "gnome-terminal"),
        ("konsole", "konsole"),
        ("xfce4-terminal", "xfce4-terminal"),
        ("mate-terminal", "mate-terminal"),
        ("xterm", "xterm"),
        ("alacritty", "alacritty"),
        ("wezterm", "wezterm"),
        ("kitty", "kitty"),
        ("foot", "foot"),
    ]
    if _is_wsl():
        options.extend([
            ("Windows Terminal (wt)", "wt"),
            ("Command Prompt (cmd)", "cmd"),
            ("PowerShell", "powershell"),
        ])
    options.append(("Other", "other"))
    return options


SFTP_METHOD_OPTIONS = [
    ("Subprocess (terminal sftp)", "subprocess"),
    ("Paramiko (in-app browser)", "paramiko"),
]


class ChangePasswordScreen(ModalScreen):
    """Modal to change master password."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Static("[b]Change master password[/b]", id="change-pw-title")
        yield Label("Current password")
        yield Input(placeholder="Current master password", id="current-pw", password=True)
        yield Label("New password")
        yield Input(placeholder="New master password", id="new-pw", password=True)
        yield Label("Confirm new password")
        yield Input(placeholder="Confirm new password", id="confirm-pw", password=True)
        with Horizontal(id="change-pw-buttons"):
            yield Button("Change", variant="primary", id="btn-change-pw")
            yield Button("Cancel", id="btn-cancel-pw")

    def on_mount(self) -> None:
        self.query_one("#current-pw", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-pw":
            self.dismiss(None)
        elif event.button.id == "btn-change-pw":
            self._do_change()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _do_change(self) -> None:
        current = self.query_one("#current-pw", Input).value
        new = self.query_one("#new-pw", Input).value
        confirm = self.query_one("#confirm-pw", Input).value
        if not current:
            self.notify("Enter current password", severity="error")
            return
        if not new:
            self.notify("Enter new password", severity="error")
            return
        if new != confirm:
            self.notify("New password and confirm do not match", severity="error")
            return
        try:
            vault = encryption.change_master_password(current, new)
            assert self.app is not None
            self.app.vault = vault
            clitty_notify("Master password changed", context=CTX_UI)
            self.dismiss(True)
        except ValueError as e:
            self.notify(str(e), severity="error")


class SettingsScreen(Screen):
    BINDINGS = [
        Binding("r", "refresh", "Refresh", show=True),
    ]

    DEFAULT_CSS = """
    SettingsScreen {
        align: left top;
    }
    SettingsScreen #settings-form {
        height: auto;
    }
    SettingsScreen #settings-columns {
        width: 100%;
        height: auto;
        grid-gutter: 2;
    }
    SettingsScreen #settings-left,
    SettingsScreen #settings-right {
        width: 1fr;
        height: auto;
    }
    SettingsScreen .settings-column VerticalGroup {
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(" [b]System Settings[/b]  |  Modify and Save", id="nav-bar")
        with VerticalGroup(id="settings-form"):
            with Horizontal(id="settings-columns"):
                with Vertical(id="settings-left", classes="settings-column"):
                    with VerticalGroup(id="agent-section"):
                        yield Label("[b]SSH Agent[/b]")
                        yield Checkbox("Automatically add passphrase-protected keys to agent", id="auto-add-keys-agent")
                    with VerticalGroup(id="logging-section"):
                        yield Label("[b]Logging[/b]")
                        yield Checkbox("Enable logging", id="logging-enabled")
                        with VerticalGroup(id="log-level-section"):
                            yield Label("Log level")
                            yield Select(
                                [
                                    ("Debug", "debug"),
                                    ("Info", "info"),
                                    ("Warning", "warning"),
                                    ("Error", "error"),
                                ],
                                id="log-level",
                                value=db.get_setting("log_level", "info"),
                            )
                    with VerticalGroup(id="host-key-section"):
                        yield Label("[b]Host Key Verification[/b]")
                        yield Checkbox("Enable host key verification", id="host-key-verification")
                        with VerticalGroup(id="host-key-policy-section"):
                            yield Label("Host key policy (when verification is on)")
                            yield Select(
                                [
                                    ("Accept on first connect", "accept_new"),
                                    ("Strict (known hosts only)", "strict"),
                                    ("Warn on change", "warn"),
                                ],
                                id="host-key-policy",
                                value=db.get_setting("host_key_policy", "accept_new"),
                            )
                with Vertical(id="settings-right", classes="settings-column"):
                    yield Label("[b]Methods[/b]")
                    yield Label("SSH method")
                    yield Select(_get_ssh_methods(), id="ssh-method", value=db.get_setting("ssh_method", "subprocess"))
                    with VerticalGroup(id="terminal-section"):
                        yield Label("Terminal emulator (for new window)")
                        yield Select(_get_terminal_options(), id="terminal-emulator", value="auto")
                        yield Input(
                            id="terminal-other",
                            placeholder="e.g. wt.exe or C:\\path\\to\\alacritty.exe" if _is_windows() else ("e.g. alacritty, wt, or /usr/bin/wezterm" if _is_wsl() else "e.g. alacritty or /usr/bin/wezterm"),
                            value="",
                        )
                    yield Label("SFTP method")
                    yield Select(SFTP_METHOD_OPTIONS, id="sftp-method", value=db.get_setting("sftp_method", "subprocess"))
                    yield Label("Telnet / connection method")
                    yield Select(
                        [
                            ("Subprocess (same terminal)", "subprocess"),
                            ("Subprocess in new window", "subprocess_new_window"),
                        ],
                        id="telnet-method",
                        value=db.get_setting("telnet_method", "subprocess"),
                    )

                    with VerticalGroup(id="master-pw-section"):
                        yield Label("[b]Master Password[/b]")
                        yield Button("Change master password", id="btn-change-master-pw")
                        yield Checkbox("Auto lock after inactivity", id="auto-lock-enabled")
                        with VerticalGroup(id="auto-lock-section"):
                            yield Label("Lock after (seconds)")
                            yield Input(id="auto-lock-seconds", placeholder="e.g. 300 (0 = disabled)", value="0")
                    yield Label("[b]Other[/b]")
                    yield Checkbox("Auto-probe credentials and keys on connect", id="auto-probe-credentials")
                    yield Checkbox("Limit auth tries (avoid fail2ban)", id="limit-auth-tries")
                    with VerticalGroup(id="max-auth-tries-section"):
                        yield Label("Max auth tries")
                        yield Input(
                            id="max-auth-tries",
                            placeholder="3",
                            value=db.get_setting("max_auth_tries", "3"),
                        )
                    yield Label("Default Profile ID (blank = none)")
                    yield Input(id="default-profile", placeholder="leave blank for none", value=db.get_setting("default_profile_id", ""))
                    yield Label("Jump host suffix (when adding via SSH forward)")
                    yield Input(id="jump-host-add", placeholder="[JUMP]", value=db.get_setting("jump_host_add", "[JUMP]"))
                    with VerticalGroup(id="status-bar-section"):
                        yield Label("")
                        yield Label("[b]Status Bar[/b] (when connected)")
                        yield Checkbox("Enable status bar", id="status-bar-enabled")
                        yield Label("Refresh interval (seconds)")
                        yield Input(id="status-bar-interval", placeholder="30", value="30")
                        yield Label("Providers to show")
                        yield Checkbox("Uptime", id="sb-uptime")
                        yield Checkbox("OS release", id="sb-os-release")
                        yield Checkbox("IP addresses", id="sb-ip-addrs")
                        yield Checkbox("Hostname", id="sb-hostname")
            yield Label("")
            yield Button("Save Settings", variant="primary", id="btn-save-settings")
        yield Footer()

    def on_mount(self) -> None:
        self._load_values()
        self._update_visibility()

    def _update_visibility(self) -> None:
        """Show/hide terminal section, status bar section based on selections."""
        method = self.query_one("#ssh-method", Select).value
        method_str = str(method) if method is not Select.BLANK else ""

        show_terminal_section = method_str in ("subprocess_new_window", "subprocess_new_window_embed")
        terminal_section = self.query_one("#terminal-section", VerticalGroup)
        terminal_section.display = show_terminal_section

        if show_terminal_section:
            terminal_emulator = self.query_one("#terminal-emulator", Select).value
            terminal_other = self.query_one("#terminal-other", Input)
            terminal_other.display = terminal_emulator == "other"

        show_status_bar_section = method_str in ("embedded", "subprocess_new_window_embed")
        status_bar_section = self.query_one("#status-bar-section", VerticalGroup)
        status_bar_section.display = show_status_bar_section

        host_key_verification = self.query_one("#host-key-verification", Checkbox).value
        host_key_policy_section = self.query_one("#host-key-policy-section", VerticalGroup)
        host_key_policy_section.display = host_key_verification

        limit_auth_tries = self.query_one("#limit-auth-tries", Checkbox).value
        max_auth_tries_section = self.query_one("#max-auth-tries-section", VerticalGroup)
        max_auth_tries_section.display = limit_auth_tries

        auto_lock_enabled = self.query_one("#auto-lock-enabled", Checkbox).value
        auto_lock_section = self.query_one("#auto-lock-section", VerticalGroup)
        auto_lock_section.display = auto_lock_enabled

        logging_enabled = self.query_one("#logging-enabled", Checkbox).value
        log_level_section = self.query_one("#log-level-section", VerticalGroup)
        log_level_section.display = logging_enabled

    def _load_values(self) -> None:
        auto_add = (db.get_setting("auto_add_keys_to_agent", "false") or "false").lower() in ("true", "1", "yes")
        self.query_one("#auto-add-keys-agent", Checkbox).value = auto_add

        method = db.get_setting("ssh_method", "subprocess")
        connection_window = db.get_setting("connection_window", "same")
        nwsb = (db.get_setting("new_window_status_bar", "true") or "true").lower() in ("true", "1", "yes")

        if connection_window == "new" and method == "subprocess":
            from src.ui.screens.embedded_ssh import TERMINAL_AVAILABLE
            if nwsb and TERMINAL_AVAILABLE:
                select_value = "subprocess_new_window_embed"
            else:
                select_value = "subprocess_new_window"
            options = [m[1] for m in _get_ssh_methods()]
            if select_value in options:
                self.query_one("#ssh-method", Select).value = select_value
            else:
                self.query_one("#ssh-method", Select).value = "subprocess_new_window"
        else:
            self.query_one("#ssh-method", Select).value = method

        terminal_emulator = db.get_setting("terminal_emulator", "auto")
        if _is_windows():
            known_values = {"auto", "wt", "cmd", "powershell"}
        elif _is_wsl():
            known_values = {"auto", "gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal", "xterm", "alacritty", "wezterm", "kitty", "foot", "wt", "cmd", "powershell"}
        else:
            known_values = {"auto", "gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal", "xterm", "alacritty", "wezterm", "kitty", "foot"}
        if terminal_emulator in known_values:
            self.query_one("#terminal-emulator", Select).value = terminal_emulator
            self.query_one("#terminal-other", Input).value = ""
        else:
            self.query_one("#terminal-emulator", Select).value = "other"
            self.query_one("#terminal-other", Input).value = terminal_emulator or ""
        auto_probe = (db.get_setting("auto_probe_credentials", "true") or "true").lower() in ("true", "1", "yes")
        self.query_one("#auto-probe-credentials", Checkbox).value = auto_probe
        limit_auth_tries = (db.get_setting("limit_auth_tries", "true") or "true").lower() in ("true", "1", "yes")
        self.query_one("#limit-auth-tries", Checkbox).value = limit_auth_tries
        self.query_one("#max-auth-tries", Input).value = db.get_setting("max_auth_tries", "3")
        self.query_one("#default-profile", Input).value = db.get_setting("default_profile_id", "")
        self.query_one("#jump-host-add", Input).value = db.get_setting("jump_host_add", "[JUMP]")
        self.query_one("#sftp-method", Select).value = db.get_setting("sftp_method", "subprocess")
        self.query_one("#telnet-method", Select).value = db.get_setting("telnet_method", "subprocess")

        cfg = sb.get_status_bar_config(vault=self.app.vault)
        self.query_one("#status-bar-enabled", Checkbox).value = cfg.get("enabled", True)
        self.query_one("#status-bar-interval", Input).value = str(cfg.get("refresh_interval_sec", 30))
        provider_map = {p["id"]: p.get("enabled", True) for p in cfg.get("providers", [])}
        self.query_one("#sb-uptime", Checkbox).value = provider_map.get("uptime", True)
        self.query_one("#sb-os-release", Checkbox).value = provider_map.get("os_release", True)
        self.query_one("#sb-ip-addrs", Checkbox).value = provider_map.get("ip_addrs", True)
        self.query_one("#sb-hostname", Checkbox).value = provider_map.get("hostname", False)

        logging_enabled = (db.get_setting("logging_enabled", "false") or "false").lower() in ("true", "1", "yes")
        self.query_one("#logging-enabled", Checkbox).value = logging_enabled
        log_level = db.get_setting("log_level", "info") or "info"
        log_level_select = self.query_one("#log-level", Select)
        if log_level in ("debug", "info", "warning", "error"):
            log_level_select.value = log_level
        else:
            log_level_select.value = "info"

        auto_lock_sec = db.get_setting("auto_lock_seconds", "0")
        auto_lock_enabled = (db.get_setting("auto_lock_enabled", "false") or "false").lower() in ("true", "1", "yes")
        self.query_one("#auto-lock-enabled", Checkbox).value = auto_lock_enabled
        self.query_one("#auto-lock-seconds", Input).value = auto_lock_sec or "0"

        host_key_verification = (db.get_setting("host_key_verification", "on") or "on").lower() in ("true", "1", "yes", "on")
        self.query_one("#host-key-verification", Checkbox).value = host_key_verification
        host_key_policy = db.get_setting("host_key_policy", "accept_new") or "accept_new"
        policy_select = self.query_one("#host-key-policy", Select)
        if host_key_policy in ("accept_new", "strict", "warn"):
            policy_select.value = host_key_policy
        else:
            policy_select.value = "accept_new"

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.control.id in ("ssh-method", "terminal-emulator"):
            self._update_visibility()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.control.id in ("host-key-verification", "logging-enabled", "limit-auth-tries", "auto-lock-enabled"):
            self._update_visibility()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-change-master-pw":
            self.push_screen(ChangePasswordScreen())
        elif event.button.id == "btn-save-settings":
            changes: list[tuple[str, str, str]] = []  # (key, old_value, new_value)

            def _maybe_set(key: str, new_val: str, *, default: str = "") -> None:
                old = (db.get_setting(key, default) or default).strip()
                new_str = (str(new_val) if new_val is not None else "").strip()
                if old != new_str:
                    db.set_setting(key, new_str)
                    changes.append((key, old or "(empty)", new_str or "(empty)"))

            auto_add = self.query_one("#auto-add-keys-agent", Checkbox).value
            _maybe_set("auto_add_keys_to_agent", "true" if auto_add else "false", default="false")

            method = self.query_one("#ssh-method", Select).value
            if method and method is not Select.BLANK:
                method_str = str(method)
                if method_str == "subprocess_new_window":
                    _maybe_set("connection_window", "new", default="same")
                    _maybe_set("ssh_method", "subprocess", default="subprocess")
                    _maybe_set("new_window_status_bar", "false", default="true")
                elif method_str == "subprocess_new_window_embed":
                    _maybe_set("connection_window", "new", default="same")
                    _maybe_set("ssh_method", "subprocess", default="subprocess")
                    _maybe_set("new_window_status_bar", "true", default="false")
                else:
                    _maybe_set("connection_window", "same", default="same")
                    _maybe_set("ssh_method", method_str, default="subprocess")

            terminal_emulator = self.query_one("#terminal-emulator", Select).value
            if terminal_emulator and terminal_emulator is not Select.BLANK:
                if terminal_emulator == "other":
                    terminal_value = self.query_one("#terminal-other", Input).value.strip()
                    _maybe_set("terminal_emulator", terminal_value or "auto", default="auto")
                else:
                    _maybe_set("terminal_emulator", str(terminal_emulator), default="auto")

            default_profile = self.query_one("#default-profile", Input).value.strip()
            _maybe_set("default_profile_id", default_profile, default="")
            jump_host_add = self.query_one("#jump-host-add", Input).value.strip() or "[JUMP]"
            _maybe_set("jump_host_add", jump_host_add, default="[JUMP]")

            sftp_method = self.query_one("#sftp-method", Select).value
            if sftp_method and sftp_method is not Select.BLANK:
                _maybe_set("sftp_method", str(sftp_method), default="subprocess")
            telnet_method = self.query_one("#telnet-method", Select).value
            if telnet_method and telnet_method is not Select.BLANK:
                _maybe_set("telnet_method", str(telnet_method), default="subprocess")

            auto_probe = self.query_one("#auto-probe-credentials", Checkbox).value
            _maybe_set("auto_probe_credentials", "true" if auto_probe else "false", default="true")

            limit_auth_tries = self.query_one("#limit-auth-tries", Checkbox).value
            _maybe_set("limit_auth_tries", "true" if limit_auth_tries else "false", default="true")
            max_auth_tries = self.query_one("#max-auth-tries", Input).value.strip() or "3"
            try:
                _ = max(1, min(20, int(max_auth_tries)))
                max_auth_tries = str(_)
            except ValueError:
                max_auth_tries = "3"
            _maybe_set("max_auth_tries", max_auth_tries, default="3")

            logging_enabled = self.query_one("#logging-enabled", Checkbox).value
            _maybe_set("logging_enabled", "true" if logging_enabled else "false", default="false")
            log_level = self.query_one("#log-level", Select).value
            if log_level and log_level is not Select.BLANK:
                _maybe_set("log_level", str(log_level), default="info")

            auto_lock_enabled = self.query_one("#auto-lock-enabled", Checkbox).value
            _maybe_set("auto_lock_enabled", "true" if auto_lock_enabled else "false", default="false")
            try:
                auto_lock_sec = max(0, int(self.query_one("#auto-lock-seconds", Input).value.strip() or "0"))
            except ValueError:
                auto_lock_sec = 0
            _maybe_set("auto_lock_seconds", str(auto_lock_sec), default="0")

            host_key_verification = self.query_one("#host-key-verification", Checkbox).value
            _maybe_set("host_key_verification", "on" if host_key_verification else "off", default="on")
            host_key_policy = self.query_one("#host-key-policy", Select).value
            if host_key_policy and host_key_policy is not Select.BLANK:
                _maybe_set("host_key_policy", str(host_key_policy), default="accept_new")

            old_cfg = sb.get_status_bar_config(vault=self.app.vault)
            cfg = sb.get_status_bar_config(vault=self.app.vault)
            cfg["enabled"] = self.query_one("#status-bar-enabled", Checkbox).value
            try:
                cfg["refresh_interval_sec"] = max(15, int(self.query_one("#status-bar-interval", Input).value or "30"))
            except ValueError:
                cfg["refresh_interval_sec"] = 30
            providers = cfg.get("providers", [])
            provider_ids = ["uptime", "os_release", "ip_addrs", "hostname"]
            for pid in provider_ids:
                for p in providers:
                    if p.get("id") == pid:
                        p["enabled"] = self.query_one(f"#sb-{pid.replace('_', '-')}", Checkbox).value
                        break
                else:
                    providers.append({"id": pid, "enabled": self.query_one(f"#sb-{pid.replace('_', '-')}", Checkbox).value})
            cfg["providers"] = providers
            sb_changed = (
                old_cfg.get("enabled") != cfg["enabled"]
                or old_cfg.get("refresh_interval_sec") != cfg["refresh_interval_sec"]
                or any(
                    next((p.get("enabled") for p in old_cfg.get("providers", []) if p.get("id") == pid), True)
                    != next((p.get("enabled") for p in cfg["providers"] if p.get("id") == pid), True)
                    for pid in provider_ids
                )
            )
            if sb_changed:
                sb.set_status_bar_config(cfg, vault=self.app.vault)
                old_summary = f"enabled={old_cfg.get('enabled')}, interval={old_cfg.get('refresh_interval_sec', 30)}"
                new_summary = f"enabled={cfg['enabled']}, interval={cfg['refresh_interval_sec']}"
                changes.append(("status_bar", old_summary, new_summary))

            # Ensure logging configuration changes take effect immediately.
            refresh_logging_from_db()

            clitty_notify("Settings saved", context=CTX_UI)
            if changes:
                msg = "; ".join(f"{k}: {o}→{n}" for k, o, n in changes)
                clitty_notify(f"Settings changed: {msg}", level="info", log_only=True, force_log=True)

    def action_refresh(self) -> None:
        self._load_values()
        self._update_visibility()
