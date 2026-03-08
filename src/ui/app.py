"""Main Textual application for cliTTY."""

from __future__ import annotations

import time
from pathlib import Path
import threading
import tempfile

from src import database as db
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from src import clitty_notify
from src import ssh_manager
from src.encryption import Vault
from src.ui.screens.credentials import CredentialsScreen
from src.ui.screens.help import (
    CredentialsHelpScreen,
    HostKeysHelpScreen,
    HostsHelpScreen,
    KeysHelpScreen,
    ProfilesHelpScreen,
    SettingsHelpScreen,
)
from src.ui.screens.host_keys import HostKeysScreen
from src.ui.screens.hosts import HostsScreen
from src.ui.screens.keys import KeysScreen
from src.ui.screens.profiles import ProfilesScreen
from src.ui.screens.export_import import MasterPasswordPromptScreen
from src.ui.screens.settings import SettingsScreen

CSS_PATH = Path(__file__).parent / "styles.tcss"


class ClittyApp(App):
    TITLE = "cliTTY SSH Manager"
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("1", "switch_screen('hosts')", "Hosts", show=True),
        Binding("2", "switch_screen('credentials')", "Credentials", show=True),
        Binding("3", "switch_screen('keys')", "Keys", show=True),
        Binding("4", "switch_screen('profiles')", "Profiles", show=True),
        Binding("5", "switch_screen('settings')", "Settings", show=True),
        Binding("6", "switch_screen('host_keys')", "Host Keys", show=True),
        Binding("h", "help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    SCREENS = {
        "hosts": HostsScreen,
        "credentials": CredentialsScreen,
        "keys": KeysScreen,
        "profiles": ProfilesScreen,
        "settings": SettingsScreen,
        "host_keys": HostKeysScreen,
    }

    def __init__(self, vault: Vault, **kwargs):
        super().__init__(**kwargs)
        self.vault = vault
        self._last_activity: float = 0.0

    def _scan_temp_files_background(self) -> None:
        """Run temp file scan in a background thread, then show UI toast."""
        try:
            leftover_files = ssh_manager.scan_temp_files()
        except Exception as exc:
            clitty_notify.clitty_notify(
                f"Temp file scan failed: {exc}",
                level="debug",
                log_only=True,
            )
            return
        if not leftover_files:
            return
        tmpdir = tempfile.gettempdir()
        count = len(leftover_files)
        clitty_notify.clitty_notify(
            f"Found {count} cliTTY temp file(s) in {tmpdir}. They can be safely deleted when no cliTTY sessions are running.",
            level="info",
            context=clitty_notify.CTX_UI,
        )

    def on_mount(self) -> None:
        self._reset_activity()
        self.push_screen("hosts")
        ssh_manager.register_host_key_warning_callback(self._on_host_key_notify)
        clitty_notify.set_ui_callback(self._notify_ui)
        # Kick off temp file scan without blocking UI startup.
        threading.Thread(target=self._scan_temp_files_background, daemon=True).start()
        try:
            sec = int(db.get_setting("auto_lock_seconds", "0") or "0")
            enabled = (db.get_setting("auto_lock_enabled", "false") or "false").lower() in ("true", "1", "yes")
            if enabled and sec > 0:
                self.set_interval(1, self._auto_lock_check)
        except ValueError:
            pass

    def _reset_activity(self) -> None:
        self._last_activity = time.monotonic()

    def _auto_lock_check(self) -> None:
        try:
            sec = int(db.get_setting("auto_lock_seconds", "0") or "0")
            enabled = (db.get_setting("auto_lock_enabled", "false") or "false").lower() in ("true", "1", "yes")
        except ValueError:
            return
        if not enabled or sec <= 0:
            return
        if self.vault is None:
            return
        if time.monotonic() - self._last_activity >= sec:
            self._do_lock()

    def _do_lock(self) -> None:
        self.vault = None
        db.set_settings_vault(None)
        self.push_screen(
            MasterPasswordPromptScreen(prompt="Enter master password to unlock:", return_vault=True),
            self._on_unlock,
        )

    def _on_unlock(self, result: Vault | None) -> None:
        if result is not None:
            self.vault = result
            db.set_settings_vault(result)
        self._reset_activity()
        if self.vault is None:
            self._do_lock()

    def on_key(self, event) -> None:
        self._reset_activity()

    def on_mouse_down(self, event) -> None:
        self._reset_activity()

    def on_input_changed(self, event) -> None:
        self._reset_activity()

    def _notify_ui(self, msg: str, sev: str = "information") -> None:
        """Show toast. Use call_from_thread when in worker thread; notify directly when on app thread."""
        try:
            self.call_from_thread(self.notify, msg, severity=sev)
        except RuntimeError as e:
            if "must run in a different thread" in str(e):
                self.notify(msg, severity=sev)
            else:
                raise

    def _on_host_key_notify(self, message: str, severity: str = "information") -> None:
        """Show host key notification in UI (callable from worker threads)."""
        self.call_from_thread(self.notify, message, severity=severity)

    def action_switch_screen(self, screen_name: str) -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(screen_name)

    def action_help(self) -> None:
        screen = self.screen
        if isinstance(screen, HostsScreen):
            self.push_screen(HostsHelpScreen())
        elif isinstance(screen, CredentialsScreen):
            self.push_screen(CredentialsHelpScreen())
        elif isinstance(screen, KeysScreen):
            self.push_screen(KeysHelpScreen())
        elif isinstance(screen, ProfilesScreen):
            self.push_screen(ProfilesHelpScreen())
        elif isinstance(screen, SettingsScreen):
            self.push_screen(SettingsHelpScreen())
        elif isinstance(screen, HostKeysScreen):
            self.push_screen(HostKeysHelpScreen())
        else:
            self.push_screen(HostsHelpScreen())
