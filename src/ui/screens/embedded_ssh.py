"""Embedded SSH session using textual-terminal with status bar."""

from __future__ import annotations

from typing import Callable

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from src import ssh_manager
from src.clitty_notify import CTX_UI, clitty_notify
from src.encryption import Vault
from src.ui.widgets.status_bar import RemoteStatusBar

# Compatibility shim: textual-terminal expects DEFAULT_COLORS from textual.app,
# which was removed in newer Textual. Inject it before importing textual_terminal.
import textual.app as _textual_app
if not hasattr(_textual_app, "DEFAULT_COLORS"):
    from textual.theme import BUILTIN_THEMES
    _textual_app.DEFAULT_COLORS = {
        "dark": BUILTIN_THEMES["textual-dark"].to_color_system(),
        "light": BUILTIN_THEMES["textual-light"].to_color_system(),
    }

try:
    from textual_terminal import Terminal

    class PastableTerminal(Terminal):
        """Terminal that forwards paste events to the PTY, enabling Ctrl+Shift+V paste."""

        async def on_paste(self, event: events.Paste) -> None:
            if self.emulator is None:
                return
            event.stop()
            await self.send_queue.put(["stdin", event.text])

    class SessionTerminal(PastableTerminal):
        """Terminal that emits TerminalExited when the process exits, for session mode."""

        def stop(self) -> None:
            self.post_message(TerminalExited())
            super().stop()

    TERMINAL_AVAILABLE = True
except Exception as e:
    import logging
    logging.getLogger(__name__).debug(
        "textual_terminal import failed (e.g. no pty on Windows): %s", e
    )
    Terminal = None  # type: ignore[misc, assignment]
    PastableTerminal = None  # type: ignore[misc, assignment]
    SessionTerminal = None  # type: ignore[misc, assignment]
    TERMINAL_AVAILABLE = False


class TerminalExited(Message, bubble=True):
    """Posted when the terminal process exits (e.g. user typed exit in SSH)."""


class EmbeddedSSHScreen(Screen):
    """SSH session embedded in a terminal widget with status bar."""

    DEFAULT_CSS = """
    #embedded-ssh-container {
        width: 100%;
        height: 1fr;
        min-height: 1;
        layout: vertical;
    }
    #embedded-terminal {
        width: 100%;
        height: 1fr;
        min-height: 5;
    }
    #embedded-status-bar {
        width: 100%;
        height: 1;
        min-height: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+f1", "unfocus_terminal", "Release focus", show=True),
        Binding("escape", "close", "Close", show=True),
    ]

    def __init__(
        self,
        host_id: int | None = None,
        profile_id: int | None = None,
        vault: Vault | None = None,
        profile_opts: dict | None = None,
        *,
        ip: str | None = None,
        username: str | None = None,
        password: str | None = None,
        use_agent: bool = False,
        host_key_host: str | None = None,
        host_key_port: int | None = None,
        host_key_via_host_id: int | None = None,
        port: int | None = None,
        on_disconnect: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.host_id = host_id
        self.profile_id = profile_id
        self.vault = vault
        self._profile_opts = profile_opts
        self._ip = ip
        self._username = username
        self._password = password
        self._use_agent = use_agent
        self._host_key_host = host_key_host
        self._host_key_port = host_key_port
        self._host_key_via_host_id = host_key_via_host_id
        self._port = port
        self._on_disconnect = on_disconnect
        self._ssh_client = None
        self._paramiko_for_status = None

    def compose(self) -> ComposeResult:
        if Terminal is None:
            yield Header()
            yield Static(
                "textual-terminal not available. Run: pip install textual-terminal\n"
                "(If installed, it may be incompatible with your Textual version.)",
                id="embedded-ssh-error",
            )
            yield Footer()
            return

        terminal_cls = getattr(self, "_terminal_cls", PastableTerminal) or PastableTerminal
        yield Header()
        with Vertical(id="embedded-ssh-container"):
            yield Static("Connecting...", id="embedded-ssh-status")
            yield terminal_cls(command="true", id="embedded-terminal")
            yield RemoteStatusBar(id="embedded-status-bar")
        yield Footer()

    def on_mount(self) -> None:
        if Terminal is None:
            return
        self.run_worker(self._connect_and_start, thread=True, exclusive=True)

    def _connect_and_start(self) -> None:
        from src import database as db

        if self._ip and self._username is not None:
            ip = self._ip
            opts = None
            if isinstance(self._profile_opts, dict) and self._profile_opts:
                opts = ssh_manager.ProfileOpts(**self._profile_opts)
            try:
                cmd_str, err = ssh_manager.build_ssh_command_string_from_creds(
                    ip, self._username, self._password, profile_id=self.profile_id,
                    use_agent=self._use_agent,
                    host_key_host=self._host_key_host, host_key_port=self._host_key_port,
                    host_key_via_host_id=self._host_key_via_host_id,
                    port=self._port,
                    opts=opts,
                )
            except OSError as e:
                self.app.call_from_thread(self._show_error, str(e))
                return
            if err:
                clitty_notify(err, level="debug", log_only=True)
                self.app.call_from_thread(self._show_error, err)
                return
            try:
                self._paramiko_for_status = ssh_manager.open_paramiko_from_creds(
                    ip, self._username, self._password, profile_id=self.profile_id,
                    use_agent=self._use_agent,
                    host_key_host=self._host_key_host, host_key_port=self._host_key_port,
                    host_key_via_host_id=self._host_key_via_host_id,
                    port=self._port,
                    opts=opts,
                )[0]
            except Exception:
                self._paramiko_for_status = None
        else:
            host = db.get_host(self.host_id)
            if not host or not host["ip_address"]:
                self.app.call_from_thread(self._show_error, "Host not found")
                return
            ip = host["ip_address"]
            credential_id = host["credential_id"]
            key_id = host["key_id"] if "key_id" in host.keys() else None
            try:
                cmd_str, err = ssh_manager.build_ssh_command_string(
                    ip, self.vault, credential_id, profile_id=self.profile_id, key_id=key_id,
                    host_id=self.host_id,
                )
            except OSError as e:
                self.app.call_from_thread(self._show_error, str(e))
                return
            if err:
                self.app.call_from_thread(self._show_error, err)
                return
            try:
                self._paramiko_for_status = ssh_manager.open_paramiko_sftp(
                    ip, self.vault, credential_id, profile_id=self.profile_id, key_id=key_id,
                    host_id=self.host_id,
                )[0]
            except Exception:
                self._paramiko_for_status = None

        clitty_notify(f"Connected to {ip}", context=CTX_UI)
        clitty_notify(f"Embedded SSH connected to {ip}", level="info", log_only=True)

        def start_terminal():
            from src import status_bar_config as sb

            status = self.query_one("#embedded-ssh-status", Static)
            status.update("")
            status.display = False
            term = self.query_one("#embedded-terminal", Terminal)
            term.command = cmd_str
            term.start()
            bar = self.query_one("#embedded-status-bar", RemoteStatusBar)
            vault = getattr(self.app, "vault", None)
            cfg = sb.get_status_bar_config(vault=vault)
            if self._paramiko_for_status and cfg.get("enabled", True):
                bar.start(self._paramiko_for_status)
            else:
                bar.display = False

        self.app.call_from_thread(start_terminal)

    def _show_error(self, msg: str) -> None:
        clitty_notify(msg, level="error", context=CTX_UI)
        self.dismiss()

    def action_unfocus_terminal(self) -> None:
        self.set_focus(None)

    def action_close(self) -> None:
        bar = self.query_one("#embedded-status-bar", RemoteStatusBar)
        bar.stop()
        term = self.query_one("#embedded-terminal")
        if hasattr(term, "stop"):
            term.stop()
        if self._paramiko_for_status:
            try:
                self._paramiko_for_status.close()
            except Exception:
                pass
        if self._on_disconnect:
            try:
                self._on_disconnect()
            except Exception:
                pass
        self.dismiss()
