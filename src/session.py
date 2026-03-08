#!/usr/bin/env python3
"""cliTTY session launcher - runs embedded SSH + status bar in a new terminal.
Receives credentials and status bar config from parent via --session-data-file; no master password prompt.
Agent keys are inherited from the parent process via SSH_AUTH_SOCK."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Project root (parent of src/) for imports when run as subprocess
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))


def _read_session_data(path: str | None) -> tuple[str | None, bool, dict, str | None, int | None, int | None, int | None, dict | None]:
    """Read session data from JSON file and unlink it.
    Returns (password, use_agent, status_bar_config, host_key_host, host_key_port, host_key_via_host_id, port, profile_opts)."""
    if not path or not os.path.isfile(path):
        return None, False, {}, None, None, None, None, None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        password = data.get("password") if isinstance(data.get("password"), str) else None
        use_agent = bool(data.get("use_agent", False))
        config = data.get("status_bar_config") if isinstance(data.get("status_bar_config"), dict) else {}
        hkh = data.get("host_key_host") if isinstance(data.get("host_key_host"), str) else None
        hkp = data.get("host_key_port") if isinstance(data.get("host_key_port"), (int, float)) else None
        hkpid = data.get("host_key_via_host_id") if isinstance(data.get("host_key_via_host_id"), (int, float)) else None
        sp = data.get("port") if isinstance(data.get("port"), (int, float)) else None
        profile_opts = data.get("profile_opts") if isinstance(data.get("profile_opts"), dict) else None
        return password, use_agent, config, hkh, int(hkp) if hkp is not None else None, int(hkpid) if hkpid is not None else None, int(sp) if sp is not None else None, profile_opts
    except (json.JSONDecodeError, OSError):
        return None, False, {}, None, None, None, None, None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="cliTTY SSH session with status bar")
    parser.add_argument("--session-data-file", dest="session_data_file", required=True, help="Path to temp JSON with password and status_bar_config (from parent)")
    parser.add_argument("--ip", required=True, help="Host IP address")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--profile-id", type=int, default=0, help="Connection profile ID (0 = none)")
    args = parser.parse_args()

    profile_id = args.profile_id if args.profile_id else None
    password, use_agent, status_bar_config, host_key_host, host_key_port, host_key_via_host_id, port, profile_opts = _read_session_data(args.session_data_file)

    import status_bar_config as sb
    sb.set_session_config(status_bar_config)

    from textual.app import App
    from textual.binding import Binding

    from src.ui.screens.embedded_ssh import EmbeddedSSHScreen, SessionTerminal, TerminalExited

    class SessionSSHScreen(EmbeddedSSHScreen):
        """Embedded SSH screen for session mode. ESC/close and terminal exit both quit the app and close the window."""

        _terminal_cls = SessionTerminal

        def _show_error(self, msg: str) -> None:
            import clitty_notify
            clitty_notify.clitty_notify(msg, level="error", context=None)
            self.app.exit()

        BINDINGS = [
            Binding("ctrl+f1", "unfocus_terminal", "Release focus", show=True),
            Binding("escape", "close", "Close", show=True),
        ]

        def action_close(self) -> None:
            bar = self.query_one("#embedded-status-bar")
            bar.stop()
            term = self.query_one("#embedded-terminal")
            if hasattr(term, "stop"):
                term.stop()
            if self._paramiko_for_status:
                try:
                    self._paramiko_for_status.close()
                except Exception:
                    pass
            self.app.exit()

        def on_terminal_exited(self, _event: TerminalExited) -> None:
            """When the SSH process exits (e.g. user typed exit), quit the app and close the window."""
            if self._paramiko_for_status:
                try:
                    self._paramiko_for_status.close()
                except Exception:
                    pass
            bar = self.query_one("#embedded-status-bar")
            bar.stop()
            self.app.exit()

    class SessionApp(App):
        """Minimal app showing only the embedded SSH screen."""

        TITLE = "cliTTY SSH"
        BINDINGS = [("q", "quit", "Quit")]

        def _notify_ui(self, msg: str, sev: str = "information") -> None:
            """Show toast. Use call_from_thread when in worker thread; notify directly when on app thread."""
            try:
                self.call_from_thread(self.notify, msg, severity=sev)
            except RuntimeError as e:
                if "must run in a different thread" in str(e):
                    self.notify(msg, severity=sev)
                else:
                    raise

        def on_mount(self) -> None:
            import clitty_notify
            import ssh_manager
            clitty_notify.set_ui_callback(self._notify_ui)
            ssh_manager.register_host_key_warning_callback(
                lambda msg, severity="information": self.call_from_thread(self.notify, msg, severity=severity)
            )
            self.push_screen(
                SessionSSHScreen(
                    ip=args.ip,
                    username=args.username,
                    password=password,
                    use_agent=use_agent,
                    profile_id=profile_id,
                    profile_opts=profile_opts,
                    host_key_host=host_key_host,
                    host_key_port=host_key_port,
                    host_key_via_host_id=host_key_via_host_id,
                    port=port,
                )
            )

    app = SessionApp()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
