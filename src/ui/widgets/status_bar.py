"""Remote status bar widget showing uptime, OS, IPs, etc. from SSH."""

from __future__ import annotations

from typing import Optional

import paramiko
from textual.widgets import Static

from src import status_bar_config as sb


class RemoteStatusBar(Static):
    """Status bar that fetches remote info via Paramiko and displays it."""

    DEFAULT_CSS = """
    RemoteStatusBar {
        height: 1;
        background: $accent;
        color: $text;
        padding: 0 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._refresh_handle = None

    def start(self, ssh_client: paramiko.SSHClient) -> None:
        """Start refreshing the status bar with the given SSH client."""
        self._ssh_client = ssh_client
        vault = getattr(self.app, "vault", None)
        cfg = sb.get_status_bar_config(vault=vault)
        if not cfg.get("enabled", True):
            return
        self.update("Loading...")
        self._schedule_refresh()
        self.run_worker(self._fetch_and_update, thread=True, exclusive=False)

    def stop(self) -> None:
        """Stop the refresh timer."""
        if self._refresh_handle:
            self._refresh_handle.stop()
            self._refresh_handle = None
        self._ssh_client = None

    def _schedule_refresh(self) -> None:
        vault = getattr(self.app, "vault", None)
        cfg = sb.get_status_bar_config(vault=vault)
        interval = max(15, int(cfg.get("refresh_interval_sec", 30)))
        self._refresh_handle = self.set_interval(interval, self._do_refresh)

    def _do_refresh(self) -> None:
        """Trigger a fetch (runs on main thread)."""
        if self._ssh_client:
            self.run_worker(self._fetch_and_update, thread=True, exclusive=False)

    def _fetch_and_update(self) -> None:
        """Run in worker: fetch from remote and update widget."""
        client = self._ssh_client
        if client is None:
            return
        vault = getattr(self.app, "vault", None)
        providers = sb.get_enabled_providers(vault=vault)
        if not providers:
            self.app.call_from_thread(self.update, "—")
            return
        parts: list[str] = []
        for p in providers:
            try:
                val = sb.fetch_provider(client, p)
                if val:
                    parts.append(f"{p.label}: {val}")
            except Exception:
                pass
        text = " | ".join(parts) if parts else "—"
        self.app.call_from_thread(self.update, text)
