"""Host keys management screen for SSH host key verification."""

from __future__ import annotations

import re

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static, TextArea

from src import database as db
from src import ssh_manager
from src.clitty_notify import CTX_UI, clitty_notify
from src.ui.screens.confirm import ConfirmScreen


def _parse_known_hosts_line(line: str) -> list[tuple[str, int, str, str]]:
    """Parse a known_hosts line. Returns list of (host, port, key_type, key_data)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    parts = line.split(None, 2)
    if len(parts) < 3:
        return []
    host_part, key_type, key_data = parts[0], parts[1], parts[2]
    if not (key_type.startswith("ssh-") or key_type.startswith("ecdsa-")):
        return []
    host = host_part
    port = 22
    if host_part.startswith("[") and "]:" in host_part:
        match = re.match(r"\[([^\]]+)\]:(\d+)", host_part)
        if match:
            host, port = match.group(1), int(match.group(2))
    elif host_part.startswith("[") and "]" in host_part:
        host = host_part[1 : host_part.index("]")]
    return [(host, port, key_type, key_data)]


class AddHostKeyScreen(ModalScreen[bool]):
    """Modal to add host keys: fetch from server or paste known_hosts line."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    AddHostKeyScreen {
        align: center middle;
    }
    #add-hostkey-container {
        width: 70;
        min-height: 20;
        border: solid $primary;
        padding: 1 2;
    }
    #add-hostkey-tabs {
        height: auto;
        margin-bottom: 1;
    }
    #add-hostkey-fetch {
        height: auto;
    }
    #add-hostkey-paste {
        height: auto;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="add-hostkey-container"):
            yield Label("[b]Add Host Key[/b]")
            yield Label("Fetch from server or paste a known_hosts line", classes="hint")
            with Vertical(id="add-hostkey-fetch"):
                yield Label("Fetch:")
                yield Input(placeholder="Host or IP", id="add-host")
                yield Input(placeholder="Port (22)", id="add-port", value="22")
                yield Button("Fetch keys", variant="primary", id="btn-fetch")
            yield Label("")
            with Vertical(id="add-hostkey-paste"):
                yield Label("Or paste known_hosts line:")
                yield TextArea(
                    placeholder="e.g. hostname ssh-rsa AAAAB3... or [host]:22 ecdsa-sha2-nistp256 AAAAE2Vj...",
                    id="add-paste",
                    language="text",
                )
                yield Button("Parse and add", id="btn-paste")
            yield Label("")
            yield Button("Cancel", id="btn-cancel")

    def _fetch_and_add(self) -> bool:
        host_inp = self.query_one("#add-host", Input)
        port_inp = self.query_one("#add-port", Input)
        host = host_inp.value.strip()
        if not host:
            clitty_notify("Enter host or IP", level="warn", context=CTX_UI)
            return False
        try:
            port = int(port_inp.value.strip() or "22")
        except ValueError:
            port = 22
        try:
            keys = ssh_manager.fetch_host_keys_from_server(host, port)
        except OSError as e:
            clitty_notify(str(e), level="error", context=CTX_UI)
            return False
        if not keys:
            clitty_notify(f"No keys returned for {host}:{port}", level="warn", context=CTX_UI)
            return False
        for key_type, key_data in keys:
            db.set_host_key(host, port, key_type, key_data)
        clitty_notify(f"Added {len(keys)} key(s) for {host}:{port}", context=CTX_UI)
        clitty_notify(f"Host keys added: {host}:{port}, count={len(keys)}, types={[k[0] for k in keys]}", level="debug", log_only=True)
        return True

    def _paste_and_add(self) -> bool:
        text = self.query_one("#add-paste", TextArea).text.strip()
        if not text:
            clitty_notify("Paste a known_hosts line", level="warn", context=CTX_UI)
            return False
        added = 0
        for line in text.splitlines():
            for host, port, key_type, key_data in _parse_known_hosts_line(line):
                db.set_host_key(host, port, key_type, key_data)
                added += 1
        if added == 0:
            clitty_notify("No valid known_hosts lines found", level="warn", context=CTX_UI)
            return False
        clitty_notify(f"Added {added} key(s)", context=CTX_UI)
        return True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return
        if event.button.id == "btn-fetch":
            if self._fetch_and_add():
                self.dismiss(True)
        elif event.button.id == "btn-paste":
            if self._paste_and_add():
                self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class HostKeysScreen(Screen):
    BINDINGS = [
        Binding("a", "add_host_key", "Add", show=True),
        Binding("d", "delete_host_key", "Delete", show=True),
        Binding("r", "refresh_table", "Refresh", show=True),
        Binding("/", "focus_search", "Search", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            " [b]Host Keys[/b]  |  a Add  d Delete  r Refresh  / Search  |  Stored keys for SSH verification",
            id="nav-bar",
        )
        with Vertical(id="search-box"):
            yield Input(placeholder="Filter by host...", id="search-input")
        yield DataTable(id="hostkeys-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hostkeys-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Host", "Port", "Key type", "Via", "Added", "Last changed")
        self._refresh_rows()

    def _refresh_rows(self, search: str = "") -> None:
        table = self.query_one("#hostkeys-table", DataTable)
        table.clear()
        rows = db.list_host_keys()
        for row in rows:
            host = row["host"]
            port = row["port"]
            key_type = row["key_type"]
            via_id = row["via_host_id"] if "via_host_id" in row.keys() else None
            via_label = "–"
            if via_id is not None and via_id != -1 and via_id > 0:
                jump = db.get_host(via_id)
                via_label = jump["ip_address"] if jump else str(via_id)
            created_at = row["created_at"]
            updated_at = row["updated_at"] if "updated_at" in row.keys() else created_at
            if search and search.lower() not in host.lower():
                continue
            added_str = created_at[:19] if created_at and len(created_at) >= 19 else created_at or ""
            changed_str = updated_at[:19] if updated_at and len(updated_at) >= 19 else updated_at or ""
            vid = via_id if via_id is not None and via_id != -1 else ""
            table.add_row(
                host,
                str(port),
                key_type,
                via_label,
                added_str,
                changed_str,
                key=f"{host}\0{port}\0{key_type}\0{vid}",
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._refresh_rows(event.value)

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_refresh_table(self) -> None:
        self._refresh_rows(self.query_one("#search-input", Input).value)

    def _get_selected_row(self) -> tuple[str, int, str, int | None] | None:
        table = self.query_one("#hostkeys-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        if row_key is None or row_key.value is None:
            return None
        key_str = str(row_key.value)
        parts = key_str.split("\0")
        if len(parts) < 3:
            return None
        try:
            via = int(parts[3]) if len(parts) > 3 and parts[3] and parts[3].isdigit() else None
            return (parts[0], int(parts[1]), parts[2], via)
        except (ValueError, TypeError):
            return None

    def action_add_host_key(self) -> None:
        self.app.push_screen(AddHostKeyScreen(), callback=self._on_form_dismiss)

    def action_delete_host_key(self) -> None:
        row = self._get_selected_row()
        if row is None:
            clitty_notify("No host key selected", level="warn", context=CTX_UI)
            return
        host, port, key_type, via = row
        via_str = f" via {via}" if via else ""
        self.app.push_screen(
            ConfirmScreen(f"Delete host key for [b]{host}:{port}[/b] ({key_type}){via_str}?"),
            callback=lambda ok: self._do_delete(host, port, key_type, via) if ok else None,
        )

    def _do_delete(self, host: str, port: int, key_type: str, via_host_id: int | None = None) -> None:
        db.delete_host_key(host, port, key_type, via_host_id=via_host_id)
        clitty_notify(f"Deleted {host}:{port} ({key_type})", context=CTX_UI)
        clitty_notify(f"Host key deleted: {host}:{port}, key_type={key_type}, via_host_id={via_host_id}", level="debug", log_only=True)
        self._refresh_rows(self.query_one("#search-input", Input).value)

    def _on_form_dismiss(self, result: bool | None) -> None:
        if result:
            self._refresh_rows(self.query_one("#search-input", Input).value)
