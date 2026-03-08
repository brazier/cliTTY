"""Host browser screen with search/filter and connection launching."""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static
from textual.containers import Vertical

from src import database as db
from src.clitty_notify import CTX_UI, clitty_notify


class HostsScreen(Screen):
    BINDINGS = [
        Binding("slash", "focus_search", "Search", show=True),
        Binding("a", "add_host", "Add", show=True),
        Binding("e", "edit_host", "Edit", show=True),
        Binding("d", "delete_host", "Delete", show=True),
        Binding("i", "import_csv", "Import CSV", show=True),
        Binding("x", "export_hosts", "Export", show=True),
        Binding("m", "manual_connect", "Manual", show=True),
        Binding("r", "refresh_table", "Refresh", show=True),
        Binding("s", "sftp_host", "SFTP", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(" [b]Hosts[/b]  |  / Search  a Add  e Edit  d Delete  i Import  x Export  m Manual  s SFTP  Enter Connect", id="nav-bar")
        with Vertical(id="search-box"):
            yield Input(placeholder="Type to filter hosts...", id="search-input")
        yield DataTable(id="hosts-table")
        yield Footer()

    def _get_table_columns(self) -> list[str]:
        """Build column headers from host_column_defs (visible only, by seq) + fixed."""
        defs = db.get_column_defs()
        visible = [d["col_name"] for d in defs if d["visible"]]
        if not visible:
            return ["ID", "Name", "IP Address", "Cred", "Via", "Proto"]
        pretty_visible: list[str] = []
        for col in visible:
            if col == "name":
                pretty_visible.append("Name")
            elif col == "ip_address":
                pretty_visible.append("IP Address")
            else:
                pretty_visible.append(col)
        return ["ID"] + pretty_visible + ["Cred", "Via", "Proto"]

    def on_mount(self) -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.cursor_type = "row"
        table.add_columns(*self._get_table_columns())
        self._refresh_rows()

    def _refresh_rows(self, search: str = "") -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.clear(columns=True)
        cols = self._get_table_columns()
        table.add_columns(*cols)
        rows = db.list_hosts(search)
        defs = db.get_column_defs()
        visible_cols = [d["col_name"] for d in defs if d["visible"]]
        if not visible_cols:
            visible_cols = ["name", "ip_address"]

        for row in rows:
            cred_label = ""
            if row["credential_id"]:
                cred = db.get_credential(row["credential_id"])
                label = (cred["label"] or cred["username"]) if cred else ""
                cred_label = f"{label} (pass)" if label else ""
            elif "key_id" in row.keys() and row["key_id"]:
                key_row = db.get_ssh_key(row["key_id"])
                label = (key_row["label"] or key_row["username"]) if key_row else ""
                cred_label = f"{label} (key)" if label else ""
            via_id = row["connect_through_host_id"] if "connect_through_host_id" in row.keys() else None
            via_label = "–"
            if via_id:
                jump = db.get_host(via_id)
                via_label = jump["ip_address"] if jump else str(via_id)
            proto = row["proto"] if "proto" in row.keys() else "ssh"

            data: dict[str, str] = {}
            if "data" in row.keys() and row["data"]:
                try:
                    raw = row["data"]
                    data = json.loads(raw) if isinstance(raw, str) else (raw or {})
                except (json.JSONDecodeError, TypeError):
                    pass

            def _val(c: str) -> str:
                if c == "name":
                    return row["name"] or ""
                if c == "ip_address":
                    return row["ip_address"] or ""
                return str(data.get(c, ""))

            cells: list[str] = [str(row["id"])]
            for c in visible_cols:
                cells.append(_val(c))
            cells.extend([cred_label, via_label, proto])
            table.add_row(*cells, key=str(row["id"]))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._refresh_rows(event.value)

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_refresh_table(self) -> None:
        search = self.query_one("#search-input", Input).value
        self._refresh_rows(search)

    def _get_selected_host_id(self) -> int | None:
        table = self.query_one("#hosts-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        try:
            return int(row_key.value)
        except (ValueError, TypeError):
            return None

    # --- Actions that push modal screens ---

    def action_add_host(self) -> None:
        from src.ui.screens.connect import HostFormScreen
        self.app.push_screen(HostFormScreen(), callback=self._on_form_dismiss)

    def action_edit_host(self) -> None:
        host_id = self._get_selected_host_id()
        if host_id is None:
            clitty_notify("No host selected", level="warn", context=CTX_UI)
            return
        from src.ui.screens.connect import HostFormScreen
        self.app.push_screen(HostFormScreen(host_id=host_id), callback=self._on_form_dismiss)

    def action_delete_host(self) -> None:
        host_id = self._get_selected_host_id()
        if host_id is None:
            clitty_notify("No host selected", level="warn", context=CTX_UI)
            return
        host = db.get_host(host_id)
        if host:
            name = host["name"]
            from src.ui.screens.confirm import ConfirmScreen
            self.app.push_screen(
                ConfirmScreen(f"Delete host [b]{name}[/b]?"),
                callback=lambda ok: self._do_delete_host(host_id, name) if ok else None,
            )

    def _do_delete_host(self, host_id: int, name: str) -> None:
        host = db.get_host(host_id)
        ip = host["ip_address"] if host else ""
        db.delete_host(host_id)
        clitty_notify(f"Deleted host {name}", context=CTX_UI)
        clitty_notify(f"Host deleted: id={host_id}, name={name}, ip={ip}", level="debug", log_only=True)
        self._refresh_rows(self.query_one("#search-input", Input).value)

    def action_import_csv(self) -> None:
        from src.ui.screens.connect import CSVImportScreen
        self.app.push_screen(CSVImportScreen(), callback=self._on_form_dismiss)

    def action_export_hosts(self) -> None:
        from src.ui.screens.export_import import ExportHostsScreen, MasterPasswordPromptScreen
        self.app.push_screen(
            MasterPasswordPromptScreen(prompt="Enter master password to allow export:"),
            callback=lambda ok: self.app.push_screen(ExportHostsScreen(), callback=self._on_form_dismiss) if ok else None,
        )

    def action_manual_connect(self) -> None:
        from src.ui.screens.connect import ManualConnectScreen
        self.app.push_screen(ManualConnectScreen())

    def action_sftp_host(self) -> None:
        host_id = self._get_selected_host_id()
        if host_id is None:
            clitty_notify("No host selected", level="warn", context=CTX_UI)
            return
        host = db.get_host(host_id)
        if not host or not host["ip_address"]:
            clitty_notify("Host has no IP address", level="error", context=CTX_UI)
            return
        proto = host["proto"] if "proto" in host.keys() else "ssh"
        if proto != "ssh":
            clitty_notify("SFTP only available for SSH hosts", level="error", context=CTX_UI)
            return
        from src.ui.screens.connect import ProfileSelectScreen
        self.app.push_screen(ProfileSelectScreen(host_id=host_id, action="sftp"))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._connect_selected_host()

    def _connect_selected_host(self) -> None:
        host_id = self._get_selected_host_id()
        if host_id is None:
            clitty_notify("No host selected", level="warn", context=CTX_UI)
            return
        host = db.get_host(host_id)
        if not host:
            clitty_notify("Host not found", level="error", context=CTX_UI)
            return
        proto = host["proto"] if "proto" in host.keys() else "ssh"
        via_id = host["connect_through_host_id"] if "connect_through_host_id" in host.keys() and host["connect_through_host_id"] else None
        if via_id and host["ip_address"]:
            chain = db.get_jump_chain(host_id)
            if len(chain) >= 2:
                for h in chain[:-1]:
                    h_proto = h["proto"] if "proto" in h.keys() else "ssh"
                    if h_proto != "ssh":
                        clitty_notify("All jump hosts must be SSH", level="error", context=CTX_UI)
                        return
        if via_id:
            jump = db.get_host(via_id)
            if jump and host["ip_address"]:
                jump_proto = jump["proto"] if "proto" in jump.keys() else "ssh"
                if jump_proto != "ssh":
                    clitty_notify("Jump host must be SSH", level="error", context=CTX_UI)
                    return
                from src.ui.screens.connect import ProfileSelectScreen
                self.app.push_screen(ProfileSelectScreen(
                    host_id=host_id,
                    action="ssh" if proto == "ssh" else "telnet",
                    ssh_forward_prefill=host["ip_address"],
                ))
                return
        if not host["ip_address"]:
            clitty_notify("Host has no IP address", level="error", context=CTX_UI)
            return
        from src.ui.screens.connect import ProfileSelectScreen
        self.app.push_screen(ProfileSelectScreen(host_id=host_id, action="ssh" if proto == "ssh" else "telnet"))

    def _on_form_dismiss(self, result=None) -> None:
        search = self.query_one("#search-input", Input).value
        self._refresh_rows(search)
