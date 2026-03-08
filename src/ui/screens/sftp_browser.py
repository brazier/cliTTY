"""Paramiko SFTP file browser screen."""

from __future__ import annotations

import stat
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, DirectoryTree, Footer, Label, Static

from src import ssh_manager
from src.clitty_notify import CTX_UI, clitty_notify
from src.encryption import Vault


class SFTPBrowserScreen(ModalScreen):
    """In-app SFTP file browser using Paramiko. Navigate, download, upload."""

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
        Binding("enter", "activate", "Open", show=True),
        Binding("u", "up", "Up", show=True),
        Binding("d", "download", "Download", show=True),
        Binding("p", "upload", "Upload", show=True),
    ]

    DEFAULT_CSS = """
    SFTPBrowserScreen {
        align: center middle;
    }
    #sftp-browser {
        width: 90;
        height: 35;
        border: solid green;
        padding: 1 2;
    }
    #sftp-panes {
        height: 1fr;
        min-height: 12;
    }
    #sftp-local-pane, #sftp-remote-pane {
        width: 1fr;
        min-width: 20;
        border: solid $primary;
        padding: 0 1;
    }
    #sftp-path {
        color: $accent;
        padding-bottom: 1;
    }
    #sftp-local-tree, #sftp-table {
        height: 1fr;
        min-height: 8;
    }
    #sftp-up-row {
        height: auto;
        margin-top: 1;
    }
    #sftp-up-row #sftp-up-spacer {
        width: 1fr;
    }
    #sftp-up-row #btn-up {
        width: 1fr;
    }
    #sftp-buttons {
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        host_id: int,
        profile_id: int | None,
        vault: Vault,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.host_id = host_id
        self.profile_id = profile_id
        self.vault = vault
        self._ssh_client = None
        self._sftp_client = None
        self._cwd = "/"
        self._host_name = ""
        self._ip = ""
        self._path_stack: list[str] = []
        self._error: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="sftp-browser"):
            yield Static("[b]SFTP Browser[/b]", id="sftp-title")
            with Horizontal(id="sftp-panes"):
                with Vertical(id="sftp-local-pane"):
                    yield Label("[b]Local[/b]")
                    yield DirectoryTree(
                        str(Path.home()),
                        id="sftp-local-tree",
                    )
                with Vertical(id="sftp-remote-pane"):
                    yield Label("[b]Remote[/b]")
                    yield Static("Connecting...", id="sftp-path")
                    yield DataTable(id="sftp-table", cursor_type="row")
            with Horizontal(id="sftp-up-row"):
                yield Static("", id="sftp-up-spacer")
                yield Button("Up", id="btn-up", variant="default")
            with Horizontal(id="sftp-buttons"):
                yield Button("Download", id="btn-download", variant="primary")
                yield Button("Upload", id="btn-upload")
                yield Button("Close", id="btn-close")
        yield Footer()

    def on_mount(self) -> None:
        self.run_worker(self._connect_and_list, thread=True, exclusive=True)

    def _connect_and_list(self) -> None:
        from src import database as db

        host = db.get_host(self.host_id)
        if not host or not host["ip_address"]:
            self._error = "Host not found"
            self.app.call_from_thread(self._show_error)
            return

        self._host_name = host["name"] or host["ip_address"]
        self._ip = host["ip_address"]
        credential_id = host["credential_id"]
        key_id = host["key_id"] if "key_id" in host.keys() else None

        try:
            self._ssh_client, self._sftp_client = ssh_manager.open_paramiko_sftp(
                self._ip, self.vault, credential_id, profile_id=self.profile_id, key_id=key_id,
                host_id=self.host_id,
            )
            self._cwd = self._sftp_client.normalize(".")
        except Exception as exc:
            self._error = str(exc)
            self.app.call_from_thread(self._show_error)
            return

        clitty_notify(f"SFTP connected to {self._host_name}", context=CTX_UI)
        clitty_notify(f"SFTP connected to {self._ip} ({self._host_name})", level="info", log_only=True)
        self.app.call_from_thread(self._list_cwd)

    def _show_error(self) -> None:
        msg = self._error or "Connection failed"
        clitty_notify(msg, level="error", context=CTX_UI)
        clitty_notify(f"SFTP connection failed: {msg}", level="error", log_only=True)
        self.dismiss()

    def _list_cwd(self) -> None:
        if self._sftp_client is None:
            return
        table = self.query_one("#sftp-table", DataTable)
        path_static = self.query_one("#sftp-path", Static)
        path_static.update(f"Remote: [b]{self._cwd}[/b]")

        table.clear(columns=True)
        table.add_columns("Name", "Size", "Type")

        try:
            entries = self._sftp_client.listdir_attr(self._cwd)
        except Exception as exc:
            clitty_notify(f"List failed: {exc}", level="error", context=CTX_UI)
            return

        # Sort: dirs first, then by name; filter out . and ..
        dirs: list[tuple[str, int, str]] = []
        files: list[tuple[str, int, str]] = []
        for attr in entries:
            name = attr.filename
            if name in (".", ".."):
                continue
            size = attr.st_size or 0
            is_dir = stat.S_ISDIR(attr.st_mode)
            kind = "dir" if is_dir else "file"
            (dirs if is_dir else files).append((name, size, kind))

        dirs.sort(key=lambda x: x[0].lower())
        files.sort(key=lambda x: x[0].lower())

        for name, size, kind in dirs + files:
            size_str = f"{size:,}" if kind == "file" else "-"
            table.add_row(name, size_str, kind, key=name)

    def _cd(self, name: str) -> None:
        if self._sftp_client is None:
            return
        new_path = self._cwd.rstrip("/") + "/" + name
        try:
            self._sftp_client.chdir(new_path)
            self._path_stack.append(self._cwd)
            self._cwd = self._sftp_client.normalize(".")
            self._list_cwd()
        except Exception as exc:
            clitty_notify(f"Cannot enter: {exc}", level="error", context=CTX_UI)

    def _cd_up(self) -> None:
        if self._sftp_client is None:
            return
        if self._path_stack:
            self._cwd = self._path_stack.pop()
            try:
                self._sftp_client.chdir(self._cwd)
            except Exception:
                self._path_stack.clear()
                self._cwd = "/"
                try:
                    self._sftp_client.chdir("/")
                except Exception:
                    pass
        else:
            parent = "/".join(self._cwd.rstrip("/").split("/")[:-1]) or "/"
            try:
                self._sftp_client.chdir(parent)
                self._cwd = self._sftp_client.normalize(".")
            except Exception as exc:
                clitty_notify(f"Cannot go up: {exc}", level="error", context=CTX_UI)
                return
        self._list_cwd()

    def _get_selected(self) -> tuple[str, str] | None:
        table = self.query_one("#sftp-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        name = str(row_key.value) if row_key else None
        if not name:
            return None
        row = table.get_row(row_key)
        kind = row[2] if len(row) >= 3 else ""
        return (name, kind)

    def _get_selected_local_path(self) -> Path | None:
        """Get the selected local path (file or directory) from the DirectoryTree.
        Returns the path for download dest (dir or parent of file) or upload source (file).
        """
        local_tree = self.query_one("#sftp-local-tree", DirectoryTree)
        node = local_tree.cursor_node
        if node is None or node.data is None:
            return None
        return node.data.path

    def _download_selected(self) -> None:
        sel = self._get_selected()
        if not sel:
            clitty_notify("Select a file to download (remote)", level="warn", context=CTX_UI)
            return
        name, kind = sel
        if kind == "dir":
            clitty_notify("Cannot download directory (select a file)", level="warn", context=CTX_UI)
            return
        local_path = self._get_selected_local_path()
        if local_path is None:
            clitty_notify("Select a local folder or file (for download destination)", level="warn", context=CTX_UI)
            return
        if local_path.is_file():
            dest_dir = local_path.parent
        else:
            dest_dir = local_path
        target_path = dest_dir / name

        remote_path = self._cwd.rstrip("/") + "/" + name
        try:
            self._sftp_client.get(remote_path, str(target_path))
            clitty_notify(f"Downloaded to {target_path}", context=CTX_UI)
        except Exception as exc:
            clitty_notify(f"Download failed: {exc}", level="error", context=CTX_UI)

    def _upload(self) -> None:
        local_path = self._get_selected_local_path()
        if local_path is None:
            clitty_notify("Select a local file to upload", level="warn", context=CTX_UI)
            return
        if not local_path.exists():
            clitty_notify("Selected path does not exist", level="error", context=CTX_UI)
            return
        if not local_path.is_file():
            clitty_notify("Select a file to upload (not a directory)", level="warn", context=CTX_UI)
            return
        remote_path = self._cwd.rstrip("/") + "/" + local_path.name
        try:
            self._sftp_client.put(str(local_path), remote_path)
            clitty_notify(f"Uploaded {local_path.name}", context=CTX_UI)
            self._list_cwd()
        except Exception as exc:
            clitty_notify(f"Upload failed: {exc}", level="error", context=CTX_UI)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        try:
            row = event.data_table.get_row(row_key)
        except Exception:
            return
        if len(row) >= 3 and row[2] == "dir":
            self._cd(str(row[0]))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.action_close()
            return
        if event.button.id == "btn-up":
            self._cd_up()
            return
        if event.button.id == "btn-download":
            self._download_selected()
            return
        if event.button.id == "btn-upload":
            self._upload()
            return

    def action_activate(self) -> None:
        """Enter key: open remote directory (when remote pane focused). Local tree handles its own Enter."""
        remote_table = self.query_one("#sftp-table", DataTable)
        if self.focused != remote_table:
            return
        sel = self._get_selected()
        if not sel:
            return
        name, kind = sel
        if kind == "dir":
            self._cd(name)

    def action_close(self) -> None:
        if self._ssh_client:
            try:
                self._sftp_client.close()
            except Exception:
                pass
            try:
                self._ssh_client.close()
            except Exception:
                pass
        self.dismiss()

    def action_up(self) -> None:
        local_tree = self.query_one("#sftp-local-tree", DirectoryTree)
        remote_table = self.query_one("#sftp-table", DataTable)
        local_pane = self.query_one("#sftp-local-pane")
        # Up on local when focus is in local pane
        in_local = self.focused and (self.focused == local_tree or local_pane in self.focused.ancestors_with_self)
        if in_local:
            node = local_tree.cursor_node
            if node and node.data:
                path = node.data.path
                parent = path.parent
                if parent != path and parent.exists():
                    local_tree.path = str(parent)
        else:
            self._cd_up()

    def action_download(self) -> None:
        self._download_selected()

    def action_upload(self) -> None:
        self._upload()
