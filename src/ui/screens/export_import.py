"""Export and import modals for hosts, keys, and credentials."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Label, Static

from src import encryption
from src import exporter
from src.clitty_notify import CTX_UI, clitty_notify


# ---------------------------------------------------------------------------
# Master password prompt (reusable, like Reveal password)
# ---------------------------------------------------------------------------


class MasterPasswordPromptScreen(ModalScreen[bool | Any]):
    """Standalone prompt for master password. Dismisses True (or Vault if return_vault) on success, None on cancel."""

    DEFAULT_CSS = """
    MasterPasswordPromptScreen {
        align: center middle;
    }
    """

    def __init__(self, *, prompt: str = "Enter master password:", return_vault: bool = False, **kwargs) -> None:
        super().__init__(**kwargs)
        self._prompt = prompt
        self._return_vault = return_vault

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container", id="master-pw-form"):
            yield Label("[b]Master Password[/b]")
            yield Label(self._prompt, id="master-pw-prompt")
            yield Input(id="master-pw", placeholder="Master password", password=True)
            yield Button("Unlock", variant="primary", id="btn-unlock")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
            return
        if event.button.id != "btn-unlock":
            return
        master_pw = self.query_one("#master-pw", Input).value
        if not master_pw:
            clitty_notify("Enter master password", level="warn", context=CTX_UI)
            return
        try:
            vault = encryption.unlock(master_pw)
        except ValueError:
            clitty_notify("Incorrect master password", level="error", context=CTX_UI, force_log=True)
            return
        self.dismiss(vault if self._return_vault else True)


def _get_selected_path(tree_id: str, screen) -> Path | None:
    tree = screen.query_one(f"#{tree_id}", DirectoryTree)
    node = tree.cursor_node
    if node is None or node.data is None:
        return None
    return node.data.path


# ---------------------------------------------------------------------------
# Export Hosts (CSV, unencrypted)
# ---------------------------------------------------------------------------


class ExportHostsScreen(ModalScreen[bool]):
    """Pick file path, export hosts as CSV."""

    DEFAULT_CSS = """
    ExportHostsScreen {
        align: center middle;
    }
    #export-hosts-container {
        width: 70;
        height: 26;
        border: solid $primary;
        padding: 1 2;
    }
    #export-hosts-tree {
        height: 1fr;
        min-height: 10;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="export-hosts-container"):
            yield Label("[b]Export Hosts (CSV)[/b]")
            yield Label("Choose destination folder, enter filename, then Export")
            yield DirectoryTree(str(Path.home()), id="export-hosts-tree")
            yield Label("Filename")
            yield Input(placeholder="hosts.csv", id="export-hosts-filename", value="hosts.csv")
            with Vertical():
                yield Button("Export", variant="primary", id="btn-export-hosts")
                yield Button("Cancel", id="btn-cancel-hosts")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-hosts":
            self.dismiss(False)
            return
        if event.button.id != "btn-export-hosts":
            return
        path = _get_selected_path("export-hosts-tree", self)
        if path is None:
            clitty_notify("Select a folder", level="warn", context=CTX_UI)
            return
        if path.is_file():
            path = path.parent
        fn = self.query_one("#export-hosts-filename", Input).value.strip() or "hosts.csv"
        out_path = path / fn
        try:
            count = exporter.export_hosts_csv(out_path)
            clitty_notify(f"Exported {count} hosts to {out_path}", context=CTX_UI)
            self.dismiss(True)
        except OSError as e:
            clitty_notify(f"Export failed: {e}", level="error", context=CTX_UI)


# ---------------------------------------------------------------------------
# Export Keys (encrypted JSON)
# ---------------------------------------------------------------------------


class ExportKeysScreen(ModalScreen[bool]):
    """Pick path, enter export password, export keys."""

    DEFAULT_CSS = """
    ExportKeysScreen {
        align: center middle;
    }
    #export-keys-container {
        width: 70;
        height: 32;
        border: solid $primary;
        padding: 1 2;
    }
    #export-keys-tree {
        height: 1fr;
        min-height: 8;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="export-keys-container"):
            yield Label("[b]Export Keys (encrypted JSON)[/b]")
            yield Label("Choose folder, filename, export password (used only for this file)")
            yield DirectoryTree(str(Path.home()), id="export-keys-tree")
            yield Label("Filename")
            yield Input(placeholder="keys_export.json", id="export-keys-filename", value="keys_export.json")
            yield Label("Export password")
            yield Input(placeholder="Enter export password", id="export-keys-pw", password=True)
            yield Label("Confirm export password")
            yield Input(placeholder="Confirm", id="export-keys-pw-confirm", password=True)
            with Vertical():
                yield Button("Export", variant="primary", id="btn-export-keys")
                yield Button("Cancel", id="btn-cancel-keys")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-keys":
            self.dismiss(False)
            return
        if event.button.id != "btn-export-keys":
            return
        path = _get_selected_path("export-keys-tree", self)
        if path is None:
            clitty_notify("Select a folder", level="warn", context=CTX_UI)
            return
        if path.is_file():
            path = path.parent
        fn = self.query_one("#export-keys-filename", Input).value.strip() or "keys_export.json"
        out_path = path / fn
        pw = self.query_one("#export-keys-pw", Input).value
        pw_confirm = self.query_one("#export-keys-pw-confirm", Input).value
        if not pw:
            clitty_notify("Enter export password", level="warn", context=CTX_UI)
            return
        if pw != pw_confirm:
            clitty_notify("Passwords do not match", level="error", context=CTX_UI)
            return
        vault = self.app.vault  # type: ignore[attr-defined]
        try:
            count = exporter.export_keys(out_path, vault, pw)
            clitty_notify(f"Exported {count} keys to {out_path}", context=CTX_UI)
            self.dismiss(True)
        except OSError as e:
            clitty_notify(f"Export failed: {e}", level="error", context=CTX_UI)


# ---------------------------------------------------------------------------
# Export Credentials
# ---------------------------------------------------------------------------


class ExportCredentialsScreen(ModalScreen[bool]):
    """Pick path, enter export password, export credentials."""

    DEFAULT_CSS = """
    ExportCredentialsScreen {
        align: center middle;
    }
    #export-creds-container {
        width: 70;
        height: 32;
        border: solid $primary;
        padding: 1 2;
    }
    #export-creds-tree {
        height: 1fr;
        min-height: 8;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="export-creds-container"):
            yield Label("[b]Export Credentials (encrypted JSON)[/b]")
            yield Label("Choose folder, filename, export password")
            yield DirectoryTree(str(Path.home()), id="export-creds-tree")
            yield Label("Filename")
            yield Input(placeholder="credentials_export.json", id="export-creds-filename", value="credentials_export.json")
            yield Label("Export password")
            yield Input(placeholder="Enter export password", id="export-creds-pw", password=True)
            yield Label("Confirm export password")
            yield Input(placeholder="Confirm", id="export-creds-pw-confirm", password=True)
            with Vertical():
                yield Button("Export", variant="primary", id="btn-export-creds")
                yield Button("Cancel", id="btn-cancel-creds")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-creds":
            self.dismiss(False)
            return
        if event.button.id != "btn-export-creds":
            return
        path = _get_selected_path("export-creds-tree", self)
        if path is None:
            clitty_notify("Select a folder", level="warn", context=CTX_UI)
            return
        if path.is_file():
            path = path.parent
        fn = self.query_one("#export-creds-filename", Input).value.strip() or "credentials_export.json"
        out_path = path / fn
        pw = self.query_one("#export-creds-pw", Input).value
        pw_confirm = self.query_one("#export-creds-pw-confirm", Input).value
        if not pw:
            clitty_notify("Enter export password", level="warn", context=CTX_UI)
            return
        if pw != pw_confirm:
            clitty_notify("Passwords do not match", level="error", context=CTX_UI)
            return
        vault = self.app.vault  # type: ignore[attr-defined]
        try:
            count = exporter.export_credentials(out_path, vault, pw)
            clitty_notify(f"Exported {count} credentials to {out_path}", context=CTX_UI)
            self.dismiss(True)
        except OSError as e:
            clitty_notify(f"Export failed: {e}", level="error", context=CTX_UI)


# ---------------------------------------------------------------------------
# Import Keys (JSON, plain or encrypted)
# ---------------------------------------------------------------------------


class ImportKeysScreen(ModalScreen[bool]):
    """Pick JSON file, optionally enter export password if encrypted."""

    DEFAULT_CSS = """
    ImportKeysScreen {
        align: center middle;
    }
    #import-keys-container {
        width: 70;
        height: 28;
        border: solid $primary;
        padding: 1 2;
    }
    #import-keys-tree {
        height: 1fr;
        min-height: 10;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="import-keys-container"):
            yield Label("[b]Import Keys (JSON)[/b]")
            yield Label("Select a JSON file (plain or encrypted). Enter export password if encrypted.")
            yield DirectoryTree(str(Path.home()), id="import-keys-tree")
            yield Label("Export password (leave blank if file is plain)")
            yield Input(placeholder="Export password", id="import-keys-pw", password=True)
            with Vertical():
                yield Button("Import", variant="primary", id="btn-import-keys")
                yield Button("Cancel", id="btn-cancel-import-keys")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-import-keys":
            self.dismiss(False)
            return
        if event.button.id != "btn-import-keys":
            return
        path = _get_selected_path("import-keys-tree", self)
        if path is None:
            clitty_notify("Select a file", level="warn", context=CTX_UI)
            return
        if path.is_dir():
            clitty_notify("Select a file, not a directory", level="warn", context=CTX_UI)
            return
        pw = self.query_one("#import-keys-pw", Input).value.strip() or None
        vault = self.app.vault  # type: ignore[attr-defined]
        try:
            count = exporter.import_keys(path, vault, export_password=pw)
            clitty_notify(f"Imported {count} keys", context=CTX_UI)
            self.dismiss(True)
        except ValueError as e:
            clitty_notify(str(e), level="error", context=CTX_UI)
        except OSError as e:
            clitty_notify(f"Import failed: {e}", level="error", context=CTX_UI)


# ---------------------------------------------------------------------------
# Import Credentials (JSON or CSV)
# ---------------------------------------------------------------------------


class ImportCredentialsScreen(ModalScreen[bool]):
    """Pick JSON or CSV file, optionally enter export password if encrypted."""

    DEFAULT_CSS = """
    ImportCredentialsScreen {
        align: center middle;
    }
    #import-creds-container {
        width: 70;
        height: 28;
        border: solid $primary;
        padding: 1 2;
    }
    #import-creds-tree {
        height: 1fr;
        min-height: 10;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="import-creds-container"):
            yield Label("[b]Import Credentials (JSON or CSV)[/b]")
            yield Label("Select JSON (plain/encrypted) or CSV. Enter export password if encrypted.")
            yield DirectoryTree(str(Path.home()), id="import-creds-tree")
            yield Label("Export password (leave blank if file is plain)")
            yield Input(placeholder="Export password", id="import-creds-pw", password=True)
            with Vertical():
                yield Button("Import", variant="primary", id="btn-import-creds")
                yield Button("Cancel", id="btn-cancel-import-creds")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-import-creds":
            self.dismiss(False)
            return
        if event.button.id != "btn-import-creds":
            return
        path = _get_selected_path("import-creds-tree", self)
        if path is None:
            clitty_notify("Select a file", level="warn", context=CTX_UI)
            return
        if path.is_dir():
            clitty_notify("Select a file, not a directory", level="warn", context=CTX_UI)
            return
        pw = self.query_one("#import-creds-pw", Input).value.strip() or None
        vault = self.app.vault  # type: ignore[attr-defined]
        try:
            count = exporter.import_credentials(path, vault, export_password=pw)
            clitty_notify(f"Imported {count} credentials", context=CTX_UI)
            self.dismiss(True)
        except ValueError as e:
            clitty_notify(str(e), level="error", context=CTX_UI)
        except OSError as e:
            clitty_notify(f"Import failed: {e}", level="error", context=CTX_UI)
