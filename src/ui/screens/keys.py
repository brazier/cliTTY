"""SSH keys management screen."""

from __future__ import annotations

from pathlib import Path

from src import encryption
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import Button, Checkbox, DataTable, DirectoryTree, Footer, Header, Input, Label, Static, TextArea

from src import database as db
from src import ssh_manager
from src.clitty_notify import CTX_UI, clitty_notify
from src.encryption import Vault


class ImportPEMScreen(ModalScreen[str | None]):
    """Browse to select a PEM file; loads content into add-key form on select."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    ImportPEMScreen {
        align: center middle;
    }
    #import-pem-container {
        width: 70;
        height: 25;
        border: solid $primary;
        padding: 1 2;
    }
    #import-pem-tree {
        height: 1fr;
        min-height: 10;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="import-pem-container"):
            yield Label("[b]Import PEM Key[/b]")
            yield Label("Browse to a PEM file, select it, then press Select")
            yield DirectoryTree(str(Path.home()), id="import-pem-tree")
            with Vertical():
                yield Button("Select", variant="primary", id="btn-import-select")
                yield Button("Cancel", id="btn-import-cancel")

    def _get_selected_path(self) -> Path | None:
        tree = self.query_one("#import-pem-tree", DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return None
        return node.data.path

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-import-cancel":
            self.dismiss(None)
            return
        if event.button.id == "btn-import-select":
            path = self._get_selected_path()
            if path is None:
                clitty_notify("Select a file", level="warn", context=CTX_UI)
                return
            if path.is_dir():
                clitty_notify("Select a file, not a directory", level="warn", context=CTX_UI)
                return
            try:
                pem = path.read_text()
            except OSError as e:
                clitty_notify(f"Cannot read file: {e}", level="error", context=CTX_UI)
                return
            if "-----BEGIN" not in pem or "-----END" not in pem:
                clitty_notify(
                    "File does not contain a valid PEM key",
                    level="warn",
                    context=CTX_UI,
                )
                return
            self.dismiss(pem)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RevealPassphraseScreen(ModalScreen[None]):
    """Prompt for master password, then show the key passphrase temporarily."""

    DEFAULT_CSS = """
    RevealPassphraseScreen {
        align: center middle;
    }
    """

    def __init__(self, key_id: int, **kwargs):
        super().__init__(**kwargs)
        self.key_id = key_id

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container", id="reveal-form"):
            yield Label("[b]Reveal Passphrase[/b]")
            yield Label("Enter master password to reveal:", id="reveal-prompt")
            yield Input(id="master-pw", placeholder="Master password", password=True)
            yield Button("Reveal", variant="primary", id="btn-reveal")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss()
            return
        if event.button.id == "btn-reveal":
            master_pw = self.query_one("#master-pw", Input).value
            key_row = db.get_ssh_key(self.key_id)
            if not key_row:
                clitty_notify("Key not found", level="error", context=CTX_UI)
                return
            if not key_row["passphrase_enc"]:
                clitty_notify("This key has no stored passphrase", level="info", context=CTX_UI)
                return
            try:
                vault = encryption.unlock(master_pw)
                plain = vault.decrypt(key_row["passphrase_enc"])
            except ValueError:
                clitty_notify("Incorrect master password", level="error", context=CTX_UI, force_log=True)
                return
            form = self.query_one("#reveal-form")
            self.query_one("#master-pw", Input).remove()
            self.query_one("#reveal-prompt", Label).remove()
            self.query_one("#btn-reveal", Button).remove()
            self.query_one("#btn-cancel", Button).remove()
            form.mount(Label("[b]Passphrase:[/b]"))
            form.mount(Static(plain, id="revealed-passphrase"))
            form.mount(Button("Close", id="btn-close"))
            return
        if event.button.id == "btn-close":
            self.dismiss()


class KeyFormScreen(ModalScreen[bool]):
    """Modal for adding or editing an SSH key. Edit requires master password to unlock."""

    DEFAULT_CSS = """
    KeyFormScreen {
        align: center middle;
    }
    #key-text-area {
        height: 10;
        min-height: 8;
    }
    """

    def __init__(
        self,
        key_id: int | None = None,
        initial_pem: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.key_id = key_id
        self._unlocked = False  # True after master password verified for edit
        # Always store a string (TextArea doesn't accept None for its text argument)
        self._initial_pem = (initial_pem or "").strip()

    def compose(self) -> ComposeResult:
        if self.key_id and not self._unlocked:
            # Edit mode: show unlock prompt first (unique IDs to avoid DuplicateIds on replace)
            with Vertical(classes="form-container", id="key-form-container"):
                yield Label("[b]Edit Key[/b]")
                yield Label("Enter master password to unlock:", id="unlock-prompt")
                yield Input(id="master-pw", placeholder="Master password", password=True)
                yield Button("Unlock", variant="primary", id="btn-unlock")
                yield Button("Cancel", id="btn-unlock-cancel")
        else:
            # Add mode or edit after unlock: show full form
            yield from self._compose_full_form()

    def _compose_full_form(self) -> ComposeResult:
        title = "Edit Key" if self.key_id else "Add Key"
        initial_key = self._initial_pem if not self.key_id else ""
        with Vertical(classes="form-container", id="key-form-container"):
            yield Label(f"[b]{title}[/b]")
            yield Label("Label")
            yield Input(id="key-label", placeholder="e.g. Production server key")
            yield Label("Username")
            yield Input(id="key-username", placeholder="root")
            yield Label("Private key (PEM)")
            yield TextArea(initial_key, id="key-text-area", show_line_numbers=False)
            yield Label("Passphrase (leave empty if none)")
            yield Input(id="key-passphrase", placeholder="passphrase", password=True)
            yield Checkbox("Prompt for passphrase at connect", id="key-prompt-passphrase")
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        if self.key_id and not self._unlocked:
            return  # Unlock phase, nothing to prefill
        if self.key_id:
            self._populate_edit_form()

    def _populate_edit_form(self) -> None:
        key_row = db.get_ssh_key(self.key_id)
        if not key_row:
            return
        self.query_one("#key-label", Input).value = key_row["label"]
        self.query_one("#key-username", Input).value = key_row["username"]
        vault: Vault = self.app.vault  # type: ignore[attr-defined]
        try:
            key_pem = vault.decrypt(key_row["private_key_enc"])
            self.query_one("#key-text-area", TextArea).load_text(key_pem)
        except Exception:
            pass
        if key_row["passphrase_enc"]:
            try:
                self.query_one("#key-passphrase", Input).value = vault.decrypt(key_row["passphrase_enc"])
            except Exception:
                pass
        self.query_one("#key-prompt-passphrase", Checkbox).value = bool(key_row["prompt_passphrase"])

    def _replace_with_edit_form(self, key_pem: str, passphrase_plain: str, prompt_passphrase: bool) -> None:
        """Replace unlock UI with full edit form, pre-filled with decrypted data."""
        container = self.query_one("#key-form-container")
        for child in list(container.children):
            child.remove()
        # Compose the full form widgets into the container
        container.mount(Label("[b]Edit Key[/b]"))
        container.mount(Label("Label"))
        label_input = Input(id="key-label", placeholder="e.g. Production server key")
        container.mount(label_input)
        container.mount(Label("Username"))
        user_input = Input(id="key-username", placeholder="root")
        container.mount(user_input)
        container.mount(Label("Private key (PEM)"))
        key_area = TextArea(key_pem, id="key-text-area", show_line_numbers=False)
        container.mount(key_area)
        container.mount(Label("Passphrase (leave empty if none)"))
        pass_input = Input(id="key-passphrase", placeholder="passphrase", password=True)
        container.mount(pass_input)
        container.mount(Checkbox("Prompt for passphrase at connect", id="key-prompt-passphrase"))
        container.mount(Button("Save", variant="primary", id="btn-save"))
        container.mount(Button("Cancel", id="btn-cancel"))
        # Populate from key_row
        key_row = db.get_ssh_key(self.key_id)
        if key_row:
            label_input.value = key_row["label"]
            user_input.value = key_row["username"]
            pass_input.value = passphrase_plain
            self.query_one("#key-prompt-passphrase", Checkbox).value = prompt_passphrase

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in ("btn-cancel", "btn-unlock-cancel"):
            self.dismiss(False)
            return

        if event.button.id == "btn-unlock":
            master_pw = self.query_one("#master-pw", Input).value
            key_row = db.get_ssh_key(self.key_id)
            if not key_row:
                clitty_notify("Key not found", level="error", context=CTX_UI)
                return
            try:
                vault = encryption.unlock(master_pw)
                key_pem = vault.decrypt(key_row["private_key_enc"])
                passphrase_plain = vault.decrypt(key_row["passphrase_enc"]) if key_row["passphrase_enc"] else ""
            except ValueError:
                clitty_notify("Incorrect master password", level="error", context=CTX_UI, force_log=True)
                return
            self._unlocked = True
            self._replace_with_edit_form(key_pem, passphrase_plain, bool(key_row["prompt_passphrase"]))
            return

        vault: Vault = self.app.vault  # type: ignore[attr-defined]
        label = self.query_one("#key-label", Input).value.strip()
        username = self.query_one("#key-username", Input).value.strip()
        key_pem = self.query_one("#key-text-area", TextArea).text.strip() + "\n"
        passphrase = self.query_one("#key-passphrase", Input).value
        prompt_passphrase = self.query_one("#key-prompt-passphrase", Checkbox).value

        if not username:
            clitty_notify("Username is required", level="error", context=CTX_UI)
            return
        if not key_pem or "-----BEGIN" not in key_pem or "-----END" not in key_pem:
            clitty_notify("Valid private key PEM is required", level="error", context=CTX_UI)
            return

        private_key_enc = vault.encrypt(key_pem)
        if prompt_passphrase:
            passphrase_enc = ""
            prompt_val = 1
        elif passphrase:
            passphrase_enc = vault.encrypt(passphrase)
            prompt_val = 0
        else:
            passphrase_enc = ""
            prompt_val = 0

        if self.key_id:
            db.update_ssh_key(
                self.key_id,
                label=label,
                username=username,
                private_key_enc=private_key_enc,
                passphrase_enc=passphrase_enc,
                prompt_passphrase=prompt_val,
            )
            clitty_notify("Key updated", context=CTX_UI)
            clitty_notify(f"Key updated: id={self.key_id}, label={label}", level="debug", log_only=True)
        else:
            key_id = db.add_ssh_key(label, username, private_key_enc, passphrase_enc, prompt_passphrase=prompt_val)
            clitty_notify("Key added", context=CTX_UI)
            clitty_notify(f"Key added: id={key_id}, label={label}", level="debug", log_only=True)
        self.dismiss(True)


class KeysScreen(Screen):
    BINDINGS = [
        Binding("a", "add_key", "Add", show=True),
        Binding("i", "import_key", "Import PEM", show=True),
        Binding("I", "import_keys_json", "Import JSON", show=True),
        Binding("x", "export_keys", "Export", show=True),
        Binding("e", "edit_key", "Edit", show=True),
        Binding("d", "delete_key", "Delete", show=True),
        Binding("r", "refresh_table", "Refresh", show=True),
        Binding("v", "reveal_passphrase", "Reveal", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            " [b]Keys[/b]  |  a Add  i Import PEM  I Import JSON  x Export  e Edit  d Delete  r Refresh  v Reveal",
            id="nav-bar",
        )
        yield Static("", id="agent-status-bar")
        yield DataTable(id="keys-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#keys-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Label", "Username", "Passphrase", "Agent")
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        import os
        agent_running = ssh_manager.is_agent_running()
        status_bar = self.query_one("#agent-status-bar", Static)
        sock = os.environ.get("SSH_AUTH_SOCK", "")
        if agent_running:
            status_bar.update(f" [b green]Agent running[/b green]  (socket: {sock})")
        else:
            status_bar.update(" [b red]Agent not running[/b red]")

        table = self.query_one("#keys-table", DataTable)
        table.clear()
        for key_row in db.list_ssh_keys():
            if key_row["prompt_passphrase"]:
                passphrase_display = "prompt"
            elif key_row["passphrase_enc"]:
                passphrase_display = "********"
            else:
                passphrase_display = "none"
            agent_status = "yes" if ssh_manager.is_key_loaded(key_row["id"]) else ""
            table.add_row(
                str(key_row["id"]),
                key_row["label"],
                key_row["username"],
                passphrase_display,
                agent_status,
                key=str(key_row["id"]),
            )

    def _get_selected_id(self) -> int | None:
        table = self.query_one("#keys-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        try:
            return int(row_key.value)
        except (ValueError, TypeError):
            return None

    def action_add_key(self) -> None:
        self.app.push_screen(KeyFormScreen(), callback=self._on_dismiss)

    def action_import_key(self) -> None:
        """Browse to select a PEM file, then open Add form with its content."""
        self.app.push_screen(ImportPEMScreen(), callback=self._on_import_done)

    def action_import_keys_json(self) -> None:
        """Bulk import keys from JSON (plain or encrypted)."""
        from src.ui.screens.export_import import ImportKeysScreen
        self.app.push_screen(ImportKeysScreen(), callback=self._on_dismiss)

    def action_export_keys(self) -> None:
        """Export keys as encrypted JSON."""
        from src.ui.screens.export_import import ExportKeysScreen, MasterPasswordPromptScreen
        self.app.push_screen(
            MasterPasswordPromptScreen(prompt="Enter master password to allow export:"),
            callback=lambda ok: self.app.push_screen(ExportKeysScreen(), callback=self._on_dismiss) if ok else None,
        )

    def _on_import_done(self, pem: str | None) -> None:
        if pem:
            self.app.push_screen(KeyFormScreen(initial_pem=pem), callback=self._on_dismiss)

    def action_edit_key(self) -> None:
        kid = self._get_selected_id()
        if kid is None:
            clitty_notify("No key selected", level="warn", context=CTX_UI)
            return
        self.app.push_screen(KeyFormScreen(key_id=kid), callback=self._on_dismiss)

    def action_delete_key(self) -> None:
        kid = self._get_selected_id()
        if kid is None:
            clitty_notify("No key selected", level="warn", context=CTX_UI)
            return
        key_row = db.get_ssh_key(kid)
        if key_row:
            label_or_user = key_row["label"] or key_row["username"]
            db.delete_ssh_key(kid)
            clitty_notify(f"Deleted key {label_or_user}", context=CTX_UI)
            clitty_notify(f"Key deleted: id={kid}, label={key_row['label']}", level="debug", log_only=True)
            self._refresh_rows()

    def action_reveal_passphrase(self) -> None:
        kid = self._get_selected_id()
        if kid is None:
            clitty_notify("No key selected", level="warn", context=CTX_UI)
            return
        self.app.push_screen(RevealPassphraseScreen(key_id=kid))

    def action_refresh_table(self) -> None:
        self._refresh_rows()

    def _on_dismiss(self, result=None) -> None:
        self._refresh_rows()
