"""Credentials management screen."""

from __future__ import annotations

from src import encryption
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from src import database as db
from src.clitty_notify import CTX_UI, clitty_notify
from src.encryption import Vault


class RevealPasswordScreen(ModalScreen[None]):
    """Prompt for master password, then show the credential password temporarily."""

    DEFAULT_CSS = """
    RevealPasswordScreen {
        align: center middle;
    }
    """

    def __init__(self, cred_id: int, **kwargs):
        super().__init__(**kwargs)
        self.cred_id = cred_id

    def compose(self) -> ComposeResult:
        with Vertical(classes="form-container", id="reveal-form"):
            yield Label("[b]Reveal Password[/b]")
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
            cred = db.get_credential(self.cred_id)
            if not cred:
                clitty_notify("Credential not found", level="error", context=CTX_UI)
                return
            try:
                vault = encryption.unlock(master_pw)
                plain = vault.decrypt(cred["password"])
            except ValueError:
                clitty_notify("Incorrect master password", level="error", context=CTX_UI, force_log=True)
                return
            # Replace content with revealed password
            form = self.query_one("#reveal-form")
            self.query_one("#master-pw", Input).remove()
            self.query_one("#reveal-prompt", Label).remove()
            self.query_one("#btn-reveal", Button).remove()
            self.query_one("#btn-cancel", Button).remove()
            form.mount(Label("[b]Password:[/b]"))
            form.mount(Static(plain, id="revealed-pw"))
            form.mount(Button("Close", id="btn-close"))
            return
        if event.button.id == "btn-close":
            self.dismiss()


class CredentialFormScreen(ModalScreen[bool]):
    """Modal for adding or editing a credential."""

    DEFAULT_CSS = """
    CredentialFormScreen {
        align: center middle;
    }
    """

    def __init__(self, cred_id: int | None = None, **kwargs):
        super().__init__(**kwargs)
        self.cred_id = cred_id

    def compose(self) -> ComposeResult:
        title = "Edit Credential" if self.cred_id else "Add Credential"
        with Vertical(classes="form-container"):
            yield Label(f"[b]{title}[/b]")
            yield Label("Label")
            yield Input(id="cred-label", placeholder="e.g. Admin account")
            yield Label("Username")
            yield Input(id="cred-username", placeholder="root")
            yield Label("Password")
            yield Input(id="cred-password", placeholder="password", password=True)
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        if self.cred_id:
            cred = db.get_credential(self.cred_id)
            if cred:
                self.query_one("#cred-label", Input).value = cred["label"]
                self.query_one("#cred-username", Input).value = cred["username"]
                vault: Vault = self.app.vault  # type: ignore[attr-defined]
                try:
                    self.query_one("#cred-password", Input).value = vault.decrypt(cred["password"])
                except Exception:
                    pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return

        vault: Vault = self.app.vault  # type: ignore[attr-defined]
        label = self.query_one("#cred-label", Input).value.strip()
        username = self.query_one("#cred-username", Input).value.strip()
        password = self.query_one("#cred-password", Input).value

        if not username:
            clitty_notify("Username is required", level="error", context=CTX_UI)
            return

        password_enc = vault.encrypt(password)

        if self.cred_id:
            db.update_credential(self.cred_id, username=username, password_enc=password_enc, label=label)
            clitty_notify("Credential updated", context=CTX_UI)
            clitty_notify(f"Credential updated: id={self.cred_id}, label={label}, username={username}", level="debug", log_only=True)
        else:
            cred_id = db.add_credential(username, password_enc, label=label)
            clitty_notify("Credential added", context=CTX_UI)
            clitty_notify(f"Credential added: id={cred_id}, label={label}, username={username}", level="debug", log_only=True)
        self.dismiss(True)


class CredentialsScreen(Screen):
    BINDINGS = [
        Binding("a", "add_cred", "Add", show=True),
        Binding("e", "edit_cred", "Edit", show=True),
        Binding("d", "delete_cred", "Delete", show=True),
        Binding("I", "import_credentials", "Import", show=True),
        Binding("x", "export_credentials", "Export", show=True),
        Binding("r", "refresh_table", "Refresh", show=True),
        Binding("v", "reveal_password", "Reveal", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(" [b]Credentials[/b]  |  a Add  e Edit  d Delete  I Import  x Export  r Refresh  v Reveal", id="nav-bar")
        yield DataTable(id="cred-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#cred-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Label", "Username", "Password")
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        table = self.query_one("#cred-table", DataTable)
        table.clear()
        for cred in db.list_credentials():
            table.add_row(
                str(cred["id"]),
                cred["label"],
                cred["username"],
                "********",
                key=str(cred["id"]),
            )

    def _get_selected_id(self) -> int | None:
        table = self.query_one("#cred-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        try:
            return int(row_key.value)
        except (ValueError, TypeError):
            return None

    def action_add_cred(self) -> None:
        self.app.push_screen(CredentialFormScreen(), callback=self._on_dismiss)

    def action_edit_cred(self) -> None:
        cid = self._get_selected_id()
        if cid is None:
            clitty_notify("No credential selected", level="warn", context=CTX_UI)
            return
        self.app.push_screen(CredentialFormScreen(cred_id=cid), callback=self._on_dismiss)

    def action_delete_cred(self) -> None:
        cid = self._get_selected_id()
        if cid is None:
            clitty_notify("No credential selected", level="warn", context=CTX_UI)
            return
        cred = db.get_credential(cid)
        if cred:
            label_username = cred["label"] or cred["username"]
            db.delete_credential(cid)
            clitty_notify(f"Deleted credential {label_username}", context=CTX_UI)
            clitty_notify(f"Credential deleted: id={cid}, label={cred['label']}, username={cred['username']}", level="debug", log_only=True)
            self._refresh_rows()

    def action_import_credentials(self) -> None:
        from src.ui.screens.export_import import ImportCredentialsScreen
        self.app.push_screen(ImportCredentialsScreen(), callback=self._on_dismiss)

    def action_export_credentials(self) -> None:
        from src.ui.screens.export_import import ExportCredentialsScreen, MasterPasswordPromptScreen
        self.app.push_screen(
            MasterPasswordPromptScreen(prompt="Enter master password to allow export:"),
            callback=lambda ok: self.app.push_screen(ExportCredentialsScreen(), callback=self._on_dismiss) if ok else None,
        )

    def action_reveal_password(self) -> None:
        cid = self._get_selected_id()
        if cid is None:
            clitty_notify("No credential selected", level="warn", context=CTX_UI)
            return
        self.app.push_screen(RevealPasswordScreen(cred_id=cid))

    def action_refresh_table(self) -> None:
        self._refresh_rows()

    def _on_dismiss(self, result=None) -> None:
        self._refresh_rows()
