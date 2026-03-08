"""Connection profiles management screen."""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Label, Static, TabbedContent, TabPane

from src import database as db
from src.clitty_notify import CTX_UI, clitty_notify
from src.encryption import decrypt_profile_row, encrypt_profile_fields


# ---------------------------------------------------------------------------
# Reusable dynamic list widget for port forwards
# ---------------------------------------------------------------------------

class ForwardList(Vertical):
    """A dynamic list of text inputs with Add/Remove buttons."""

    DEFAULT_CSS = """
    ForwardList {
        height: auto;
        margin-bottom: 1;
    }
    ForwardList Vertical {
        height: auto;
    }
    ForwardList .forward-row {
        height: 3;
        layout: horizontal;
    }
    ForwardList .forward-row Input {
        width: 1fr;
    }
    ForwardList .forward-row Button {
        width: 5;
        min-width: 5;
    }
    ForwardList .add-btn {
        width: 100%;
        margin-top: 0;
    }
    """

    def __init__(self, label: str, placeholder: str, list_id: str, **kwargs):
        super().__init__(**kwargs)
        self.list_label = label
        self.placeholder = placeholder
        self.list_id = list_id
        self._counter = 0

    def compose(self) -> ComposeResult:
        yield Label(f"[b]{self.list_label}[/b]")
        yield Vertical(id=f"{self.list_id}-rows")
        yield Button(f"+ Add {self.list_label.split('(')[0].strip()}", id=f"{self.list_id}-add", classes="add-btn")

    def add_row(self, value: str = "") -> None:
        self._counter += 1
        row_id = f"{self.list_id}-row-{self._counter}"
        container = self.query_one(f"#{self.list_id}-rows", Vertical)
        row = Horizontal(
            Input(value=value, placeholder=self.placeholder, id=f"{row_id}-input"),
            Button("X", variant="error", id=f"{row_id}-del"),
            classes="forward-row",
            id=row_id,
        )
        container.mount(row)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == f"{self.list_id}-add":
            self.add_row()
            event.stop()
        elif btn_id.startswith(self.list_id) and btn_id.endswith("-del"):
            row_id = btn_id.rsplit("-del", 1)[0]
            try:
                self.query_one(f"#{row_id}").remove()
            except Exception:
                pass
            event.stop()

    def get_values(self) -> list[str]:
        values = []
        container = self.query_one(f"#{self.list_id}-rows", Vertical)
        for child in container.children:
            inp = child.query("Input")
            if inp:
                val = inp.first().value.strip()
                if val:
                    values.append(val)
        return values

    def set_values(self, values: list[str]) -> None:
        for v in values:
            self.add_row(v)


# ---------------------------------------------------------------------------
# Profile form modal
# ---------------------------------------------------------------------------

class ProfileFormScreen(ModalScreen[bool]):
    """Modal for adding or editing a connection profile."""

    DEFAULT_CSS = """
    ProfileFormScreen {
        align: center middle;
    }
    ProfileFormScreen TabbedContent {
        height: auto;
    }
    ProfileFormScreen TabPane {
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, profile_id: int | None = None, **kwargs):
        super().__init__(**kwargs)
        self.profile_id = profile_id

    def compose(self) -> ComposeResult:
        title = "Edit Profile" if self.profile_id else "Add Profile"
        with Vertical(classes="form-container"):
            yield Label(f"[b]{title}[/b]")
            with TabbedContent():
                with TabPane("Basic"):
                    yield Label("Name")
                    yield Input(id="prof-name", placeholder="e.g. default")
                    yield Label("Port")
                    yield Input(id="prof-port", placeholder="22", value="22")
                    yield Label("Key File (path)")
                    yield Input(id="prof-keyfile", placeholder="/path/to/key")
                    yield Label("Timeout (seconds)")
                    yield Input(id="prof-timeout", placeholder="30", value="30")
                    yield Checkbox("Compression (-C)", id="prof-compression")
                    yield Checkbox("Forward Agent (-A)", id="prof-forward-agent")
                    yield Checkbox("No Execute (-N)", id="prof-no-execute")
                with TabPane("Advanced"):
                    yield Label("Proxy Command")
                    yield Input(id="prof-proxy", placeholder="ssh -W %h:%p jumphost")
                    yield Label("Ciphers (comma-separated)")
                    yield Input(id="prof-ciphers", placeholder="aes256-ctr,aes128-ctr")
                    yield Label("MACs (comma-separated)")
                    yield Input(id="prof-macs", placeholder="hmac-sha2-256,hmac-sha2-512")
                    yield Label("Host Key Algorithms")
                    yield Input(id="prof-hostkeyalg", placeholder="ssh-ed25519,ssh-rsa")
                    yield Label("Remote Command")
                    yield Input(id="prof-remotecmd", placeholder="command to run on connect")
                    yield Label("Extra SSH Args (free-form)")
                    yield Input(id="prof-extra", placeholder="-o StrictHostKeyChecking=no")
                with TabPane("Forwarding"):
                    yield ForwardList("Local Forwards (-L)", "8080:localhost:80", "lf")
                    yield ForwardList("Remote Forwards (-R)", "9090:localhost:3000", "rf")
                    yield ForwardList("Dynamic Forwards (-D)", "1080", "df")
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        vault = getattr(self.app, "vault", None)
        if self.profile_id and vault:
            prof_row = db.get_profile(self.profile_id)
            prof = decrypt_profile_row(prof_row, vault) if prof_row else {}
            if prof:
                self.query_one("#prof-name", Input).value = prof.get("name", "")
                self.query_one("#prof-port", Input).value = str(prof.get("port", 22))
                self.query_one("#prof-keyfile", Input).value = prof.get("key_file", "")
                self.query_one("#prof-timeout", Input).value = str(prof.get("timeout", 30))
                self.query_one("#prof-compression", Checkbox).value = bool(prof.get("compression", 0))
                self.query_one("#prof-forward-agent", Checkbox).value = bool(prof.get("forward_agent", 0))
                self.query_one("#prof-no-execute", Checkbox).value = bool(prof.get("no_execute", 0))
                self.query_one("#prof-proxy", Input).value = prof.get("proxy_command", "")
                self.query_one("#prof-ciphers", Input).value = prof.get("ciphers", "")
                self.query_one("#prof-macs", Input).value = prof.get("macs", "")
                self.query_one("#prof-hostkeyalg", Input).value = prof.get("host_key_algorithms", "")
                self.query_one("#prof-remotecmd", Input).value = prof.get("remote_command", "")
                self.query_one("#prof-extra", Input).value = prof.get("extra_args", "")

                for fl in self.query(ForwardList):
                    if fl.list_id == "lf":
                        fl.set_values(_json_list(prof.get("local_forwards", "[]")))
                    elif fl.list_id == "rf":
                        fl.set_values(_json_list(prof.get("remote_forwards", "[]")))
                    elif fl.list_id == "df":
                        fl.set_values(_json_list(prof.get("dynamic_forwards", "[]")))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
            return
        if event.button.id != "btn-save":
            return

        name = self.query_one("#prof-name", Input).value.strip()
        if not name:
            clitty_notify("Name is required", level="error", context=CTX_UI)
            return
        try:
            port = int(self.query_one("#prof-port", Input).value)
        except ValueError:
            clitty_notify("Port must be a number", level="error", context=CTX_UI)
            return
        key_file = self.query_one("#prof-keyfile", Input).value.strip()
        try:
            timeout = int(self.query_one("#prof-timeout", Input).value)
        except ValueError:
            clitty_notify("Timeout must be a number", level="error", context=CTX_UI)
            return

        compression = int(self.query_one("#prof-compression", Checkbox).value)
        forward_agent = int(self.query_one("#prof-forward-agent", Checkbox).value)
        no_execute = int(self.query_one("#prof-no-execute", Checkbox).value)
        proxy_command = self.query_one("#prof-proxy", Input).value.strip()
        ciphers = self.query_one("#prof-ciphers", Input).value.strip()
        macs_val = self.query_one("#prof-macs", Input).value.strip()
        host_key_algorithms = self.query_one("#prof-hostkeyalg", Input).value.strip()
        remote_command = self.query_one("#prof-remotecmd", Input).value.strip()
        extra_args = self.query_one("#prof-extra", Input).value.strip()

        local_forwards: list[str] = []
        remote_forwards: list[str] = []
        dynamic_forwards: list[str] = []
        for fl in self.query(ForwardList):
            if fl.list_id == "lf":
                local_forwards = fl.get_values()
            elif fl.list_id == "rf":
                remote_forwards = fl.get_values()
            elif fl.list_id == "df":
                dynamic_forwards = fl.get_values()

        vault = getattr(self.app, "vault", None)
        if not vault:
            clitty_notify("Vault unavailable; cannot save profile", level="error", context=CTX_UI)
            return
        kwargs = dict(
            name=name, port=port, key_file=key_file, timeout=timeout,
            compression=compression, forward_agent=forward_agent, no_execute=no_execute,
            proxy_command=proxy_command, ciphers=ciphers, macs=macs_val,
            host_key_algorithms=host_key_algorithms, remote_command=remote_command,
            local_forwards=local_forwards, remote_forwards=remote_forwards,
            dynamic_forwards=dynamic_forwards, extra_args=extra_args,
        )
        kwargs = encrypt_profile_fields(kwargs, vault)

        if self.profile_id:
            db.update_profile(self.profile_id, **kwargs)
            clitty_notify("Profile updated", context=CTX_UI)
            clitty_notify(f"Profile updated: id={self.profile_id}, name={name}", level="debug", log_only=True)
        else:
            try:
                profile_id = db.add_profile(**kwargs)
                clitty_notify("Profile added", context=CTX_UI)
                clitty_notify(f"Profile added: id={profile_id}, name={name}", level="debug", log_only=True)
            except Exception:
                clitty_notify("Profile name must be unique", level="error", context=CTX_UI)
                return
        self.dismiss(True)


def _json_list(raw: str) -> list[str]:
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Profiles list screen
# ---------------------------------------------------------------------------

class ProfilesScreen(Screen):
    BINDINGS = [
        Binding("a", "add_profile", "Add", show=True),
        Binding("e", "edit_profile", "Edit", show=True),
        Binding("d", "delete_profile", "Delete", show=True),
        Binding("r", "refresh_table", "Refresh", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(" [b]Connection Profiles[/b]  |  a Add  e Edit  d Delete  r Refresh", id="nav-bar")
        yield DataTable(id="prof-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#prof-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Name", "Port", "Key", "Tmout", "Comp", "Agent", "-N", "Proxy", "Fwds")
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        table = self.query_one("#prof-table", DataTable)
        table.clear()
        vault = getattr(self.app, "vault", None)
        for prof_row in db.list_profiles():
            prof = decrypt_profile_row(prof_row, vault) if vault else dict(prof_row)
            fwd_count = (
                len(_json_list(prof.get("local_forwards", "[]")))
                + len(_json_list(prof.get("remote_forwards", "[]")))
                + len(_json_list(prof.get("dynamic_forwards", "[]")))
            )
            table.add_row(
                str(prof["id"]),
                prof.get("name", ""),
                str(prof.get("port", 22)),
                (prof.get("key_file") or "")[:20],
                str(prof.get("timeout", 30)),
                "Y" if prof.get("compression") else "",
                "Y" if prof.get("forward_agent") else "",
                "Y" if prof.get("no_execute", 0) else "",
                (prof.get("proxy_command") or "")[:20],
                str(fwd_count) if fwd_count else "",
                key=str(prof["id"]),
            )

    def _get_selected_id(self) -> int | None:
        table = self.query_one("#prof-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        try:
            return int(row_key.value)
        except (ValueError, TypeError):
            return None

    def action_add_profile(self) -> None:
        self.app.push_screen(ProfileFormScreen(), callback=self._on_dismiss)

    def action_edit_profile(self) -> None:
        pid = self._get_selected_id()
        if pid is None:
            clitty_notify("No profile selected", level="warn", context=CTX_UI)
            return
        self.app.push_screen(ProfileFormScreen(profile_id=pid), callback=self._on_dismiss)

    def action_delete_profile(self) -> None:
        pid = self._get_selected_id()
        if pid is None:
            clitty_notify("No profile selected", level="warn", context=CTX_UI)
            return
        prof = db.get_profile(pid)
        if prof:
            name = prof["name"]
            db.delete_profile(pid)
            clitty_notify(f"Deleted profile '{name}'", context=CTX_UI)
            clitty_notify(f"Profile deleted: id={pid}, name={name}", level="debug", log_only=True)
            self._refresh_rows()

    def action_refresh_table(self) -> None:
        self._refresh_rows()

    def _on_dismiss(self, result=None) -> None:
        self._refresh_rows()
