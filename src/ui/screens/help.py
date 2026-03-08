"""Help screens for each main screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalGroup
from textual.screen import ModalScreen
from textual.widgets import Button, Static


HOSTS_HELP = """[b]Hosts Screen[/b]

Manage SSH hosts and connect quickly. Hosts are stored locally with optional metadata. Cred column shows [b](pass)[/b] for password auth or [b](key)[/b] for key auth.

[b]Actions[/b]

• [b]/[/b] Focus search and filter hosts by name, IP, status, tenant, site, or role.

• [b]a[/b] Add a new host. Enter name, IP, and optionally link a credential (password) or key.

• [b]e[/b] Edit the selected host.

• [b]d[/b] Delete the selected host.

• [b]i[/b] Import hosts from a CSV file.

• [b]m[/b] Manual connect by IP. Enter an IP to connect; cliTTY will probe credentials if the host is new.

• [b]r[/b] Refresh the table.

• [b]s[/b] Open SFTP for the selected host (in terminal or in-app, per Settings).

• [b]Enter[/b] Connect via SSH to the selected host."""


CREDENTIALS_HELP = """[b]Credentials Screen[/b]

Store SSH usernames and passwords. Credentials are encrypted with your master password.

[b]Actions[/b]

• [b]a[/b] Add a new credential (label, username, password).

• [b]e[/b] Edit the selected credential.

• [b]d[/b] Delete the selected credential.

• [b]r[/b] Refresh the table.

• [b]v[/b] Reveal the password for the selected credential (requires master password).

[b]Notes[/b]

• Assign credentials to hosts via the host form (Credential ID).

• Leave Credential ID blank on a host to auto-probe available credentials."""


KEYS_HELP = """[b]Keys Screen[/b]

Store SSH private keys and passphrases. Keys and passphrases are encrypted with your master password. The Agent column shows whether a key is loaded into ssh-agent.

[b]Actions[/b]

• [b]a[/b] Add a new key (label, username, private key PEM, optional passphrase).

• [b]i[/b] Import a key file. Browse to select a PEM file; it is loaded into the add-key form.

• [b]e[/b] Edit the selected key.

• [b]d[/b] Delete the selected key.

• [b]r[/b] Refresh the table.

• [b]v[/b] Reveal the passphrase for the selected key (requires master password).

• [b]l[/b] Load the selected key into ssh-agent. Keys with "prompt" passphrase must be loaded individually.

• [b]L[/b] Load all unloaded keys into ssh-agent. Skips keys that require passphrase at connect.

• [b]s[/b] Start ssh-agent.

• [b]k[/b] Close (stop) ssh-agent.

[b]Passphrase options[/b]

• [b]none[/b]: Key is unencrypted.

• [b]stored[/b]: Passphrase is saved (encrypted) and used automatically when connecting.

• [b]prompt[/b]: Passphrase is requested when connecting (checkbox "Prompt for passphrase at connect").

[b]Notes[/b]

• Assign keys to hosts via the host form (Key ID). Hosts use either a credential (password) or a key, not both.

• Empty passphrase with "prompt" checked means the key is encrypted; you will be asked for the passphrase at connect time."""


PROFILES_HELP = """[b]Connection Profiles Screen[/b]

Define reusable SSH connection profiles (port, key file, forwards, proxy, etc.).

[b]Actions[/b]

• [b]a[/b] Add a new profile.

• [b]e[/b] Edit the selected profile.

• [b]d[/b] Delete the selected profile.

• [b]r[/b] Refresh the table.

[b]Profile Options[/b]

• [b]Basic[/b]: Name, port, key file, timeout, compression, forward agent.

• [b]Advanced[/b]: Proxy command, ciphers, MACs, host key algorithms, remote command, extra SSH args.

• [b]Forwarding[/b]: Local (-L), remote (-R), and dynamic (-D) port forwards.

When connecting, you can pick a profile or use defaults. Profiles apply per connection."""


SETTINGS_HELP = """[b]Settings Screen[/b]

Configure SSH connection behavior, terminal emulator, SFTP, and status bar.

[b]Actions[/b]

• [b]r[/b] Refresh — reload settings from storage and update the form.

[b]Options[/b]

• [b]SSH Agent[/b]: Automatically add passphrase-protected keys to ssh-agent at startup. When enabled, all keys with stored passphrases are loaded into ssh-agent at startup.

• [b]SSH Method[/b]: How SSH connections are launched. See methods below.

• [b]Terminal emulator[/b]: Used when SSH opens in a new window. Choose a preset or specify "Other" with a custom path.

• [b]Host key policy[/b]: Accept on first connect (store key, verify later); Strict (only connect if key pre-known); Warn (allow key changes, log warning).

• [b]SFTP method[/b]: Subprocess spawns sftp in terminal; Paramiko opens in-app file browser.

• [b]Telnet / connection method[/b]: Applies to telnet and similar connections.

• [b]Auto lock[/b]: After inactivity, vault locks; enter master password to unlock.

• [b]Limit auth tries[/b]: When enabled, limits credential/key probe attempts (helps avoid fail2ban).

• [b]Jump host suffix[/b]: Suffix added to host name when jump target is added from profile selector.

• [b]Default Profile ID[/b]: Connection profile ID to use when none is selected (blank = none).

• [b]Status Bar[/b]: When using embedded SSH, enable the status bar, set refresh interval, and choose providers (uptime, OS release, IPs, hostname).

[b]SSH Methods[/b]

• [b]subprocess[/b]: SSH in the same terminal (app suspends). All platforms.

• [b]subprocess in new window (plain)[/b]: Plain SSH in external terminal. All platforms.

• [b]subprocess in new window (embed SSH + status bar)[/b]: Embedded terminal + status bar in a new window. Linux/macOS only (requires textual-terminal/pty).

• [b]embedded[/b]: In-app terminal + status bar. Linux/macOS only.

• [b]paramiko[/b]: In-app SSH browser (Python client). All platforms.

• [b]auto[/b]: Chooses based on platform.

[b]Embedded terminal (copy & paste)[/b]

• Hold [b]Shift[/b] while click-dragging to select; [b]Ctrl+Shift+C[/b] to copy.
• [b]Ctrl+Shift+V[/b] to paste into the SSH session.

[b]SFTP Methods[/b]

• [b]Subprocess[/b]: Spawns sftp in an external terminal. All platforms.

• [b]Paramiko[/b]: In-app file browser. All platforms."""


HOST_KEYS_HELP = """[b]Host Keys Screen[/b]

View and manage SSH host keys used for host key verification. Keys are stored in the database and used when connecting to prevent MITM attacks (when host key verification is enabled in Settings).

[b]Actions[/b]

• [b]a[/b] Add host key(s). Fetch from server via ssh-keyscan, or paste a known_hosts line.

• [b]d[/b] Delete the selected host key. Use after a server legitimately rotates its key.

• [b]r[/b] Refresh the table.

• [b]/[/b] Focus search and filter by host.

[b]Add options[/b]

• [b]Fetch[/b]: Enter host/IP and port, then click Fetch keys. Requires ssh-keyscan (usually bundled with OpenSSH).

• [b]Paste[/b]: Paste a line from ~/.ssh/known_hosts (e.g. hostname ssh-rsa AAAAB3... or [host]:22 ecdsa-sha2-nistp256 AAAAE2Vj...).

[b]Notes[/b]

• When host key verification is on (Settings), first connect to a new host stores the key automatically. Use this screen to pre-add keys (e.g. for strict mode) or remove keys after server key rotation."""


class _BaseHelpScreen(ModalScreen):
    """Base class for help modals."""

    HELP_CONTENT: str = ""

    def compose(self) -> ComposeResult:
        with VerticalGroup():
            yield Static(self.HELP_CONTENT)
            yield Button("Close", variant="primary", id="btn-help-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-help-close":
            self.dismiss()


class HostsHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = HOSTS_HELP


class CredentialsHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = CREDENTIALS_HELP


class KeysHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = KEYS_HELP


class ProfilesHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = PROFILES_HELP


class SettingsHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = SETTINGS_HELP


class HostKeysHelpScreen(_BaseHelpScreen):
    HELP_CONTENT = HOST_KEYS_HELP
