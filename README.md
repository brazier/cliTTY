# cliTTY

<p align="center"><img width="642" height="644" alt="clitty-icon-3" src="https://github.com/user-attachments/assets/762a9611-6ea4-4f55-bc24-e9e8593fe76d" /></p>

> [!CAUTION]
> Make sure to read [Security Considerations](#security-considerations) before you start using this.

Terminal-based SSH manager with a TUI. Manage hosts, credentials, SSH keys, and connection profiles. In no way a fork of putty and kitty, but made in their image. Connects via embedded terminal or subprocess SSH/SFTP. Thoroughly tested by 1 subject, does not run well under windows(missing sshpass) but runs well under WSL and has the option to detect it and spawn winows terminals.

<img width="1920" height="1050" alt="swappy-20260308_155734" src="https://github.com/user-attachments/assets/8409d08e-54a3-48f3-a688-1cdb2b818e53" />

## Features

- **Hosts** — Import from CSV, add/edit/delete, jump hosts, credential or SSH key auth
- **Credentials** — Encrypted storage, credential probing on first connect
- **SSH keys** — Import keys with optional passphrase, add to agent
- **Connection profiles** — Custom settings (timeout, ProxyCommand, etc.) per connection
- **Host key verification** — DB-backed known hosts with accept/warn/strict policies
- **Export/import** — Hosts as CSV, credentials and keys as encrypted JSON ([docs](docs/import-export.md))

## Requirements

- Python 3 with `venv` (and `cryptography`, `textual`, `textual-terminal`, `paramiko` installed via install -r requrements.txt)
- OpenSSH client (`ssh`, `sftp`)
- `sshpass`

---

## Installation

### General manual install

```bash
mkdir clitty
tar -xvzf clitty-0.8.0.tar.gz -C clitty
cd clitty
python3 -m venv .venv
.venv/bin/activate
pip install -r requirements.txt
./main.py
```
You can then option to change the file install/clitty-run to this dir and then copy that file to somewhere in PATH


### Linux (system-wide)

Run as root (or via `sudo`):

```bash
sudo bash install/clitty-install.sh
```

This installs to `/opt/clitty`, creates a virtualenv, installs dependencies, and adds `clitty` to `/usr/local/bin`. Supported: Debian/Ubuntu, Fedora/RHEL, Arch, Alpine.

### Windows

Run from a Command Prompt or PowerShell in the project root:

```cmd
install\clitty-install.bat
```

Installs to `%LOCALAPPDATA%\clitty`. Add that folder to `PATH` or run `clitty-run.bat` directly.

---

## Usage

```bash
clitty
```

Enter your master password at startup. Use the TUI to browse hosts, connect, manage credentials/keys, and adjust settings.

---

## Security Considerations

> **Important:** cliTTY stores SSH credentials and keys. Use it with care and understand the following security aspects.

### What cliTTY Does Well

- **Encryption** — PBKDF2 + Fernet envelope encryption for credentials, SSH keys, connection profiles (including ProxyCommand), and status bar config (including custom commands). Sensitive data in the DB is unreadable without the master password.
- **Parameterized queries** — No SQL injection; all DB access uses placeholders
- **Temp files** — `mkstemp` with `0o600`/`0o700` permissions; cleanup where feasible
- **Master password** — Prompted via `getpass`, never written to disk in plaintext
- **Host key verification** — Configurable policies backed by a known hosts DB

### Known Concerns and Limitations

1. **Password in temp file (wrapper)** — For embedded password-based SSH, the password is written to a short-lived temp file and passed to `ssh_wrapper.py`. The file has strict permissions and is deleted after use, but the password briefly exists on disk.

2. **Session data file** — When spawning a new terminal session with status bar, session data (including password) is written to a temp file for the child to read. There is a small race window before the child deletes it; use a secure temp directory if concerned.

3. **Custom status bar commands** — Custom status bar providers run arbitrary commands on the remote host. Status bar config (including custom commands) is **encrypted at rest**, so someone with DB access but no master password cannot read or inject malicious commands. The risk applies when importing plaintext config from untrusted sources or when your session is compromised.

4. **Proxy command** — `ProxyCommand` from connection profiles is passed directly to SSH. Profiles (including ProxyCommand) are **encrypted at rest**, so DB theft does not expose them. The risk applies when importing untrusted profiles or if a profile is crafted with shell metacharacters—it is passed as-is to SSH.

5. **Host / IP input** — Manual connect and host forms accept arbitrary input. Sanitize or validate if entering data from untrusted sources.

6. **Known hosts temp files** — Host keys are written to temp files under system temp; these are not always cleaned up.

### Best Practices

- Use a **strong master password**; it protects all credentials and keys
- Prefer **SSH key auth** where possible; it avoids password temp files
- Run only on **single-user machines**; the DB and temp files are not shared
- Keep the **DB location** (`~/.clitty/`) and system temp directory private
- Do **not** import connection profiles or status bar config from untrusted sources; encryption protects data at rest, but imported plaintext config is applied as-is and can run arbitrary commands

---

## Data Storage

- **Database:** `~/.clitty/clitty.db` (SQLite)
- **Encryption:** Envelope encryption (DEK + KEK); master password unlocks the vault
