#!/usr/bin/env python3
"""cliTTY - Terminal SSH Manager entry point."""

from __future__ import annotations

import argparse
import getpass
import sys

from src import clitty_notify
from src import database as db
from src import encryption
from src import ssh_manager
from src.clitty_notify import CTX_TERMINAL, NotifyContext
from src.ui.app import ClittyApp


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="cliTTY SSH Manager")
    parser.add_argument(
        "--force-debug",
        action="store_true",
        help="Enable logging at debug level for this session only (does not change DB)",
    )
    return parser.parse_args()


def _prompt_master_password() -> encryption.Vault:
    """Handle first-run setup or unlock with the master password."""
    db.init_db()

    if not encryption.is_initialized():
        print("Welcome to cliTTY! Set a master password to encrypt your credentials.")
        while True:
            pw1 = getpass.getpass("New master password: ")
            if not pw1:
                print("Password cannot be empty.")
                continue
            pw2 = getpass.getpass("Confirm master password: ")
            if pw1 != pw2:
                print("Passwords do not match. Try again.")
                continue
            vault = encryption.initialize(pw1)
            db.set_settings_vault(vault)
            db.set_setting("ssh_method", "subprocess")
            clitty_notify.clitty_notify("Initial setup: ssh_method=subprocess", level="info", log_only=True)
            print("Master password set. Starting cliTTY...\n")
            return vault
    else:
        while True:
            pw = getpass.getpass("Master password: ")
            try:
                vault = encryption.unlock(pw)
                db.set_settings_vault(vault)
                return vault
            except ValueError:
                clitty_notify.clitty_notify(
                    "Incorrect password. Try again.",
                    level="warn",
                    force_log=True,
                    context=CTX_TERMINAL,
                )


def main() -> None:
    args = _parse_args()
    if args.force_debug:
        clitty_notify.set_cli_overrides(enabled=True, level="debug")
        clitty_notify.clitty_notify(
            "Force-debug: logging enabled level=debug",
            level="debug",
            log_only=True,
        )

    try:
        vault = _prompt_master_password()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)

    auto_add = (db.get_setting("auto_add_keys_to_agent", "false") or "false").lower() in ("true", "1", "yes")
    if auto_add:
        keys = db.list_ssh_keys()
        has_keys_to_preload = any(not k["prompt_passphrase"] for k in keys)
        if has_keys_to_preload:
            n = ssh_manager.preload_agent_keys(vault)
            if n:
                clitty_notify.clitty_notify(
                    f"Loaded {n} key(s) into ssh-agent",
                    level="info",
                    context=NotifyContext(terminal_available=True, ui_available=False),
                )

    app = ClittyApp(vault=vault)
    app.run()


if __name__ == "__main__":
    main()
