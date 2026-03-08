#!/usr/bin/env python3
"""cliTTY SSH wrapper: reads password from temp file, sets SSHPASS, runs ssh.

Contains NO user data (no password, no credentials). Used when textual-terminal
runs password-based SSH and cannot receive environment variables.
"""

import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 3:
        return 1
    pw_path = sys.argv[1]
    cmd = sys.argv[2:]
    try:
        with open(pw_path, "rb") as f:
            pw = f.read().decode("utf-8", errors="replace").strip()
    finally:
        try:
            os.unlink(pw_path)
        except OSError:
            pass
    os.environ["SSHPASS"] = pw
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
