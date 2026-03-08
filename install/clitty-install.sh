#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/clitty"
VENV_DIR="$INSTALL_DIR/.venv"
BIN_TARGET="/usr/local/bin/clitty"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[[ $EUID -ne 0 ]] && exec sudo bash "$0" "$@"
[[ ! -f "$SOURCE_DIR/main.py" ]] && { echo "Error: clitty source not found at $SOURCE_DIR" >&2; exit 1; }

# Detect distro; set distro-specific package names (venv, openssh, python)
[[ -f /etc/os-release ]] && . /etc/os-release
id="${ID:-}"; like="${ID_LIKE:-}"
pkg_venv="python3-venv"; pkg_openssh="openssh-client"; pkg_python="python3"
case "$id" in
    debian|ubuntu|linuxmint|pop) ;;
    fedora|rhel|centos|almalinux|rocky|ol) pkg_venv="python3"; pkg_openssh="openssh-clients" ;;
    alpine) pkg_venv="py3-venv" ;;
    arch|manjaro) pkg_venv=""; pkg_openssh="openssh"; pkg_python="python" ;;
    *) [[ "$like" =~ rhel|fedora ]] && { pkg_venv="python3"; pkg_openssh="openssh-clients"; } ;;
esac

# Build package list from missing deps
pkgs=()
command -v python3 &>/dev/null || pkgs+=("$pkg_python")
python3 -c "import venv" 2>/dev/null || { [[ -n "$pkg_venv" ]] && pkgs+=("$pkg_venv"); }
command -v ssh &>/dev/null || pkgs+=("$pkg_openssh")
command -v sftp &>/dev/null || pkgs+=("$pkg_openssh")
command -v sshpass &>/dev/null || pkgs+=(sshpass)

if [[ ${#pkgs[@]} -gt 0 ]]; then
    pkgs=($(printf '%s\n' "${pkgs[@]}" | sort -u))
    echo "==> Installing: ${pkgs[*]}"
    case "$id" in
        debian|ubuntu|linuxmint|pop) apt-get update -qq && apt-get install -y "${pkgs[@]}" ;;
        fedora|rhel|centos|almalinux|rocky|ol) dnf install -y "${pkgs[@]}" ;;
        alpine) apk add --no-cache "${pkgs[@]}" ;;
        arch|manjaro) pacman -Sy --noconfirm "${pkgs[@]}" ;;
        *) if [[ "$like" =~ debian ]]; then apt-get update -qq && apt-get install -y "${pkgs[@]}"; elif [[ "$like" =~ rhel|fedora ]]; then dnf install -y "${pkgs[@]}"; else echo "Error: Unknown distro" >&2; exit 1; fi ;;
    esac
    # Re-check
    for cmd in python3 ssh sftp sshpass; do command -v "$cmd" &>/dev/null || { echo "Error: $cmd still missing" >&2; exit 1; }; done
    python3 -c "import venv" || { echo "Error: python3-venv still missing" >&2; exit 1; }
fi

[[ -d "$INSTALL_DIR" ]] && { echo "WARNING: $INSTALL_DIR exists and will be replaced." >&2; read -rp "Continue? [y/N] " c; [[ "${c,,}" =~ ^y(es)?$ ]] || exit 1; }

echo "==> Copying to $INSTALL_DIR"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_DIR/main.py" "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/src" "$INSTALL_DIR/"

echo "==> Copying clitty-run"
install -m 755 "$SCRIPT_DIR/clitty-run" "$INSTALL_DIR/clitty-run"

echo "==> Creating venv"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install -q --upgrade pip
pip install -q -r "$INSTALL_DIR/requirements.txt"

echo "==> Installing clitty command"
install -m 755 "$INSTALL_DIR/clitty-run" "$BIN_TARGET"

echo "Done. Run 'clitty' to start."
