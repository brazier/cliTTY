"""Status bar configuration and remote info providers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from src import database as db

if TYPE_CHECKING:
    from src.encryption import Vault

_session_config: dict[str, Any] | None = None

DEFAULT_CONFIG = {
    "enabled": True,
    "refresh_interval_sec": 30,
    "providers": [
        {"id": "uptime", "enabled": True},
        {"id": "os_release", "enabled": True},
        {"id": "ip_addrs", "enabled": True},
        {"id": "hostname", "enabled": False},
    ],
    "custom": [],
}


def set_session_config(config: dict[str, Any]) -> None:
    """Inject config for session mode (no vault). Called by session.py at startup."""
    global _session_config
    _session_config = config


def get_status_bar_config(vault: Vault | None = None) -> dict[str, Any]:
    """Load status bar config from system_settings (or injected session config)."""
    global _session_config
    if _session_config is not None:
        result = DEFAULT_CONFIG.copy()
        for k, v in _session_config.items():
            if k in result:
                result[k] = v
        return result

    raw = db.get_setting("status_bar", "{}", vault=vault)
    if not raw:
        return DEFAULT_CONFIG.copy()
    try:
        cfg = json.loads(raw)
        result = DEFAULT_CONFIG.copy()
        for k, v in cfg.items():
            if k in result:
                result[k] = v
        return result
    except json.JSONDecodeError:
        return DEFAULT_CONFIG.copy()


def set_status_bar_config(config: dict[str, Any], vault: Vault | None = None) -> None:
    """Save status bar config to system_settings."""
    db.set_setting("status_bar", json.dumps(config), vault=vault)
    try:
        from src import clitty_notify
        clitty_notify.clitty_notify("Status bar config saved", level="debug", log_only=True)
    except Exception:
        pass


def _parse_uptime(output: str) -> str:
    """Parse uptime output to a compact one-liner."""
    return output.strip().split("\n")[0][:80] if output.strip() else ""


def _parse_os_release(output: str) -> str:
    """Parse /etc/os-release PRETTY_NAME or fallback."""
    for line in output.strip().split("\n"):
        if line.startswith("PRETTY_NAME="):
            val = line.split("=", 1)[1].strip().strip('"')
            return val[:50] if val else ""
    # Fallback: first non-empty line (e.g. redhat-release)
    for line in output.strip().split("\n"):
        if line.strip():
            return line.strip()[:50]
    return ""


def _parse_ip_addrs(output: str) -> str:
    """Parse ip/ifconfig output to compact list of iface: ip."""
    parts: list[str] = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if ": " in line and "/" in line:
            # awk output: "eth0: 10.0.0.1/24"
            iface, rest = line.split(": ", 1)
            addr = rest.split("/")[0].strip()
            if addr and addr != "127.0.0.1":
                parts.append(f"{iface}:{addr}")
        elif "inet " in line:
            toks = line.split()
            if len(toks) >= 4:
                iface = toks[1].rstrip(":")
                addr = toks[3].split("/")[0]
                if addr != "127.0.0.1":
                    parts.append(f"{iface}:{addr}")
    return " ".join(parts[:5])[:60] if parts else ""


def _parse_hostname(output: str) -> str:
    return output.strip()[:40] if output.strip() else ""


@dataclass
class Provider:
    id: str
    label: str
    command: str
    parse: Callable[[str], str]


BUILTIN_PROVIDERS: dict[str, Provider] = {
    "uptime": Provider(
        id="uptime",
        label="Uptime",
        command="uptime 2>/dev/null",
        parse=_parse_uptime,
    ),
    "os_release": Provider(
        id="os_release",
        label="OS",
        command="cat /etc/os-release 2>/dev/null | grep PRETTY_NAME || cat /etc/redhat-release 2>/dev/null || echo ''",
        parse=_parse_os_release,
    ),
    "ip_addrs": Provider(
        id="ip_addrs",
        label="IPs",
        command="ip -4 -o addr show 2>/dev/null | awk '{print $2\": \"$4}' | grep -v '127.0.0.1' | head -5",
        parse=_parse_ip_addrs,
    ),
    "hostname": Provider(
        id="hostname",
        label="Host",
        command="hostname 2>/dev/null",
        parse=_parse_hostname,
    ),
}


def get_enabled_providers(vault: Vault | None = None) -> list[Provider]:
    """Return providers that are enabled in config."""
    cfg = get_status_bar_config(vault=vault)
    if not cfg.get("enabled", True):
        return []
    result: list[Provider] = []
    # Built-in
    for p in cfg.get("providers", []):
        pid = p.get("id", "")
        if p.get("enabled") and pid in BUILTIN_PROVIDERS:
            result.append(BUILTIN_PROVIDERS[pid])
    # Custom
    for c in cfg.get("custom", []):
        if not c.get("enabled", True):
            continue
        result.append(
            Provider(
                id=c.get("id", "custom"),
                label=c.get("label", "Custom"),
                command=c.get("command", "echo"),
                parse=lambda x: (x.strip()[:40] if x else ""),
            )
        )
    return result


def fetch_provider(client, provider: Provider, timeout: float = 5.0) -> str:
    """Run provider command on remote and return parsed output."""
    import paramiko

    if not isinstance(client, paramiko.SSHClient):
        return ""
    try:
        _, stdout, stderr = client.exec_command(provider.command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        return provider.parse(out) or ""
    except Exception:
        return ""
