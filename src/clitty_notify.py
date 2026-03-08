"""Unified notification and logging for cliTTY."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

LOG_PATH = Path.home() / ".clitty" / "clitty.log"
_COLORS = {
    "info": "\033[34m",
    "warn": "\033[33m",
    "error": "\033[31m",
    "debug": "\033[38;5;208m",  # orange
}
_RESET = "\033[0m"

_cli_logging_enabled: bool | None = None
_cli_log_level: str | None = None
_ui_callback: object | None = None
_logger: logging.Logger | None = None
_in_logging_check: bool = False
_db_logging_enabled_cached: bool | None = None
_db_log_level_cached: str | None = None


def set_cli_overrides(*, enabled: bool | None = None, level: str | None = None) -> None:
    """Set CLI overrides for logging. Called from main() before DB init."""
    global _cli_logging_enabled, _cli_log_level
    if enabled is not None:
        _cli_logging_enabled = enabled
    if level is not None:
        _cli_log_level = level
        if enabled is None:
            _cli_logging_enabled = True  # --log-level implies --enable-logging


def set_ui_callback(callback) -> None:
    """Register callback(app, msg, severity) for UI toasts. Called from app on_mount."""
    global _ui_callback
    _ui_callback = callback


@dataclass
class NotifyContext:
    """Context for routing notifications: terminal vs UI toast."""

    ssh_mode: str = "subprocess_same"
    terminal_available: bool = False
    ui_available: bool = False
    embed_opened: bool | None = None


CTX_TERMINAL = NotifyContext(terminal_available=True, ui_available=False)
CTX_UI = NotifyContext(terminal_available=False, ui_available=True)


def _is_logging_enabled() -> bool:
    global _in_logging_check, _db_logging_enabled_cached
    if _cli_logging_enabled is not None:
        return _cli_logging_enabled
    # Prevent recursion when logging is used inside the database layer, which
    # itself calls back into clitty_notify. If we're already in the middle of
    # a logging_enabled check, short‑circuit to False.
    if _db_logging_enabled_cached is not None:
        return _db_logging_enabled_cached
    if _in_logging_check:
        return False
    try:
        _in_logging_check = True
        from src import database as db

        val = (db.get_setting("logging_enabled", "false") or "false").lower()
        _db_logging_enabled_cached = val in ("true", "1", "yes")
        return _db_logging_enabled_cached
    except Exception:
        return False
    finally:
        _in_logging_check = False


def _get_log_level() -> str:
    global _db_log_level_cached
    if _cli_log_level is not None:
        return _cli_log_level
    if _db_log_level_cached is not None:
        return _db_log_level_cached
    try:
        from src import database as db

        _db_log_level_cached = db.get_setting("log_level", "info") or "info"
        return _db_log_level_cached
    except Exception:
        return "info"


def refresh_logging_from_db() -> None:
    """Refresh cached logging settings from the database.

    Called after settings are saved so that logging_enabled/log_level changes
    take effect without requiring an app restart.
    """
    global _cli_logging_enabled, _cli_log_level, _db_logging_enabled_cached, _db_log_level_cached
    _cli_logging_enabled = None
    _cli_log_level = None
    _db_logging_enabled_cached = None
    _db_log_level_cached = None
    try:
        from src import database as db

        val = (db.get_setting("logging_enabled", "false") or "false").lower()
        _db_logging_enabled_cached = val in ("true", "1", "yes")
        _db_log_level_cached = db.get_setting("log_level", "info") or "info"
    except Exception:
        _db_logging_enabled_cached = None
        _db_log_level_cached = None


def _should_log(level: str) -> bool:
    order = ["debug", "info", "warning", "error"]
    configured = _get_log_level().lower()
    try:
        return order.index(level.lower()) >= order.index(configured)
    except ValueError:
        return level.lower() in ("info", "warn", "error", "debug")


def _ensure_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    _logger = logging.getLogger("clitty.general")
    _logger.setLevel(logging.DEBUG)
    _logger.handlers.clear()
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    _logger.addHandler(handler)
    return _logger


def _log(level: str, message: str) -> None:
    log_level_map = {"info": logging.INFO, "warn": logging.WARNING, "warning": logging.WARNING, "error": logging.ERROR, "debug": logging.DEBUG}
    log_level = log_level_map.get(level.lower(), logging.INFO)
    logger = _ensure_logger()
    logger.log(log_level, "%s", message)


def _severity_from_level(level: str) -> str:
    if level in ("error",):
        return "error"
    if level in ("warn", "warning",):
        return "warning"
    return "information"


def clitty_notify(
    message: str,
    level: Literal["info", "warn", "error", "debug"] = "info",
    *,
    log_only: bool = False,
    notify: bool = True,
    force_log: bool = False,
    context: NotifyContext | None = None,
) -> None:
    """Unified notification: log to file, terminal (colored), or UI toast.

    Args:
        message: The message to deliver.
        level: Log level (info, warn, error, debug).
        log_only: If True, only write to log file; no terminal, no toast.
        notify: If True and not log_only, deliver to user (terminal or toast per context).
        force_log: If True, always write to log file, ignoring logging_enabled and level filter.
        context: Optional routing context. If None, uses heuristics (TTY → terminal, else UI).
    """
    # Log decision: force_log or (enabled and level passes)
    if force_log or (_is_logging_enabled() and _should_log(level)):
        _log(level, message)

    if log_only:
        return

    if not notify:
        return

    ctx = context
    if ctx is None:
        # Heuristic: if UI callback registered, use UI; else terminal (e.g. headless or suspended)
        ctx = CTX_UI if _ui_callback is not None else CTX_TERMINAL

    if ctx.terminal_available:
        color = _COLORS.get(level, _COLORS["info"])
        print(f"{color}[cliTTY] {message}{_RESET}", flush=True)
        return

    if ctx.ui_available and _ui_callback is not None:
        try:
            severity = _severity_from_level(level)
            _ui_callback(message, severity)
        except Exception:
            pass
