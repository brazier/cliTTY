"""CSV importer for host exports with flexible header mapping."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from src import database as db


def _strip_cidr(ip: str) -> str:
    """Remove CIDR suffix, e.g. '10.0.0.1/29' -> '10.0.0.1'."""
    return ip.split("/")[0].strip() if ip else ""


def _default_col_name(header: str) -> str:
    """Capitalize first letter of header."""
    h = (header or "").strip()
    return h[:1].upper() + h[1:].lower() if h else ""


def get_csv_headers(path: str | Path) -> list[str]:
    """Read the first row of a CSV file and return header names."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        row = next(reader, None)
        if not row:
            return []
        return [str(h).strip() for h in row]


def import_csv_with_mapping(
    path: str | Path,
    mapping: list[dict[str, Any]],
    skip_empty_ip: bool = False,
) -> int:
    """Parse CSV using the given mapping and bulk-insert hosts.

    mapping: list of {csv_header, col_name, seq, import_, visible}
    - csv_header: header from CSV
    - col_name: "ip_address" | "name" | user-defined
    - import_: if False, skip this column
    - Only rows with import_=True are used
    """
    # Build csv_header -> col_name for imported columns
    header_to_col: dict[str, str] = {}
    for m in mapping:
        if not m.get("import_", True):
            continue
        header_to_col[m["csv_header"]] = m["col_name"]

    rows: list[dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            name = ""
            ip_address = ""
            data: dict[str, str] = {}
            for h, col in header_to_col.items():
                val = (raw.get(h) or "").strip()
                if col == "ip_address":
                    ip_address = _strip_cidr(val)
                elif col == "name":
                    name = val
                else:
                    data[col] = val
            if skip_empty_ip and not ip_address:
                continue
            rows.append({"name": name, "ip_address": ip_address, "data": data})

    # Save column definitions for imported columns
    defs = [
        {"col_name": m["col_name"], "seq": m["seq"], "visible": 1 if m.get("visible", True) else 0}
        for m in sorted(mapping, key=lambda x: x["seq"])
        if m.get("import_", True)
    ]
    if defs:
        db.save_column_defs(defs)

    count = db.bulk_insert_hosts_v2(rows)
    try:
        from src import clitty_notify
        clitty_notify.clitty_notify(
            f"Import: inserted {count} hosts from {path}", level="debug", log_only=True
        )
    except Exception:
        pass
    return count
