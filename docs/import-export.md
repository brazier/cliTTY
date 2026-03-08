# Import and Export

cliTTY supports importing and exporting data for **hosts**, **keys**, and **credentials**. This document describes the functionality in each module and points to the schema specifications.

## Overview by Module

| Module      | Import                               | Export                     | Encryption                    |
|-------------|--------------------------------------|----------------------------|-------------------------------|
| **Hosts**   | CSV (with header mapping)             | CSV (plain)                | None                          |
| **Keys**    | JSON (plain or encrypted)             | JSON (encrypted)           | Export password               |
| **Credentials** | CSV or JSON (plain or encrypted) | JSON (encrypted)           | Export password               |

**Master password:** Required before any export. Unlock the vault to proceed.

**Export password:** Separate from the master password. You enter it when exporting keys or credentials; use the same password when importing an encrypted file.

---

## Hosts

### Import hosts from CSV

- **Where:** Hosts screen → `i` (Import CSV)
- **Flow:** Choose a CSV file, map CSV columns to cliTTY fields (name, ip_address, custom columns), then import
- **Format:** Flexible headers—you map your CSV columns to internal fields. See [Hosts CSV schema](schemas/csv-hosts.md)

### Export hosts to CSV

- **Where:** Hosts screen → `x` (Export)
- **Format:** Plain CSV with columns from your host column definitions (name, ip_address, custom visible columns, proto). See [Hosts CSV schema](schemas/csv-hosts.md)

---

## Keys

### Import keys from JSON

- **Where:** Keys screen → `I` (Import JSON)
- **Formats:** Plain JSON or encrypted cliTTY export. For encrypted files, enter the export password.
- **Schema:** See [Keys JSON schema](schemas/json-keys.md)

### Export keys to JSON

- **Where:** Keys screen → `x` (Export)
- **Format:** Encrypted JSON using an export password. See [Keys JSON schema](schemas/json-keys.md)

---

## Credentials

### Import credentials from CSV or JSON

- **Where:** Credentials screen → `I` (Import)
- **Formats:**
  - CSV (plain, headers: `label`, `username`, `password` or `username`, `password`)
  - JSON (plain or encrypted). Enter export password for encrypted files.
- **Schema:** See [Credentials CSV schema](schemas/csv-credentials.md) and [Credentials JSON schema](schemas/json-credentials.md)

### Export credentials to JSON

- **Where:** Credentials screen → `x` (Export)
- **Format:** Encrypted JSON using an export password. See [Credentials JSON schema](schemas/json-credentials.md)

---

## Security Notes

- **Hosts CSV** is plain text; do not include sensitive data in host columns.
- **Keys and credentials** are exported encrypted with your export password. Store export files securely.
- **Plain JSON** import (keys/credentials) has no encryption; use only for trusted sources.
