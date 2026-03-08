# Credentials JSON Schema

Credentials are exported as encrypted JSON. Import accepts plain JSON or encrypted cliTTY export.

## Plain JSON (Import Only)

Used for bulk import from trusted sources. Not encrypted.

### Structure

```json
{
  "items": [
    {
      "label": "string",
      "username": "string",
      "password": "string"
    }
  ]
}
```

### Fields

| Field     | Type   | Required | Description       |
|-----------|--------|----------|-------------------|
| `label`   | string | No       | Optional label    |
| `username`| string | Yes      | Login username    |
| `password`| string | Yes      | Plain password    |

### Example: Plain JSON

```json
{
  "items": [
    {
      "label": "Acme Prod",
      "username": "admin",
      "password": "SecretPass123"
    },
    {
      "label": "",
      "username": "deploy",
      "password": "DeployKey99"
    }
  ]
}
```

### Alternative: Array Format

Import accepts a bare array instead of `{"items": [...]}`:

```json
[
  {"label": "Web", "username": "webadmin", "password": "pwd1"},
  {"label": "DB", "username": "dbuser", "password": "pwd2"}
]
```

---

## Encrypted Export (Export and Import)

cliTTY export uses the same envelope format as keys.

### Envelope Structure

```json
{
  "clitty_export": true,
  "version": 1,
  "type": "credentials",
  "encrypted": true,
  "salt": "base64-encoded-16-bytes",
  "iterations": 480000,
  "data": "base64-encoded-fernet-ciphertext"
}
```

### Fields

| Field           | Type   | Description                                      |
|-----------------|--------|--------------------------------------------------|
| `clitty_export` | bool   | Must be `true` to identify format                |
| `version`       | int    | Schema version (1)                               |
| `type`          | string | `"credentials"` for credential exports           |
| `encrypted`     | bool   | `true` for encrypted files                       |
| `salt`          | string | Base64 salt for PBKDF2                           |
| `iterations`    | int    | PBKDF2 iterations (480000)                       |
| `data`          | string | Base64-encoded Fernet ciphertext                 |

The `data` field decrypts to: `{"items": [{"label","username","password"}, ...]}`.

### Encryption

- Same as keys: PBKDF2-HMAC-SHA256 + Fernet.
- Export password is separate from the master password.

### Example: Encrypted File (opaque)

```json
{
  "clitty_export": true,
  "version": 1,
  "type": "credentials",
  "encrypted": true,
  "salt": "YW5vdGhlci1zYWx0MTY=",
  "iterations": 480000,
  "data": "gAAAAABn..."
}
```

---

## Import Rules

- Plain JSON: parse `items` (or bare array), add each valid item.
- Encrypted JSON: detect `clitty_export` + `encrypted: true`, prompt for export password, decrypt, parse.
- Items without `username` are skipped.
- All imported credentials are added; no merge by label.
