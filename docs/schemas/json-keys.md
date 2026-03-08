# Keys JSON Schema

SSH keys are exported as encrypted JSON. Import accepts plain JSON or encrypted cliTTY export.

## Plain JSON (Import Only)

Used for bulk import from trusted sources. Not encrypted.

### Structure

Either `{"items": [...]}` or a bare array of key objects.

```json
{
  "items": [
    {
      "label": "string",
      "username": "string",
      "private_key": "string (PEM)",
      "passphrase": "string (optional)",
      "prompt_passphrase": 0
    }
  ]
}
```

### Fields

| Field              | Type   | Required | Description                              |
|--------------------|--------|----------|------------------------------------------|
| `label`            | string | No       | Optional label                           |
| `username`         | string | Yes      | Default username for this key            |
| `private_key`      | string | Yes      | PEM-encoded private key (must contain `-----BEGIN`) |
| `passphrase`       | string | No       | Key passphrase if encrypted              |
| `prompt_passphrase`| int    | No       | 1 = prompt at connect; 0 = use stored    |

### Example: Plain JSON

```json
{
  "items": [
    {
      "label": "GitHub",
      "username": "git",
      "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n...\n-----END OPENSSH PRIVATE KEY-----\n",
      "passphrase": "",
      "prompt_passphrase": 0
    },
    {
      "label": "Work key",
      "username": "admin",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
      "passphrase": "",
      "prompt_passphrase": 1
    }
  ]
}
```

---

## Encrypted Export (Export and Import)

cliTTY export uses a wrapper envelope with PBKDF2 + Fernet encryption.

### Envelope Structure

```json
{
  "clitty_export": true,
  "version": 1,
  "type": "keys",
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
| `type`          | string | `"keys"` for key exports                         |
| `encrypted`     | bool   | `true` for encrypted files                       |
| `salt`          | string | Base64 salt for PBKDF2                           |
| `iterations`    | int    | PBKDF2 iterations (480000)                       |
| `data`          | string | Base64-encoded Fernet ciphertext                 |

The `data` field decrypts to the plain JSON payload: `{"items": [...]}`.

### Encryption

- **Algorithm:** PBKDF2-HMAC-SHA256(export_password, salt, 480000) → 32 bytes → base64 = Fernet key
- **Cipher:** Fernet (AES-128-CBC + HMAC-SHA256)

### Example: Encrypted File (opaque)

```json
{
  "clitty_export": true,
  "version": 1,
  "type": "keys",
  "encrypted": true,
  "salt": "dGVzdC1zYWx0LTE2Ynl0ZXM=",
  "iterations": 480000,
  "data": "gAAAAABm..."
}
```

---

## Import Rules

- Plain JSON: parse directly, add each valid item.
- Encrypted JSON: detect `clitty_export` + `encrypted: true`, prompt for export password, decrypt, then parse.
- Items without `username` or without `private_key` containing `-----BEGIN` are skipped.
- All imported keys are added; no merge by label.
