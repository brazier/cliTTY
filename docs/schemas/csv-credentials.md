# Credentials CSV Schema

Credentials can be imported from plain CSV. Export is JSON only (encrypted).

## Import

### Headers

| Header   | Aliases   | Required | Description        |
|----------|-----------|----------|--------------------|
| `username` | `user`  | Yes      | Login username     |
| `password` | `pass`  | Yes      | Plain password     |
| `label`    | —       | No       | Optional label     |

Header matching is case-insensitive.

### Format Rules

- First row must be headers.
- One credential per row.
- Empty username rows are skipped.

### Encoding

- UTF-8

### Example: Full Headers

```csv
label,username,password
Acme Prod,admin,SecretPass123
Web Login,deploy,DeployKey99
```

### Example: Username and Password Only

```csv
username,password
admin,SecretPass123
deploy,DeployKey99
```

### Example: Alternative Aliases

```csv
user,pass
admin,SecretPass123
deploy,DeployKey99
```

---

## Security

- CSV is plain text. Do not commit or share credential CSV files.
- Credentials are encrypted in the database using the vault (master password) after import.
