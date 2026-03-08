# Hosts CSV Schema

Hosts are imported and exported as plain CSV. Import uses flexible header mapping; export uses the configured visible columns plus `proto`.

## Import

### Header Mapping

The importer lets you map your CSV columns to cliTTY fields:

| Target field  | Description           | Required |
|---------------|-----------------------|----------|
| `ip_address`  | IP address or hostname | Yes (unless skip-empty-ip) |
| `name`        | Display name          | No       |
| *custom*      | Any user-defined column | No     |

- CSV headers can be arbitrary; you map each to `ip_address`, `name`, or a custom column name.
- Custom columns become host data and can be shown in the hosts table.
- IP values with CIDR suffixes (e.g. `10.0.0.1/29`) are stripped to `10.0.0.1`.

### Encoding

- UTF-8 with optional BOM (`utf-8-sig`)

### Example: Minimal

```csv
name,ip_address
server-01,192.168.1.10
server-02,192.168.1.11
```

### Example: With Custom Columns (e.g. NetBox export)

```csv
Name,Status,Tenant,Role,Site,IP Address
AR Server 01,Active,Acme,TMS,AR Site,10.0.1.1
AR Server 02,Active,Acme,TMS,AR Site,10.0.1.2
```

Map: `Name` → name, `IP Address` → ip_address, `Status`, `Tenant`, `Role`, `Site` → custom columns.

### Example: Alternative Headers

```csv
hostname,address,notes
db-prod-01,10.0.0.5,Primary database
web-01,10.0.0.10,Web server
```

Map: `hostname` → name, `address` → ip_address, `notes` → custom column.

---

## Export

### Columns

Export includes, in order:

1. `name` (always)
2. `ip_address` (always)
3. Visible custom columns (from host column definitions)
4. `proto` (ssh, sftp, etc.; default `ssh`)

Columns follow the current visible column definitions. If none exist, export uses `name`, `ip_address`, `proto`.

### Encoding

- UTF-8

### Example: Export Output

```csv
name,ip_address,Status,Tenant,proto
server-01,192.168.1.10,Active,Acme,ssh
server-02,192.168.1.11,Active,Acme,ssh
```

---

## Notes

- Export is unencrypted. Do not put credentials or secrets in host columns.
- Credential/key and jump host associations are not exported; set them via Edit Host after import.
