# Database

> MariaDB setup, configuration, and complete table schema reference.

---

## Table of Contents

- [Setup](#database-setup-mariadb)
- [Schema Auto-Sync](#schema-auto-sync)
- [CbomImport BLOB Columns](#cbomimport-blob-columns)
- [Sequelize Configuration](#sequelize-configuration)
- [Connection Pooling](#connection-pooling)
- [Models](#models)
- [Table Schemas](#table-schemas)

---

## Database Setup (MariaDB)

Integration configurations and discovered assets are persisted in a **MariaDB** database using **Sequelize ORM**. The database is named `dcone-quantum-gaurd`.

### Prerequisites

1. Install MariaDB (or MySQL — Sequelize supports both):

```bash
# macOS
brew install mariadb && brew services start mariadb

# Ubuntu / Debian
sudo apt install mariadb-server && sudo systemctl start mariadb
```

2. Create the database:

```sql
CREATE DATABASE `dcone-quantum-gaurd`;
```

3. Set credentials in `.env`:

```bash
DB_DATABASE=dcone-quantum-gaurd
DB_USERNAME=root
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=3306
DB_DIALECT=mariadb
```

### Schema Auto-Sync

On startup, the backend calls `sequelize.sync({ alter: true })`, which automatically creates or updates tables to match the Sequelize model definitions. No manual migration step is needed for development.

The backend also attempts to increase MariaDB's `max_allowed_packet` to **64 MB** (`SET GLOBAL max_allowed_packet = 67108864`) to accommodate large BOM BLOB inserts. This requires `SUPER` privilege; if unavailable, a warning is logged but the server continues.

### CbomImport BLOB Columns

The `cbom_imports` table stores up to three BOM files per import record as BLOBs:

| Column | Type | Description |
|--------|------|-------------|
| `cbomFile` | `BLOB` | The raw CBOM JSON (CycloneDX) |
| `cbomFileType` | `STRING` | MIME type (typically `application/json`) |
| `sbomFile` | `BLOB` | The raw SBOM JSON from Trivy (if available) |
| `sbomFileType` | `STRING` | MIME type |
| `xbomFile` | `BLOB` | The merged xBOM JSON (if available) |
| `xbomFileType` | `STRING` | MIME type |

List endpoints (`GET /api/cbom-imports`) exclude the BLOB columns for performance. The single-record endpoint (`GET /api/cbom-imports/:id`) returns all three files as **base64-encoded** strings.

### Sequelize Configuration

The database config lives in two places:

| File | Purpose |
|------|---------|
| `backend/src/config/database.ts` | Runtime Sequelize instance — reads from `process.env` |
| `backend/sequelize.config.cjs` | Sequelize CLI config — for manual migrations if needed |

### Connection Pooling

```typescript
pool: {
  max: 10,      // max concurrent connections
  min: 0,       // min idle connections
  acquire: 30000, // ms to wait for connection before error
  idle: 10000,    // ms before idle connection is released
}
```

---

## Models

| Model | Table | Description |
|-------|-------|-------------|
| `Integration` | `integrations` | User-configured integration instances — stores template type, connection config (JSON), import scope (JSON), sync schedule, status, and sync history |
| `Certificate` | `certificates` | TLS/SSL certificates discovered via DigiCert Trust Lifecycle Manager |
| `Endpoint` | `endpoints` | TLS endpoints discovered via Network Scanner |
| `Software` | `software` | Software signing data from DigiCert Software Trust Manager |
| `Device` | `devices` | IoT/industrial devices from DigiCert Device Trust Manager |
| `CbomImport` | `cbom_imports` | CycloneDX CBOM file import records |
| `SyncLog` | `sync_logs` | Audit trail of every sync run (scheduled or manual) |
| `CryptoPolicy` | `crypto_policies` | Cryptographic compliance policies with JSON-serialised rules |
| `Ticket` | `tickets` | Remediation tickets created via JIRA, GitHub, or ServiceNow |
| `TicketConnector` | `ticket_connectors` | JIRA / GitHub / ServiceNow connector credentials and defaults |
| `CbomUpload` | `cbom_uploads` | CBOMs uploaded via the CBOM Analyzer page (persisted for Dashboard welcome page) |

> All five discovery tables and `sync_logs` have an `integration_id` foreign key referencing `integrations.id` with `ON DELETE CASCADE` — deleting an integration removes all its discovered data and sync history.

---

## Table Schemas

### CbomUpload Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `file_name` | `VARCHAR(255)` | Original uploaded file name |
| `component_name` | `VARCHAR(255)` | Top-level component name from the CBOM |
| `format` | `VARCHAR(50)` | BOM format (e.g., `CycloneDX`) |
| `spec_version` | `VARCHAR(20)` | Spec version (e.g., `1.6`) |
| `total_assets` | `INTEGER` | Total cryptographic assets count |
| `quantum_safe` | `INTEGER` | Count of quantum-safe assets |
| `not_quantum_safe` | `INTEGER` | Count of not-quantum-safe assets |
| `conditional` | `INTEGER` | Count of conditionally safe assets |
| `unknown` | `INTEGER` | Count of unknown-safety assets |
| `upload_date` | `DATE` | Upload timestamp |
| `cbom_file` | `BLOB` | Raw CBOM JSON file |
| `cbom_file_type` | `VARCHAR(100)` | MIME type (typically `application/json`) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Crypto Policy Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `name` | `VARCHAR(255)` | Policy name |
| `description` | `TEXT` | Policy description with NIST reference |
| `severity` | `ENUM` | `High`, `Medium`, `Low` |
| `status` | `ENUM` | `active`, `draft` |
| `operator` | `ENUM` | `AND`, `OR` |
| `rules` | `JSON` | Array of `PolicyRule` objects (serialised as JSON string) |
| `preset_id` | `VARCHAR(50)` | ID of the preset template (nullable) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Ticket Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `ticket_id` | `VARCHAR(100)` | Platform-specific ID (e.g. `CRYPTO-1245`, `#342`, `INC0012345`) |
| `type` | `ENUM` | `JIRA`, `GitHub`, `ServiceNow` |
| `title` | `VARCHAR(500)` | Ticket title |
| `description` | `TEXT` | Full description |
| `status` | `VARCHAR(50)` | `To Do`, `In Progress`, `Done`, `Blocked`, `Open`, `New` |
| `priority` | `VARCHAR(20)` | `Critical`, `High`, `Medium`, `Low` |
| `severity` | `VARCHAR(20)` | `Critical`, `High`, `Medium`, `Low` |
| `entity_type` | `VARCHAR(50)` | `Certificate`, `Endpoint`, `Application`, `Device`, `Software` |
| `entity_name` | `VARCHAR(255)` | Name of the affected asset |
| `assignee` | `VARCHAR(255)` | Assigned person (display name for JIRA) |
| `labels` | `JSON` | Array of label strings |
| `external_url` | `VARCHAR(500)` | URL to the ticket on the external platform |
| `platform_details` | `JSON` | Platform-specific metadata / error details |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Ticket Connector Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `type` | `VARCHAR(20)` | `JIRA`, `GitHub`, `ServiceNow` |
| `name` | `VARCHAR(255)` | User-given name |
| `base_url` | `VARCHAR(500)` | Platform base URL |
| `enabled` | `BOOLEAN` | Whether the connector is active |
| `config` | `JSON` | Platform-specific credentials and defaults (serialised) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Integration Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `template_type` | `VARCHAR(50)` | References the catalog type (`digicert-tlm`, `network-scanner`, etc.) |
| `name` | `VARCHAR(255)` | User-given name for this instance |
| `description` | `TEXT` | Integration description |
| `status` | `ENUM` | `not_configured`, `configuring`, `testing`, `connected`, `error`, `disabled` |
| `enabled` | `BOOLEAN` | Whether the integration is active |
| `config` | `JSON` | Connection fields (API URL, API key, tokens, etc.) |
| `import_scope` | `JSON` | Array of selected import scope values |
| `sync_schedule` | `ENUM` | `manual`, `1h`, `6h`, `12h`, `24h` |
| `last_sync` | `VARCHAR(100)` | Timestamp of last successful sync |
| `last_sync_items` | `INTEGER` | Number of items imported in the last sync |
| `last_sync_errors` | `INTEGER` | Number of errors in the last sync |
| `next_sync` | `VARCHAR(100)` | Scheduled time for next sync |
| `error_message` | `TEXT` | Last error message (if status is `error`) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Certificates Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `common_name` | `VARCHAR(255)` | Certificate common name (CN) |
| `ca_vendor` | `VARCHAR(100)` | Certificate Authority vendor |
| `status` | `ENUM` | `Issued`, `Expired`, `Revoked`, `Pending` |
| `key_algorithm` | `VARCHAR(50)` | Key algorithm (RSA, ECDSA, ML-DSA, etc.) |
| `key_length` | `VARCHAR(50)` | Key length / parameter set |
| `quantum_safe` | `BOOLEAN` | Whether the key algorithm is PQC-safe |
| `source` | `VARCHAR(100)` | Data source identifier |
| `expiry_date` | `VARCHAR(100)` | Certificate expiration date (nullable) |
| `serial_number` | `VARCHAR(255)` | Certificate serial number (nullable) |
| `signature_algorithm` | `VARCHAR(100)` | Signature algorithm (nullable) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Endpoints Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `hostname` | `VARCHAR(255)` | Server hostname |
| `ip_address` | `VARCHAR(45)` | IPv4 or IPv6 address |
| `port` | `INTEGER` | TCP port number |
| `tls_version` | `VARCHAR(20)` | TLS protocol version (e.g. `TLS 1.3`) |
| `cipher_suite` | `VARCHAR(100)` | Negotiated cipher suite |
| `key_agreement` | `VARCHAR(100)` | Key agreement algorithm (ECDHE, X25519, etc.) |
| `quantum_safe` | `BOOLEAN` | Whether the cipher suite is PQC-safe |
| `source` | `VARCHAR(100)` | Data source identifier |
| `last_scanned` | `VARCHAR(100)` | Timestamp of last scan (nullable) |
| `cert_common_name` | `VARCHAR(255)` | CN of the certificate served (nullable) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Software Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `name` | `VARCHAR(255)` | Software package name |
| `version` | `VARCHAR(50)` | Version string |
| `vendor` | `VARCHAR(100)` | Software vendor |
| `signing_algorithm` | `VARCHAR(50)` | Code signing algorithm |
| `signing_key_length` | `VARCHAR(50)` | Signing key length |
| `hash_algorithm` | `VARCHAR(50)` | Hash algorithm used for signing |
| `crypto_libraries` | `JSON` | Array of crypto library names used |
| `quantum_safe` | `BOOLEAN` | Whether the signing is PQC-safe |
| `source` | `VARCHAR(100)` | Data source identifier |
| `release_date` | `VARCHAR(100)` | Software release date (nullable) |
| `sbom_linked` | `BOOLEAN` | Whether an SBOM is linked (default `false`) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Devices Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `device_name` | `VARCHAR(255)` | Device name / identifier |
| `device_type` | `VARCHAR(100)` | Device type (Gateway, Sensor, Controller, etc.) |
| `manufacturer` | `VARCHAR(100)` | Device manufacturer |
| `firmware_version` | `VARCHAR(50)` | Current firmware version |
| `cert_algorithm` | `VARCHAR(50)` | Certificate algorithm used on device |
| `key_length` | `VARCHAR(50)` | Key length |
| `quantum_safe` | `BOOLEAN` | Whether the device crypto is PQC-safe |
| `enrollment_status` | `ENUM` | `Enrolled`, `Pending`, `Revoked`, `Expired` |
| `last_checkin` | `VARCHAR(100)` | Timestamp of last device check-in |
| `source` | `VARCHAR(100)` | Data source identifier |
| `device_group` | `VARCHAR(100)` | Logical device group (nullable) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### CBOM Imports Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `file_name` | `VARCHAR(255)` | Imported CBOM file name |
| `format` | `VARCHAR(50)` | CBOM format (e.g. `CycloneDX`) |
| `spec_version` | `VARCHAR(20)` | Spec version (e.g. `1.7`) |
| `total_components` | `INTEGER` | Total components in CBOM |
| `crypto_components` | `INTEGER` | Number of crypto components |
| `quantum_safe_components` | `INTEGER` | Number of PQC-safe components |
| `non_quantum_safe_components` | `INTEGER` | Number of non-PQC-safe components |
| `import_date` | `VARCHAR(100)` | Import timestamp |
| `status` | `ENUM` | `Processed`, `Processing`, `Failed`, `Partial` |
| `source` | `VARCHAR(100)` | Data source identifier |
| `application_name` | `VARCHAR(255)` | Application name (nullable) |
| `cbom_file` | `BLOB` | Raw CBOM JSON content (CycloneDX) |
| `cbom_file_type` | `VARCHAR(100)` | MIME type of the CBOM file (e.g. `application/json`) |
| `sbom_file` | `BLOB` | Raw SBOM JSON from Trivy (nullable) |
| `sbom_file_type` | `VARCHAR(100)` | MIME type of the SBOM file |
| `xbom_file` | `BLOB` | Merged xBOM JSON (nullable) |
| `xbom_file_type` | `VARCHAR(100)` | MIME type of the xBOM file |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

### Sync Logs Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | `VARCHAR(36)` PK | UUID v4 |
| `integration_id` | `VARCHAR(36)` FK | References `integrations.id` (CASCADE) |
| `trigger` | `ENUM` | `scheduled`, `manual` |
| `status` | `ENUM` | `running`, `success`, `partial`, `failed` |
| `started_at` | `VARCHAR(100)` | ISO timestamp when the sync started |
| `completed_at` | `VARCHAR(100)` | ISO timestamp when the sync finished (nullable) |
| `duration_ms` | `INTEGER` | Duration of the sync run in milliseconds (nullable) |
| `items_fetched` | `INTEGER` | Number of items fetched from the connector (default 0) |
| `items_created` | `INTEGER` | Number of items bulk-inserted into the discovery table (default 0) |
| `items_updated` | `INTEGER` | Number of items updated (default 0, reserved for future delta sync) |
| `items_deleted` | `INTEGER` | Number of old items deleted in full-refresh (default 0) |
| `errors` | `INTEGER` | Total error count (default 0) |
| `error_details` | `JSON` | Array of error message strings (nullable) |
| `sync_schedule` | `VARCHAR(10)` | The schedule that triggered this sync (e.g. `6h`, `manual`) |
| `created_at` | `DATETIME` | Auto-managed by Sequelize |
| `updated_at` | `DATETIME` | Auto-managed by Sequelize |

---

*Back to [README](../README.md) · See also [Architecture](architecture.md) · [API Reference](api-reference.md)*
