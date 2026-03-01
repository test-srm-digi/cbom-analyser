# API Reference

> Complete REST API documentation for all backend endpoints.

---

## Table of Contents

- [CBOM Management](#cbom-management)
- [CBOM Uploads (Persisted)](#cbom-uploads-persisted)
- [Network Scanning](#network-scanning)
- [Code Scanning](#code-scanning)
- [AI Suggestions](#ai-suggestions)
- [Project Insight](#project-insight)
- [Health](#health)
- [Integrations REST API](#integrations-rest-api)
- [Discovery Data REST API](#discovery-data-rest-api)
- [Policies REST API](#policies-rest-api)
- [Tickets REST API](#tickets-rest-api)
- [Ticket Connectors REST API](#ticket-connectors-rest-api)
- [Sync Logs REST API](#sync-logs-rest-api)
- [Scheduler REST API](#scheduler-rest-api)

---

## CBOM Management

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/upload` | Multipart form, field `cbom` (JSON file) | `{ success, cbom, readinessScore, compliance }` |
| `POST` | `/api/upload/raw` | Raw JSON body (CBOM document) | Same as above |
| `GET` | `/api/cbom/list` | — | `{ success, cboms: [{ id, component, assetCount, timestamp }] }` |
| `GET` | `/api/cbom/:id` | — | `{ success, cbom, readinessScore, compliance }` |

> **Note:** `POST /api/upload` also persists the uploaded CBOM to the `cbom_uploads` database table (fire-and-forget) so that uploads are available on the Dashboard welcome page.

---

## CBOM Uploads (Persisted)

Uploaded CBOMs are persisted in a separate `cbom_uploads` table and surfaced on the Dashboard welcome page.

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `GET` | `/api/cbom-uploads` | — | `{ success, data: [{ id, fileName, componentName, format, specVersion, totalAssets, quantumSafe, notQuantumSafe, conditional, unknown, uploadDate }] }` |
| `GET` | `/api/cbom-uploads/:id` | — | `{ success, data: { ...fields, cbomFile (base64), cbomFileType } }` |
| `DELETE` | `/api/cbom-uploads/:id` | — | `{ success, message }` |

The list endpoint excludes the BLOB column (`cbomFile`) for performance. The single-record endpoint returns the CBOM file as a **base64-encoded** string.

---

## Network Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-network` | `{ url, port? }` | `{ success, result, cbomAsset }` |
| `POST` | `/api/scan-network/batch` | `{ hosts: [{ host, port? }] }` | `{ success, results, cbomAssets, errors }` |
| `POST` | `/api/scan-network/merge/:cbomId` | `{ url, port? }` | Updated CBOM with network asset merged |

---

## Code Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-code` | `{ repoPath, excludePatterns? }` | `{ success, cbomId, cbom, readinessScore, compliance }` |
| `POST` | `/api/scan-code/regex` | `{ repoPath, excludePatterns? }` | Same (regex scanner only, no sonar) |
| `POST` | `/api/scan-code/full` | `{ repoPath, networkHosts?, excludePatterns? }` | Same + `cbom.thirdPartyLibraries` + PQC verdicts |

The **`/api/scan-code/full`** endpoint runs the complete 6-step pipeline:
1. Code scan (sonar-cryptography or regex fallback) — 8 languages, 1 000+ patterns
2. Configuration & artifact scan (PEM certs, java.security, openssl.cnf, TLS configs)
3. Dependency scan (manifest file analysis + transitive resolution)
4. Network scan (if `networkHosts` provided)
5. Merge all discovered crypto assets
6. Smart PQC parameter analysis on conditional assets

---

## AI Suggestions

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/ai-suggest` | `{ algorithmName, primitive?, keyLength?, fileName?, lineNumber?, quantumSafety?, recommendedPQC? }` | `{ success, suggestion, replacement, migrationSteps, effort }` |

---

## Project Insight

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/ai-summary` | `{ assets, stats }` | `{ success, insight: { riskScore, headline, summary, priorities[], migrationEstimate } }` |

The **`/api/ai-summary`** endpoint generates a holistic project-level risk assessment. The request includes:
- `assets` — array of crypto asset summaries (`{ name, type, quantumSafety }`)
- `stats` — aggregate counts (`{ total, notSafe, conditional, safe, unknown }`)

The response `insight` object contains:
- `riskScore` (0–100) — 0 = fully PQC-ready, 100 = critical risk
- `headline` — one-line risk summary
- `summary` — 2–3 sentence executive overview
- `priorities[]` — ranked migration actions with `impact` (High/Medium/Low) and `effort` (Low/Medium/High) ratings
- `migrationEstimate` — human-readable time estimate for full PQC migration

Falls back to a **deterministic local engine** when AWS Bedrock credentials are not configured.

---

## Health

| Method | Endpoint | Response |
|--------|----------|----------|
| `GET` | `/api/health` | `{ status: 'ok', service, version, timestamp }` |

---

## Examples

**Upload a CBOM file:**
```bash
curl -X POST http://localhost:3001/api/upload \
  -F "cbom=@my-cbom.json"
```

**Scan a local repository:**
```bash
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/repo"}' \
  -o cbom.json
```

**Scan with file exclusions:**
```bash
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{
    "repoPath": "/path/to/repo",
    "excludePatterns": ["**/test/**", "**/*.test.ts"]
  }'
```

**Full pipeline scan (code + dependencies + network + PQC analysis):**
```bash
curl -X POST http://localhost:3001/api/scan-code/full \
  -H "Content-Type: application/json" \
  -d '{
    "repoPath": "/path/to/repo",
    "networkHosts": ["api.example.com", "auth.example.com"]
  }' \
  -o full-cbom.json
```

**Scan a TLS endpoint:**
```bash
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}'
```

**Batch scan multiple endpoints:**
```bash
curl -X POST http://localhost:3001/api/scan-network/batch \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [
      {"host": "github.com"},
      {"host": "google.com"},
      {"host": "api.stripe.com"}
    ]
  }'
```

**Get AI-powered migration suggestion:**
```bash
curl -X POST http://localhost:3001/api/ai-suggest \
  -H "Content-Type: application/json" \
  -d '{
    "algorithmName": "RSA-2048",
    "primitive": "public-key-encryption",
    "keyLength": 2048,
    "fileName": "src/auth/TokenService.java",
    "quantumSafety": "not-quantum-safe"
  }'
```

**Get project-level risk insight:**
```bash
curl -X POST http://localhost:3001/api/ai-summary \
  -H "Content-Type: application/json" \
  -d '{
    "assets": [
      { "name": "RSA-2048", "type": "algorithm", "quantumSafety": "not-quantum-safe" },
      { "name": "AES-256", "type": "algorithm", "quantumSafety": "quantum-safe" }
    ],
    "stats": { "total": 2, "notSafe": 1, "conditional": 0, "safe": 1, "unknown": 0 }
  }'
```

---

## Integrations REST API

The backend exposes a full CRUD REST API for managing integrations, mounted at `/api/integrations`.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/integrations` | List all integrations (ordered by creation date, newest first) |
| `GET` | `/api/integrations/:id` | Get a single integration by ID |
| `POST` | `/api/integrations` | Create a new integration |
| `PUT` | `/api/integrations/:id` | Update an existing integration |
| `DELETE` | `/api/integrations/:id` | Delete an integration |
| `PATCH` | `/api/integrations/:id/toggle` | Toggle enabled/disabled state |
| `POST` | `/api/integrations/:id/sync` | Trigger a manual sync |
| `POST` | `/api/integrations/:id/test` | Test the connection |

### Response Format

All endpoints return a consistent JSON envelope:

```json
{
  "success": true,
  "data": { /* integration object or array */ },
  "message": "optional message"
}
```

### Create Integration — Request Body

```json
{
  "templateType": "digicert-tlm",
  "name": "Production TLM — US East",
  "description": "Import certificates from...",
  "config": {
    "apiBaseUrl": "https://one.digicert.com",
    "apiKey": "your-api-key",
    "accountId": "12345"
  },
  "importScope": ["certificates", "endpoints", "keys"],
  "syncSchedule": "24h",
  "status": "connected"
}
```

### Update Integration — Request Body

All fields are optional — only provided fields are updated:

```json
{
  "name": "Updated Name",
  "config": { "apiKey": "new-key" },
  "importScope": ["certificates", "keys"],
  "syncSchedule": "6h"
}
```

### Example Requests

```bash
# List all integrations
curl http://localhost:3001/api/integrations

# Create a new TLM integration
curl -X POST http://localhost:3001/api/integrations \
  -H "Content-Type: application/json" \
  -d '{
    "templateType": "digicert-tlm",
    "name": "Production TLM",
    "description": "DigiCert TLM for prod certs",
    "config": { "apiBaseUrl": "https://one.digicert.com", "apiKey": "xxx" },
    "importScope": ["certificates", "endpoints"],
    "syncSchedule": "24h"
  }'

# Toggle enabled/disabled
curl -X PATCH http://localhost:3001/api/integrations/<id>/toggle

# Trigger manual sync
curl -X POST http://localhost:3001/api/integrations/<id>/sync

# Test connection
curl -X POST http://localhost:3001/api/integrations/<id>/test

# Delete
curl -X DELETE http://localhost:3001/api/integrations/<id>
```

---

## Discovery Data REST API

Each discovery tab has a dedicated CRUD REST API. All five resources follow the same 8-endpoint pattern with a `{ success, data, message }` response envelope.

### Shared Endpoint Pattern

Every discovery resource (`certificates`, `endpoints`, `software`, `devices`, `cbom-imports`) exposes:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/{resource}` | List all records (newest first) |
| `GET` | `/api/{resource}/integration/:integrationId` | List records for a specific integration |
| `GET` | `/api/{resource}/:id` | Get a single record by ID |
| `POST` | `/api/{resource}` | Create a single record (UUID auto-assigned) |
| `POST` | `/api/{resource}/bulk` | Bulk create — accepts `{ "items": [...] }` |
| `PUT` | `/api/{resource}/:id` | Update a record |
| `DELETE` | `/api/{resource}/:id` | Delete a single record |
| `DELETE` | `/api/{resource}/integration/:integrationId` | Delete all records for an integration |

### Resource Base Paths

| Resource | Base Path | Model | Discovery Tab |
|----------|-----------|-------|---------------|
| Certificates | `/api/certificates` | `Certificate` | Certificates (TLM) |
| Endpoints | `/api/endpoints` | `Endpoint` | Endpoints (Network Scanner) |
| Software | `/api/software` | `Software` | Software (STM) |
| Devices | `/api/devices` | `Device` | Devices (DTM) |
| CBOM Imports | `/api/cbom-imports` | `CbomImport` | CBOM Imports |
| CBOM Uploads | `/api/cbom-uploads` | `CbomUpload` | Dashboard Welcome Page |

### Response Format

All endpoints return the same JSON envelope used by the Integrations API:

```json
{
  "success": true,
  "data": { /* record object or array */ },
  "message": "optional message"
}
```

### Bulk Create — Request Body

```json
{
  "items": [
    { "integrationId": "uuid-1", "commonName": "*.example.com", "..." : "..." },
    { "integrationId": "uuid-1", "commonName": "api.example.com", "..." : "..." }
  ]
}
```

Each item in the array gets a UUID auto-assigned. All items are created in a single database call via `Model.bulkCreate()`.

### Example cURL Commands (Certificates)

```bash
# List all certificates
curl http://localhost:3001/api/certificates

# List certificates for a specific integration
curl http://localhost:3001/api/certificates/integration/<integrationId>

# Get a single certificate
curl http://localhost:3001/api/certificates/<id>

# Create a certificate
curl -X POST http://localhost:3001/api/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "integrationId": "uuid",
    "commonName": "*.example.com",
    "caVendor": "DigiCert",
    "status": "Issued",
    "keyAlgorithm": "RSA",
    "keyLength": "2048",
    "quantumSafe": false,
    "source": "DigiCert TLM"
  }'

# Bulk create
curl -X POST http://localhost:3001/api/certificates/bulk \
  -H "Content-Type: application/json" \
  -d '{ "items": [ { "integrationId": "uuid", "commonName": "a.com", "..." : "..." } ] }'

# Update
curl -X PUT http://localhost:3001/api/certificates/<id> \
  -H "Content-Type: application/json" \
  -d '{ "status": "Expired" }'

# Delete one
curl -X DELETE http://localhost:3001/api/certificates/<id>

# Delete all for an integration
curl -X DELETE http://localhost:3001/api/certificates/integration/<integrationId>
```

> The same cURL pattern applies to all six resources — just swap the base path.

---

## Policies REST API

The backend exposes a full CRUD REST API for cryptographic policies, mounted at `/api/policies`.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/policies` | List all policies (newest first) |
| `GET` | `/api/policies/:id` | Get a single policy by ID |
| `POST` | `/api/policies` | Create a new policy |
| `POST` | `/api/policies/bulk` | Bulk create (used by preset seeding) |
| `PUT` | `/api/policies/:id` | Update a policy |
| `DELETE` | `/api/policies/:id` | Delete a single policy |
| `DELETE` | `/api/policies/all` | Delete all policies |

### Create Policy — Request Body

```json
{
  "name": "No SHA-1 Usage",
  "description": "SHA-1 algorithm is prohibited across all systems.",
  "severity": "High",
  "status": "active",
  "operator": "AND",
  "rules": [
    { "asset": "certificate", "field": "signatureAlgorithm", "condition": "not-contains", "value": "SHA-1" },
    { "asset": "certificate", "field": "hashFunction", "condition": "not-equals", "value": "SHA-1" }
  ]
}
```

### Example Requests

```bash
# List all policies
curl http://localhost:3001/api/policies

# Create a policy
curl -X POST http://localhost:3001/api/policies \
  -H "Content-Type: application/json" \
  -d '{ "name": "PQC Readiness", "severity": "Medium", "status": "active", "operator": "AND", "rules": [{ "asset": "cbom-component", "field": "quantumSafe", "condition": "equals", "value": "true" }] }'

# Toggle status
curl -X PUT http://localhost:3001/api/policies/<id> \
  -H "Content-Type: application/json" \
  -d '{ "status": "draft" }'

# Delete
curl -X DELETE http://localhost:3001/api/policies/<id>
```

---

## Tickets REST API

The backend exposes CRUD for remediation tickets at `/api/tickets`. When creating a ticket, the backend automatically calls the external platform API (JIRA, GitHub, or ServiceNow) if a connector is configured and enabled.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/tickets` | List all tickets (newest first) |
| `GET` | `/api/tickets/:id` | Get a single ticket |
| `POST` | `/api/tickets` | Create a ticket (calls external API if connector available) |
| `PUT` | `/api/tickets/:id` | Update a ticket |
| `DELETE` | `/api/tickets/:id` | Delete a single ticket |
| `DELETE` | `/api/tickets/all` | Delete all tickets |

### Create Ticket — Request Body

```json
{
  "type": "JIRA",
  "title": "High Risk: Non-quantum-safe certificate for *.example.com",
  "description": "RSA-2048 certificate needs PQC migration...",
  "priority": "High",
  "severity": "High",
  "entityType": "Certificate",
  "entityName": "*.example.com",
  "assignee": "John Smith",
  "labels": ["cryptography", "security"],
  "project": "CRYPTO",
  "issueType": "Bug"
}
```

### Ticket Creation Flow

When `POST /api/tickets` is called:

1. **JIRA** — looks up the enabled JIRA connector, calls the JIRA Cloud REST API (`POST /rest/api/3/issue`), stores the returned `key` (e.g. `CRYPTO-42`) as `ticketId` and the `self` URL as `externalUrl`
2. **GitHub** — looks up the enabled GitHub connector, calls the GitHub Issues API (`POST /repos/{owner}/{repo}/issues`), stores `#<number>` as `ticketId` and the `html_url` as `externalUrl`
3. **ServiceNow** — looks up the enabled ServiceNow connector, calls the ServiceNow Table API (`POST /api/now/table/incident`), stores the `number` (e.g. `INC0012345`) as `ticketId`

If the external API call fails, the ticket is still stored locally with error details in `platformDetails`.

If no connector is configured, a synthetic ticket ID is generated (e.g. `CRYPTO-1234`, `#1234`, `INC-1234`).

---

## Ticket Connectors REST API

The ticket connectors API manages JIRA, GitHub, and ServiceNow integration credentials. Each connector stores platform-specific configuration and default values.

### CRUD Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/ticket-connectors` | List all connectors |
| `GET` | `/api/ticket-connectors/:id` | Get a single connector |
| `POST` | `/api/ticket-connectors` | Create / upsert a connector |
| `PUT` | `/api/ticket-connectors/:id` | Update a connector |
| `PATCH` | `/api/ticket-connectors/:id/toggle` | Toggle enabled/disabled |
| `DELETE` | `/api/ticket-connectors/:id` | Delete a connector |

### Platform-Specific Endpoints

#### JIRA

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ticket-connectors/jira/test` | Test JIRA connection (requires `baseUrl`, `email`, `apiToken`) |
| `GET` | `/api/ticket-connectors/jira/projects` | List JIRA projects for the configured connector |
| `GET` | `/api/ticket-connectors/jira/boards?project=KEY` | List JIRA boards filtered by project |
| `GET` | `/api/ticket-connectors/jira/issue-types?project=KEY` | List issue types for a project |
| `GET` | `/api/ticket-connectors/jira/assignable?project=KEY` | List assignable users for a project |
| `GET` | `/api/ticket-connectors/jira/users?q=...` | Search JIRA users by name/email |

#### GitHub

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ticket-connectors/github/test` | Test GitHub connection (requires `token`) |
| `GET` | `/api/ticket-connectors/github/repos` | List repositories for the configured token |
| `GET` | `/api/ticket-connectors/github/orgs` | List organizations for the authenticated user |
| `GET` | `/api/ticket-connectors/github/repos-by-owner?owner=X` | List repositories for a specific owner/org |
| `GET` | `/api/ticket-connectors/github/collaborators?owner=X&repo=Y` | List collaborators for a repo |

#### ServiceNow

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ticket-connectors/servicenow/test` | Test ServiceNow connection (requires `baseUrl`, `username`, `password`) |

---

## Sync Logs REST API

The sync logs API provides read-only access to the audit trail of all sync runs, plus cleanup endpoints.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/sync-logs` | List all sync logs (newest first, default limit 100, max 500) |
| `GET` | `/api/sync-logs/integration/:integrationId` | List sync logs for a specific integration |
| `GET` | `/api/sync-logs/:id` | Get a single sync log by ID |
| `DELETE` | `/api/sync-logs/integration/:integrationId` | Delete all sync logs for an integration |

### Query Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `limit` | `100` | Max records to return (capped at 500) |

### Example Requests

```bash
# List recent sync logs (default limit 100)
curl http://localhost:3001/api/sync-logs

# List with custom limit
curl http://localhost:3001/api/sync-logs?limit=20

# Logs for a specific integration
curl http://localhost:3001/api/sync-logs/integration/<integrationId>

# Get a single log entry
curl http://localhost:3001/api/sync-logs/<id>

# Delete all logs for an integration
curl -X DELETE http://localhost:3001/api/sync-logs/integration/<integrationId>
```

### Response Example

```json
{
  "success": true,
  "data": [
    {
      "id": "abc-123",
      "integrationId": "int-456",
      "trigger": "scheduled",
      "status": "success",
      "startedAt": "2025-01-15T02:00:00.000Z",
      "completedAt": "2025-01-15T02:00:03.542Z",
      "durationMs": 3542,
      "itemsFetched": 25,
      "itemsCreated": 25,
      "itemsUpdated": 0,
      "itemsDeleted": 18,
      "errors": 0,
      "errorDetails": null,
      "syncSchedule": "24h"
    }
  ]
}
```

---

## Scheduler REST API

The scheduler API provides operational control over the cron job scheduler.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scheduler/status` | Get scheduler status — active jobs, uptime, server time |
| `POST` | `/api/scheduler/stop` | Stop all scheduled cron jobs |
| `POST` | `/api/scheduler/restart` | Stop all jobs, then reload from DB and reschedule |

### Status Response Example

```json
{
  "success": true,
  "data": {
    "totalJobs": 3,
    "jobs": [
      {
        "integrationId": "int-456",
        "integrationName": "Production TLM",
        "schedule": "24h",
        "cronExpression": "0 2 * * *",
        "createdAt": "2025-01-15T00:00:00.000Z",
        "lastRunAt": "2025-01-15T02:00:00.000Z",
        "runCount": 5
      }
    ],
    "uptime": 86400,
    "serverTime": "2025-01-16T02:00:00.000Z"
  }
}
```

### Example Requests

```bash
# Check scheduler status
curl http://localhost:3001/api/scheduler/status

# Stop all scheduled jobs
curl -X POST http://localhost:3001/api/scheduler/stop

# Restart scheduler (reload from DB)
curl -X POST http://localhost:3001/api/scheduler/restart
```

---

*Back to [README](../README.md) · See also [Getting Started](getting-started.md) · [Database](database.md)*
