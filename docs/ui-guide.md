# UI Guide

> Navigation, pages, and feature walkthrough for the QuantumGuard frontend.

---

## Table of Contents

- [Application Layout](#ui-navigation--application-layout)
- [Dashboard Welcome Page](#dashboard-welcome-page)
- [Integrations Hub](#integrations-hub)
- [Discovery Pages](#discovery-pages)
- [Real Connectors](#real-connectors)
- [Cryptographic Policies](#cryptographic-policies)
- [Violations Page](#violations-page)
- [Ticket & Issue Tracking](#ticket--issue-tracking)
- [Quantum Safety Dashboard](#quantum-safety-dashboard)
- [Project Insight Panel](#project-insight-panel)
- [AI-Powered Suggested Fixes](#ai-powered-suggested-fixes)

---

## UI Navigation & Application Layout

The frontend is organized as a single-page application with a persistent sidebar and a main content area. All pages are accessible from the **Quantum Readiness Advisor** section in the sidebar.

### Sidebar Structure

```
digicert ONE
└─ Quantum Readiness Advisor
   ├─ Dashboard              — PQC readiness overview & risk score
   ├─ Inventory              — Full crypto-asset table with filters
   ├─ Visualize              — Dependency & algorithm graphs
   ├─ Violations             — Policy violations & compliance gaps
   ├─ Integrations           — Configure data sources (see below)
   ├─ Discovery              — Expandable parent with 5 child pages:
   │  ├─ Certificates        — TLS / PKI certificates (from DigiCert TLM)
   │  ├─ Endpoints           — Network TLS endpoints (from Network Scanner)
   │  ├─ Software            — Signing artifacts (from DigiCert STM)
   │  ├─ Devices             — IoT / OT devices (from DigiCert DTM)
   │  └─ BOM Imports         — CycloneDX BOM files (CBOM + SBOM + xBOM from CI/CD)
   ├─ Network Scanner        — Live TLS endpoint scanner
   ├─ Tracking               — Remediation ticket tracking (JIRA / GitHub / ServiceNow)
   ├─ Policies               — Crypto policy management (NIST SP 800-57 presets)
   └─ Settings               — Ticket connector configuration (JIRA / GitHub / ServiceNow)
```

Additional sidebar sections (below the main nav):
- **Private CA** — Private CA certificate quantum assessment
- **Trust Lifecycle** — (Coming Soon) End-to-end PQC migration workflows
- **Software Trust** — (Coming Soon) Software supply-chain crypto scanning
- **Device Trust** — IoT firmware crypto inventory
- **Document Trust** — Document-signing PQC migration

The Discovery parent item is **auto-expandable** — clicking it reveals 6 child navigation items and navigates to the first child. When any child page is active, the parent stays highlighted and expanded.

### Dashboard Welcome Page

When no CBOM is loaded, the Dashboard shows a **welcome page** with:

| Section | Description |
|---------|-------------|
| **Welcome banner** | Title, description, and guidance to get started |
| **Quick actions** | Upload a CBOM, scan a repository, or load sample data |
| **Uploaded CBOMs** | Table of previously uploaded CBOMs (persisted in the `cbom_uploads` DB table) |

The **Uploaded CBOMs** table shows:

| Column | Description |
|--------|-------------|
| **Component** | Top-level component name from the CBOM |
| **File Name** | Original uploaded file name |
| **Upload Date** | When the file was uploaded |
| **Crypto Assets** | Total cryptographic asset count |
| **Quantum-safe** | Count of quantum-safe assets (green badge) |
| **Not Safe** | Count of not-quantum-safe assets (red badge) |
| **Download** | Download the original CBOM JSON file |

Each row has a download button that fetches the CBOM file via `GET /api/cbom-uploads/:id`, decodes the base64 BLOB, and triggers a browser download.

---

## Integrations Hub

The **Integrations** page is the central configuration point for connecting external data sources to the crypto inventory. It provides a catalog-driven workflow for adding, configuring, and managing integrations.

All integration configurations are **persisted in MariaDB** via Sequelize ORM and accessed through the [Integrations REST API](api-reference.md#integrations-rest-api). The frontend uses **RTK Query** for automatic data fetching, caching, and cache invalidation — see [Architecture](architecture.md#frontend-state-management-rtk-query).

### Integration Catalog

Six pre-built integration templates are available:

| Integration | Vendor | Category | Description |
|-------------|--------|----------|-------------|
| **DigiCert Trust Lifecycle Manager** | DigiCert | `digicert` | Import certificates, keys, and endpoint data from TLM. Enables discovery of TLS certificates, CA hierarchies, and cryptographic posture across managed PKI. |
| **DigiCert Software Trust Manager** | DigiCert | `digicert` | Import code signing certificates, software hashes, and SBOM-linked crypto assets. Analyze signing algorithms across your software supply chain. |
| **DigiCert Device Trust Manager** | DigiCert | `digicert` | Import IoT device certificates and embedded crypto configurations. Track quantum readiness of device fleets and firmware crypto. |
| **Network TLS Scanner** | Built-in | `scanner` | Scan your network to discover TLS endpoints, cipher suites, certificate chains, and key exchange algorithms. |
| **CBOM File Import** | CycloneDX | `import` | Upload or link CycloneDX CBOM files from CI/CD pipelines, SBOM tools, or manual audits. |

### Configuration Workflow

Each integration follows a 4-step configuration flow inside a slide-out drawer:

```
┌──────────────────────────────────────────────────────────────┐
│  Step 1 — INTEGRATION NAME                                   │
│  User-friendly name for this integration instance            │
│  e.g., "Production TLM — US East"                            │
├──────────────────────────────────────────────────────────────┤
│  Step 2 — CONNECTION DETAILS                                 │
│  Type-specific fields (API URL, API Key, tokens, etc.)       │
│  Each template defines its own required/optional fields      │
├──────────────────────────────────────────────────────────────┤
│  Step 3 — IMPORT SCOPE (multi-select)                        │
│  Choose which data categories to pull from this source       │
│  Each integration has unique scope options (see below)       │
├──────────────────────────────────────────────────────────────┤
│  Step 4 — SYNC SCHEDULE                                      │
│  Manual only │ Every hour │ 6h │ 12h │ 24h                  │
└──────────────────────────────────────────────────────────────┘
```

The drawer also includes a **Test Connection** button that validates credentials before saving.

### Per-Integration Import Scopes

Each integration type has unique import scope options that reflect the actual data categories available from that source:

**DigiCert Trust Lifecycle Manager (TLM):**

| Scope | Description |
|-------|-------------|
| Certificates | TLS, CA, and private certificates from managed PKI |
| Endpoints | Hosts and IPs discovered via network & cloud scans |
| Keys | Key algorithms, strength, and lifecycle data |
| CA Hierarchies | Intermediate & root CA chain mappings |

**DigiCert Software Trust Manager (STM):**

| Scope | Description |
|-------|-------------|
| Signing Certificates | Code signing & timestamping certificates |
| Keypairs | Signing key pairs and algorithm metadata |
| Releases | Software release windows and signing audit trails |
| Threat Detection | Vulnerability and threat scan results |

**DigiCert Device Trust Manager (DTM):**

| Scope | Description |
|-------|-------------|
| Device Certificates | IoT/OT device identity certificates |
| Devices | Device records, enrollment status, and profiles |
| Firmware | Firmware versions and signing verification data |
| Device Groups | Logical groupings and enrollment profiles |

**Network TLS Scanner:**

| Scope | Description |
|-------|-------------|
| Endpoints | TLS-enabled hosts, IPs, and port configurations |
| Certificates | Certificate chains extracted from TLS handshakes |
| Cipher Suites | Supported cipher suites per endpoint |
| Key Exchange | KEX algorithms (ECDHE, X25519, ML-KEM, etc.) |

**CBOM File Import:**

| Scope | Description |
|-------|-------------|
| Crypto Components | Algorithms, protocols, and crypto primitives from CBOM |
| Certificates | Certificates referenced in the CBOM |
| Keys | Key material and parameters in the CBOM |
| Dependencies | Crypto library dependencies and versions |
| SBOM (optional) | Full SBOM JSON stored as BLOB — fetched from pipeline artifacts when `includeSbom` is enabled |
| xBOM (optional) | Full xBOM JSON stored as BLOB — fetched from pipeline artifacts when `includeXbom` is enabled |

### Integration Card States

Once configured, each integration appears as a card on the Integrations page showing:
- **Status badge** — Connected / Disconnected / Error / Syncing
- **Enabled toggle** — Enable or disable the integration without deleting it
- **Last sync timestamp** — When data was last pulled
- **Quick actions** — Edit, Sync Now, Delete

### Stats Row

The page header displays aggregate statistics:
- Total integrations configured
- Active (connected & enabled) count
- Errored integrations
- Last sync time across all integrations

---

## Discovery Pages

The **Discovery** section contains 6 specialized pages, each showing cryptographic assets discovered from a specific integration source. Every page follows the same pattern: an **empty state** with guided setup steps when no data is loaded, and a rich data table once assets are available.

### Page Architecture

Each discovery page provides:

| Component | Description |
|-----------|-------------|
| **Header** | Breadcrumb (`Discovery`) + page title + contextual subtitle |
| **Stat Cards** | Quick metrics — total count, quantum-safe %, key algorithm breakdown |
| **Toolbar** | Search bar, export options, filter controls |
| **Data Table** | Sortable, filterable table with type-specific columns |
| **AI Banner** | Contextual AI insight banner (when data is loaded) |
| **Empty State** | Integration setup guide with step-by-step instructions |

### Empty State → Integration Flow

When no data has been imported, each discovery page shows an **EmptyState** component with:

1. An illustration and message explaining the data source
2. **Step-by-step integration instructions** specific to that page:
   - Navigate to Integrations page
   - Locate the relevant catalog template
   - Configure connection credentials
   - Select import scope
   - Run initial sync
3. A **"Load Sample Data"** button to populate the page with demo data for exploration

### Discovery Tabs

| Page | Source Integration | Key Columns | Description |
|------|-------------------|-------------|-------------|
| **Certificates** | DigiCert TLM | Common Name, CA Vendor, Status, Key Algorithm, Key Length, Quantum Safe | TLS / PKI certificates — algorithm inventory, expiry tracking, PQC-readiness |
| **Endpoints** | Network Scanner | Hostname, IP, Port, TLS Version, Cipher Suite, Key Agreement, Quantum Safe | Network endpoints — TLS config, cipher suites, key-agreement protocols |
| **Software** | DigiCert STM | Name, Version, Vendor, Signing Algorithm, Key Length, Hash, Quantum Safe | Software releases — signing algorithm and PQC migration status |
| **Devices** | DigiCert DTM | Device Name, Type, Manufacturer, Firmware, Cert Algorithm, Key Length, Enrollment | IoT devices — firmware crypto, certificate enrollment, key-strength audit |
| **BOM Imports** | CBOM File Import | Component Name, Type, Algorithm, Version, Quantum Safe, Spec Version, BOMs (CBOM/SBOM/xBOM) | CycloneDX BOM contents — crypto component inventory, PQC breakdown, and multi-BOM availability indicators |

### Integration → Discovery Data Flow

```
┌─────────────────────┐     ┌─────────────────────┐     ┌──────────────────────┐
│   Integrations Hub  │────▶│   Sync / Import     │────▶│   Discovery Pages    │
│                     │     │                     │     │                      │
│  Configure sources  │     │  Pull data from     │     │  View, search, and   │
│  Set import scopes  │     │  external APIs or   │     │  analyze discovered  │
│  Schedule syncs     │     │  file imports       │     │  crypto assets       │
└─────────────────────┘     └─────────────────────┘     └──────────────────────┘
```

Each integration type feeds into its corresponding Discovery page:
- **DigiCert TLM** → Certificates page
- **Network TLS Scanner** → Endpoints page
- **DigiCert STM** → Software page
- **DigiCert DTM** → Devices page
- **CBOM File Import** → BOM Imports page (with xBOM Analysis sub-tab)

### Policy Violations in Discovery Tabs

The **Certificates**, **Endpoints**, **Devices**, and **CBOM Imports** tabs each include a **Policies Violated** column. This column evaluates every row against all active cryptographic policies and shows the count of violated policies. A red violation badge links to the details.

Each tab also adds a **Policy Violations** stat card in the header, showing the total number of items that fail at least one policy.

The evaluation is asset-type-aware:
- **CBOM Imports** — only `cbom-component`-scoped rules apply
- **Certificates** — `certificate` and `cbom-component` rules apply
- **Endpoints** — `endpoint` and `cbom-component` rules apply
- **Devices** — `device`, `certificate`, and `cbom-component` rules apply (devices carry certificate info)

### Export CSV

All five Discovery tabs support **Export to CSV** via the toolbar Export button. Clicking Export generates a date-stamped CSV file containing all rows currently in the table. The export uses a shared utility (`exportTableToCSV`) in `frontend/src/pages/discovery/utils/exportCsv.ts` that:

- Accepts a generic row array, column definitions, and a filename prefix
- Generates a CSV with headers from column labels
- Downloads the file as `<prefix>_YYYY-MM-DD.csv`

### Actions Dropdown (BOM Imports)

The **BOM Imports** tab Actions column uses a compact **dropdown menu** (triggered by a vertical ellipsis icon) instead of inline download buttons. The dropdown shows up to three color-coded items:

| Item | Color | Shown When |
|------|-------|------------|
| **Download CBOM** | Purple | CBOM file exists |
| **Download SBOM** | Blue | SBOM file exists |
| **Download xBOM** | Amber | xBOM file exists |

Clicking the icon opens the dropdown; clicking outside or selecting an item closes it.

### AI Migration Suggestions in Discovery Tabs

The **Certificates**, **Endpoints**, and **Devices** tabs each include an **AI Fix** button on rows that are not quantum-safe. Clicking the button calls `POST /api/ai-suggest` with the row's algorithm details and opens an inline expandable panel showing:

- **Loading state** — spinner with "Generating AI migration suggestion…"
- **Error state** — error message with retry option
- **Success state** — replacement algorithm, migration steps, estimated effort, and code snippet

Each expanded AI suggestion panel includes a **close button** (✕ icon) to dismiss the panel without scrolling.

### Sync Button UX

When a sync is in progress, the integration card's **Sync Now** button shows a spinning refresh icon and is disabled until the API call completes (including a 3.5 s cooldown). This prevents double-clicks and gives clear visual feedback.

### Catalog Type Filtering

When an integration type tile is selected in the "Available Integration Types" row and the user clicks the **"+ Add Integration"** button beneath it, the catalog modal shows only templates of that type. The header-level **"+ Add Integration"** button always shows all types.

---

## Real Connectors

While the `CONNECTOR_REGISTRY` in `connectors.ts` contains simulated fallback connectors, three integration types have **real production connectors** that talk to external APIs.

### DigiCert Trust Lifecycle Manager

**File:** `backend/src/services/digicertTlmConnector.ts`

Fetches certificate data from the **DigiCert ONE REST API** and maps it to the normalised `Certificate` model.

#### Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `apiBaseUrl` | Yes | DigiCert ONE base URL (e.g. `https://one.digicert.com`) |
| `apiKey` | Yes | DigiCert ONE API key |
| `accountId` | No | Account ID filter |
| `divisionId` | No | Restrict to a specific division |
| `allowInsecureTls` | No | `"true"` to accept self-signed / internal CA certs |
| `apiPath` | No | Override the certificate list endpoint path |

#### Endpoint Auto-Detection

The connector tries multiple well-known DigiCert ONE API paths in fallback order:

| Priority | Path | Method | Notes |
|----------|------|--------|-------|
| 1 | `mpki/api/v1/certificate/search` | POST | MPKI micro-service (preferred) |
| 2 | `em/api/v1/certificate/search` | POST | Enterprise Manager |
| 3 | `tlm/api/v1/certificate/search` | POST | TLM micro-service |
| 4 | `mpki/api/v1/certificate` | GET | Classic MPKI collection |
| 5 | `em/api/v1/certificate` | GET | Classic EM collection |
| 6 | `tlm/api/v1/certificate` | GET | Classic TLM collection |
| 7 | `certcentral/api/v1/certificate` | GET | CertCentral v1 |
| 8 | `services/v2/order/certificate` | GET | CertCentral v2 |

The first path that returns a 200 is cached for subsequent pages. POST endpoints use `{ offset, limit }` JSON body; GET endpoints use query string pagination.

If an explicit `apiPath` is configured and ends with `/search`, POST is used automatically.

#### Features

- **Pagination** — fetches up to 5 000 certificates (100 per page, max 50 pages)
- **Test Connection** — validates the API key and base URL before saving
- **TLS bypass** — `allowInsecureTls: "true"` for on-prem deployments with internal CA certs
- **Certificate normalisation** — maps DigiCert fields (`common_name`, `key_type`, `key_size`, `status`, `valid_till`, `serial_number`, `signature_hash`) to the standard `Certificate` model with PQC safety classification

### GitHub CBOM Connector

**File:** `backend/src/services/githubCbomConnector.ts`

Fetches CBOM artifacts from **GitHub Actions workflow runs**, extracts the JSON, and analyses the cryptographic components.

#### Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `githubRepo` | Yes | Repository in `owner/repo` format |
| `githubToken` | Yes | GitHub PAT with `actions:read` scope |
| `artifactName` | No | CBOM artifact name to look for (default: `cbom-report`) |
| `workflowFile` | No | Filter to a specific workflow file (e.g. `pipeline.yml`) |
| `branch` | No | Filter to a specific branch |
| `includeSbom` | No | `"true"` to also download the SBOM artifact from the same workflow run |
| `includeXbom` | No | `"true"` to also download the xBOM artifact from the same workflow run |
| `sbomArtifactName` | No | SBOM artifact name (default: matches any artifact containing `sbom`) |
| `xbomArtifactName` | No | xBOM artifact name (default: matches any artifact containing `xbom`) |

#### Sync Flow

```
1.  List workflow runs  →  GET /repos/{owner}/{repo}/actions/runs
2.  Filter successful   →  conclusion === 'success'
3.  List artifacts      →  GET /repos/{owner}/{repo}/actions/runs/{id}/artifacts
4.  Match CBOM artifact →  artifact.name contains 'cbom-report'
5.  Download CBOM ZIP   →  GET {archive_download_url} (follows 302 redirect)
6.  Extract CBOM JSON   →  Unzip → find *.json → parse CycloneDX
7.  Match SBOM artifact →  artifact.name contains 'sbom' (if available)
8.  Download SBOM ZIP   →  Same ZIP extraction flow
9.  Match xBOM artifact →  artifact.name contains 'xbom' (if available)
10. Download xBOM ZIP   →  Same ZIP extraction flow
11. Analyse CBOM        →  Count crypto components, quantum-safe breakdown
12. Store record        →  Insert into cbom_imports (cbomFile + sbomFile + xbomFile BLOBs)
13. Load xBOM store     →  Populate in-memory xBOM store from newly imported xBOM files
```

#### Features

- **Multi-BOM sync** — downloads CBOM, SBOM, and xBOM artifacts from the same workflow run and stores all three as BLOBs in a single `cbom_imports` record
- **Incremental sync** — only fetches runs completed after the integration's `lastSync` timestamp
- **Per-record insert** — inserts each import record individually to avoid MariaDB `max_allowed_packet` limits with large BLOB payloads
- **ZIP extraction** — handles GitHub's artifact ZIP format using Central Directory parsing for reliable size info
- **Redirect handling** — follows 302 redirect to Azure Blob storage without leaking the auth header
- **Per-CBOM analysis** — counts total components, crypto components, quantum-safe vs. not-safe
- **xBOM auto-loading** — after sync, any imported xBOM files are automatically loaded into the in-memory xBOM store so they appear in the xBOM Analysis tab

### Network TLS Connector

**File:** `backend/src/services/networkTlsConnector.ts`

Performs real TLS handshakes against user-configured targets and extracts cipher suite, key agreement, and certificate information.

#### Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `targets` | Yes | Comma-separated hosts, IPs, or CIDR ranges (e.g. `google.com, 10.0.0.1, 192.168.1.0/24`) |
| `ports` | Yes | Comma-separated ports to probe (e.g. `443, 8443, 636`) |
| `concurrency` | No | Max parallel connections (default: 10) |
| `timeout` | No | Per-connection timeout in seconds (default: 10) |

#### Features

- **CIDR expansion** — `/24` to `/32` ranges (max 256 IPs per range)
- **DNS resolution** — resolves hostnames to IPs for the `ipAddress` field
- **Concurrency control** — parallel scans with configurable limit
- **TLS version & cipher extraction** — uses Node.js `tls.connect()` to negotiate and inspect the connection
- **Quantum-safety classification** — marks endpoints with PQC key exchange (ML-KEM, X25519Kyber768) as quantum-safe

---

## Cryptographic Policies

The **Policies** page provides a rule-based engine for defining and enforcing cryptographic compliance requirements. Policies are evaluated against all crypto assets — CBOM components, certificates, endpoints, and devices — with violations surfaced across the application.

### Policy Structure

Each policy consists of:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Human-readable policy name |
| `description` | `string` | Detailed description with NIST reference |
| `severity` | `High \| Medium \| Low` | Impact level |
| `status` | `active \| draft` | Only `active` policies are evaluated |
| `operator` | `AND \| OR` | How multiple rules combine |
| `rules` | `PolicyRule[]` | Array of rule conditions |

### Policy Rules

Each rule defines a condition on a specific asset type and field:

| Property | Options |
|----------|---------|
| **Asset** | `certificate`, `endpoint`, `software`, `device`, `cbom-component` |
| **Field** | `keyAlgorithm`, `keyLength`, `signatureAlgorithm`, `tlsVersion`, `cipherSuite`, `hashFunction`, `quantumSafe`, `expiryDays`, `protocol` |
| **Condition** | `equals`, `not-equals`, `greater-than`, `less-than`, `contains`, `not-contains`, `in`, `not-in` |
| **Value** | The expected value (e.g. `RSA`, `2047`, `true`, `TLS 1.0, TLS 1.1`) |

### Preset Policies (NIST SP 800-57)

Ten NIST-aligned preset policies are available and auto-seeded on first visit:

| Preset | Severity | Description |
|--------|----------|-------------|
| **TLS 1.3 Requirement** | High | All endpoints must support TLS 1.3+ (SP 800-52 Rev 2) |
| **Minimum RSA Key Size** | High | RSA keys ≥ 2048 bits (SP 800-57 Table 2) |
| **No SHA-1 Usage** | High | SHA-1 prohibited (SP 800-131A Rev 2) |
| **PQC Readiness** | Medium | All CBOM components must be quantum-safe (FIPS 203/204/205) |
| **No Deprecated Algorithms** | High | DES, 3DES, RC4, MD5 not allowed |
| **Minimum ECC Key Size** | High | ECC keys ≥ 256 bits (P-256+) |
| **Minimum AES Key Size** | Medium | AES keys ≥ 128 bits |
| **Approved Hash Functions** | High | Only SHA-256/384/512 and SHA3 variants |
| **Certificate Max Lifetime** | Medium | Certificates ≤ 90 days (CA/Browser Forum) |
| **CNSA 2.0 Compliance** | High | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384+ |

### Evaluation Engine

The evaluation engine (`evaluator.ts`) uses **prerequisite-aware AND evaluation**:

1. **Prerequisite rules** (equals, contains, in) act as filters — if a prerequisite doesn't match an asset, the policy simply doesn't apply to it
2. **Constraint rules** (greater-than, less-than, not-equals, etc.) are checked only when all prerequisites match
3. A constraint failure = **violation**

This prevents spurious violations (e.g. "RSA key must be ≥ 2048 bits" won't flag ECDSA keys).

#### Cross-Asset Evaluation

| Evaluator | Function | Applicable Rule Assets |
|-----------|----------|------------------------|
| `evaluatePolicies()` | CBOM components | `cbom-component` only |
| `evaluateCertificatePolicies()` | Discovery certificates | `certificate`, `cbom-component` |
| `evaluateEndpointPolicies()` | Discovery endpoints | `endpoint`, `cbom-component` |
| `evaluateDevicePolicies()` | Discovery devices | `device`, `certificate`, `cbom-component` |
| `evaluateSingleAssetPolicies()` | Single crypto asset | `cbom-component` |

Policies are persisted in MariaDB and managed via the [Policies REST API](api-reference.md#policies-rest-api).

### Policies Page UI

- **Stats** — total policies, active count, draft count
- **Filtering** — by name, description, severity, status
- **Sorting** — by name, description, severity, status (ascending/descending)
- **Create Policy** — modal with preset selection or custom rule builder
- **Toggle Status** — switch between `active` and `draft`
- **Delete** — remove individual policies

---

## Violations Page

The **Violations** page filters the loaded CBOM to show only cryptographic assets that are **not quantum-safe** or **conditional**, providing a focused remediation view.

### Stat Cards

| Card | Color | Description |
|------|-------|-------------|
| **Not Quantum Safe** | Red | Assets that require immediate migration |
| **Conditional** | Amber | Assets whose safety depends on parameters |
| **Total At Risk** | — | Combined count of not-safe + conditional |

The asset table below uses the same `AssetListView` component as the Inventory page, including AI Suggested Fix, PQC verdict, and the ability to create remediation tickets.

---

## Ticket & Issue Tracking

The application includes a full **remediation ticket management** system that integrates with three external platforms: **JIRA**, **GitHub Issues**, and **ServiceNow**.

### Architecture

```
┌───────────────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
│   Discovery Tables    │────▶│  CreateTicketModal    │────▶│   External Platform   │
│   + CBOM Asset View   │     │  (JIRA/GitHub/SNow)  │     │   API                 │
│                       │     │                      │     │                       │
│  "Create Ticket" btn  │     │  Pre-filled form:    │     │  • JIRA Cloud REST    │
│  on every row with    │     │  title, description,  │     │  • GitHub Issues API  │
│  policy violations    │     │  priority, assignee   │     │  • ServiceNow Table   │
└───────────────────────┘     └──────┬───────────────┘     └───────────────────────┘
                                     │
                                     ▼
                              ┌──────────────────────┐
                              │   Tickets Table (DB)  │
                              │   + Tracking Page UI  │
                              └──────────────────────┘
```

### Ticket Connectors (Settings Page)

Before creating tickets, configure connectors on the **Settings** page (`/settings`). Each connector stores credentials and default values.

#### JIRA Connector

| Field | Description |
|-------|-------------|
| Base URL | Atlassian Cloud URL (e.g. `https://your-org.atlassian.net`) |
| Email | Atlassian account email |
| API Token | JIRA API token ([generate here](https://id.atlassian.com/manage/api-tokens)) |
| Default Project | Project key for new issues (cascade-loaded from JIRA) |
| Default Issue Type | Issue type (e.g. Bug, Task — cascade-loaded per project) |
| Default Assignee | Assignable user (cascade-loaded per project, displayed by name) |

JIRA fields use **SearchableSelect** dropdowns that load data from your JIRA instance in real-time:
- Select project → loads issue types + assignable users for that project
- Assignees show display names, store account IDs

#### GitHub Connector

| Field | Description |
|-------|-------------|
| Personal Access Token | GitHub PAT with `repo` scope |
| Default Owner/Org | GitHub org or user (cascade: select org → loads repos) |
| Default Repository | Repository for issues (cascade-loaded per owner) |
| Default Assignee | Collaborator (cascade-loaded per repo) |
| Default Labels | Labels to apply (e.g. `cryptography, security`) |

GitHub fields use **cascade dropdowns**: select org → repos load → select repo → collaborators load.

#### ServiceNow Connector

| Field | Description |
|-------|-------------|
| Instance URL | ServiceNow instance (e.g. `https://your-org.service-now.com`) |
| Username | ServiceNow username |
| Password | ServiceNow password |
| Default Category | Incident category (e.g. `Security`) |
| Default Subcategory | Incident subcategory (e.g. `Cryptography`) |
| Default Impact | Impact level |
| Default Assignment Group | Team to assign incidents to |

Each connector has a **Test Connection** button and a **View / Edit** mode toggle.

### CreateTicketModal

The ticket creation modal appears from:
- **Discovery tabs** (Certificates, Endpoints, Software, Devices) — on rows with policy violations
- **CBOM Asset View** (Inventory) — on individual crypto assets

The modal workflow:
1. **Select platform** — choose JIRA, GitHub, or ServiceNow (cards are only shown if a connector is configured and enabled)
2. **Fill form** — auto-populated with context:
   - Title: `"{Severity} Risk: Non-quantum-safe {entityType} for {entityName}"`
   - Description: problem statement + file location as clickable GitHub link (if repo/branch available)
   - Priority: derived from severity
   - Platform-specific fields pre-filled from connector defaults
3. **AI Suggestion** — optional AI-generated remediation text appended to description
4. **Submit** — creates ticket via the external API and stores it locally

#### CBOM-Specific Enhancements

When creating a ticket from the CBOM tab:
- **GitHub repo and branch** are pre-populated from the CBOM import metadata
- **File location** is rendered as a clickable GitHub link (`https://github.com/{owner}/{repo}/blob/{branch}/{path}#L{line}`)
- **GitHub Issues** card is available; other tabs only show JIRA and ServiceNow

### Tracking Page

The **Tracking** page (`/tracking`) shows all created remediation tickets in a filterable table.

#### Stat Cards

| Card | Description |
|------|-------------|
| **Total Tickets** | All tickets across all platforms |
| **Completed** | Tickets marked as Done |
| **In Progress** | Tickets being worked on |
| **Pending** | Tickets with status To Do, Open, or New |
| **Blocked** | Tickets that are blocked |
| **High Priority** | Critical + High priority tickets |

#### Table Columns

| Column | Description |
|--------|-------------|
| Ticket ID | Platform-specific ID (clickable link to external URL) |
| Type | JIRA / GitHub / ServiceNow badge |
| Title | Ticket title |
| Status | To Do, In Progress, Done, Blocked, Open, New |
| Priority | Critical, High, Medium, Low |
| Entity Type | Certificate, Endpoint, Application, Device, Software |
| Entity Name | Name of the affected asset |
| Assignee | Assigned person |
| Created | Timestamp |

#### Filters

Search by title, ticket ID, entity name, or assignee. Filter by status, priority, entity type, or ticket platform.

---

## Quantum Safety Dashboard

The asset list includes a **Quantum Safety** column that provides at-a-glance risk classification with interactive filtering.

### Color-Coded Safety Badges

Each crypto asset displays a labeled badge in the **Quantum Safety** column:

| Badge | Color | Meaning |
|-------|-------|---------|
| **Not Safe** | Red | Vulnerable to quantum attack (RSA, ECDSA, DH, etc.) |
| **Conditional** | Cyan | Safety depends on parameters — check PQC verdict |
| **Safe** | Green | Post-quantum safe (AES-256, ML-KEM, ML-DSA, etc.) |
| **Unknown** | Gray | Insufficient data to classify |

### Filter Chips

Above the asset table, clickable **filter chips** let you focus on specific risk categories:

- **Not Safe (12)** — red chip with live count
- **Conditional (5)** — cyan chip with live count
- **Safe (8)** — green chip with live count
- **Unknown (0)** — gray chip with live count

Click a chip to show only those assets. Click again to clear the filter. The text search also matches safety labels (e.g., typing "not safe" filters to at-risk assets).

### Sorting

The Quantum Safety column is **sortable by risk priority**: Not Safe → Conditional → Unknown → Safe. This puts the most urgent items at the top.

### Location Column Enhancements

For assets discovered via **dependency scanning**, the Location column displays:
- **Provider library name** (e.g., `BouncyCastle bcprov-jdk18on`) with an amber package icon
- **Manifest file path** below (e.g., `pom.xml:45`)

This makes it clear which third-party library introduced each crypto asset.

---

## Project Insight Panel

The **Project Insight** button (bar-chart icon) in the toolbar generates a high-level PQC migration risk assessment for all loaded crypto assets.

### How It Works

1. Click the **Project Insight** button in the dashboard toolbar
2. The frontend aggregates asset statistics (total, not-safe, conditional, safe, unknown)
3. Calls `POST /api/ai-summary` with the asset list and stats
4. Displays a gradient insight panel between the filter chips and the asset table

### Insight Panel Contents

| Section | Description |
|---------|-------------|
| **Risk Score** | 0–100 progress bar (0 = fully PQC-ready, 100 = critical risk). Color-coded: green ≤ 30, amber ≤ 60, red > 60 |
| **Headline** | One-line risk summary (e.g., *"High Risk — 67% of crypto assets need migration"*) |
| **Summary** | 2–3 sentence executive overview of the project's PQC posture |
| **Prioritized Actions** | Ranked list of migration tasks, each with **Impact** (High/Medium/Low) and **Effort** (Low/Medium/High) ratings |
| **Migration Estimate** | Human-readable time estimate for full PQC migration |

### Risk Scoring (Fallback Engine)

When AWS Bedrock is not configured, the deterministic fallback engine calculates risk:

```
riskScore = (notSafeRatio × 80) + (conditionalRatio × 40) + (unknownRatio × 20)
```

- > 60% not-safe → "Critical Risk"
- > 30% not-safe → "High Risk"
- > 50% conditional → "Moderate Risk"
- All safe → "PQC Ready"

The panel can be dismissed with the **×** button and re-generated at any time.

---

## AI-Powered Suggested Fixes

Each crypto asset in the dashboard has an **AI Suggested Fix** column powered by AWS Bedrock (Claude 3 Sonnet). It provides:
- PQC-safe replacement algorithm
- Migration code snippet
- Step-by-step migration instructions
- Estimated effort level

### Availability

AI Suggested Fix is available in:
- **CBOM Analyzer dashboard** — AI Suggested Fix column in the asset table
- **Discovery → Certificates** — AI Fix button on non-quantum-safe rows
- **Discovery → Endpoints** — AI Fix button on non-quantum-safe rows
- **Discovery → Devices** — AI Fix button on non-quantum-safe rows

In the Discovery tabs, clicking the AI Fix button expands an inline panel below the row with the migration suggestion. Each panel includes a **close button** (✕) to dismiss it.

### Requirements

Set your AWS Bedrock credentials in `.env`:

```bash
AWS_BEARER_TOKEN_BEDROCK=your-bedrock-bearer-token
VITE_BEDROCK_API_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com
```

If AWS credentials are not configured, a **static fallback** provides sensible suggestions for 6 common categories (hash functions, symmetric ciphers, key exchange, digital signatures, key derivation, random number generation).

---

*Back to [README](../README.md) · See also [API Reference](api-reference.md) · [Architecture](architecture.md)*
