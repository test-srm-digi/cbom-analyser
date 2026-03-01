# xBOM — Unified Software + Cryptographic Bill of Materials

> Merge SBOM + CBOM into a single CycloneDX document with cross-references, vulnerability tracking, and quantum readiness analysis.

---

## Table of Contents

- [Concept](#concept)
- [Architecture](#architecture)
- [Cross-Reference Linking](#cross-reference-linking-strategies)
- [REST API](#rest-api)
- [Frontend Pages](#frontend-pages)
- [RTK Query Hooks](#rtk-query-hooks)
- [Unified Pipeline](#unified-pipeline)
- [Trivy Integration](#trivy-integration)
- [xBOM DB Loader](#xbom-db-loader)
- [File Reference](#file-reference)

---

## Concept

**xBOM** merges a **Software Bill of Materials (SBOM)** with a **Cryptographic Bill of Materials (CBOM)** into a single CycloneDX document. This unified view links every software dependency to the cryptographic algorithms it uses, providing complete visibility into both supply-chain vulnerabilities and quantum readiness in one artefact.

| Layer | Source | Content |
|-------|--------|---------|
| **SBOM** | [Trivy](https://github.com/aquasecurity/trivy) (Aqua Security) | Packages, licenses, CVEs |
| **CBOM** | CBOM Analyser (this project) | Algorithms, protocols, keys, certificates |
| **Cross-references** | Merge engine | Links between software components and crypto assets |

---

## Architecture

```
Repository/directory
     │
     ├── Trivy scan ──► SBOM (CycloneDX JSON)
     │                         │
     ├── CBOM Analyser ──► CBOM (CycloneDX JSON)
     │                         │
     └───────┬─────────────────┘
             ▼
      xBOM Merge Service
             │
             ▼
      xBOM (unified CycloneDX)
        ├── components[]          (software packages)
        ├── cryptoAssets[]        (crypto primitives)
        ├── vulnerabilities[]     (CVEs from Trivy)
        ├── crossReferences[]     (software ↔ crypto links)
        └── thirdPartyLibraries[] (crypto-aware deps)
```

---

## Cross-Reference Linking Strategies

The merge engine builds relational links between SBOM components and CBOM crypto assets using three strategies:

| Strategy | Key | How it works |
|----------|-----|-------------|
| **Dependency Manifest** | `dependency-manifest` | Matches CBOM third-party library PURLs against SBOM component PURLs |
| **File Co-location** | `file-co-location` | When a crypto asset's source file path falls inside a component's directory |
| **Dependency Graph** | `dependency-graph` | CBOM dependency refs that match SBOM component bom-refs |

---

## REST API

All endpoints are mounted at `/api/xbom`.

### GET `/api/xbom/status`

Check Trivy availability and xBOM service health.

**Response:**
```json
{
  "success": true,
  "trivyInstalled": true,
  "trivyVersion": "0.58.0",
  "storedXBOMs": 3,
  "capabilities": {
    "sbomGeneration": true,
    "cbomGeneration": true,
    "xbomMerge": true
  }
}
```

### POST `/api/xbom/generate`

Generate an xBOM by scanning a local repository/directory. Runs Trivy for SBOM + CBOM Analyser for CBOM, then merges.

**Request body:**
```json
{
  "repoPath": "/path/to/repo",
  "mode": "full",
  "repoUrl": "https://github.com/owner/repo",
  "branch": "main",
  "excludePatterns": ["node_modules", "vendor"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repoPath` | string | Yes | Path to local repository or directory |
| `mode` | string | No | `full` (default), `sbom-only`, or `cbom-only` |
| `sbomJson` | string | No | Pre-supplied SBOM JSON (skip Trivy) |
| `cbomJson` | string | No | Pre-supplied CBOM JSON (skip scanner) |
| `repoUrl` | string | No | Repository URL for metadata |
| `branch` | string | No | Branch name for metadata |
| `excludePatterns` | string[] | No | Glob patterns to exclude |

**Response:** `{ success, message, xbom, analytics }`

### POST `/api/xbom/merge`

Merge pre-existing SBOM + CBOM documents. Accepts JSON body or multipart file upload (fields: `sbomFile`, `cbomFile`).

**JSON body:**
```json
{
  "sbom": { "bomFormat": "CycloneDX", "components": ["..."] },
  "cbom": { "bomFormat": "CycloneDX", "cryptoAssets": ["..."] },
  "repoUrl": "https://github.com/owner/repo"
}
```

**Response:** `{ success, message, xbom, analytics }`

### GET `/api/xbom/list`

List stored xBOMs with summary metadata.

**Response:**
```json
{
  "success": true,
  "xboms": [
    {
      "id": "abc123",
      "component": "my-app",
      "timestamp": "2025-01-15T10:30:00Z",
      "softwareComponents": 142,
      "cryptoAssets": 23,
      "vulnerabilities": 7,
      "crossReferences": 15
    }
  ]
}
```

### GET `/api/xbom/:id`

Retrieve a specific xBOM with computed analytics (quantum readiness, compliance, vulnerability summary).

**Response:** `{ success, xbom, analytics }`

### GET `/api/xbom/:id/download`

Download the xBOM as a JSON file (`Content-Disposition: attachment`).

### DELETE `/api/xbom/:id`

Delete a stored xBOM.

---

## Frontend Pages

xBOMs are accessible from **two locations** in the UI:

### A. Tools → xBOM Page

The standalone xBOM page provides:

| View | Description |
|------|-------------|
| **Status cards** | Trivy availability, stored xBOM count, SBOM/CBOM capability status |
| **Generate form** | Scan a local repo path; select mode (full / SBOM-only / CBOM-only) |
| **Merge form** | Paste or upload existing SBOM + CBOM JSON files to merge |
| **Stored xBOMs list** | Table of previously generated xBOMs with view/delete actions |

### B. Discovery → BOM Imports → xBOM Analysis Tab

The **BOM Imports** page includes an **xBOM Analysis** sub-tab that shows all stored xBOMs (including those automatically imported from GitHub Actions pipeline artifacts). This tab provides:

| Feature | Description |
|---------|-------------|
| **Stored xBOMs table** | Component name, timestamp, software component count, crypto asset count, vulnerability count, cross-reference count |
| **Inline detail view** | Click any xBOM row to expand an inline detail panel (no page navigation) |
| **Delete** | Remove individual xBOMs from the store |
| **Pagination** | Paginated table with configurable page size |

The xBOM list is populated from:
1. **GitHub Actions sync** — xBOM artifacts imported via the CBOM File Import connector are automatically loaded into the in-memory store
2. **Manual generation** — xBOMs created via the Tools → xBOM page
3. **Server startup** — previously stored xBOMs are loaded from the DB on boot via `xbomDbLoader`

### Detail View Tabs

Clicking an xBOM (in either page) opens the **Detail View** with five tabs:

| Tab | Content |
|-----|---------|
| **Overview** | Summary cards, quantum readiness scores, vulnerability breakdown |
| **Software** | Table of all SBOM components (name, version, type, PURL, licenses) |
| **Crypto Assets** | Table of all CBOM crypto assets (algorithm, primitive, quantum safety, source file) |
| **Vulnerabilities** | CVEs from Trivy with severity, score, description, recommendation |
| **Cross-References** | Relational links between software and crypto, grouped by link method |

---

## RTK Query Hooks

```typescript
import {
  useGetXBOMStatusQuery,
  useGenerateXBOMMutation,
  useMergeXBOMMutation,
  useGetXBOMListQuery,
  useGetXBOMQuery,
  useDeleteXBOMMutation,
} from './store/api';
```

See [Architecture — xBOM API Hooks](architecture.md#xbom-api-hooks) for the full hook reference table.

---

## Unified Pipeline

The unified pipeline (`.github/workflows/pipeline.yml`) automates CBOM, SBOM, and xBOM generation in CI.

```yaml
name: Pipeline
on:
  push:
    branches: [main, master, develop, X-bom]
  pull_request:
    branches: [main, master]
  release:
    types: [created]
  workflow_dispatch:
```

### Jobs & Artifacts

| Job | Produces | Description |
|-----|----------|-------------|
| `cbom-scan` | `cbom-report` | Runs CBOM Analyser action → `cbom-report.json` |
| `sbom-scan` | `sbom-report` | Runs Trivy SBOM scan → `sbom.json` |
| `xbom-merge` | `xbom-report` | Merges SBOM + CBOM → `xbom.json` with cross-references and analytics |
| `build-backend` | — | Builds backend Docker image |
| `build-frontend` | — | Builds frontend Docker image |
| `deploy` | — | Deploys to production (on release) |

### xBOM Merge Step Details

1. **Downloads** both `sbom-report` and `cbom-report` artifacts
2. **Merges** software components, crypto assets, dependencies, vulnerabilities
3. **Builds cross-references** by matching CBOM third-party library PURLs against SBOM component PURLs
4. **Computes analytics** — quantum readiness score, vulnerability breakdown, component counts
5. **Writes** `xbom.json` and uploads as `xbom-report` artifact

**Key outputs:** `total-components`, `total-crypto-assets`, `total-vulnerabilities`, `total-cross-references`, `readiness-score`, `quantum-safe`, `not-quantum-safe`, `vuln-critical`, `vuln-high`

### Auto-Sync to BOM Imports

When a **CBOM File Import** integration is configured with `includeSbom: "true"` and `includeXbom: "true"`, the GitHub connector automatically downloads all three artifacts from each workflow run and stores them as BLOBs in the `cbom_imports` table. The imported xBOM files are then loaded into the in-memory xBOM store, making them immediately visible in the **BOM Imports → xBOM Analysis** tab.

---

## Trivy Integration

The backend Trivy scanner (`backend/src/services/trivyScanner.ts`) wraps the Trivy CLI:

| Function | Description |
|----------|-------------|
| `isTrivyInstalled()` | Checks if `trivy` is on `$PATH` |
| `getTrivyVersion()` | Returns installed Trivy version |
| `runTrivyScan(options)` | Runs `trivy fs --format cyclonedx` with severity filter, 5-min timeout |
| `parseSBOMFile(input)` | Parses CycloneDX JSON from string or file path |

If Trivy is not installed, the xBOM API gracefully degrades — SBOM generation is unavailable but CBOM-only mode and manual merge still work.

---

## xBOM DB Loader

The `xbomDbLoader` service (`backend/src/services/xbomDbLoader.ts`) bridges the gap between DB-persisted xBOM files and the in-memory `xbomStore` used by the xBOM API endpoints.

**When it runs:**
- **Server startup** — restores previously imported xBOMs from DB into the store
- **After sync** — called by `syncExecutor` after creating new `CbomImport` records

**How it works:**
1. Queries `cbom_imports` for all records where `xbomFile IS NOT NULL`
2. Parses each xBOM BLOB as JSON
3. Validates `bomFormat === 'CycloneDX'`
4. Uses the `serialNumber` (or `cbom-import:<id>`) as the store key
5. Skips entries already present in the store (idempotent)

---

## File Reference

| File | Purpose |
|------|---------|
| `backend/src/types/sbom.types.ts` | Trivy CycloneDX SBOM type definitions |
| `backend/src/types/xbom.types.ts` | Unified xBOM type definitions |
| `backend/src/services/trivyScanner.ts` | Trivy CLI integration |
| `backend/src/services/xbomMergeService.ts` | SBOM + CBOM → xBOM merge with cross-references |
| `backend/src/services/xbomDbLoader.ts` | Loads xBOM files from DB into in-memory `xbomStore` |
| `backend/src/routes/xbomRoutes.ts` | 7 REST API endpoints |
| `backend/src/services/githubCbomConnector.ts` | GitHub Actions connector — fetches CBOM, SBOM, xBOM artifacts |
| `.github/workflows/pipeline.yml` | Unified CI pipeline — CBOM scan, SBOM scan, xBOM merge |
| `frontend/src/pages/XBOMPage.tsx` | xBOM list, generate, merge, and detail views |
| `frontend/src/pages/XBOMPage.module.scss` | Styles for xBOM page |
| `frontend/src/pages/discovery/tabs/CbomImportsTab.tsx` | BOM Imports tab with xBOM Analysis sub-tab |
| `frontend/src/components/bom-panels/BomDownloadButtons.tsx` | Download buttons with labeled BOM type |
| `frontend/src/store/api/xbomApi.ts` | RTK Query API slice with 6 hooks |
| `frontend/src/pages/discovery/utils/exportCsv.ts` | Generic CSV export utility |

---

*Back to [README](../README.md) · See also [PQC Standards](pqc-standards.md) · [Architecture](architecture.md)*
