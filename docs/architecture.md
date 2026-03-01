# Architecture

> System architecture, project structure, technology stack, sync scheduler, and frontend state management.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Communication Flow](#communication-flow)
- [Sync Scheduler](#sync-scheduler)
- [Frontend State Management (RTK Query)](#frontend-state-management-rtk-query)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    MONOREPO ROOT                         │
│  package.json (npm workspaces: backend, frontend)       │
├────────────────────────┬────────────────────────────────┤
│                        │                                │
│   BACKEND (Node.js)    │    FRONTEND (React + Vite)     │
│   Port 3001            │    Port 5173 (dev) / 80 (prod) │
│                        │                                │
│  ┌──────────────────┐  │  ┌──────────────────────────┐  │
│  │ Express Server   │  │  │ React 18 + TypeScript    │  │
│  │ ├─ CBOM Routes   │  │  │ ├─ Dashboard Layout      │  │
│  │ ├─ Network Routes│◄─┼──┤ ├─ 10 Components         │  │
│  │ └─ Scan Routes   │  │  │ ├─ 4 Chart Visualizations│  │
│  ├──────────────────┤  │  │ ├─ Upload/Scan UI        │  │
│  │ Services         │  │  │ └─ Client-side Fallback  │  │
│  │ ├─ PQC Risk Eng. │  │  └──────────────────────────┘  │
│  │ ├─ Network Scan  │  │                                │
│  │ └─ Aggregator    │  │  Tailwind CSS (dark theme)     │
│  ├──────────────────┤  │  Recharts (visualizations)     │
│  │ Types (CycloneDX)│  │  Lucide (icons)                │
│  └──────────────────┘  │                                │
│                        │                                │
├────────────────────────┴────────────────────────────────┤
│  Docker Compose (backend:3001, frontend:nginx:80)       │
└─────────────────────────────────────────────────────────┘
```

## Communication Flow

Frontend calls backend REST API at `/api/*`. In development, Vite proxies requests. In production, nginx reverse-proxies to the backend container. If the backend is unreachable, the frontend **falls back to client-side parsing**.

---

## Project Structure

```
cbom-analyser/
├── backend/                        # Node.js + Express backend
│   └── src/
│       ├── index.ts                # Express entry point (port 3001)
│       ├── config/
│       │   └── database.ts         # Sequelize instance + pool config
│       ├── types/
│       │   ├── cbom.types.ts       # CycloneDX 1.6/1.7 TypeScript interfaces
│       │   └── index.ts            # Barrel exports
│       ├── models/
│       │   ├── Integration.ts      # Integration config + scheduling
│       │   ├── Certificate.ts      # TLS certificates
│       │   ├── Endpoint.ts         # Network endpoints
│       │   ├── Software.ts         # Software signing data
│       │   ├── Device.ts           # IoT/industrial devices
│       │   ├── CbomImport.ts       # CBOM file imports (with BLOBs)
│       │   ├── SyncLog.ts          # Sync audit trail
│       │   └── index.ts            # Sequelize associations
│       ├── services/
│       │   ├── pqcRiskEngine.ts    # Quantum safety classification
│       │   ├── pqcParameterAnalyzer.ts # Per-algorithm parameter analysis
│       │   ├── networkScanner.ts   # Live TLS endpoint scanning
│       │   ├── scannerAggregator.ts# Code scanning + CBOM merging
│       │   ├── dependencyScanner.ts# Third-party crypto dependency detection
│       │   ├── connectors.ts       # 6 connector functions + CONNECTOR_REGISTRY
│       │   ├── syncExecutor.ts     # 8-step sync lifecycle
│       │   ├── syncScheduler.ts    # Cron job management (node-cron)
│       │   ├── xbomDbLoader.ts     # Loads xBOM from DB into memory
│       │   ├── digicertTlmConnector.ts   # DigiCert TLM real connector
│       │   ├── githubCbomConnector.ts    # GitHub CBOM real connector
│       │   ├── networkTlsConnector.ts    # Network TLS real connector
│       │   ├── bedrockService.ts         # AWS Bedrock AI suggestions
│       │   ├── scanner/            # Language-specific pattern files
│       │   └── index.ts            # Barrel exports
│       └── routes/
│           ├── cbomRoutes.ts       # Upload, list, get CBOMs
│           ├── cbomImportRoutes.ts # CBOM import CRUD
│           ├── networkRoutes.ts    # Network TLS scanning
│           ├── scanRoutes.ts       # Code scanning endpoints
│           ├── integrationRoutes.ts# Integration CRUD + sync trigger
│           ├── certificateRoutes.ts# Discovery certificates CRUD
│           ├── endpointRoutes.ts   # Discovery endpoints CRUD
│           ├── softwareRoutes.ts   # Discovery software CRUD
│           ├── deviceRoutes.ts     # Discovery devices CRUD
│           ├── syncLogRoutes.ts    # Sync log read + cleanup
│           ├── schedulerRoutes.ts  # Scheduler control
│           └── index.ts            # Barrel exports
│
├── frontend/                       # React + Vite frontend
│   └── src/
│       ├── App.tsx                 # Main app: state + dashboard layout
│       ├── main.tsx                # Redux Provider + React root
│       ├── sampleData.ts           # 58 crypto assets for demo
│       ├── layouts/
│       │   └── AppShell.tsx        # Sidebar + content layout
│       ├── pages/                  # Route-level page components
│       ├── store/
│       │   ├── store.ts            # configureStore with API reducers
│       │   └── api/                # 13 RTK Query API slices
│       ├── components/             # Reusable UI components
│       ├── styles/                 # Global SCSS + Tailwind
│       ├── types/                  # Frontend type definitions
│       └── utils/                  # Utility functions
│
├── demo-code/                      # Demo source files with crypto API calls
│   ├── java/
│   ├── python/
│   └── typescript/
│
├── sample-data/                    # Example CBOM JSON files
│
├── docs/                           # Documentation (this folder)
│
├── .github/workflows/              # CI/CD pipelines
├── action.yml                      # GitHub Action definition
├── Dockerfile.action               # Docker image for GitHub Action
├── docker-compose.yml              # Container orchestration
└── sonarqube/                      # SonarQube plugins (sonar-cryptography)
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | Node.js 20+ | JavaScript/TypeScript runtime |
| **Language** | TypeScript | Type-safe development |
| **Backend** | Express.js | REST API server |
| **ORM** | Sequelize | MariaDB schema management + queries |
| **Database** | MariaDB | Integration configs, discovery assets, sync logs |
| **Frontend** | React 18 + Vite | UI framework + build tool |
| **State** | Redux Toolkit / RTK Query | Server state caching + mutations |
| **CSS** | Tailwind CSS + SCSS Modules | Dark-theme utility classes + scoped styles |
| **Charts** | Recharts | Donut, scatter, pie, bar charts |
| **Icons** | Lucide React | Shield, Alert, CheckCircle, etc. |
| **Containerisation** | Docker + nginx | Production deployment |
| **Monorepo** | npm workspaces | Shared dependencies |
| **Scheduler** | node-cron | In-process cron jobs for sync scheduling |

---

## Sync Scheduler

The backend includes a cron-based sync scheduler that automatically pulls data from external integrations on a configurable schedule. It uses **`node-cron`** for in-process cron job scheduling — no external daemon or message queue required.

### Scheduler Architecture

```
┌──────────────────────┐
│  Integration CRUD    │  ← user creates/updates/deletes integrations
│  (REST routes)       │
└──────┬───────────────┘
       │  lifecycle events
       ▼
┌──────────────────────┐
│  SyncScheduler       │  ← singleton, manages Map<integrationId, ScheduledJob>
│  (node-cron)         │  ← starts/stops/restarts cron tasks per integration
└──────┬───────────────┘
       │  on cron tick (or manual trigger)
       ▼
┌──────────────────────┐
│  SyncExecutor        │  ← 8-step sync lifecycle per integration
│                      │  ← creates SyncLog → calls connector → bulk inserts → finalises log
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Connectors          │  ← per-type data fetcher (e.g. fetchCertificates, fetchEndpoints)
│  (CONNECTOR_REGISTRY)│  ← maps templateType → { fetch, model, label }
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Discovery Tables    │  ← full-refresh: delete old → bulk insert new
│  + SyncLog Table     │  ← audit trail with metrics
└──────────────────────┘
```

### Schedule-to-Cron Mapping

| Sync Schedule | Cron Expression | Description |
|---------------|-----------------|-------------|
| `manual` | *(no cron job)* | Only syncs when user clicks "Sync Now" |
| `1h` | `0 * * * *` | Every hour at minute 0 |
| `6h` | `0 */6 * * *` | Every 6 hours (00:00, 06:00, 12:00, 18:00) |
| `12h` | `0 */12 * * *` | Every 12 hours (00:00, 12:00) |
| `24h` | `0 2 * * *` | Daily at 02:00 |

### Connector Registry

Each integration `templateType` maps to a connector in the `CONNECTOR_REGISTRY`:

| Template Type | Connector Function | Discovery Table | Label |
|---------------|-------------------|-----------------|-------|
| `digicert-tlm` | `fetchCertificates()` | `certificates` | DigiCert TLM (Certificates) |
| `network-scanner` | `fetchEndpoints()` | `endpoints` | Network Scanner (Endpoints) |
| `digicert-stm` | `fetchSoftware()` | `software` | DigiCert STM (Software) |
| `digicert-dtm` | `fetchDevices()` | `devices` | DigiCert DTM (Devices) |
| `cbom-import` | `fetchCbomImports()` | `cbom_imports` | CBOM Import (CBOM Files) |

> **Simulated fallback**: Connectors in `connectors.ts` return simulated data when used without real credentials. Three integration types (**DigiCert TLM**, **GitHub CBOM Import**, and **Network TLS Scanner**) have production-grade connectors that call real external APIs — see the [UI Guide](ui-guide.md#real-connectors).

### Sync Execution Lifecycle (8 Steps)

When a sync runs (either from a cron tick or a manual trigger), the `SyncExecutor` performs:

1. **Create SyncLog** — inserts a `running` record with `startedAt` timestamp
2. **Load Integration** — fetches the integration from DB and validates it exists + is enabled
3. **Lookup Connector** — resolves the `templateType` → connector via `CONNECTOR_REGISTRY`
4. **Fetch Data** — calls the connector's `fetch()` function, passing integration config
5. **Persist Data** — for `CbomImport` records (which carry large BLOB fields), inserts records one-by-one to avoid MariaDB `max_allowed_packet` limits; other models use `bulkCreate`. If the connector signals `meta.incremental`, existing records are kept (append-only); otherwise a full refresh deletes → re-inserts.
6. **Load xBOM Store** — if the connector model is `CbomImport`, calls `loadXBOMsFromImports()` to populate the in-memory xBOM store with any newly imported xBOM files
7. **Update Integration** — sets `lastSync`, `lastSyncItems`, `lastSyncErrors`, and calculates `nextSync`
8. **Finalise SyncLog** — updates the log with `completedAt`, `durationMs`, item counts, and final status

### Scheduler Lifecycle

| Event | Handler | Behaviour |
|-------|---------|----------|
| Server startup | `initScheduler()` | Loads all enabled, non-manual integrations from DB and schedules cron jobs |
| Integration created | `scheduleJob()` | Starts a cron job if schedule is not `manual` |
| Schedule changed | `onScheduleChanged()` | Removes old job, starts new job with updated cron |
| Integration deleted | `onIntegrationDeleted()` | Removes the cron job |
| Integration toggled off | `onIntegrationToggled(false)` | Removes the cron job |
| Integration toggled on | `onIntegrationToggled(true)` | Schedules a new cron job |
| Server shutdown (SIGTERM/SIGINT) | `stopAllJobs()` | Stops all active cron tasks gracefully |

### Backend Service Files

```
backend/src/services/
├── connectors.ts      — 6 connector functions + CONNECTOR_REGISTRY
├── syncExecutor.ts    — executeSyncForIntegration() — 8-step lifecycle
├── syncScheduler.ts   — cron job management (node-cron)
├── xbomDbLoader.ts    — loads xBOM files from cbom_imports into in-memory xbomStore
└── index.ts           — barrel re-exports
```

---

## Frontend State Management (RTK Query)

The frontend uses **Redux Toolkit** with **RTK Query** for server state management. RTK Query provides automatic caching, cache invalidation, and optimistic updates for all API slices.

### Store Setup

The Redux store is configured in `frontend/src/store/store.ts` and wrapped around the app via `<Provider>` in `main.tsx`.

```
frontend/src/store/
├── store.ts                 — configureStore with API reducers + middleware
├── index.ts                 — barrel exports
└── api/
    ├── integrationsApi.ts   — Integrations CRUD (8 hooks)
    ├── certificatesApi.ts   — Certificates CRUD (8 hooks)
    ├── endpointsApi.ts      — Endpoints CRUD (8 hooks)
    ├── softwareApi.ts       — Software CRUD (8 hooks)
    ├── devicesApi.ts        — Devices CRUD (8 hooks)
    ├── cbomImportsApi.ts    — CBOM Imports CRUD (8 hooks)
    ├── cbomUploadsApi.ts    — CBOM Uploads (3 hooks)
    ├── xbomApi.ts           — xBOM CRUD (6 hooks)
    ├── syncLogsApi.ts       — Sync Logs (4 hooks)
    ├── schedulerApi.ts      — Scheduler status & control (3 hooks)
    ├── policiesApi.ts       — Policies CRUD (6 hooks)
    ├── trackingApi.ts       — Tickets + Connectors + platform helpers
    └── index.ts             — re-exports all hooks + types
```

### Integrations API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetIntegrationsQuery()` | Query | Fetch all integrations |
| `useGetIntegrationQuery(id)` | Query | Fetch a single integration |
| `useCreateIntegrationMutation()` | Mutation | Create a new integration |
| `useUpdateIntegrationMutation()` | Mutation | Update an existing integration |
| `useDeleteIntegrationMutation()` | Mutation | Delete an integration |
| `useToggleIntegrationMutation()` | Mutation | Toggle enabled/disabled |
| `useSyncIntegrationMutation()` | Mutation | Trigger a manual sync |
| `useTestIntegrationMutation()` | Mutation | Test connection credentials |

### Discovery API Hooks

Each of the five discovery API slices generates 8 hooks following the same pattern:

| Resource | List All | List by Integration | Get One | Create | Bulk Create | Update | Delete | Delete by Integration |
|----------|----------|-------------------|---------|--------|-------------|--------|--------|----------------------|
| **Certificates** | `useGetCertificatesQuery()` | `useGetCertificatesByIntegrationQuery(id)` | `useGetCertificateQuery(id)` | `useCreateCertificateMutation()` | `useBulkCreateCertificatesMutation()` | `useUpdateCertificateMutation()` | `useDeleteCertificateMutation()` | `useDeleteCertificatesByIntegrationMutation()` |
| **Endpoints** | `useGetEndpointsQuery()` | `useGetEndpointsByIntegrationQuery(id)` | `useGetEndpointQuery(id)` | `useCreateEndpointMutation()` | `useBulkCreateEndpointsMutation()` | `useUpdateEndpointMutation()` | `useDeleteEndpointMutation()` | `useDeleteEndpointsByIntegrationMutation()` |
| **Software** | `useGetSoftwareListQuery()` | `useGetSoftwareByIntegrationQuery(id)` | `useGetSoftwareQuery(id)` | `useCreateSoftwareMutation()` | `useBulkCreateSoftwareMutation()` | `useUpdateSoftwareMutation()` | `useDeleteSoftwareMutation()` | `useDeleteSoftwareByIntegrationMutation()` |
| **Devices** | `useGetDevicesQuery()` | `useGetDevicesByIntegrationQuery(id)` | `useGetDeviceQuery(id)` | `useCreateDeviceMutation()` | `useBulkCreateDevicesMutation()` | `useUpdateDeviceMutation()` | `useDeleteDeviceMutation()` | `useDeleteDevicesByIntegrationMutation()` |
| **CBOM Imports** | `useGetCbomImportsQuery()` | `useGetCbomImportsByIntegrationQuery(id)` | `useGetCbomImportQuery(id)` | `useCreateCbomImportMutation()` | `useBulkCreateCbomImportsMutation()` | `useUpdateCbomImportMutation()` | `useDeleteCbomImportMutation()` | `useDeleteCbomImportsByIntegrationMutation()` |

### xBOM API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetXBOMStatusQuery()` | Query | Check Trivy availability and xBOM service health |
| `useGenerateXBOMMutation()` | Mutation | Generate an xBOM by scanning a local repo |
| `useMergeXBOMMutation()` | Mutation | Merge pre-existing SBOM + CBOM documents |
| `useGetXBOMListQuery()` | Query | List all stored xBOMs (summary metadata) |
| `useGetXBOMQuery(id)` | Query | Retrieve a specific xBOM with analytics |
| `useDeleteXBOMMutation()` | Mutation | Delete a stored xBOM |

### CBOM Uploads API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetCbomUploadsQuery()` | Query | List all uploaded CBOMs (excludes BLOB) |
| `useGetCbomUploadQuery(id)` | Query | Fetch a single upload with base64-encoded CBOM |
| `useDeleteCbomUploadMutation()` | Mutation | Delete an uploaded CBOM |

### Sync Logs API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetSyncLogsQuery(limit?)` | Query | Fetch all sync logs (optional limit, default 100) |
| `useGetSyncLogsByIntegrationQuery(id)` | Query | Fetch sync logs for a specific integration |
| `useGetSyncLogQuery(id)` | Query | Fetch a single sync log by ID |
| `useDeleteSyncLogsByIntegrationMutation()` | Mutation | Delete all sync logs for an integration |

### Scheduler API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetSchedulerStatusQuery()` | Query | Fetch scheduler status (active jobs, uptime) |
| `useStopSchedulerMutation()` | Mutation | Stop all cron jobs |
| `useRestartSchedulerMutation()` | Mutation | Restart scheduler — stops all, reloads from DB |

### Policies API Hooks

| Hook | Type | Description |
|------|------|-------------|
| `useGetPoliciesQuery()` | Query | Fetch all policies |
| `useGetPolicyQuery(id)` | Query | Fetch a single policy |
| `useCreatePolicyMutation()` | Mutation | Create a new policy |
| `useBulkCreatePoliciesMutation()` | Mutation | Bulk create (preset seeding) |
| `useUpdatePolicyMutation()` | Mutation | Update a policy |
| `useDeletePolicyMutation()` | Mutation | Delete a policy |

### Tracking API Hooks

**Tickets:**

| Hook | Type | Description |
|------|------|-------------|
| `useGetTicketsQuery()` | Query | Fetch all remediation tickets |
| `useGetTicketQuery(id)` | Query | Fetch a single ticket |
| `useCreateTicketMutation()` | Mutation | Create a ticket (calls external API) |
| `useUpdateTicketMutation()` | Mutation | Update a ticket |
| `useDeleteTicketMutation()` | Mutation | Delete a ticket |

**Ticket Connectors:**

| Hook | Type | Description |
|------|------|-------------|
| `useGetConnectorsQuery()` | Query | Fetch all ticket connectors |
| `useCreateConnectorMutation()` | Mutation | Create a connector |
| `useUpdateConnectorMutation()` | Mutation | Update a connector |
| `useToggleConnectorMutation()` | Mutation | Toggle enabled/disabled |
| `useDeleteConnectorMutation()` | Mutation | Delete a connector |
| `useTestJiraConnectionMutation()` | Mutation | Test JIRA credentials |
| `useTestGitHubConnectionMutation()` | Mutation | Test GitHub token |
| `useTestServiceNowConnectionMutation()` | Mutation | Test ServiceNow credentials |
| `useGetJiraProjectsQuery()` | Query | List JIRA projects |
| `useLazyGetJiraIssueTypesQuery()` | Lazy Query | Load issue types for a project |
| `useLazyGetJiraAssignableUsersQuery()` | Lazy Query | Load assignable users |
| `useLazyGetJiraBoardsQuery()` | Lazy Query | Load boards |
| `useLazyGetGitHubOrgsQuery()` | Lazy Query | Load GitHub organizations |
| `useLazyGetGitHubReposByOwnerQuery()` | Lazy Query | Load repos for an owner/org |
| `useLazyGetGitHubCollaboratorsQuery()` | Lazy Query | Load collaborators |

### Cache Invalidation Strategy

RTK Query uses **tags** for automatic cache invalidation across all API slices:

- Each record is tagged with `{ type: '<Tag>', id }` (e.g., `{ type: 'Certificate', id: 'abc-123' }`)
- The full list is tagged with `{ type: '<Tag>', id: 'LIST' }`
- Mutations (create, bulk create, update, delete) **invalidate** both the specific tag and the list tag
- Any list query auto-refetches after any mutation — no manual refetch needed

**Tag types:** `Integration`, `Certificate`, `Endpoint`, `Software`, `Device`, `CbomImport`, `CbomUpload`, `SyncLog`, `Scheduler`, `Policy`, `Ticket`, `TicketConnector`

### Usage Example

```tsx
import {
  useGetIntegrationsQuery,
  useCreateIntegrationMutation,
  useDeleteIntegrationMutation,
} from '../../store';

function IntegrationsPage() {
  // Queries — auto-fetch on mount, re-fetch on cache invalidation
  const { data: integrations = [], isLoading } = useGetIntegrationsQuery();

  // Mutations — returns [triggerFn, { isLoading, error }]
  const [createIntegration] = useCreateIntegrationMutation();
  const [deleteIntegration] = useDeleteIntegrationMutation();

  const handleSave = async () => {
    await createIntegration({
      templateType: 'digicert-tlm',
      name: 'My TLM',
      description: '...',
      config: { apiBaseUrl: '...', apiKey: '...' },
      importScope: ['certificates', 'endpoints'],
      syncSchedule: '24h',
    });
    // No manual refetch needed — cache is auto-invalidated
  };
}
```

---

*Back to [README](../README.md) · See also [Database](database.md) · [API Reference](api-reference.md)*
