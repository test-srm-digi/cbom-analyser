# QuantumGuard CBOM Hub — Usage Guide

> **Practical guide for running, integrating, and using QuantumGuard CBOM Hub**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [GitHub Actions Integration](#github-actions-integration)
3. [Docker Deployment](#docker-deployment)
4. [API Reference](#api-reference)
5. [Scanning Approaches](#scanning-approaches)
6. [UI Navigation & Application Layout](#ui-navigation--application-layout)
7. [Integrations Hub](#integrations-hub)
8. [Discovery Pages](#discovery-pages)
9. [Real Connectors](#real-connectors)
10. [Cryptographic Policies](#cryptographic-policies)
11. [Violations Page](#violations-page)
12. [Ticket & Issue Tracking](#ticket--issue-tracking)
13. [Database Setup (MariaDB)](#database-setup-mariadb)
14. [Integrations REST API](#integrations-rest-api)
15. [Discovery Data REST API](#discovery-data-rest-api)
16. [Policies REST API](#policies-rest-api)
17. [Tickets REST API](#tickets-rest-api)
18. [Ticket Connectors REST API](#ticket-connectors-rest-api)
19. [Sync Scheduler](#sync-scheduler)
20. [Sync Logs REST API](#sync-logs-rest-api)
21. [Scheduler REST API](#scheduler-rest-api)
22. [Frontend State Management (RTK Query)](#frontend-state-management-rtk-query)
23. [Variable Resolution & Context Scanning](#variable-resolution--context-scanning)
24. [Third-Party Dependency Scanning](#third-party-dependency-scanning)
25. [PQC Readiness Verdicts](#pqc-readiness-verdicts)
26. [Quantum Safety Dashboard](#quantum-safety-dashboard)
27. [Project Insight Panel](#project-insight-panel)
28. [AI-Powered Suggested Fixes](#ai-powered-suggested-fixes)
29. [Sample Data & Demo Code](#sample-data--demo-code)
30. [Configuration](#configuration)
31. [CycloneDX 1.7 Standard](#cyclonedx-17-standard)

---

## Quick Start

```bash
# Clone
git clone https://github.com/test-srm-digi/cbom-analyser.git
cd cbom-analyser

# Install dependencies
npm install

# Run (backend: 3001, frontend: 5173)
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) — upload a CBOM JSON or click **"sample CBOM file"** to explore the dashboard.

---

## GitHub Actions Integration

Add a single workflow file to **any repository** to scan it for cryptographic assets and generate a CBOM.

### Setup

Create `.github/workflows/cbom-scan.yml` in your repository — that's it. No other files needed.

### Basic Usage

```yaml
name: CBOM Scan
on: [push, pull_request]

permissions:
  contents: read

jobs:
  cbom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run CBOM Scanner
        uses: test-srm-digi/cbom-analyser@main
        with:
          scan-path: '.'
          output-format: 'json'

      - name: Upload CBOM Report
        uses: actions/upload-artifact@v4
        with:
          name: cbom-report
          path: cbom.json
```

### Advanced Usage

```yaml
name: CBOM Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  cbom-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run QuantumGuard CBOM Scanner
        id: cbom
        uses: test-srm-digi/cbom-analyser@main
        with:
          scan-path: '.'
          output-format: 'sarif'
          fail-on-vulnerable: 'true'
          quantum-safe-threshold: '50'
          exclude-patterns: 'default'

      - name: Upload CBOM Report
        uses: actions/upload-artifact@v4
        with:
          name: cbom-report
          path: cbom.json

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cbom.sarif
```

### SARIF Integration for GitHub Security Tab

```yaml
- name: CBOM Scan with SARIF
  uses: test-srm-digi/cbom-analyser@main
  with:
    output-format: 'sarif'

- name: Upload SARIF Results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cbom.sarif
```

> **Note:** Add `security-events: write` to `permissions` when uploading SARIF results.

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan (relative to repo root) | `.` |
| `output-format` | Output format: `json`, `sarif`, or `summary` | `summary` |
| `output-file` | Path to save the CBOM output file | `cbom-report.json` |
| `fail-on-vulnerable` | Fail if non-quantum-safe algorithms found | `false` |
| `quantum-safe-threshold` | Minimum quantum readiness score (0-100) to pass | `0` |
| `exclude-patterns` | Comma-separated glob patterns to exclude, or `default` | (none) |
| `sonar-host-url` | SonarQube server URL (enables IBM sonar-cryptography deep analysis) | (none) |
| `sonar-token` | SonarQube authentication token (required when `sonar-host-url` is set) | (none) |

### SonarQube Integration (Optional)

By default the action uses a fast built-in **regex scanner**.
To enable IBM **sonar-cryptography** deep analysis set the two optional
Sonar inputs — the action image ships with `sonar-scanner` pre-installed.

> **Important:** Your SonarQube instance must be **network-reachable** from the
> GitHub Actions runner. Internal/corporate SonarQube servers (e.g.
> `sonar.dev.company.com`) are **not reachable** from GitHub-hosted runners
> (`ubuntu-latest`). Use a **self-hosted runner** on the same network instead.

#### Basic Example (self-hosted runner)

```yaml
jobs:
  cbom:
    runs-on: self-hosted      # must be on a network that can reach your SonarQube
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: CBOM Analysis (SonarQube)
        uses: test-srm-digi/cbom-analyser@main
        with:
          sonar-host-url: ${{ secrets.SONAR_HOST_URL }}
          sonar-token: ${{ secrets.SONAR_TOKEN }}
          output-format: sarif
          fail-on-vulnerable: true
```

#### With Java Build Step (recommended for full accuracy)

SonarQube's Java analyzer delivers bytecode-level insights when compiled
`.class` files are available. The scanner auto-detects common build output
directories (`target/classes`, `build/classes`, `out/production`, `bin`).
If none exist it creates a temporary empty directory so the scan still
proceeds — but you get source-level analysis only.

For **full accuracy**, add a build step before the CBOM scan:

**Maven project:**

```yaml
jobs:
  cbom:
    runs-on: self-hosted
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Build (compile only — no tests)
        run: mvn compile -q -DskipTests

      - name: CBOM Analysis (SonarQube)
        uses: test-srm-digi/cbom-analyser@main
        with:
          sonar-host-url: ${{ secrets.SONAR_HOST_URL }}
          sonar-token: ${{ secrets.SONAR_TOKEN }}
          output-format: sarif
          fail-on-vulnerable: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cbom.sarif
```

**Gradle project:** replace the build step with:
```yaml
      - name: Build (compile only)
        run: ./gradlew classes
```

| Build Command | What it does | Output dir auto-detected |
|---------------|-------------|--------------------------|
| `mvn compile` | Compiles `src/main/java` → bytecode | `target/classes/` |
| `./gradlew classes` | Same for Gradle | `build/classes/` |
| `mvn package -DskipTests` | Compile + package (slower) | `target/classes/` + `.jar` |
| *(no build step)* | Source-level analysis only | temp empty dir created automatically |

#### Runner Selection Guide

| SonarQube location | `runs-on` | Build step needed? |
|--------------------|-----------|-------------------|
| Internal corporate server (e.g. `sonar.dev.company.com`) | `self-hosted` | Optional (recommended for Java) |
| Public URL (e.g. `https://sonarcloud.io`) | `ubuntu-latest` | Optional (recommended for Java) |
| Not using SonarQube | `ubuntu-latest` | No |

#### Setting Up a Self-Hosted Runner

If your SonarQube is on an internal network, you need a **self-hosted runner**
— a machine (your laptop, a VM, or a server) on the same network:

1. In your repo go to **Settings → Actions → Runners → New self-hosted runner**.
2. Select your OS (Linux/macOS/Windows) and follow the generated commands:
   ```bash
   mkdir actions-runner && cd actions-runner
   curl -o actions-runner-linux-x64-2.321.0.tar.gz -L \
     https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
   tar xzf ./actions-runner-linux-x64-2.321.0.tar.gz
   ./config.sh --url https://github.com/YOUR_ORG/YOUR_REPO --token <TOKEN_FROM_GITHUB>
   ./run.sh
   # Or install as a service:
   # sudo ./svc.sh install && sudo ./svc.sh start
   ```
3. Once it shows **Idle** in Settings → Runners, your workflows with `runs-on: self-hosted` will use it.

> **Requirement:** The self-hosted runner must have **Docker** installed
> (the action uses `Dockerfile.action`).

> **How it works:** When both `sonar-host-url` and `sonar-token` are set the
> backend's scanner aggregator runs `sonar-scanner` against the checkout,
> fetches the resulting CycloneDX 1.7 CBOM from SonarQube, and merges it
> with the regex + dependency + network scan results. When the inputs are
> absent the scanner falls back to regex mode automatically.

### Setting Up SonarQube Secrets for a New Repository

To use the SonarQube integration you need a running SonarQube instance and a
project token. Follow these steps **once per GitHub repository**:

#### 1. Start SonarQube (or use an existing instance)

If you have an existing corporate SonarQube (e.g. `sonar.dev.company.com`),
skip to step 2. Otherwise spin one up locally:

```bash
# From the cbom-analyser checkout — bundles the IBM sonar-cryptography plugin
docker compose -f docker-compose.sonarqube.yml up -d

# Wait for SonarQube to become ready (~60 s)
until curl -sf http://localhost:9090/api/system/status | grep -q '"UP"'; do sleep 5; done
echo "SonarQube is ready"
```

#### 2. Generate a Token

1. Open **http://localhost:9090** (default login: `admin` / `admin`, you'll be prompted to change the password).
2. Go to **My Account → Security → Tokens**.
3. Click **Generate Tokens**, enter a name (e.g. `cbom-ci`), and choose type **Project Analysis Token** for a specific project or **Global Analysis Token** for all projects.
4. Copy the token string — it looks like `sqp_abc123…`.

> The token is shown only once. If you lose it, revoke and generate a new one.

#### 3. Add Secrets to Your GitHub Repository

1. In your GitHub repository go to **Settings → Secrets and variables → Actions**.
2. Click **New repository secret** and create:

   | Secret name | Value |
   |-------------|-------|
   | `SONAR_HOST_URL` | Your SonarQube URL, e.g. `http://sonarqube.internal:9090` or `https://sonarcloud.io` |
   | `SONAR_TOKEN` | The token from step 2, e.g. `sqp_abc123…` |

3. (Optional) For **organization-wide** reuse, add these as **Organization secrets** under **Organization Settings → Secrets and variables → Actions** and grant access to selected repositories.

#### 4. Reference in Your Workflow

```yaml
jobs:
  cbom:
    runs-on: self-hosted      # use self-hosted if SonarQube is on an internal network
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: CBOM Analysis
        uses: test-srm-digi/cbom-analyser@main
        with:
          sonar-host-url: ${{ secrets.SONAR_HOST_URL }}
          sonar-token: ${{ secrets.SONAR_TOKEN }}
          output-format: sarif
          fail-on-vulnerable: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cbom.sarif
```

> No build step needed — see [Optional: Java Build Step](#optional-java-build-step-for-enhanced-bytecode-analysis)
> if you want bytecode-level analysis for Java projects.

> **Network note:** The runner must be able to reach the SonarQube URL.
> Internal servers require a **self-hosted runner** — see
> [Setting Up a Self-Hosted Runner](#setting-up-a-self-hosted-runner) above.

#### Without SonarQube (default)

If you don't set the secrets the action uses the **built-in regex scanner**
automatically — no SonarQube instance required. You can always add the secrets
later to upgrade to deep analysis without changing the workflow file.

### Outputs

| Output | Description |
|--------|-------------|
| `readiness-score` | Quantum readiness score (0-100) |
| `total-assets` | Total cryptographic assets found |
| `vulnerable-assets` | Number of non-quantum-safe assets |
| `quantum-safe-assets` | Number of quantum-safe assets |
| `cbom-file` | Path to the generated CBOM output file (user-specified format) |
| `cbom-json-file` | Path to the always-generated `cbom.json` file (for artifact download) |

### Excluding Files from Scans

Use `exclude-patterns` to skip test files, mocks, or other directories:

```yaml
# Use default exclusions (test files, mocks, fixtures, etc.)
- uses: test-srm-digi/cbom-analyser@main
  with:
    exclude-patterns: 'default'

# Custom exclusions
- uses: test-srm-digi/cbom-analyser@main
  with:
    exclude-patterns: '**/test/**,**/*.test.ts,**/mock/**'

# Combine default + custom
- uses: test-srm-digi/cbom-analyser@main
  with:
    exclude-patterns: 'default,**/legacy/**,**/vendor/**'
```

**Default Exclusion Patterns:**
- `**/test/**`, `**/tests/**`, `**/__tests__/**`
- `**/*.test.ts`, `**/*.test.js`, `**/*.test.tsx`, `**/*.test.jsx`
- `**/*.spec.ts`, `**/*.spec.js`, `**/*.spec.tsx`, `**/*.spec.jsx`
- `**/Test.java`, `**/*Test.java`, `**/*Tests.java`
- `**/test_*.py`, `**/*_test.py`

### Downloading BOM Artifacts

After a workflow run completes the unified pipeline produces **three artifacts**:

| Artifact | Description |
|----------|-------------|
| `cbom-report` | Cryptographic Bill of Materials (CBOM) — crypto assets, algorithms, protocols |
| `sbom-report` | Software Bill of Materials (SBOM) — packages, licenses, CVEs (via Trivy) |
| `xbom-report` | Unified xBOM — merged SBOM + CBOM with cross-references and analytics |

**Via GitHub UI:**
1. Go to **Actions** → Select workflow run
2. Scroll to **Artifacts** section
3. Download `cbom-report`, `sbom-report`, or `xbom-report`

**Via GitHub CLI:**
```bash
# List artifacts
gh run list --workflow=pipeline.yml
gh run view <run-id>

# Download individual artifacts
gh run download <run-id> -n cbom-report
gh run download <run-id> -n sbom-report
gh run download <run-id> -n xbom-report
```

**Via REST API:**
```bash
# List artifacts
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/OWNER/REPO/actions/runs/RUN_ID/artifacts"

# Download (get archive_download_url from above response)
curl -L -H "Authorization: token $GITHUB_TOKEN" \
  "<archive_download_url>" -o cbom-report.zip
```

---

## Docker Deployment

### Using Docker Compose (Recommended)

The `docker-compose.yml` spins up all three services — **MariaDB**, **backend**, and **frontend** — in a single command:

```bash
docker compose up --build
# DB       → MariaDB 11 on port 3306
# Backend  → http://localhost:3001
# Frontend → http://localhost:8080
```

#### Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `db` | `mariadb:11` | `3306` | MariaDB database with a health check. Auto-creates the `dcone-quantum-gaurd` database. Data persisted in a `db_data` named volume. |
| `backend` | Custom (Node 20 Alpine) | `3001` | Express + Sequelize API server. Waits for `db` to report healthy before starting. |
| `frontend` | Custom (nginx Alpine) | `8080` | Vite-built SPA served by nginx. API requests at `/api/*` are proxied to `backend:3001`. |

#### Environment Variables Set in Docker Compose

The `backend` service is pre-configured with all database connection variables:

| Variable | Value | Description |
|----------|-------|-------------|
| `DB_HOST` | `db` | Docker service name for MariaDB |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_DATABASE` | `dcone-quantum-gaurd` | Database name |
| `DB_USERNAME` | `root` | MariaDB user |
| `DB_PASSWORD` | `asdasd` | MariaDB password |

Additional secrets (API keys, tokens) are loaded from a `.env` file via `env_file: .env`. Create a `.env` in the project root with any keys you need (e.g. `AWS_BEARER_TOKEN_BEDROCK`, `SONAR_TOKEN`).

#### Health Check & Startup Order

The `db` service uses MariaDB's built-in health check (`healthcheck.sh --connect --innodb_initialized`). The `backend` has `depends_on: db: condition: service_healthy`, so it only starts once the database is ready to accept connections. The `frontend` starts after the backend.

#### Persistent Volume

The `db_data` Docker volume persists database contents across restarts:

```bash
# Remove everything including the database volume
docker compose down -v

# Keep the database between rebuilds
docker compose down
docker compose up --build
```

### Manual Docker Build

```bash
# Build backend
cd backend && docker build -t cbom-backend .

# Build frontend
cd frontend && docker build -t cbom-frontend .

# Run (you must provide your own MariaDB instance)
docker run -d -p 3001:3001 \
  -e DB_HOST=host.docker.internal \
  -e DB_DATABASE=dcone-quantum-gaurd \
  cbom-backend
docker run -d -p 8080:80 cbom-frontend
```

### Production URLs
- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:3001` (or proxied through nginx at `:8080/api/`)

---

## API Reference

### CBOM Management

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/upload` | Multipart form, field `cbom` (JSON file) | `{ success, cbom, readinessScore, compliance }` |
| `POST` | `/api/upload/raw` | Raw JSON body (CBOM document) | Same as above |
| `GET` | `/api/cbom/list` | — | `{ success, cboms: [{ id, component, assetCount, timestamp }] }` |
| `GET` | `/api/cbom/:id` | — | `{ success, cbom, readinessScore, compliance }` |

> **Note:** `POST /api/upload` also persists the uploaded CBOM to the `cbom_uploads` database table (fire-and-forget) so that uploads are available on the Dashboard welcome page.

### CBOM Uploads (Persisted)

Uploaded CBOMs are persisted in a separate `cbom_uploads` table and surfaced on the Dashboard welcome page.

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `GET` | `/api/cbom-uploads` | — | `{ success, data: [{ id, fileName, componentName, format, specVersion, totalAssets, quantumSafe, notQuantumSafe, conditional, unknown, uploadDate }] }` |
| `GET` | `/api/cbom-uploads/:id` | — | `{ success, data: { ...fields, cbomFile (base64), cbomFileType } }` |
| `DELETE` | `/api/cbom-uploads/:id` | — | `{ success, message }` |

The list endpoint excludes the BLOB column (`cbomFile`) for performance. The single-record endpoint returns the CBOM file as a **base64-encoded** string.

### Network Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-network` | `{ url, port? }` | `{ success, result, cbomAsset }` |
| `POST` | `/api/scan-network/batch` | `{ hosts: [{ host, port? }] }` | `{ success, results, cbomAssets, errors }` |
| `POST` | `/api/scan-network/merge/:cbomId` | `{ url, port? }` | Updated CBOM with network asset merged |

### Code Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-code` | `{ repoPath, excludePatterns? }` | `{ success, cbomId, cbom, readinessScore, compliance }` |
| `POST` | `/api/scan-code/regex` | `{ repoPath, excludePatterns? }` | Same (regex scanner only, no sonar) |
| `POST` | `/api/scan-code/full` | `{ repoPath, networkHosts?, excludePatterns? }` | Same + `cbom.thirdPartyLibraries` + PQC verdicts |

The **`/api/scan-code/full`** endpoint runs the complete 5-step pipeline:
1. Code scan (sonar-cryptography or regex fallback)
2. Dependency scan (manifest file analysis + transitive resolution)
3. Network scan (if `networkHosts` provided)
4. Merge all discovered crypto assets
5. Smart PQC parameter analysis on conditional assets

### AI Suggestions

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/ai-suggest` | `{ algorithmName, primitive?, keyLength?, fileName?, lineNumber?, quantumSafety?, recommendedPQC? }` | `{ success, suggestion, replacement, migrationSteps, effort }` |

### Project Insight

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

### Health

| Method | Endpoint | Response |
|--------|----------|----------|
| `GET` | `/api/health` | `{ status: 'ok', service, version, timestamp }` |

### Examples

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

## Scanning Approaches

### Approach 1: Built-In Regex Scanner (Easiest — No Setup)

Uses the QuantumGuard regex scanner that's built into this project. No external tools needed.

```bash
# Clone any GitHub repo
git clone https://github.com/spring-projects/spring-petclinic.git /tmp/petclinic

# Scan it (backend must be running on port 3001)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' \
  -o petclinic-cbom.json
```

| Pros | Cons |
|------|------|
| Zero setup — works out of the box | Pattern-based, may miss uncommon crypto APIs |
| Fast — scans 500 files in seconds | Doesn't analyze dependencies/transitive crypto |
| Covers 7 language ecosystems (Java, Python, JS/TS, C/C++, C#/.NET, Go, PHP) | No bytecode analysis |

### Approach 2: IBM sonar-cryptography (Most Accurate for Java)

Uses SonarQube with IBM's cryptography plugin for deep static analysis.
Generates CycloneDX 1.7 CBOM with precise algorithm detection, key sizes, and OIDs.

> **GitHub Actions:** You can also enable sonar-cryptography in the GitHub
> Action by setting the `sonar-host-url` and `sonar-token` inputs — see
> [SonarQube Integration](#sonarqube-integration-optional) above.

**Quick Setup:**

```bash
# 1. Start SonarQube with the crypto plugin (already bundled)
docker compose -f docker-compose.sonarqube.yml up -d

# 2. Wait for SonarQube to start (~60s), then check:
curl -s http://localhost:9090/api/system/status
# Should return: {"status":"UP"}

# 3. Set your SONAR_TOKEN in .env (generate at http://localhost:9090)
#    Default login: admin / QuantumGuard2024@

# 4. Scan via the API (sonar-scanner must be on $PATH)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/your/java-project"}'
```

**Manual sonar-scanner run:**

```bash
# Install sonar-scanner CLI
brew install sonar-scanner   # macOS

# Create sonar-project.properties in your target project root
# (see sonar-project.properties.example for a template)

cd /path/to/your/java-project
sonar-scanner \
  -Dsonar.host.url=http://localhost:9090 \
  -Dsonar.token=YOUR_TOKEN \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=src

# The plugin generates cbom.json in the project root
cat cbom.json | python3 -m json.tool
```

**Supported languages:**
- Java (JCA 100%, BouncyCastle 100%)
- Python (pyca/cryptography 100%)
- Go (crypto stdlib 100%)

### Approach 3: Network TLS Scanner (Runtime Crypto Discovery)

Scan live endpoints to discover what cryptography is actually used at runtime.

```bash
# Scan a single endpoint
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}'
```

### Approach 4: Full Pipeline (Recommended)

For the most complete CBOM, use the **`/api/scan-code/full`** endpoint — it runs all scanners in sequence and produces a unified CBOM with definitive PQC verdicts:

```bash
# Single command — runs code scan + dependency scan + network scan + PQC analysis
curl -X POST http://localhost:3001/api/scan-code/full \
  -H "Content-Type: application/json" \
  -d '{
    "repoPath": "/tmp/your-app",
    "networkHosts": ["your-app.com", "api.your-app.com"]
  }' \
  -o full-cbom.json
```

This produces a CBOM that includes:
- All crypto assets from source code (sonar or regex)
- Third-party crypto libraries discovered from manifest files (`pom.xml`, `package.json`, `requirements.txt`, `go.mod`, etc.)
- Known algorithms provided by each library (dependency graph with `provides` field)
- Network TLS scan results (if `networkHosts` specified)
- **Definitive PQC verdicts** on conditional assets (PBKDF2 iteration counts, AES key sizes, SecureRandom providers, KeyPairGenerator algorithms, etc.)

**Alternatively**, you can still combine scanners manually:

```bash
# Step 1: Scan source code
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/your-app"}' \
  -o your-app-cbom.json

# Step 2: Upload the CBOM
curl -X POST http://localhost:3001/api/upload/raw \
  -H "Content-Type: application/json" \
  -d @your-app-cbom.json
# Note the cbomId from the response

# Step 3: Merge network scan results
curl -X POST http://localhost:3001/api/scan-network/merge/urn:uuid:YOUR-CBOM-ID \
  -H "Content-Type: application/json" \
  -d '{"url": "your-app.com"}'
```

### Comparison Matrix

| Approach | Setup | Speed | Accuracy | Languages | Deps | PQC Verdicts | Runtime Crypto |
|----------|-------|-------|----------|-----------|------|-------------|----------------|
| **Regex Scanner** | None | Fast | Medium | Java, Python, JS/TS, C/C++, C#/.NET, Go, PHP | No | No | No |
| **sonar-cryptography** | High | Slow | Very High | Java, Python, Go | No | No | No |
| **Network TLS Scanner** | None | Fast | High (TLS) | N/A | No | No | Yes |
| **Full Pipeline** | Low–High | Medium | Highest | All | Yes | Yes | Yes |

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

All integration configurations are **persisted in MariaDB** via Sequelize ORM and accessed through the [Integrations REST API](#integrations-rest-api). The frontend uses **RTK Query** for automatic data fetching, caching, and cache invalidation — see [Frontend State Management](#frontend-state-management-rtk-query).

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

Policies are persisted in MariaDB and managed via the [Policies REST API](#policies-rest-api).

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

Both follow the same pattern as the reference config in `git-interface-app/server/sequelize.config.cjs`.

### Connection Pooling

```typescript
pool: {
  max: 10,      // max concurrent connections
  min: 0,       // min idle connections
  acquire: 30000, // ms to wait for connection before error
  idle: 10000,    // ms before idle connection is released
}
```

### Models

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

#### CbomUpload Table Schema

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

#### Crypto Policy Table Schema

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

#### Ticket Table Schema

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

#### Ticket Connector Table Schema

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

#### Integration Table Schema

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

#### Certificates Table Schema

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

#### Endpoints Table Schema

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

#### Software Table Schema

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

#### Devices Table Schema

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

#### CBOM Imports Table Schema

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

#### Sync Logs Table Schema

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

## Sync Scheduler

The backend includes a cron-based sync scheduler that automatically pulls data from external integrations on a configurable schedule. It uses **`node-cron`** for in-process cron job scheduling — no external daemon or message queue required.

### Architecture Overview

```
┌──────────────────────┐
│  Integration CRUD    │  ← user creates/updates/deletes integrations
│  (REST routes)       │
└──────┬───────────────┘
       │  lifecycle events (scheduleJob / onScheduleChanged / onIntegrationDeleted / onIntegrationToggled)
       ▼
┌──────────────────────┐
│  SyncScheduler       │  ← singleton, manages Map<integrationId, ScheduledJob>
│  (node-cron)         │  ← starts/stops/restarts cron tasks per integration
└──────┬───────────────┘
       │  on cron tick (or manual trigger)
       ▼
┌──────────────────────┐
│  SyncExecutor        │  ← 7-step sync lifecycle per integration
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

> **Simulated fallback**: Connectors in `connectors.ts` return simulated data when used without real credentials. Three integration types (**DigiCert TLM**, **GitHub CBOM Import**, and **Network TLS Scanner**) have production-grade connectors that call real external APIs — see [Real Connectors](#real-connectors).

### Sync Execution Lifecycle (7 Steps)

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
    ├── trackingApi.ts       — Tickets + Ticket Connectors + JIRA/GitHub/ServiceNow helpers
    └── index.ts             — re-exports all hooks + types
```

### Integrations API Hooks

The `integrationsApi` slice generates the following hooks, ready to use in any component:

| Hook | Type | Description |
|------|------|-------------|
| `useGetIntegrationsQuery()` | Query | Fetch all integrations (cached, auto-refetch on invalidation) |
| `useGetIntegrationQuery(id)` | Query | Fetch a single integration by ID |
| `useCreateIntegrationMutation()` | Mutation | Create a new integration |
| `useUpdateIntegrationMutation()` | Mutation | Update an existing integration |
| `useDeleteIntegrationMutation()` | Mutation | Delete an integration |
| `useToggleIntegrationMutation()` | Mutation | Toggle enabled/disabled |
| `useSyncIntegrationMutation()` | Mutation | Trigger a manual sync |
| `useTestIntegrationMutation()` | Mutation | Test connection credentials |

### Discovery API Hooks

Each of the five discovery API slices generates 8 hooks following the same pattern. The table below shows the hook names for each resource:

| Resource | List All | List by Integration | Get One | Create | Bulk Create | Update | Delete | Delete by Integration |
|----------|----------|-------------------|---------|--------|-------------|--------|--------|----------------------|
| **Certificates** | `useGetCertificatesQuery()` | `useGetCertificatesByIntegrationQuery(id)` | `useGetCertificateQuery(id)` | `useCreateCertificateMutation()` | `useBulkCreateCertificatesMutation()` | `useUpdateCertificateMutation()` | `useDeleteCertificateMutation()` | `useDeleteCertificatesByIntegrationMutation()` |
| **Endpoints** | `useGetEndpointsQuery()` | `useGetEndpointsByIntegrationQuery(id)` | `useGetEndpointQuery(id)` | `useCreateEndpointMutation()` | `useBulkCreateEndpointsMutation()` | `useUpdateEndpointMutation()` | `useDeleteEndpointMutation()` | `useDeleteEndpointsByIntegrationMutation()` |
| **Software** | `useGetSoftwareListQuery()` | `useGetSoftwareByIntegrationQuery(id)` | `useGetSoftwareQuery(id)` | `useCreateSoftwareMutation()` | `useBulkCreateSoftwareMutation()` | `useUpdateSoftwareMutation()` | `useDeleteSoftwareMutation()` | `useDeleteSoftwareByIntegrationMutation()` |
| **Devices** | `useGetDevicesQuery()` | `useGetDevicesByIntegrationQuery(id)` | `useGetDeviceQuery(id)` | `useCreateDeviceMutation()` | `useBulkCreateDevicesMutation()` | `useUpdateDeviceMutation()` | `useDeleteDeviceMutation()` | `useDeleteDevicesByIntegrationMutation()` |
| **CBOM Imports** | `useGetCbomImportsQuery()` | `useGetCbomImportsByIntegrationQuery(id)` | `useGetCbomImportQuery(id)` | `useCreateCbomImportMutation()` | `useBulkCreateCbomImportsMutation()` | `useUpdateCbomImportMutation()` | `useDeleteCbomImportMutation()` | `useDeleteCbomImportsByIntegrationMutation()` |

### xBOM API Hooks

The `xbomApi` slice provides hooks for managing the in-memory xBOM store:

| Hook | Type | Description |
|------|------|-------------|
| `useGetXBOMStatusQuery()` | Query | Check Trivy availability and xBOM service health |
| `useGenerateXBOMMutation()` | Mutation | Generate an xBOM by scanning a local repo |
| `useMergeXBOMMutation()` | Mutation | Merge pre-existing SBOM + CBOM documents |
| `useGetXBOMListQuery()` | Query | List all stored xBOMs (summary metadata) |
| `useGetXBOMQuery(id)` | Query | Retrieve a specific xBOM with analytics |
| `useDeleteXBOMMutation()` | Mutation | Delete a stored xBOM |

### CBOM Uploads API Hooks

The `cbomUploadsApi` slice provides hooks for managing CBOMs uploaded via the CBOM Analyzer page:

| Hook | Type | Description |
|------|------|-------------|
| `useGetCbomUploadsQuery()` | Query | List all uploaded CBOMs (excludes BLOB) |
| `useGetCbomUploadQuery(id)` | Query | Fetch a single upload with base64-encoded CBOM file |
| `useDeleteCbomUploadMutation()` | Mutation | Delete an uploaded CBOM |

### Sync Logs API Hooks

The `syncLogsApi` slice provides hooks for accessing the sync audit trail:

| Hook | Type | Description |
|------|------|-------------|
| `useGetSyncLogsQuery(limit?)` | Query | Fetch all sync logs (optional limit, default 100) |
| `useGetSyncLogsByIntegrationQuery(id)` | Query | Fetch sync logs for a specific integration |
| `useGetSyncLogQuery(id)` | Query | Fetch a single sync log by ID |
| `useDeleteSyncLogsByIntegrationMutation()` | Mutation | Delete all sync logs for an integration |

### Scheduler API Hooks

The `schedulerApi` slice provides hooks for monitoring and controlling the cron scheduler:

| Hook | Type | Description |
|------|------|-------------|
| `useGetSchedulerStatusQuery()` | Query | Fetch scheduler status (active jobs, uptime, server time) |
| `useStopSchedulerMutation()` | Mutation | Stop all cron jobs |
| `useRestartSchedulerMutation()` | Mutation | Restart scheduler — stops all, reloads from DB |

> All hooks are re-exported from `frontend/src/store/api/index.ts` and can be imported from `../../store`.

### Policies API Hooks

The `policiesApi` slice provides CRUD hooks for cryptographic policies:

| Hook | Type | Description |
|------|------|-------------|
| `useGetPoliciesQuery()` | Query | Fetch all policies |
| `useGetPolicyQuery(id)` | Query | Fetch a single policy |
| `useCreatePolicyMutation()` | Mutation | Create a new policy |
| `useBulkCreatePoliciesMutation()` | Mutation | Bulk create (preset seeding) |
| `useUpdatePolicyMutation()` | Mutation | Update a policy |
| `useDeletePolicyMutation()` | Mutation | Delete a policy |

### Tracking API Hooks

The `trackingApi` slice provides hooks for tickets and ticket connectors:

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
| `useLazyGetJiraAssignableUsersQuery()` | Lazy Query | Load assignable users for a project |
| `useLazyGetJiraBoardsQuery()` | Lazy Query | Load boards for a project |
| `useLazyGetGitHubOrgsQuery()` | Lazy Query | Load GitHub organizations |
| `useLazyGetGitHubReposByOwnerQuery()` | Lazy Query | Load repos for an owner/org |
| `useLazyGetGitHubCollaboratorsQuery()` | Lazy Query | Load collaborators for a repo |

### Cache Invalidation Strategy

RTK Query uses **tags** for automatic cache invalidation across all 9 API slices:

- Each record is tagged with `{ type: '<Tag>', id }` (e.g., `{ type: 'Certificate', id: 'abc-123' }`)
- The full list is tagged with `{ type: '<Tag>', id: 'LIST' }`
- Mutations (create, bulk create, update, delete) **invalidate** both the specific tag and the list tag
- This means any list query auto-refetches after any mutation — no manual refetch needed

**Tag types:** `Integration`, `Certificate`, `Endpoint`, `Software`, `Device`, `CbomImport`, `CbomUpload`, `SyncLog`, `Scheduler`, `Policy`, `Ticket`, `TicketConnector`

### Usage in Components

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

## Variable Resolution & Context Scanning

The regex scanner includes two advanced analysis capabilities that go beyond simple pattern matching.

### Supported Languages & Libraries

The built-in regex scanner ships with **~700 patterns** covering 7 language ecosystems:

| Language | File Extensions | Libraries / APIs Covered |
|----------|----------------|-------------------------|
| **Java** | `.java` | JCE (`MessageDigest`, `Cipher`, `Signature`, `KeyPairGenerator`, `Mac`, `KeyAgreement`, `SecretKeyFactory`), `SSLContext`, `X509Certificate`, `SecureRandom`, BouncyCastle provider |
| **Python** | `.py` | `hashlib`, PyCrypto/PyCryptodome, `cryptography.hazmat` (ciphers, hashes, KDF, RSA, EC, Ed25519/Ed448, X25519/X448, DH, X.509, Fernet), PyNaCl, `ssl`, `secrets`, `bcrypt`, `argon2`, `scrypt` |
| **JavaScript / TypeScript** | `.js`, `.ts`, `.jsx`, `.tsx` | Node.js `crypto` (createHash, createCipher, createSign, ECDH, HKDF, scrypt, pbkdf2, generateKeyPair), WebCrypto (`crypto.subtle`), TLS (`createSecureContext`, `https`), npm packages (`bcrypt`, `jsonwebtoken`, `jose`, `tweetnacl`, `libsodium-wrappers`, `argon2`) |
| **C / C++** | `.c`, `.cpp`, `.cxx`, `.cc`, `.h`, `.hpp`, `.hxx` | OpenSSL EVP + legacy APIs, libsodium, Botan (including PQC: Dilithium, Kyber, SPHINCS+), Crypto++, Windows CNG/BCrypt, wolfSSL, mbedTLS, GnuTLS |
| **C# / .NET** | `.cs` | `System.Security.Cryptography` (Create, Managed, CNG, CSP variants), HMAC, `Rfc2898DeriveBytes`, HKDF, `X509Certificate2`, `SslStream`, DPAPI, ASP.NET Core Data Protection, BouncyCastle .NET |
| **Go** | `.go` | `crypto/*` stdlib (`sha256`, `aes`, `rsa`, `ecdsa`, `ecdh`, `ed25519`, `hmac`, `tls`, `x509`, `rand`, `elliptic`, `cipher`), `golang.org/x/crypto` (`chacha20poly1305`, `argon2`, `bcrypt`, `scrypt`, `nacl`, `hkdf`, `pbkdf2`, `sha3`, `blake2b/s`, `ssh`, `curve25519`) |
| **PHP** | `.php` | `openssl_*` (encrypt, sign, pkey, x509, pkcs), `hash`/`hash_hmac`/`hash_pbkdf2`, `password_hash` (bcrypt, argon2), `sodium_crypto_*` (secretbox, box, sign, aead, pwhash, kdf, kx), `mcrypt` (deprecated), phpseclib, Defuse PHP-Encryption |

### Scanner Module Architecture

The scanner is organized into a modular structure under `backend/src/services/scanner/`:

```
scanner/
├── scannerTypes.ts          # CryptoPattern interface, file extension constants, skip patterns
├── scannerUtils.ts          # globToRegex, shouldExcludeFile, normaliseAlgorithmName, resolveVariableToAlgorithm
├── contextScanners.ts       # scanWebCryptoContext, scanX509Context, scanNearbyContext
└── patterns/
    ├── index.ts             # Re-exports all patterns + combined allCryptoPatterns array
    ├── javaPatterns.ts      # ~43 Java/JCE patterns
    ├── pythonPatterns.ts    # ~60 Python patterns
    ├── jsPatterns.ts        # ~40 JavaScript/TypeScript patterns
    ├── cppPatterns.ts       # ~170 C/C++ patterns
    ├── csharpPatterns.ts    # ~100 C#/.NET patterns
    ├── goPatterns.ts        # ~130 Go patterns
    └── phpPatterns.ts       # ~130 PHP patterns
```

Each pattern file exports a `CryptoPattern[]` array. The `allCryptoPatterns` combined array is used by `scannerAggregator.ts` to drive the scan loop.

### Variable-Argument Resolution

When the scanner encounters crypto API calls that use a **variable** instead of a string literal (e.g., `KeyPairGenerator.getInstance(algorithm)` instead of `getInstance("RSA")`), it attempts to **resolve the variable to an actual algorithm name**.

**How it works:**

1. The scanner detects a variable-arg pattern like `KeyPairGenerator.getInstance(algo)`
2. It scans ±50 lines around the call site for assignment patterns:
   - `String algo = "RSA";`
   - `algo = "EC";`
   - `final String algo = "ML-KEM";`
3. If the variable is a method parameter, it traces callers in the same file for the concrete value
4. If resolved → the asset is named with the **actual algorithm** (e.g., `RSA`) and enriched with PQC data
5. If unresolved → the asset keeps a generic name with a description like *"Algorithm determined at runtime via variable `algo`"*

**Supported variable patterns (Java):**
- `KeyPairGenerator.getInstance(variable)`
- `Cipher.getInstance(variable)`
- `MessageDigest.getInstance(variable)`
- `Signature.getInstance(variable)`
- `SecretKeyFactory.getInstance(variable)`
- `KeyAgreement.getInstance(variable)`
- `Mac.getInstance(variable)`

**Additional variable resolution:**
- **Go:** Traces function parameters and `var`/`:=` assignments to resolve algorithm names passed to `crypto/*` calls
- **Algorithm normalisation:** Handles OpenSSL cipher strings (e.g., `aes-256-gcm` → `AES`), Go import paths (e.g., `crypto/sha256` → `SHA-256`), and framework-specific naming conventions

### Context Scanning

For certain crypto patterns whose security depends on **how they're used**, the scanner examines surrounding source code to provide richer context.

**How it works:**

1. Patterns like `X509Certificate`, `X509TrustManager`, and `BouncyCastleProvider` trigger context scanning
2. The scanner reads ±30 lines around the detection site
3. It looks for `getInstance()` calls and signature algorithm references (e.g., `SHA256withRSA`, `ECDSA`)
4. The asset description is enriched, e.g.:
   > *"X.509 used alongside: SHA256withRSA, RSA. Review these algorithms for PQC readiness."*

**Context-scanned patterns:**

| Pattern | Detection | Context Gathered |
|---------|-----------|------------------|
| **X.509 Certificate** | `X509Certificate`, `X509TrustManager` | Nearby `getInstance()` calls, signature algorithms |
| **BouncyCastle Provider** | `new BouncyCastleProvider()`, `PROVIDER_NAME` | Nearby algorithm instantiations |

This helps reviewers understand the **full cryptographic picture** around certificate and provider usage, even when the X.509 or provider reference itself doesn't name a specific algorithm.

---

## Third-Party Dependency Scanning

The full scan pipeline (`POST /api/scan-code/full`) automatically discovers
cryptographic libraries declared in your project's dependency manifests,
resolves transitive dependencies where tools are available, and converts every
known algorithm into a first-class CBOM crypto-asset — all without touching
source code.

### How It Works — Step by Step

```
┌─────────────────────────────────────────────────────────────────┐
│  1. DISCOVER manifest files                                     │
│     find <repoPath> … -name "pom.xml" -o -name "package.json"  │
│     … skipping node_modules, .git, target, build, dist, vendor  │
├─────────────────────────────────────────────────────────────────┤
│  2. PARSE each manifest with an ecosystem-specific parser       │
│     parseMavenPom()  → pom.xml                                  │
│     parseGradleBuild() → build.gradle / build.gradle.kts        │
│     parsePackageJson() → package.json                           │
│     parseRequirementsTxt() → requirements.txt / requirements-*  │
│     parseSetupPy() → setup.py (install_requires)                │
│     parseGoMod() → go.mod                                       │
├─────────────────────────────────────────────────────────────────┤
│  3. MATCH against Known Crypto Library Database                 │
│     groupId:artifactId prefix match (Maven/Gradle)              │
│     exact package name match (npm, pip)                         │
│     module path prefix match (Go)                               │
├─────────────────────────────────────────────────────────────────┤
│  4. RESOLVE transitive dependencies (best-effort)               │
│     Maven  → mvn dependency:tree -DoutputType=text              │
│     npm    → npm ls --json --all (walks up to depth 5)          │
│     Others → manifest-level only (direct deps)                  │
├─────────────────────────────────────────────────────────────────┤
│  5. DEDUPLICATE by groupId:artifactId:packageManager            │
│     keep the entry with the lowest dependency depth             │
├─────────────────────────────────────────────────────────────────┤
│  6. CONVERT to CBOM CryptoAssets via cryptoLibToCBOMAssets()    │
│     each algorithm the library provides → separate crypto-asset │
│     enriched with PQC verdict + quantum safety status           │
└─────────────────────────────────────────────────────────────────┘
```

### Supported Manifest Files

| Ecosystem | Manifest File(s) | Parser | Transitive Resolution |
|-----------|------------------|--------|-----------------------|
| **Maven** | `pom.xml` | `parseMavenPom()` — extracts `<dependency>` blocks with `<groupId>`, `<artifactId>`, `<version>` | Yes — `mvn dependency:tree` (120 s timeout) |
| **Gradle** | `build.gradle` / `.kts` | `parseGradleBuild()` — matches `implementation`, `api`, `compileOnly`, `runtimeOnly`, `testImplementation` | Manifest-level only |
| **npm** | `package.json` | `parsePackageJson()` — reads `dependencies` + `devDependencies` via `JSON.parse` | Yes — `npm ls --json --all` (depth ≤ 5) |
| **pip** | `requirements.txt`, `requirements-*.txt` | `parseRequirementsTxt()` — handles `==`, `>=`, `~=` specifiers + comments/flags | Manifest-level only |
| **pip** | `setup.py` | `parseSetupPy()` — extracts from `install_requires=[…]` | Manifest-level only |
| **Go** | `go.mod` | `parseGoMod()` — parses `require` blocks + single require lines | Manifest-level only |

> Every parser records the **line number** in the manifest file where the
> dependency is declared, so the dashboard links directly to the right location.

### Known Crypto Library Database

The scanner ships a curated database of **50+ cryptographic libraries** across
four ecosystems. Each entry stores the library's display name, known
algorithms, quantum safety status, and a description.

**Maven / Gradle** — matched by `groupId:artifactId` prefix:

| Library | Key | Quantum Safety | Algorithms |
|---------|-----|---------------|------------|
| BouncyCastle Provider | `org.bouncycastle:bcprov` | Conditional | RSA, ECDSA, AES, SHA-256, Ed25519, ML-KEM, ML-DSA |
| BouncyCastle PKIX | `org.bouncycastle:bcpkix` | Not Quantum Safe | X.509, CMS, OCSP, RSA, ECDSA |
| BouncyCastle PQC | `org.bouncycastle:bcpqc` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA, FALCON, SPHINCS+ |
| BouncyCastle FIPS | `org.bouncycastle:bcfips` | Conditional | AES, SHA-256, RSA, ECDSA, HMAC, DRBG |
| Google Tink | `com.google.crypto.tink:tink` | Not Quantum Safe | AES-GCM, ECDSA, Ed25519, RSA-SSA-PKCS1 |
| Conscrypt | `org.conscrypt:conscrypt` | Not Quantum Safe | TLSv1.3, AES-GCM, ChaCha20-Poly1305, ECDHE |
| Nimbus JOSE+JWT | `com.nimbusds:nimbus-jose-jwt` | Not Quantum Safe | RSA, ECDSA, AES, Ed25519 |
| JJWT | `io.jsonwebtoken:jjwt` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| Apache Commons Crypto | `org.apache.commons:commons-crypto` | Quantum Safe | AES, AES-CTR, AES-CBC |
| Spring Security Crypto | `…:spring-security-crypto` | Conditional | PBKDF2, BCrypt, SCrypt, AES-GCM, Argon2 |
| Jasypt | `org.jasypt:jasypt` | Not Quantum Safe | PBKDF2, AES, DES, 3DES, MD5 |
| Argon2 JVM | `de.mkammerer:argon2-jvm` | Quantum Safe | Argon2id, Argon2i, Argon2d |

**npm** — matched by exact package name:

| Library | Package | Quantum Safety | Algorithms |
|---------|---------|---------------|------------|
| CryptoJS | `crypto-js` | Conditional | AES, DES, SHA-256, MD5, PBKDF2, RC4 |
| Node Forge | `node-forge` | Not Quantum Safe | RSA, AES, DES, X.509, TLS |
| TweetNaCl | `tweetnacl` | Not Quantum Safe | Curve25519, Ed25519, XSalsa20 |
| libsodium | `libsodium-wrappers` | Not Quantum Safe | X25519, Ed25519, ChaCha20-Poly1305, Argon2id |
| jsonwebtoken | `jsonwebtoken` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| jose | `jose` | Not Quantum Safe | RSA, ECDSA, Ed25519, AES-GCM |
| elliptic | `elliptic` | Not Quantum Safe | ECDSA, ECDH, secp256k1 |
| OpenPGP.js | `openpgp` | Not Quantum Safe | RSA, ECDSA, ECDH, AES |
| @noble/curves | `@noble/curves` | Not Quantum Safe | secp256k1, Ed25519, P-256, P-384 |
| @noble/hashes | `@noble/hashes` | Quantum Safe | SHA-256, SHA-3, BLAKE2, BLAKE3 |
| bcrypt | `bcrypt` | Quantum Safe | BCrypt |
| argon2 | `argon2` | Quantum Safe | Argon2id, Argon2i |
| pqcrypto | `pqcrypto` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA |
| crystals-kyber | `crystals-kyber` | Quantum Safe | ML-KEM |

**pip** — matched by normalized package name (underscore → hyphen):

| Library | Package | Quantum Safety | Algorithms |
|---------|---------|---------------|------------|
| cryptography | `cryptography` | Not Quantum Safe | RSA, ECDSA, AES, X.509, HKDF, PBKDF2 |
| PyCryptodome | `pycryptodome` | Not Quantum Safe | RSA, AES, DES, ChaCha20, scrypt |
| PyNaCl | `pynacl` | Not Quantum Safe | Curve25519, Ed25519, BLAKE2b |
| pyOpenSSL | `pyopenssl` | Not Quantum Safe | RSA, ECDSA, TLS, X.509 |
| PyJWT | `pyjwt` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| passlib | `passlib` | Conditional | BCrypt, SCrypt, Argon2, PBKDF2 |
| bcrypt | `bcrypt` | Quantum Safe | BCrypt |
| argon2-cffi | `argon2-cffi` | Quantum Safe | Argon2id, Argon2i |
| pqcrypto | `pqcrypto` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA |
| liboqs-python | `oqs` | Quantum Safe | ML-KEM, ML-DSA, FALCON |

**Go** — matched by module path prefix:

| Library | Module | Quantum Safety | Algorithms |
|---------|--------|---------------|------------|
| golang.org/x/crypto | `golang.org/x/crypto` | Not Quantum Safe | ChaCha20-Poly1305, Ed25519, Argon2, BCrypt |
| Cloudflare CIRCL | `github.com/cloudflare/circl` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA, X25519, HPKE |
| liboqs-go | `github.com/open-quantum-safe/liboqs-go` | Quantum Safe | ML-KEM, ML-DSA, FALCON |

### Transitive Dependency Resolution

When available tooling exists on the runner, the scanner resolves dependencies
*beyond* the manifest file:

**Maven** — runs `mvn dependency:tree -DoutputType=text -q` (120 s timeout),
parses the indented tree output to calculate depth and identify crypto
libraries hidden behind non-crypto intermediaries.

**npm** — runs `npm ls --json --all` (60 s timeout), recursively walks the
dependency tree up to **depth 5** with cycle detection (`visited` set).

Both resolvers skip depth 0 entries (already captured by manifest parsing) and
tag results with `isDirectDependency: false` and the actual depth number.

> If Maven or npm are not installed (e.g. in the GitHub Action Docker image
> before a `build` step), transitive resolution fails silently and the scanner
> returns only direct dependencies.

### From Library to CBOM Asset

Each detected library is exploded into **one CryptoAsset per algorithm**. For
example, `node-forge` in `package.json` produces separate assets for RSA, AES,
DES, 3DES, SHA-256, MD5, HMAC, PBKDF2, X.509, and TLS — each with:

| Field | Value |
|-------|-------|
| `name` | The algorithm name (e.g. `RSA`) |
| `type` | `crypto-asset` |
| `cryptoProperties.assetType` | `algorithm`, `certificate`, or `protocol` |
| `location.fileName` | Manifest path (e.g. `package.json`) |
| `location.lineNumber` | Line where the dependency is declared |
| `provider` | Library display name (e.g. `Node Forge`) |
| `detectionSource` | `dependency` |
| `description` | "Provided by Node Forge v1.3.1 (npm: node-forge). Detected as a direct dependency in package.json:12." |
| `quantumSafety` | Enriched by `enrichAssetWithPQCData()` from the PQC Risk Engine |

### Deduplication

After all parsers + transitive resolvers run, the scanner deduplicates by
`groupId:artifactId:packageManager`. When duplicates exist (e.g. a library
appears both as a direct and transitive dependency), the entry with the
**lowest depth** wins, ensuring the most direct reference is kept.

### Dashboard View

The frontend displays a **Third-Party Crypto Libraries** section below the asset list, showing:
- Safety badge (Quantum Safe / Not Quantum Safe / Conditional / Unknown)
- Package manager badge (Maven, npm, pip, Go)
- Direct vs. transitive dependency indicator
- Transitive depth (how many hops from your direct dependencies)
- Expandable cards with dependency path and known algorithms
- Filter by package manager

---

## PQC Readiness Verdicts

For assets classified as **Conditional** (e.g., PBKDF2, AES, SecureRandom, KeyPairGenerator), the scanner now performs **smart parameter analysis** to deliver definitive PQC readiness verdicts instead of vague labels.

### How It Works

1. The scanner detects a conditional crypto usage (e.g., `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`)
2. It reads ±15 lines of surrounding source code
3. It extracts actual parameters (iteration count, key length, algorithm, provider)
4. It applies PQC-aware rules to emit a verdict with confidence score

### Verdict Types

| Verdict | Meaning | Example |
|---------|---------|--------|
| **PQC_READY** | Safe for the post-quantum era | AES-256, PBKDF2 ≥ 600k iterations + 256-bit key |
| **NOT_PQC_READY** | Vulnerable to quantum attack | RSA-2048 KeyPairGenerator, ECDSA Signature |
| **REVIEW_NEEDED** | Cannot determine automatically | Custom providers, runtime-selected algorithms |

### Analyzers

| Crypto Pattern | What's Extracted | Verdict Rules |
|---------------|-----------------|---------------|
| **PBKDF2** | Iteration count, key length, hash algorithm | ≥ 600k iterations + ≥ 256-bit key + SHA-256/512 → PQC_READY |
| **AES** | Key size (128/192/256) from constant or variable name | AES-256 → PQC_READY; AES-128 → NOT_PQC_READY |
| **SecureRandom** | Provider (NativePRNG, DRBG, SHA1PRNG, default) | DRBG/NativePRNG → PQC_READY; default → REVIEW_NEEDED |
| **KeyPairGenerator** | Algorithm (RSA, EC, ML-KEM, ML-DSA, etc.) | RSA/EC → NOT_PQC_READY; ML-KEM/ML-DSA → PQC_READY |
| **Signature** | Algorithm (SHA256withRSA, SHA384withECDSA, etc.) | RSA/ECDSA → NOT_PQC_READY; ML-DSA → PQC_READY |
| **SecretKeyFactory** | Delegates to PBKDF2 or AES analysis | Based on underlying algorithm |
| **X.509 Certificate** | Certificate type, signature algorithm, key usage | RSA/ECDSA-signed certs → NOT_PQC_READY; PQC-signed → PQC_READY |
| **TLS/SSL** | Protocol version, cipher suite | TLS 1.3 with PQC KEM → PQC_READY; legacy suites → NOT_PQC_READY |
| **TSP (Timestamping)** | Timestamp hash algorithm | SHA-256+ → REVIEW_NEEDED; SHA-1 → NOT_PQC_READY |
| **CMS/PKCS#7** | Signing algorithm, envelope encryption | RSA/ECDSA → NOT_PQC_READY |
| **OCSP** | Response signing algorithm | RSA/ECDSA → NOT_PQC_READY |

### Algorithm Database Entries

The scanner includes a comprehensive **ALGORITHM_DATABASE** with quantum safety classifications for 80+ algorithms. Recent additions include:

| Algorithm | Classification | Notes |
|-----------|---------------|-------|
| `CAST5` | NOT_QUANTUM_SAFE | Legacy 64-bit block cipher |
| `ElGamal` | NOT_QUANTUM_SAFE | Discrete logarithm-based |
| `MessageDigest` | CONDITIONAL | Java JCE wrapper — safety depends on underlying algorithm |
| `NONE` | NOT_QUANTUM_SAFE | Raw signature without digest — no cryptographic protection |
| `NONEwithRSA` | NOT_QUANTUM_SAFE | RSA signature without hashing |
| `NONEwithECDSA` | NOT_QUANTUM_SAFE | ECDSA signature without hashing |

Non-cryptographic hash functions (`CRC32`, `Murmur3`) are **excluded** from scanning results — they are checksums, not crypto primitives.

### Promotion Rules

- If verdict is `PQC_READY` or `NOT_PQC_READY` with **confidence ≥ 75%**, the asset's `quantumSafety` status is automatically promoted from `CONDITIONAL` to `QUANTUM_SAFE` or `NOT_QUANTUM_SAFE`
- Otherwise, the asset stays `CONDITIONAL` with the verdict attached for manual review

### Scoring Impact

Verdicts affect the readiness score:
- `PQC_READY` → weight 1.0 (full marks)
- `NOT_PQC_READY` → weight 0.0 (zero)
- `REVIEW_NEEDED` → weight 0.5 (partial)
- Unanalyzed conditional → weight 0.75 (legacy)

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

## Sample Data & Demo Code

### Pre-Built CBOM Files

| File | Assets | Description |
|------|--------|-------------|
| `sample-data/keycloak-cbom.json` | 8 | Minimal Keycloak simulation |
| `sample-data/spring-petclinic-cbom.json` | 34 | Comprehensive Spring app |
| `frontend/src/sampleData.ts` | 58 | Built-in demo (click "sample CBOM file") |

### Demo Source Code

The `demo-code/` directory contains real source files with crypto API calls:

- **`demo-code/java/CryptoService.java`** — SHA-256, AES-GCM, RSA, ECDSA
- **`demo-code/java/AuthenticationModule.java`** — Password hashing, token signing
- **`demo-code/python/crypto_utils.py`** — hashlib, PyCryptodome, cryptography lib
- **`demo-code/typescript/cryptoUtils.ts`** — Node.js crypto module patterns

### Scanning the Demo Code

```bash
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/cbom-analyser"}' \
  -o cbom-analyser-cbom.json

# Expected: 40+ cryptographic assets detected
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Backend server port |
| `NODE_ENV` | `development` | Environment mode |
| `SONAR_HOST_URL` | `http://localhost:9090` | SonarQube server URL (for sonar-cryptography) |
| `SONAR_TOKEN` | — | SonarQube authentication token |
| `AWS_BEARER_TOKEN_BEDROCK` | — | AWS Bedrock bearer token (for AI suggestions) |
| `VITE_BEDROCK_API_ENDPOINT` | — | AWS Bedrock API endpoint URL |
| `VITE_ACCESS_KEY_ID` | — | AWS access key ID (alternative auth) |
| `VITE_SECRET_ACCESS_KEY` | — | AWS secret access key (alternative auth) |
| `VITE_SESSION_TOKEN` | — | AWS session token (alternative auth) |
| `DB_DATABASE` | `dcone-quantum-gaurd` | MariaDB database name |
| `DB_USERNAME` | `root` | MariaDB username |
| `DB_PASSWORD` | `asdasd` | MariaDB password |
| `DB_HOST` | `localhost` | MariaDB host |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_DIALECT` | `mariadb` | Sequelize dialect (`mariadb` or `mysql`) |

### Vite Proxy Configuration

The frontend proxies `/api/*` requests to the backend in development. See `frontend/vite.config.ts`:

```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:3001',
      changeOrigin: true
    }
  }
}
```

### nginx Configuration (Production)

The production frontend uses nginx to proxy API requests. See `frontend/nginx.conf`.

---

## CycloneDX 1.7 Standard

This project implements the **CycloneDX 1.7** specification for Cryptographic Bill of Materials.

### Asset Types

| Asset Type | Description |
|-----------|-------------|
| `algorithm` | Cryptographic algorithm (AES, RSA, SHA-256, etc.) |
| `protocol` | Cryptographic protocol (TLS 1.2, SSH, etc.) |
| `certificate` | X.509 certificates and chains |
| `related-crypto-material` | Keys, salts, IVs, nonces, credentials |
| `private-key` | Private key material |
| `public-key` | Public key material |
| `secret-key` | Symmetric secret key |

### Related Crypto Material Subtypes

| Type | Description |
|------|-------------|
| `salt` | Random salt for password hashing |
| `seed` | PRNG seed |
| `nonce` | Number used once |
| `iv` | Initialization vector |
| `shared-secret` | Diffie-Hellman shared secret |
| `credential` | Username / password credential |
| `password` | Password material |
| `key` | Generic key material |
| `ciphertext` | Encrypted data |
| `signature` | Digital signature value |
| `digest` | Hash digest output |
| `token` | Authentication token (JWT, API key) |
| `tag` | GCM authentication tag |
| `initialization-vector` | Full-name alias for IV |
| `private-key` / `public-key` / `secret-key` | Typed key material |
| `unknown` | Unclassified material |

### CBOM Document Structure

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    /* timestamp, tools, component */
    "repository": {
      "url": "https://github.com/org/repo",
      "branch": "main"
    }
  },
  "components": [],
  "cryptoAssets": [
    {
      "id": "uuid",
      "name": "AES-256",
      "type": "crypto-asset",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "parameterSetIdentifier": "256",
          "cryptoFunctions": ["encrypt", "decrypt"]
        }
      },
      "location": { "fileName": "src/Crypto.java", "lineNumber": 42 },
      "quantumSafety": "conditional",
      "pqcVerdict": {
        "verdict": "PQC_READY",
        "confidence": 90,
        "reasons": ["AES-256 key size provides sufficient post-quantum security margin"],
        "parameters": { "keySize": 256 },
        "recommendation": "No changes needed — AES-256 is considered PQC-safe."
      },
      "detectionSource": "sonar"
    }
  ],
  "dependencies": [
    {
      "ref": "maven:org.bouncycastle:bcprov-jdk18on",
      "dependsOn": [],
      "provides": ["algorithm:AES", "algorithm:RSA", "algorithm:ECDSA"]
    }
  ],
  "thirdPartyLibraries": [
    {
      "name": "bcprov-jdk18on",
      "groupId": "org.bouncycastle",
      "version": "1.78.1",
      "packageManager": "maven",
      "isDirect": true,
      "transitiveDepth": 0,
      "dependencyPath": ["bcprov-jdk18on"],
      "cryptoAlgorithms": ["AES", "RSA", "ECDSA", "SHA-256"],
      "quantumSafety": "conditional"
    }
  ]
}
```

### Quantum Safety Classification

| Status | Meaning |
|--------|---------|
| `quantum-safe` | Uses NIST-approved PQC algorithm or AES-256 |
| `not-quantum-safe` | Vulnerable to quantum attack (RSA, ECDSA, etc.) |
| `conditional` | Safety depends on parameters — analyzed by PQC verdict system |
| `unknown` | Not enough information to classify |

**Resources:**
- [CycloneDX 1.7 Specification](https://cyclonedx.org/docs/1.7/json/)
- [CycloneDX CBOM Guide](https://cyclonedx.org/capabilities/cbom/)
- [IBM sonar-cryptography](https://github.com/cbomkit/sonar-cryptography)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## 17. xBOM — Unified Software + Cryptographic Bill of Materials

### 17.1 Concept

**xBOM** merges a **Software Bill of Materials (SBOM)** with a **Cryptographic Bill of Materials (CBOM)** into a single CycloneDX document. This unified view links every software dependency to the cryptographic algorithms it uses, providing complete visibility into both supply-chain vulnerabilities and quantum readiness in one artefact.

| Layer | Source | Content |
|-------|--------|---------|
| **SBOM** | [Trivy](https://github.com/aquasecurity/trivy) (Aqua Security) | Packages, licenses, CVEs |
| **CBOM** | CBOM Analyser (this project) | Algorithms, protocols, keys, certificates |
| **Cross-references** | Merge engine | Links between software components and crypto assets |

### 17.2 Architecture

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

### 17.3 Cross-Reference Linking Strategies

The merge engine builds relational links between SBOM components and CBOM crypto assets using three strategies:

| Strategy | Key | How it works |
|----------|-----|-------------|
| **Dependency Manifest** | `dependency-manifest` | Matches CBOM third-party library PURLs against SBOM component PURLs |
| **File Co-location** | `file-co-location` | When a crypto asset's source file path falls inside a component's directory |
| **Dependency Graph** | `dependency-graph` | CBOM dependency refs that match SBOM component bom-refs |

### 17.4 REST API

All endpoints are mounted at `/api/xbom`.

#### GET `/api/xbom/status`

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

#### POST `/api/xbom/generate`

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

#### POST `/api/xbom/merge`

Merge pre-existing SBOM + CBOM documents. Accepts JSON body or multipart file upload (fields: `sbomFile`, `cbomFile`).

**JSON body:**
```json
{
  "sbom": { "bomFormat": "CycloneDX", "components": [...] },
  "cbom": { "bomFormat": "CycloneDX", "cryptoAssets": [...] },
  "repoUrl": "https://github.com/owner/repo"
}
```

**Response:** `{ success, message, xbom, analytics }`

#### GET `/api/xbom/list`

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

#### GET `/api/xbom/:id`

Retrieve a specific xBOM with computed analytics (quantum readiness, compliance, vulnerability summary).

**Response:** `{ success, xbom, analytics }`

#### GET `/api/xbom/:id/download`

Download the xBOM as a JSON file (`Content-Disposition: attachment`).

#### DELETE `/api/xbom/:id`

Delete a stored xBOM.

### 17.5 Frontend Pages

xBOMs are accessible from **two locations** in the UI:

#### A. Tools → xBOM Page

The standalone xBOM page provides:

| View | Description |
|------|-------------|
| **Status cards** | Trivy availability, stored xBOM count, SBOM/CBOM capability status |
| **Generate form** | Scan a local repo path; select mode (full / SBOM-only / CBOM-only) |
| **Merge form** | Paste or upload existing SBOM + CBOM JSON files to merge |
| **Stored xBOMs list** | Table of previously generated xBOMs with view/delete actions |

#### B. Discovery → BOM Imports → xBOM Analysis Tab

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

#### Detail View Tabs

Clicking an xBOM (in either page) opens the **Detail View** with five tabs:

| Tab | Content |
|-----|---------|
| **Overview** | Summary cards, quantum readiness scores, vulnerability breakdown |
| **Software** | Table of all SBOM components (name, version, type, PURL, licenses) |
| **Crypto Assets** | Table of all CBOM crypto assets (algorithm, primitive, quantum safety, source file) |
| **Vulnerabilities** | CVEs from Trivy with severity, score, description, recommendation |
| **Cross-References** | Relational links between software and crypto, grouped by link method |

### 17.6 RTK Query Hooks

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

### 17.7 Unified Pipeline (`.github/workflows/pipeline.yml`)

The unified pipeline automates CBOM, SBOM, and xBOM generation in CI. All three scans run as separate jobs, and the xBOM merge job combines SBOM + CBOM into a unified xBOM artifact.

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

**Jobs & Artifacts:**

| Job | Produces | Description |
|-----|----------|-------------|
| `cbom-scan` | `cbom-report` | Runs CBOM Analyser action → `cbom-report.json` |
| `sbom-scan` | `sbom-report` | Runs Trivy SBOM scan → `sbom.json` |
| `xbom-merge` | `xbom-report` | Merges SBOM + CBOM → `xbom.json` with cross-references and analytics |
| `build-backend` | — | Builds backend Docker image |
| `build-frontend` | — | Builds frontend Docker image |
| `deploy` | — | Deploys to production (on release) |

**xBOM merge step details:**
1. **Downloads** both `sbom-report` and `cbom-report` artifacts
2. **Merges** software components, crypto assets, dependencies, vulnerabilities
3. **Builds cross-references** by matching CBOM third-party library PURLs against SBOM component PURLs
4. **Computes analytics** — quantum readiness score, vulnerability breakdown, component counts
5. **Writes** `xbom.json` and uploads as `xbom-report` artifact

**Key outputs:**
`total-components`, `total-crypto-assets`, `total-vulnerabilities`, `total-cross-references`, `readiness-score`, `quantum-safe`, `not-quantum-safe`, `vuln-critical`, `vuln-high`

#### Auto-Sync to BOM Imports

When a **CBOM File Import** integration is configured with `includeSbom: "true"` and `includeXbom: "true"`, the GitHub connector automatically downloads all three artifacts from each workflow run and stores them as BLOBs in the `cbom_imports` table. The imported xBOM files are then loaded into the in-memory xBOM store, making them immediately visible in the **BOM Imports → xBOM Analysis** tab.

### 17.8 Trivy Integration

The backend Trivy scanner (`backend/src/services/trivyScanner.ts`) wraps the Trivy CLI:

| Function | Description |
|----------|-------------|
| `isTrivyInstalled()` | Checks if `trivy` is on `$PATH` |
| `getTrivyVersion()` | Returns installed Trivy version |
| `runTrivyScan(options)` | Runs `trivy fs --format cyclonedx` with severity filter, 5-min timeout |
| `parseSBOMFile(input)` | Parses CycloneDX JSON from string or file path |

If Trivy is not installed, the xBOM API gracefully degrades — SBOM generation is unavailable but CBOM-only mode and manual merge still work.

### 17.9 xBOM DB Loader

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

### 17.10 File Reference

| File | Purpose |
|------|---------|
| `backend/src/types/sbom.types.ts` | Trivy CycloneDX SBOM type definitions |
| `backend/src/types/xbom.types.ts` | Unified xBOM type definitions |
| `backend/src/services/trivyScanner.ts` | Trivy CLI integration |
| `backend/src/services/xbomMergeService.ts` | SBOM + CBOM → xBOM merge with cross-references |
| `backend/src/services/xbomDbLoader.ts` | Loads xBOM files from DB into in-memory `xbomStore` |
| `backend/src/routes/xbomRoutes.ts` | 7 REST API endpoints |
| `backend/src/services/githubCbomConnector.ts` | GitHub Actions connector — fetches CBOM, SBOM, and xBOM artifacts |
| `.github/workflows/pipeline.yml` | Unified CI pipeline — CBOM scan, SBOM scan, xBOM merge |
| `frontend/src/pages/XBOMPage.tsx` | xBOM list, generate, merge, and detail views |
| `frontend/src/pages/XBOMPage.module.scss` | Styles for xBOM page |
| `frontend/src/pages/discovery/tabs/CbomImportsTab.tsx` | BOM Imports tab — includes xBOM Analysis sub-tab with inline detail view |
| `frontend/src/components/bom-panels/BomDownloadButtons.tsx` | Download buttons with labeled BOM type (CBOM / SBOM / xBOM) |
| `frontend/src/store/api/xbomApi.ts` | RTK Query API slice with 6 hooks |
| `backend/src/models/CbomUpload.ts` | Sequelize model for `cbom_uploads` table (persisted CBOM uploads) |
| `backend/src/routes/cbomUploadRoutes.ts` | CRUD routes for uploaded CBOMs (`GET`, `GET /:id`, `DELETE /:id`) |
| `frontend/src/store/api/cbomUploadsApi.ts` | RTK Query API slice for CBOM uploads (3 hooks) |
| `frontend/src/pages/discovery/utils/exportCsv.ts` | Generic CSV export utility for Discovery tab tables |
| `frontend/src/pages/discovery/components/shared.module.scss` | Shared Discovery tab styles — includes AI close button (`.aiCloseBtn`) |

---

*For detailed technical documentation, architecture deep-dives, and implementation details, see [README.md](README.md).*
