# QuantumGuard CBOM Hub — Usage Guide

> **Practical guide for running, integrating, and using QuantumGuard CBOM Hub**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [GitHub Actions Integration](#github-actions-integration)
3. [Docker Deployment](#docker-deployment)
4. [API Reference](#api-reference)
5. [Scanning Approaches](#scanning-approaches)
6. [Sample Data & Demo Code](#sample-data--demo-code)
7. [Configuration](#configuration)

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

Use QuantumGuard as a GitHub Action to scan your repository and generate a CBOM on every push or PR.

### Setup — Adding the Action to Your Repository

The CBOM scanner runs as a **Docker-based GitHub Action**. You need to copy the action files into your target repository before using it.

**Step 1:** In your target repository, create the action directory:

```bash
mkdir -p .github/actions/cbom-analyser
```

**Step 2:** Copy these 3 files from the [cbom-analyser repo](https://github.com/test-srm-digi/cbom-analyser) into `.github/actions/cbom-analyser/`:

| File | What it does |
|------|-------------|
| `action.yml` | Defines the action inputs, outputs, and Docker config |
| `Dockerfile.action` | Builds the Node.js scanner image |
| `entrypoint.sh` | Runs the scan and produces output |

You also need the `backend/` and `frontend/` source directories alongside these files for the Docker build. The simplest approach is to copy the entire cbom-analyser project:

```bash
# From your target repo root
git clone https://github.com/test-srm-digi/cbom-analyser.git /tmp/cbom-analyser

# Copy action files
cp /tmp/cbom-analyser/action.yml       .github/actions/cbom-analyser/
cp /tmp/cbom-analyser/Dockerfile.action .github/actions/cbom-analyser/
cp /tmp/cbom-analyser/entrypoint.sh     .github/actions/cbom-analyser/

# Copy source code needed by the Docker build
cp -r /tmp/cbom-analyser/backend        .github/actions/cbom-analyser/
cp -r /tmp/cbom-analyser/frontend       .github/actions/cbom-analyser/
cp /tmp/cbom-analyser/package.json      .github/actions/cbom-analyser/
cp /tmp/cbom-analyser/package-lock.json .github/actions/cbom-analyser/
cp /tmp/cbom-analyser/tsconfig.json     .github/actions/cbom-analyser/

# Clean up
rm -rf /tmp/cbom-analyser
```

**Step 3:** Your repository structure should now look like:

```
your-project/
├── .github/
│   ├── actions/
│   │   └── cbom-analyser/
│   │       ├── action.yml
│   │       ├── Dockerfile.action
│   │       ├── entrypoint.sh
│   │       ├── package.json
│   │       ├── package-lock.json
│   │       ├── tsconfig.json
│   │       ├── backend/
│   │       └── frontend/
│   └── workflows/
│       └── cbom-scan.yml          ← your workflow file
├── src/
│   └── ... (your project code)
└── ...
```

**Step 4:** Create your workflow file (see examples below).

> **Tip:** Make sure `entrypoint.sh` has execute permission. If you get a "permission denied" error, run: `chmod +x .github/actions/cbom-analyser/entrypoint.sh` and commit.

---

### Basic Usage

Create `.github/workflows/cbom-scan.yml`:

```yaml
name: CBOM Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  cbom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run CBOM Scanner
        uses: ./.github/actions/cbom-analyser
        with:
          scan-path: '.'
          output-format: 'json'
```

### Advanced Usage with All Options

```yaml
name: CBOM Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  cbom-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run QuantumGuard CBOM Scanner
        id: cbom
        uses: ./.github/actions/cbom-analyser
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
  uses: ./.github/actions/cbom-analyser
  with:
    output-format: 'sarif'

- name: Upload SARIF Results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cbom.sarif
```

> **Note:** The `permissions` block with `security-events: write` is required for SARIF uploads to the GitHub Security tab.

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan (relative to repo root) | `.` |
| `output-format` | Output format: `json`, `sarif`, or `summary` | `summary` |
| `output-file` | Path to save the CBOM output file | `cbom-report.json` |
| `fail-on-vulnerable` | Fail if non-quantum-safe algorithms found | `false` |
| `quantum-safe-threshold` | Minimum quantum readiness score (0-100) to pass | `0` |
| `exclude-patterns` | Comma-separated glob patterns to exclude, or `default` | (none) |

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
- uses: ./.github/actions/cbom-analyser
  with:
    exclude-patterns: 'default'

# Custom exclusions
- uses: ./.github/actions/cbom-analyser
  with:
    exclude-patterns: '**/test/**,**/*.test.ts,**/mock/**'

# Combine default + custom
- uses: ./.github/actions/cbom-analyser
  with:
    exclude-patterns: 'default,**/legacy/**,**/vendor/**'
```

**Default Exclusion Patterns:**
- `**/test/**`, `**/tests/**`, `**/__tests__/**`
- `**/*.test.ts`, `**/*.test.js`, `**/*.test.tsx`, `**/*.test.jsx`
- `**/*.spec.ts`, `**/*.spec.js`, `**/*.spec.tsx`, `**/*.spec.jsx`
- `**/Test.java`, `**/*Test.java`, `**/*Tests.java`
- `**/test_*.py`, `**/*_test.py`

### Downloading CBOM Artifacts

After a workflow run, download the CBOM report:

**Via GitHub UI:**
1. Go to **Actions** → Select workflow run
2. Scroll to **Artifacts** section
3. Download `cbom-report`

**Via GitHub CLI:**
```bash
# List artifacts
gh run list --workflow=ci.yml
gh run view <run-id>

# Download artifact
gh run download <run-id> -n cbom-report
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

### Using Docker Compose

```bash
docker-compose up --build
# Frontend → http://localhost:8080
# Backend  → http://localhost:3001
```

### Manual Docker Build

```bash
# Build backend
cd backend && docker build -t cbom-backend .

# Build frontend
cd frontend && docker build -t cbom-frontend .

# Run
docker run -d -p 3001:3001 cbom-backend
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
| Covers Java, Python, Node.js/TypeScript | No bytecode analysis |

### Approach 2: IBM sonar-cryptography (Most Accurate for Java)

Uses SonarQube with IBM's cryptography plugin for deep static analysis.

```bash
# If sonar-scanner is on $PATH, QuantumGuard uses it automatically
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}'
```

### Approach 3: Network TLS Scanner (Runtime Crypto Discovery)

Scan live endpoints to discover what cryptography is actually used at runtime.

```bash
# Scan a single endpoint
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}'
```

### Approach 4: Combined Approach (Recommended)

For the most complete CBOM, combine code scanning + network scanning:

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

| Approach | Setup | Speed | Accuracy | Languages | Finds Runtime Crypto |
|----------|-------|-------|----------|-----------|---------------------|
| **Regex Scanner** | None | Fast | Medium | Java, Python, JS/TS | No |
| **sonar-cryptography** | High | Slow | Very High | Java, Python | No |
| **Network TLS Scanner** | None | Fast | High (for TLS) | N/A | Yes |
| **Combined** | Varies | Medium | Highest | All | Yes |

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

## CycloneDX 1.6 Standard

This project implements the **CycloneDX 1.6** specification for Cryptographic Bill of Materials. The standard defines:

- `cryptoProperties.assetType` — algorithm, protocol, certificate, related-crypto-material
- `cryptoProperties.algorithmProperties` — primitive, mode, padding, curve, cryptoFunctions
- `cryptoProperties.protocolProperties` — TLS version and cipher suites

**Resources:**
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [CycloneDX CBOM Guide](https://cyclonedx.org/capabilities/cbom/)
- [IBM sonar-cryptography](https://github.com/IBM/sonar-cryptography)

---

*For detailed technical documentation, architecture deep-dives, and implementation details, see [README.md](README.md).*
