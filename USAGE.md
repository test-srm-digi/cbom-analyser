# QuantumGuard CBOM Hub — Usage Guide

> **Practical guide for running, integrating, and using QuantumGuard CBOM Hub**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [GitHub Actions Integration](#github-actions-integration)
3. [Docker Deployment](#docker-deployment)
4. [API Reference](#api-reference)
5. [Scanning Approaches](#scanning-approaches)
6. [Variable Resolution & Context Scanning](#variable-resolution--context-scanning)
7. [Third-Party Dependency Scanning](#third-party-dependency-scanning)
8. [PQC Readiness Verdicts](#pqc-readiness-verdicts)
9. [Quantum Safety Dashboard](#quantum-safety-dashboard)
10. [Project Insight Panel](#project-insight-panel)
11. [AI-Powered Suggested Fixes](#ai-powered-suggested-fixes)
12. [Sample Data & Demo Code](#sample-data--demo-code)
13. [Configuration](#configuration)
14. [CycloneDX 1.7 Standard](#cyclonedx-17-standard)

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
| Covers Java, Python, Node.js/TypeScript | No bytecode analysis |

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
| **Regex Scanner** | None | Fast | Medium | Java, Python, JS/TS | No | No | No |
| **sonar-cryptography** | High | Slow | Very High | Java, Python, Go | No | No | No |
| **Network TLS Scanner** | None | Fast | High (TLS) | N/A | No | No | Yes |
| **Full Pipeline** | Low–High | Medium | Highest | All | Yes | Yes | Yes |

---

## Variable Resolution & Context Scanning

The regex scanner includes two advanced analysis capabilities that go beyond simple pattern matching.

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

**Supported variable patterns:**
- `KeyPairGenerator.getInstance(variable)`
- `Cipher.getInstance(variable)`
- `MessageDigest.getInstance(variable)`
- `Signature.getInstance(variable)`
- `SecretKeyFactory.getInstance(variable)`
- `KeyAgreement.getInstance(variable)`
- `Mac.getInstance(variable)`

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

*For detailed technical documentation, architecture deep-dives, and implementation details, see [README.md](README.md).*
