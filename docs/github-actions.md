# GitHub Actions Integration

> Add a single workflow file to **any repository** to scan it for cryptographic assets and generate a CBOM.

---

## Setup

Create `.github/workflows/cbom-scan.yml` in your repository — that's it. No other files needed.

## Basic Usage

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

## Advanced Usage

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

---

## SARIF Integration for GitHub Security Tab

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

---

## Inputs

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

## Outputs

| Output | Description |
|--------|-------------|
| `readiness-score` | Quantum readiness score (0-100) |
| `total-assets` | Total cryptographic assets found |
| `vulnerable-assets` | Number of non-quantum-safe assets |
| `quantum-safe-assets` | Number of quantum-safe assets |
| `cbom-file` | Path to the generated CBOM output file (user-specified format) |
| `cbom-json-file` | Path to the always-generated `cbom.json` file (for artifact download) |

---

## SonarQube Integration (Optional)

By default the action uses a fast built-in **regex scanner**.
To enable IBM **sonar-cryptography** deep analysis set the two optional
Sonar inputs — the action image ships with `sonar-scanner` pre-installed.

> **Important:** Your SonarQube instance must be **network-reachable** from the
> GitHub Actions runner. Internal/corporate SonarQube servers (e.g.
> `sonar.dev.company.com`) are **not reachable** from GitHub-hosted runners
> (`ubuntu-latest`). Use a **self-hosted runner** on the same network instead.

### Basic Example (self-hosted runner)

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

### With Java Build Step (recommended for full accuracy)

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

### Runner Selection Guide

| SonarQube location | `runs-on` | Build step needed? |
|--------------------|-----------|-------------------|
| Internal corporate server (e.g. `sonar.dev.company.com`) | `self-hosted` | Optional (recommended for Java) |
| Public URL (e.g. `https://sonarcloud.io`) | `ubuntu-latest` | Optional (recommended for Java) |
| Not using SonarQube | `ubuntu-latest` | No |

---

## Setting Up a Self-Hosted Runner

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

---

## Setting Up SonarQube Secrets for a New Repository

To use the SonarQube integration you need a running SonarQube instance and a
project token. Follow these steps **once per GitHub repository**:

### 1. Start SonarQube (or use an existing instance)

If you have an existing corporate SonarQube (e.g. `sonar.dev.company.com`),
skip to step 2. Otherwise spin one up locally:

```bash
# From the cbom-analyser checkout — bundles the IBM sonar-cryptography plugin
docker compose -f docker-compose.sonarqube.yml up -d

# Wait for SonarQube to become ready (~60 s)
until curl -sf http://localhost:9090/api/system/status | grep -q '"UP"'; do sleep 5; done
echo "SonarQube is ready"
```

### 2. Generate a Token

1. Open **http://localhost:9090** (default login: `admin` / `admin`, you'll be prompted to change the password).
2. Go to **My Account → Security → Tokens**.
3. Click **Generate Tokens**, enter a name (e.g. `cbom-ci`), and choose type **Project Analysis Token** for a specific project or **Global Analysis Token** for all projects.
4. Copy the token string — it looks like `sqp_abc123…`.

> The token is shown only once. If you lose it, revoke and generate a new one.

### 3. Add Secrets to Your GitHub Repository

1. In your GitHub repository go to **Settings → Secrets and variables → Actions**.
2. Click **New repository secret** and create:

   | Secret name | Value |
   |-------------|-------|
   | `SONAR_HOST_URL` | Your SonarQube URL, e.g. `http://sonarqube.internal:9090` or `https://sonarcloud.io` |
   | `SONAR_TOKEN` | The token from step 2, e.g. `sqp_abc123…` |

3. (Optional) For **organization-wide** reuse, add these as **Organization secrets** under **Organization Settings → Secrets and variables → Actions** and grant access to selected repositories.

### 4. Reference in Your Workflow

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

> No build step needed — see [With Java Build Step](#with-java-build-step-recommended-for-full-accuracy)
> if you want bytecode-level analysis for Java projects.

> **Network note:** The runner must be able to reach the SonarQube URL.
> Internal servers require a **self-hosted runner** — see
> [Setting Up a Self-Hosted Runner](#setting-up-a-self-hosted-runner) above.

### Without SonarQube (default)

If you don't set the secrets the action uses the **built-in regex scanner**
automatically — no SonarQube instance required. You can always add the secrets
later to upgrade to deep analysis without changing the workflow file.

---

## Excluding Files from Scans

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

---

## Downloading BOM Artifacts

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

*Back to [README](../README.md) · See also [API Reference](api-reference.md) · [Scanning](scanning.md)*
