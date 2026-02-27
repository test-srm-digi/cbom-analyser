/**
 * GitHub Actions CBOM Connector
 *
 * Fetches CBOM artifacts from GitHub Actions workflow runs.
 * Supports incremental sync — only fetches runs completed after
 * the integration's last sync timestamp.
 *
 * Expected config:
 *   - githubRepo:     "owner/repo"
 *   - githubToken:    "ghp_xxx..." (PAT with actions:read)
 *   - artifactName:   "cbom-report" (artifact name to look for)
 *   - workflowFile:   "cbom.yml" (optional — filter to specific workflow)
 *   - branch:         "main" (optional — filter to specific branch)
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from './connectors';

/* ── GitHub API types (subset) ──────────────────────────────── */

interface WorkflowRun {
  id: number;
  name: string;
  head_branch: string;
  status: string;
  conclusion: string | null;
  created_at: string;
  updated_at: string;
  html_url: string;
  artifacts_url: string;
}

interface Artifact {
  id: number;
  name: string;
  size_in_bytes: number;
  archive_download_url: string;
  created_at: string;
  expired: boolean;
}

interface WorkflowRunsResponse {
  total_count: number;
  workflow_runs: WorkflowRun[];
}

interface ArtifactsResponse {
  total_count: number;
  artifacts: Artifact[];
}

/* ── Helpers ───────────────────────────────────────────────── */

async function githubFetch<T>(url: string, token: string): Promise<T> {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub API ${res.status}: ${res.statusText} – ${body.slice(0, 200)}`);
  }

  return res.json() as Promise<T>;
}

async function downloadArtifactZip(url: string, token: string): Promise<Buffer> {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!res.ok) {
    throw new Error(`Artifact download failed: ${res.status} ${res.statusText}`);
  }

  const arrayBuffer = await res.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

/**
 * Extract a JSON file from a ZIP buffer.
 * GitHub Actions artifacts are always served as ZIP archives.
 * Uses a lightweight approach: find the local-file-header in the ZIP
 * and decompress the first JSON entry.
 */
async function extractJsonFromZip(zipBuffer: Buffer): Promise<string | null> {
  // Use Node's built-in zlib for deflated entries
  const { inflateRawSync } = await import('zlib');

  let offset = 0;
  while (offset < zipBuffer.length - 4) {
    // Local file header signature = 0x04034b50
    if (zipBuffer.readUInt32LE(offset) !== 0x04034b50) break;

    const compressionMethod = zipBuffer.readUInt16LE(offset + 8);
    const compressedSize = zipBuffer.readUInt32LE(offset + 18);
    const uncompressedSize = zipBuffer.readUInt32LE(offset + 22);
    const fileNameLen = zipBuffer.readUInt16LE(offset + 26);
    const extraLen = zipBuffer.readUInt16LE(offset + 28);
    const fileName = zipBuffer.toString('utf-8', offset + 30, offset + 30 + fileNameLen);
    const dataStart = offset + 30 + fileNameLen + extraLen;

    if (fileName.endsWith('.json') || fileName.endsWith('.xml')) {
      const rawData = zipBuffer.subarray(dataStart, dataStart + compressedSize);
      if (compressionMethod === 0) {
        // Stored (no compression)
        return rawData.toString('utf-8');
      } else if (compressionMethod === 8) {
        // Deflated
        const inflated = inflateRawSync(rawData);
        return inflated.toString('utf-8');
      }
    }

    offset = dataStart + compressedSize;
  }

  return null;
}

/**
 * Parse a CBOM JSON string and extract summary metrics.
 */
function analyzeCbom(cbomJson: string, fileName: string): {
  totalComponents: number;
  cryptoComponents: number;
  quantumSafeComponents: number;
  nonQuantumSafeComponents: number;
  format: string;
  specVersion: string;
  applicationName: string;
} {
  try {
    const cbom = JSON.parse(cbomJson);
    const specVersion = cbom.specVersion || '1.6';
    const format = cbom.bomFormat === 'CycloneDX' ? 'CycloneDX' : 'Unknown';
    const applicationName = cbom.metadata?.component?.name || fileName.replace(/-cbom.*$/, '');

    const components = cbom.components || [];
    const cryptoAssets = cbom.cryptoAssets || cbom.components?.filter(
      (c: Record<string, unknown>) => c.type === 'crypto-asset' || (c as any).cryptoProperties,
    ) || [];

    const totalComponents = components.length + (cbom.cryptoAssets?.length || 0);
    const cryptoComponents = cryptoAssets.length;

    let quantumSafe = 0;
    let nonQuantumSafe = 0;
    for (const asset of cryptoAssets) {
      const safety = asset.quantumSafety || asset.cryptoProperties?.quantumSafety;
      if (safety === 'quantum-safe') {
        quantumSafe++;
      } else if (safety === 'not-quantum-safe' || safety === 'unknown') {
        nonQuantumSafe++;
      } else {
        nonQuantumSafe++; // default to non-quantum-safe
      }
    }

    return {
      totalComponents,
      cryptoComponents,
      quantumSafeComponents: quantumSafe,
      nonQuantumSafeComponents: nonQuantumSafe,
      format,
      specVersion,
      applicationName,
    };
  } catch {
    return {
      totalComponents: 0,
      cryptoComponents: 0,
      quantumSafeComponents: 0,
      nonQuantumSafeComponents: 0,
      format: 'Unknown',
      specVersion: '1.6',
      applicationName: fileName,
    };
  }
}

/* ── Main fetch function ───────────────────────────────────── */

export async function fetchCbomImportsFromGitHub(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const { githubRepo, githubToken, artifactName, workflowFile, branch, lastSync } = config;

  if (!githubRepo || !githubToken) {
    return {
      success: false,
      data: [],
      errors: ['GitHub repository and token are required'],
    };
  }

  const baseUrl = `https://api.github.com/repos/${githubRepo}`;
  const targetArtifact = artifactName || 'cbom-report';
  const errors: string[] = [];
  const data: Record<string, unknown>[] = [];

  try {
    /* ── 1. List completed workflow runs ────────────────────── */
    let runsUrl = `${baseUrl}/actions/runs?status=completed&per_page=30`;
    if (branch) {
      runsUrl += `&branch=${encodeURIComponent(branch)}`;
    }
    // Incremental: only fetch runs created after last sync
    if (lastSync) {
      runsUrl += `&created=>${lastSync}`;
    }

    const runsResponse = await githubFetch<WorkflowRunsResponse>(runsUrl, githubToken);
    let runs = runsResponse.workflow_runs.filter((r) => r.conclusion === 'success');

    // Filter to specific workflow file if configured
    if (workflowFile) {
      runs = runs.filter(
        (r) => r.name.toLowerCase().includes(workflowFile.replace('.yml', '').replace('.yaml', '').toLowerCase()),
      );
    }

    if (runs.length === 0) {
      return {
        success: true,
        data: [],
        errors: [],
        meta: { incremental: true, message: 'No new workflow runs found since last sync' },
      };
    }

    /* ── 2. For each run, find the CBOM artifact ───────────── */
    for (const run of runs) {
      try {
        const artifactsResponse = await githubFetch<ArtifactsResponse>(
          `${baseUrl}/actions/runs/${run.id}/artifacts`,
          githubToken,
        );

        const cbomArtifact = artifactsResponse.artifacts.find(
          (a) => !a.expired && a.name.toLowerCase().includes(targetArtifact.toLowerCase()),
        );

        if (!cbomArtifact) continue;

        /* ── 3. Download & extract the CBOM ────────────────── */
        const zipBuffer = await downloadArtifactZip(cbomArtifact.archive_download_url, githubToken);
        const cbomContent = await extractJsonFromZip(zipBuffer);

        if (!cbomContent) {
          errors.push(`Run #${run.id}: artifact "${cbomArtifact.name}" contained no JSON/XML files`);
          continue;
        }

        /* ── 4. Analyze and build the import record ────────── */
        const analysis = analyzeCbom(cbomContent, cbomArtifact.name);

        data.push({
          id: uuidv4(),
          integrationId,
          fileName: `${cbomArtifact.name}-run-${run.id}.json`,
          format: analysis.format,
          specVersion: analysis.specVersion,
          totalComponents: analysis.totalComponents,
          cryptoComponents: analysis.cryptoComponents,
          quantumSafeComponents: analysis.quantumSafeComponents,
          nonQuantumSafeComponents: analysis.nonQuantumSafeComponents,
          importDate: run.created_at,
          status: 'Processed',
          source: `GitHub Actions (${run.head_branch})`,
          applicationName: analysis.applicationName,
          cbomFile: Buffer.from(cbomContent, 'utf-8'),
          cbomFileType: 'application/json',
        });
      } catch (err) {
        errors.push(`Run #${run.id}: ${(err as Error).message}`);
      }
    }

    return {
      success: true,
      data,
      errors,
      meta: { incremental: true, runsChecked: runs.length },
    };
  } catch (err) {
    return {
      success: false,
      data: [],
      errors: [`GitHub API error: ${(err as Error).message}`],
    };
  }
}

/* ── Workflow YAML templates ───────────────────────────────── */

interface WorkflowOptions {
  language: string;         // comma-separated when multiple
  branch?: string;
  branches?: string[];
  triggers?: string[];
  artifactName?: string;
  schedule?: string;
  selfHostedRunner?: boolean;
  runnerLabel?: string;
  sonarEnabled?: boolean;
  sonarProjectKey?: string;
  pqcThresholdEnabled?: boolean;
  pqcThreshold?: number;
  excludePaths?: string[];
  retentionDays?: number;
  failOnError?: boolean;
  uploadToRelease?: boolean;
}

/**
 * Generate a ready-to-use GitHub Actions workflow YAML
 * that scans the repo for cryptographic usage and uploads
 * a CycloneDX CBOM as an artifact.
 */
export function generateWorkflowYaml(options: WorkflowOptions): string {
  const {
    language = 'java',
    branches = [options.branch || 'main'],
    triggers = ['push', 'pull_request'],
    artifactName = 'cbom-report',
    schedule,
    selfHostedRunner = false,
    runnerLabel = 'self-hosted, linux, x64',
    sonarEnabled = false,
    sonarProjectKey = '',
    pqcThresholdEnabled = false,
    pqcThreshold = 80,
    excludePaths = [],
    retentionDays = 90,
    failOnError = true,
    uploadToRelease = false,
  } = options;

  const branchList = branches.join(', ');

  // Build trigger block
  let onBlock = 'on:\n';
  if (triggers.includes('push')) {
    onBlock += `  push:\n    branches: [${branchList}]\n`;
    if (excludePaths.length > 0) {
      onBlock += `    paths-ignore:\n${excludePaths.map((p) => `      - '${p}'`).join('\n')}\n`;
    }
  }
  if (triggers.includes('pull_request')) {
    onBlock += `  pull_request:\n    branches: [${branchList}]\n`;
    if (excludePaths.length > 0) {
      onBlock += `    paths-ignore:\n${excludePaths.map((p) => `      - '${p}'`).join('\n')}\n`;
    }
  }
  if (triggers.includes('release')) {
    onBlock += `  release:\n    types: [published]\n`;
  }
  if (triggers.includes('schedule') || schedule) {
    onBlock += `  schedule:\n    - cron: '${schedule || '0 2 * * 1'}'\n`;
  }
  onBlock += `  workflow_dispatch:\n`;

  const runsOn = selfHostedRunner ? `[${runnerLabel}]` : 'ubuntu-latest';

  // Scanner steps — one per selected language
  const languages = language.split(',').map((l: string) => l.trim()).filter(Boolean);
  const scannerStep = languages.map((lang: string) => getScannerStep(lang)).join('\n');

  const sonarStep = sonarEnabled ? `
      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@v3
        env:
          SONAR_TOKEN: \${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: \${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=${sonarProjectKey || '\${{ github.repository_owner }}_\${{ github.event.repository.name }}'}
            -Dsonar.sources=.
` : '';

  const pqcStep = pqcThresholdEnabled ? `
      - name: Check PQC Readiness Threshold
        run: |
          if [ ! -f cbom-report.json ]; then
            echo "::error::CBOM report not found"
            exit 1
          fi
          PQC_PERCENT=$(python3 -c "
          import json, sys
          with open('cbom-report.json') as f:
              cbom = json.load(f)
          components = cbom.get('components', [])
          crypto = [c for c in components if c.get('type') == 'crypto-asset']
          if not crypto:
              print(100)
              sys.exit(0)
          safe = sum(1 for c in crypto
                     if c.get('cryptoProperties', {}).get('quantumSafe', False))
          print(int(safe / len(crypto) * 100))
          ")
          echo "PQC readiness: \${PQC_PERCENT}%"
          if [ "\${PQC_PERCENT}" -lt ${pqcThreshold} ]; then
            echo "::error::PQC readiness \${PQC_PERCENT}% is below threshold of ${pqcThreshold}%"
            exit 1
          fi
          echo "::notice::PQC readiness \${PQC_PERCENT}% meets threshold of ${pqcThreshold}%"
` : '';

  const releaseStep = uploadToRelease ? `
      - name: Attach CBOM to Release
        if: github.event_name == 'release'
        uses: softprops/action-gh-release@v2
        with:
          files: cbom-report.json
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
` : '';

  const permissions = `permissions:
  contents: ${uploadToRelease ? 'write' : 'read'}
  actions: write`;

  return `# ──────────────────────────────────────────────────────────
# CBOM (Cryptographic Bill of Materials) Scanner
# Generated by QuantumGuard CBOM Hub
# ──────────────────────────────────────────────────────────
name: CBOM Analysis

${onBlock}
${permissions}

jobs:
  cbom-scan:
    name: Generate CBOM Report
    runs-on: ${runsOn}

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
${scannerStep}
${sonarStep}${pqcStep}
      - name: Upload CBOM Artifact
        if: ${failOnError ? 'success()' : 'always()'}
        uses: actions/upload-artifact@v4
        with:
          name: ${artifactName}
          path: cbom-report.json
          retention-days: ${retentionDays}
          if-no-files-found: error
${releaseStep}`;
}

function getScannerStep(language: string): string {
  switch (language.toLowerCase()) {
    case 'java':
      return `      - name: Set up Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Build project
        run: |
          if [ -f "mvnw" ]; then ./mvnw compile -q; elif [ -f "gradlew" ]; then ./gradlew compileJava -q; fi

      - name: Run IBM Sonar Cryptography Scanner
        run: |
          SCANNER_VERSION="1.4.0"
          wget -q "https://github.com/IBM/sonar-cryptography/releases/download/v\${SCANNER_VERSION}/sonar-cryptography-\${SCANNER_VERSION}-all.jar" \\
            -O sonar-cryptography.jar
          java -jar sonar-cryptography.jar \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;

    case 'python':
      return `      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt 2>/dev/null || true
          pip install cryptography-finder cbom-generator

      - name: Scan for cryptographic usage
        run: |
          python -m cryptography_finder \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;

    case 'javascript':
    case 'typescript':
    case 'node':
      return `      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts

      - name: Scan for cryptographic usage
        run: |
          npx @anthropic/cbom-scanner \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;

    case 'go':
    case 'golang':
      return `      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build project
        run: go build ./...

      - name: Scan for cryptographic usage
        run: |
          go install github.com/ibm/cbom-scanner@latest
          cbom-scanner \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;

    case 'csharp':
    case 'dotnet':
    case 'c#':
      return `      - name: Set up .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '8.0'

      - name: Build project
        run: dotnet build --no-incremental

      - name: Scan for cryptographic usage
        run: |
          dotnet tool install -g CryptoScanner
          crypto-scanner \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;

    default:
      return `      - name: Run generic crypto scanner
        run: |
          # Install IBM sonar-cryptography (language-agnostic mode)
          wget -q "https://github.com/IBM/sonar-cryptography/releases/latest/download/sonar-cryptography-all.jar" \\
            -O sonar-cryptography.jar
          java -jar sonar-cryptography.jar \\
            --project-dir . \\
            --output cbom-report.json \\
            --format cyclonedx-json`;
  }
}
