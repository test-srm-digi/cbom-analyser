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
import { CbomImport } from '../models';

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
  // Step 1: Request the artifact download — GitHub returns a 302 redirect
  // to a temporary Azure Blob URL. We must NOT send the GitHub auth header
  // to the redirect target, so we handle the redirect manually.
  const redirectRes = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    redirect: 'manual',
  });

  // Follow the redirect without the Authorization header
  if (redirectRes.status === 302 || redirectRes.status === 301) {
    const location = redirectRes.headers.get('location');
    if (!location) {
      throw new Error('Artifact download redirect had no Location header');
    }
    const dataRes = await fetch(location);
    if (!dataRes.ok) {
      throw new Error(`Artifact download failed after redirect: ${dataRes.status} ${dataRes.statusText}`);
    }
    const arrayBuffer = await dataRes.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  // If no redirect (shouldn't happen), read directly
  if (!redirectRes.ok) {
    const body = await redirectRes.text().catch(() => '');
    throw new Error(`Artifact download failed: ${redirectRes.status} ${redirectRes.statusText} – ${body.slice(0, 200)}`);
  }

  const arrayBuffer = await redirectRes.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

/**
 * Extract a JSON file from a ZIP buffer.
 * GitHub Actions artifacts are always served as ZIP archives.
 *
 * Uses the Central Directory (at end of ZIP) for reliable size info,
 * since GitHub's artifacts use data descriptors (flag bit 3) which
 * set local-header sizes to 0.
 */
async function extractJsonFromZip(zipBuffer: Buffer): Promise<string | null> {
  const { inflateRawSync } = await import('zlib');

  // ── Locate End-of-Central-Directory record ──
  // Signature: 0x06054b50, appears in the last 65557 bytes
  let eocdOffset = -1;
  const searchStart = Math.max(0, zipBuffer.length - 65557);
  for (let i = zipBuffer.length - 22; i >= searchStart; i--) {
    if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    // Fallback: no EOCD found — shouldn't happen for valid ZIPs
    return null;
  }

  const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);  // offset of central directory
  const cdEntries = zipBuffer.readUInt16LE(eocdOffset + 10);  // total entries

  // ── Walk Central Directory entries ──
  let pos = cdOffset;
  for (let i = 0; i < cdEntries && pos < zipBuffer.length - 4; i++) {
    if (zipBuffer.readUInt32LE(pos) !== 0x02014b50) break; // central dir signature

    const method = zipBuffer.readUInt16LE(pos + 10);
    const compSize = zipBuffer.readUInt32LE(pos + 20);
    const uncompSize = zipBuffer.readUInt32LE(pos + 24);
    const nameLen = zipBuffer.readUInt16LE(pos + 28);
    const extraLen = zipBuffer.readUInt16LE(pos + 30);
    const commentLen = zipBuffer.readUInt16LE(pos + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(pos + 42);
    const fileName = zipBuffer.toString('utf-8', pos + 46, pos + 46 + nameLen);

    // Move to next central directory entry
    pos += 46 + nameLen + extraLen + commentLen;

    if (!fileName.endsWith('.json') && !fileName.endsWith('.xml')) continue;

    // ── Read from local file header to get data offset ──
    const localNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;

    const rawData = zipBuffer.subarray(dataStart, dataStart + compSize);

    if (method === 0) {
      // Stored (no compression)
      return rawData.toString('utf-8');
    } else if (method === 8) {
      // Deflated
      const inflated = inflateRawSync(rawData);
      return inflated.toString('utf-8');
    }
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
  const { githubRepo: rawRepo, githubToken, artifactName, workflowFile, lastSync, integrationCreatedAt } = config;
  // Support both 'branch' and 'branches' config keys
  const branch = config.branch || config.branches;

  if (!rawRepo || !githubToken) {
    return {
      success: false,
      data: [],
      errors: ['GitHub repository and token are required'],
    };
  }

  // Parse owner/repo from full URL (e.g., https://github.com/owner/repo) or plain owner/repo
  const repoMatch = rawRepo.match(/(?:https?:\/\/github\.com\/)?([\/\w.-]+\/[\w.-]+)/);
  const githubRepo = repoMatch ? repoMatch[1].replace(/\.git$/, '') : rawRepo;

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

    // Determine the earliest date to fetch runs from.
    // Priority: lastSync (if records exist) > integrationCreatedAt
    // This ensures we never pull CBOMs created before the integration was established.
    let sinceFilter = '';
    if (lastSync) {
      const existingCount = await CbomImport.count({ where: { integrationId } });
      if (existingCount > 0) {
        // Incremental: strict greater-than using exact timestamp
        sinceFilter = `&created=>${lastSync}`;
      }
    }
    // First sync: use >= with date only (YYYY-MM-DD) so runs from the
    // same day the integration was created are included.
    if (!sinceFilter && integrationCreatedAt) {
      const createdDate = integrationCreatedAt.slice(0, 10); // "YYYY-MM-DD"
      sinceFilter = `&created=>=${createdDate}`;
    }
    if (sinceFilter) {
      runsUrl += sinceFilter;
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
  outputFormat?: string;
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
    outputFormat = 'json',
    pqcThresholdEnabled = false,
    pqcThreshold = 80,
    excludePaths = [],
    retentionDays = 90,
    failOnError = true,
    uploadToRelease = false,
  } = options;

  // When sonar is enabled, default to self-hosted runner (SonarQube is typically internal)
  const useSelfHosted = sonarEnabled ? (options.selfHostedRunner !== undefined ? selfHostedRunner : true) : selfHostedRunner;

  const languages = sonarEnabled ? language.split(',').map((l: string) => l.trim()).filter(Boolean) : [];
  const isSarif = outputFormat === 'sarif';

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

  const runsOn = useSelfHosted ? `[${runnerLabel}]` : 'ubuntu-latest';

  // Permissions
  let permLines = `permissions:\n  contents: ${uploadToRelease ? 'write' : 'read'}`;
  if (isSarif) permLines += `\n  security-events: write`;

  // Build steps (only when sonar is enabled — compiled bytecode improves analysis)
  let buildSteps = '';
  if (sonarEnabled && languages.length > 0) {
    const steps = languages.map((lang: string) => getBuildStep(lang)).filter(Boolean);
    if (steps.length > 0) buildSteps = '\n\n' + steps.join('\n\n');
  }

  // Action inputs
  const withLines: string[] = [];
  withLines.push(`          scan-path: '.'`);
  withLines.push(`          output-format: '${outputFormat}'`);
  if (failOnError) withLines.push(`          fail-on-vulnerable: 'true'`);
  if (pqcThresholdEnabled) withLines.push(`          quantum-safe-threshold: '${pqcThreshold}'`);
  if (excludePaths.length > 0) withLines.push(`          exclude-patterns: '${excludePaths.join(',')}'`);
  if (sonarEnabled) {
    withLines.push(`          sonar-host-url: \${{ secrets.SONAR_HOST_URL }}`);
    withLines.push(`          sonar-token: \${{ secrets.SONAR_TOKEN }}`);
  }

  // SARIF upload step
  const sarifUpload = isSarif ? `
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cbom.sarif
` : '';

  // Upload to release step
  const releaseStep = uploadToRelease ? `
      - name: Attach CBOM to Release
        if: github.event_name == 'release'
        uses: softprops/action-gh-release@v2
        with:
          files: cbom.json
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
` : '';

  return `# ──────────────────────────────────────────────────────────
# CBOM (Cryptographic Bill of Materials) Scanner
# Generated by QuantumGuard CBOM Hub
# ──────────────────────────────────────────────────────────
name: ${sonarEnabled ? 'CBOM Security Scan' : 'CBOM Scan'}

${onBlock}
${permLines}

jobs:
  cbom-scan:
    runs-on: ${runsOn}

    steps:
      - uses: actions/checkout@v4
${buildSteps}
      - name: Run QuantumGuard CBOM Scanner
        id: cbom
        uses: test-srm-digi/cbom-analyser@main
        with:
${withLines.join('\n')}

      - name: Upload CBOM Report${failOnError ? '' : '\n        if: always()'}
        uses: actions/upload-artifact@v4
        with:
          name: ${artifactName}
          path: cbom.json
          retention-days: ${retentionDays}
${sarifUpload}${releaseStep}`;
}

function getBuildStep(language: string): string {
  switch (language.toLowerCase()) {
    case 'java':
      return `      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Build (compile only — no tests)
        run: |
          if [ -f "mvnw" ]; then ./mvnw compile -q -DskipTests
          elif [ -f "gradlew" ]; then ./gradlew classes -q
          elif [ -f "pom.xml" ]; then mvn compile -q -DskipTests
          else echo "No Java build tool detected"; fi`;

    case 'python':
      return `      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt 2>/dev/null || true`;

    case 'go':
    case 'golang':
      return `      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build project
        run: go build ./...`;

    default:
      return '';
  }
}
