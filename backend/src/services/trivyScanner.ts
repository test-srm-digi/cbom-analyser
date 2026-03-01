/**
 * Trivy SBOM Scanner
 *
 * Runs Aqua Security's Trivy on a target path (filesystem or container image)
 * and returns a CycloneDX-format SBOM with software components, dependencies,
 * and vulnerabilities (CVEs).
 *
 * Installation: Trivy must be available on $PATH.
 *   brew install trivy        # macOS
 *   apt-get install trivy     # Debian/Ubuntu
 *   apk add trivy             # Alpine (in Docker)
 *
 * @see https://aquasecurity.github.io/trivy/latest/
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SBOMDocument } from '../types/sbom.types';

const execFileAsync = promisify(execFile);

// ─── Check Trivy availability ────────────────────────────────────────────────

let trivyAvailable: boolean | null = null;

export async function isTrivyInstalled(): Promise<boolean> {
  if (trivyAvailable !== null) return trivyAvailable;
  try {
    await execFileAsync('trivy', ['version'], { timeout: 10_000 });
    trivyAvailable = true;
  } catch {
    trivyAvailable = false;
  }
  return trivyAvailable;
}

/** Reset the cached Trivy availability flag so the next call re-probes. */
export function resetTrivyCache(): void {
  trivyAvailable = null;
}

/**
 * Attempt to install Trivy automatically.
 * Returns { success, message } indicating the result.
 */
export async function installTrivy(): Promise<{ success: boolean; message: string }> {
  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      // macOS — Homebrew
      await execFileAsync('brew', ['install', 'trivy'], { timeout: 120_000 });
    } else if (platform === 'linux') {
      // Linux — try snap first (no sudo needed), fall back to apt
      try {
        await execFileAsync('snap', ['install', 'trivy'], { timeout: 120_000 });
      } catch {
        // Try curl-based install script (official Trivy installer, no sudo)
        const { stdout } = await execFileAsync('bash', ['-c', 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin'], { timeout: 120_000 });
        void stdout;
      }
    } else {
      return { success: false, message: `Automatic installation is not supported on ${platform}. Please install Trivy manually.` };
    }
    // Reset cache and re-check
    resetTrivyCache();
    const installed = await isTrivyInstalled();
    if (installed) {
      const ver = await getTrivyVersion();
      return { success: true, message: `Trivy ${ver ? 'v' + ver + ' ' : ''}installed successfully.` };
    }
    return { success: false, message: 'Installation command completed but Trivy was not found on PATH.' };
  } catch (err: any) {
    return { success: false, message: err?.message || 'Installation failed. Please install Trivy manually.' };
  }
}

export async function getTrivyVersion(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('trivy', ['version', '--format', 'json'], { timeout: 10_000 });
    const parsed = JSON.parse(stdout);
    return parsed.Version ?? parsed.version ?? null;
  } catch {
    return null;
  }
}

// ─── Scan options ────────────────────────────────────────────────────────────

export interface TrivyScanOptions {
  /** Target: directory path for `fs` scan, image name for `image` scan */
  target: string;
  /** Scan type */
  scanType?: 'fs' | 'image' | 'repo';
  /** Extra Trivy CLI flags (e.g. ['--skip-dirs', 'vendor']) */
  extraArgs?: string[];
  /** Timeout in milliseconds (default: 5 minutes) */
  timeout?: number;
  /** Include vulnerabilities in the output (default: true) */
  includeVulns?: boolean;
  /** Severity filter (default: all) */
  severities?: string[];
}

// ─── Run Trivy scan ──────────────────────────────────────────────────────────

/**
 * Run Trivy and return a parsed CycloneDX SBOM document.
 *
 * @throws if Trivy is not installed or the scan fails
 */
export async function runTrivyScan(options: TrivyScanOptions): Promise<SBOMDocument> {
  const available = await isTrivyInstalled();
  if (!available) {
    throw new Error(
      'Trivy is not installed or not on $PATH. ' +
      'Install it: https://aquasecurity.github.io/trivy/latest/getting-started/installation/'
    );
  }

  const {
    target,
    scanType = 'fs',
    extraArgs = [],
    timeout = 5 * 60 * 1000,
    includeVulns = true,
    severities,
  } = options;

  // Temp file for output (Trivy writes CycloneDX JSON here)
  const tmpDir = os.tmpdir();
  const outFile = path.join(tmpDir, `trivy-sbom-${Date.now()}.json`);

  const args: string[] = [
    scanType,
    '--format', 'cyclonedx',
    '--output', outFile,
  ];

  // Scanners: vuln + license (optionally skip vulns)
  if (includeVulns) {
    args.push('--scanners', 'vuln,license');
  } else {
    args.push('--scanners', 'license');
  }

  // Severity filter
  if (severities && severities.length > 0) {
    args.push('--severity', severities.join(','));
  }

  args.push(...extraArgs, target);

  console.log(`[Trivy] Running: trivy ${args.join(' ')}`);

  try {
    const { stderr } = await execFileAsync('trivy', args, {
      timeout,
      maxBuffer: 100 * 1024 * 1024, // 100 MB
      env: { ...process.env, TRIVY_NO_PROGRESS: '1' },
    });

    if (stderr) {
      // Trivy writes progress / warnings to stderr — log but don't fail
      const lines = stderr.split('\n').filter(l => l.trim());
      for (const line of lines.slice(0, 10)) {
        console.log(`[Trivy] ${line}`);
      }
    }

    // Read the generated CycloneDX JSON
    if (!fs.existsSync(outFile)) {
      throw new Error('Trivy did not produce an output file');
    }

    const raw = fs.readFileSync(outFile, 'utf-8');
    const sbom: SBOMDocument = JSON.parse(raw);

    // Validate basic structure
    if (sbom.bomFormat !== 'CycloneDX') {
      throw new Error(`Unexpected bomFormat: ${sbom.bomFormat}`);
    }

    console.log(
      `[Trivy] SBOM generated: ${sbom.components?.length ?? 0} components, ` +
      `${sbom.vulnerabilities?.length ?? 0} vulnerabilities`
    );

    return sbom;
  } finally {
    // Clean up temp file
    try { fs.unlinkSync(outFile); } catch { /* ignore */ }
  }
}

// ─── Parse an existing Trivy SBOM JSON file ──────────────────────────────────

/**
 * Parse a Trivy-generated CycloneDX JSON string or file path into an SBOMDocument.
 */
export function parseSBOMFile(input: string): SBOMDocument {
  let json: string;

  // If input looks like a file path, read it
  if (input.length < 500 && !input.trimStart().startsWith('{')) {
    if (!fs.existsSync(input)) {
      throw new Error(`SBOM file not found: ${input}`);
    }
    json = fs.readFileSync(input, 'utf-8');
  } else {
    json = input;
  }

  const sbom: SBOMDocument = JSON.parse(json);

  if (sbom.bomFormat !== 'CycloneDX') {
    throw new Error(`Not a CycloneDX document (bomFormat: ${sbom.bomFormat})`);
  }

  return sbom;
}
