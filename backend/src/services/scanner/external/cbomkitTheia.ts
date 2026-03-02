/**
 * cbomkit-theia Integration
 *
 * IBM's container/filesystem crypto scanner.
 * Detects certificates, keys, and crypto configurations in file trees.
 *
 * @see docs/advanced-resolution-techniques.md — Phase 3A
 */
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import type { CryptoAsset } from '../../../types';
import { AssetType, QuantumSafetyStatus } from '../../../types';
import { enrichAssetWithPQCData } from '../../pqc';
import { normaliseAlgorithmName } from '../scannerUtils';
import { checkToolAvailability } from './availability';
import type { CbomkitComponent, CbomkitOutput } from './types';

const execAsync = promisify(exec);

/**
 * Run cbomkit-theia on a repository/directory to detect crypto assets.
 *
 * cbomkit-theia uses plugins:
 *   - certificates: Scans for X.509 certs and extracts signature algorithms
 *   - javasecurity: Reads java.security config
 *   - opensslconf: Reads OpenSSL configuration
 *   - keys: Detects private/public key files
 *   - secrets: gitleaks-based secret detection
 *
 * Returns empty array if cbomkit-theia is not installed.
 */
export async function runCbomkitTheia(repoPath: string): Promise<CryptoAsset[]> {
  const availability = await checkToolAvailability();

  // Check for cbomkit-theia binary
  const binaryName = availability.cbomkitTheia
    ? (execSync('which cbomkit-theia 2>/dev/null || which cbomkit 2>/dev/null', { encoding: 'utf-8' }).trim())
    : null;

  if (!binaryName) {
    console.log('cbomkit-theia not available — skipping filesystem crypto scan');
    return [];
  }

  const assets: CryptoAsset[] = [];
  const outputFile = path.join(repoPath, '.cbom-theia-output.json');

  try {
    // Run cbomkit-theia on the directory
    console.log(`cbomkit-theia: scanning ${repoPath}...`);
    await execAsync(
      `"${binaryName}" dir "${repoPath}" --output "${outputFile}" 2>&1`,
      { timeout: 120000, cwd: repoPath },  // 2 min timeout
    );

    if (fs.existsSync(outputFile)) {
      const output: CbomkitOutput = JSON.parse(fs.readFileSync(outputFile, 'utf-8'));

      for (const component of output.components ?? []) {
        const asset = parseCbomkitComponent(component, repoPath);
        if (asset) assets.push(asset);
      }
    }

    console.log(`cbomkit-theia: found ${assets.length} crypto assets`);
  } catch (err) {
    console.warn(`cbomkit-theia integration error: ${(err as Error).message}`);
  } finally {
    try {
      fs.unlinkSync(outputFile);
    } catch { /* ignore */ }
  }

  return assets;
}

/**
 * Parse a cbomkit-theia component into a CryptoAsset.
 */
function parseCbomkitComponent(component: CbomkitComponent, repoPath: string): CryptoAsset | null {
  const props = component['crypto-properties'];
  if (!props) return null;

  const location = component.evidence?.occurrences?.[0];
  let name = component.name;
  let type = AssetType.ALGORITHM;

  // Certificate assets
  if (props.assetType === 'certificate' || props.certificateProperties) {
    type = AssetType.CERTIFICATE;
    const sigAlg = props.certificateProperties?.signatureAlgorithm;
    if (sigAlg) name = sigAlg;
  }

  // Algorithm assets
  if (props.algorithmProperties?.algorithm) {
    name = normaliseAlgorithmName(props.algorithmProperties.algorithm);
  }

  const asset: CryptoAsset = {
    id: uuidv4(),
    name,
    type,
    description: `Detected by cbomkit-theia: ${component.name}${props.oid ? ` (OID: ${props.oid})` : ''}.`,
    cryptoProperties: {
      assetType: type,
      ...(props.certificateProperties ? {
        certificateProperties: {
          signatureAlgorithm: props.certificateProperties.signatureAlgorithm,
          subjectPublicKeyAlgorithm: props.certificateProperties.subjectPublicKeyAlgorithm,
          certificateFormat: props.certificateProperties.certificateFormat,
          subjectName: props.certificateProperties.subjectName,
          issuerName: props.certificateProperties.issuerName,
        },
      } : {}),
      ...(props.oid ? { oid: props.oid } : {}),
    },
    location: {
      fileName: location?.location
        ? path.relative(repoPath, location.location)
        : 'unknown',
      lineNumber: location?.line ?? 0,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'cbomkit-theia',
  };

  return enrichAssetWithPQCData(asset);
}
