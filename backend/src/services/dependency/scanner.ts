/**
 * Dependency Scanner — Main Entry Point
 *
 * Scans project manifest files for known crypto libraries and builds
 * a dependency depth tree with quantum safety classification.
 */
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import {
  ThirdPartyCryptoLibrary,
  CryptoAsset,
  AssetType,
  QuantumSafetyStatus,
} from '../../types';
import { enrichAssetWithPQCData } from '../pqc';
import {
  parseMavenPom,
  parseGradleBuild,
  parsePackageJson,
  parseRequirementsTxt,
  parseSetupPy,
  parseGoMod,
} from './manifestParsers';
import { resolveMavenTransitive, resolveNpmTransitive } from './transitiveResolvers';

const execAsync = promisify(exec);

/**
 * Scan a repository for known third-party crypto libraries.
 * Returns both direct and (where possible) transitive dependencies.
 */
export async function scanDependencies(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
  const allLibs: ThirdPartyCryptoLibrary[] = [];

  try {
    // Find all manifest files, excluding build/deps directories
    const { stdout } = await execAsync(
      `find "${repoPath}" -type d \\( ` +
        `-name node_modules -o -name .git -o -name target -o -name build ` +
        `-o -name dist -o -name .gradle -o -name __pycache__ -o -name vendor ` +
      `\\) -prune -o -type f \\( ` +
        `-name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" ` +
        `-o -name "package.json" -o -name "requirements.txt" -o -name "requirements-*.txt" ` +
        `-o -name "setup.py" -o -name "go.mod" ` +
      `\\) -print`,
      { timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);

    for (const filePath of files) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const relativePath = path.relative(repoPath, filePath);
        const fileName = path.basename(filePath);

        if (fileName === 'pom.xml') {
          allLibs.push(...parseMavenPom(content, relativePath));
        } else if (fileName.match(/build\.gradle(\.kts)?$/)) {
          allLibs.push(...parseGradleBuild(content, relativePath));
        } else if (fileName === 'package.json') {
          allLibs.push(...parsePackageJson(content, relativePath));
        } else if (fileName.match(/requirements.*\.txt$/)) {
          allLibs.push(...parseRequirementsTxt(content, relativePath));
        } else if (fileName === 'setup.py') {
          allLibs.push(...parseSetupPy(content, relativePath));
        } else if (fileName === 'go.mod') {
          allLibs.push(...parseGoMod(content, relativePath));
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch (error) {
    console.warn('Dependency file discovery failed:', (error as Error).message);
  }

  // Attempt transitive resolution (non-blocking)
  try {
    const [mavenTransitive, npmTransitive] = await Promise.all([
      resolveMavenTransitive(repoPath),
      resolveNpmTransitive(repoPath),
    ]);
    allLibs.push(...mavenTransitive, ...npmTransitive);
  } catch {
    // Transitive resolution is best-effort
  }

  // Deduplicate by groupId:artifactId (keep the one with lowest depth)
  const deduped = new Map<string, ThirdPartyCryptoLibrary>();
  for (const lib of allLibs) {
    const key = `${lib.groupId || ''}:${lib.artifactId || lib.name}:${lib.packageManager}`;
    const existing = deduped.get(key);
    if (!existing || lib.depth < existing.depth) {
      deduped.set(key, lib);
    }
  }

  return Array.from(deduped.values());
}

/**
 * Convert a third-party crypto library into CryptoAsset entries.
 * Each known algorithm from the library becomes a separate crypto asset.
 */
export function cryptoLibToCBOMAssets(lib: ThirdPartyCryptoLibrary): CryptoAsset[] {
  return lib.cryptoAlgorithms.map(alg => {
    // Determine a more specific asset type based on the algorithm
    let assetType = AssetType.ALGORITHM;
    if (['X.509', 'X509'].includes(alg)) assetType = AssetType.CERTIFICATE;
    else if (['TLS', 'SSL', 'DTLS'].includes(alg)) assetType = AssetType.PROTOCOL;
    else if (['RSA', 'ECDSA', 'Ed25519', 'DSA', 'ML-DSA', 'SLH-DSA'].includes(alg)) assetType = AssetType.ALGORITHM;

    const asset: CryptoAsset = {
      id: uuidv4(),
      name: alg,
      type: 'crypto-asset',
      version: lib.version,
      description: `Provided by ${lib.name} v${lib.version || 'unknown'} (${lib.packageManager}: ${lib.groupId ? lib.groupId + ':' : ''}${lib.artifactId}). ` +
        `Detected as a ${lib.isDirectDependency ? 'direct' : 'transitive'} dependency in ${lib.manifestFile}${lib.lineNumber ? ':' + lib.lineNumber : ''}.`,
      cryptoProperties: {
        assetType,
      },
      location: {
        fileName: lib.manifestFile,
        lineNumber: lib.lineNumber,
      },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      provider: lib.name,
      detectionSource: 'dependency',
    };
    return enrichAssetWithPQCData(asset);
  });
}
