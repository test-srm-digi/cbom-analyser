/**
 * Full Scan Pipeline — orchestrates every scanner stage and merges
 * results into a unified CycloneDX 1.7 CBOM.
 */
import {
  CBOMDocument,
  CryptoAsset,
  CryptoDependency,
  CBOMRepository,
  ExternalToolOptions,
} from '../../types';
import { syncQuantumSafetyWithVerdict } from '../pqcRiskEngine';
import { scanNetworkCrypto, networkResultToCBOMAsset } from '../networkScanner';
import { scanDependencies, cryptoLibToCBOMAssets } from '../dependencyScanner';
import { analyzeAllConditionalAssets } from '../pqcParameterAnalyzer';
import { scanCertificateFiles } from '../scanner/certificateFileScanner';
import { runExternalToolScans, deduplicateExternalAssets } from '../scanner/externalToolIntegration';
import { filterFalsePositives } from '../scanner/scannerUtils';
import { mergeCBOMs } from './cbomBuilder';
import { runSonarCryptoScan } from './sonarScanner';

/**
 * Full pipeline: scan code + scan dependencies + scan network + analyze conditionals + merge into unified CBOM.
 */
export async function runFullScan(
  repoPath: string,
  networkHosts?: string[],
  repository?: CBOMRepository,
  externalToolOptions?: ExternalToolOptions,
): Promise<CBOMDocument> {
  // 1. Code scan (sonar or regex fallback)
  const codeCBOM = await runSonarCryptoScan(repoPath, undefined, repository);

  // 2. Dependency scan — find crypto libs in pom.xml, package.json, etc.
  let depAssets: CryptoAsset[] = [];
  try {
    const thirdPartyLibs = await scanDependencies(repoPath);
    codeCBOM.thirdPartyLibraries = thirdPartyLibs;

    // Convert each library's known algorithms to CryptoAsset entries
    for (const lib of thirdPartyLibs) {
      depAssets.push(...cryptoLibToCBOMAssets(lib));
    }

    // Build dependency graph entries for third-party libs
    if (!codeCBOM.dependencies) codeCBOM.dependencies = [];
    for (const lib of thirdPartyLibs) {
      const depEntry: CryptoDependency = {
        ref: `${lib.packageManager}:${lib.groupId ? lib.groupId + ':' : ''}${lib.artifactId || lib.name}`,
        dependsOn: [],
        provides: lib.cryptoAlgorithms.map(a => `algorithm:${a}`),
      };
      codeCBOM.dependencies.push(depEntry);
    }

    console.log(`Dependency scan found ${thirdPartyLibs.length} crypto libraries with ${depAssets.length} algorithm references`);
  } catch (err) {
    console.warn('Dependency scan failed (non-blocking):', (err as Error).message);
  }

  // 3. Network scans (if hosts provided)
  const networkAssets: CryptoAsset[] = [];
  if (networkHosts && networkHosts.length > 0) {
    for (const host of networkHosts) {
      try {
        const result = await scanNetworkCrypto(host);
        networkAssets.push(networkResultToCBOMAsset(result));
      } catch (err) {
        console.warn(`Network scan failed for ${host}:`, (err as Error).message);
      }
    }
  }

  // 4. Certificate file scanning (Phase 1A) — parse .pem/.crt/.der files
  let certAssets: CryptoAsset[] = [];
  try {
    certAssets = await scanCertificateFiles(repoPath);
    console.log(`Certificate file scan found ${certAssets.length} crypto assets`);
  } catch (err) {
    console.warn('Certificate file scan failed (non-blocking):', (err as Error).message);
  }

  // 5. External tool scanning (Phase 2A/3) — CodeQL, cbomkit-theia
  let externalAssets: CryptoAsset[] = [];
  try {
    externalAssets = await runExternalToolScans(repoPath, externalToolOptions);
    console.log(`External tool scans found ${externalAssets.length} crypto assets`);
  } catch (err) {
    console.warn('External tool scans failed (non-blocking):', (err as Error).message);
  }

  // 6. Merge all assets
  const merged = mergeCBOMs(codeCBOM, ...depAssets, ...networkAssets, ...certAssets);

  // 7. Deduplicate external tool findings against existing assets
  if (externalAssets.length > 0) {
    const uniqueExternal = deduplicateExternalAssets(merged.cryptoAssets, externalAssets);
    merged.cryptoAssets.push(...uniqueExternal);
    console.log(`External tools: ${externalAssets.length} total, ${uniqueExternal.length} unique (${externalAssets.length - uniqueExternal.length} duplicates merged)`);
  }

  // 8. Smart PQC parameter analysis — promote/demote CONDITIONAL assets
  merged.cryptoAssets = analyzeAllConditionalAssets(merged.cryptoAssets, repoPath);

  // 9. Safety-net: sync quantumSafety column with pqcVerdict
  //    (catches any ordering/overwrite issues from enrichment → analysis pipeline)
  merged.cryptoAssets = syncQuantumSafetyWithVerdict(merged.cryptoAssets);

  // 10. Final false-positive filter (removes HashMap, HashSet, etc.)
  merged.cryptoAssets = filterFalsePositives(merged.cryptoAssets);

  return merged;
}
