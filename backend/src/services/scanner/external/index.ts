/**
 * External Tool Scanner — Barrel Exports
 *
 * Unified entry point that runs all available external tools in parallel
 * and provides deduplication against existing CBOM assets.
 */
import type { CryptoAsset } from '../../../types';
import { normaliseAlgorithmName } from '../scannerUtils';
import { checkToolAvailability } from './availability';
import { runCodeQLAnalysis } from './codeql';
import { runCbomkitTheia } from './cbomkitTheia';
import { runCryptoAnalysis } from './cryptoAnalysis';

// ─── Re-exports ─────────────────────────────────────────────────────────────

export { checkToolAvailability, resetToolAvailabilityCache } from './availability';
export { runCodeQLAnalysis, CODEQL_QUERIES } from './codeql';
export { runCbomkitTheia } from './cbomkitTheia';
export { runCryptoAnalysis } from './cryptoAnalysis';
export { findFilesRecursive, findBuildTarget } from './utils';
export type {
  ToolAvailability,
  SARIFResult,
  SARIFRun,
  SARIFReport,
  CbomkitComponent,
  CbomkitOutput,
  CryptoAnalysisResult,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// Unified External Scanner Runner
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run all available external tools and merge their findings.
 *
 * This is the main entry point called from scannerAggregator.ts.
 * Each tool runs independently and fails gracefully.
 */
export async function runExternalToolScans(
  repoPath: string,
  options?: {
    enableCodeQL?: boolean;
    enableCbomkitTheia?: boolean;
    enableCryptoAnalysis?: boolean;
    codeqlLanguage?: string;
  },
): Promise<CryptoAsset[]> {
  const allAssets: CryptoAsset[] = [];
  const availability = await checkToolAvailability();

  // Run tools in parallel where possible
  const promises: Promise<CryptoAsset[]>[] = [];

  if ((options?.enableCodeQL !== false) && availability.codeql) {
    promises.push(
      runCodeQLAnalysis(repoPath, options?.codeqlLanguage)
        .catch(err => {
          console.warn('CodeQL scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if ((options?.enableCbomkitTheia !== false) && availability.cbomkitTheia) {
    promises.push(
      runCbomkitTheia(repoPath)
        .catch(err => {
          console.warn('cbomkit-theia scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if ((options?.enableCryptoAnalysis !== false) && availability.cryptoAnalysis) {
    promises.push(
      runCryptoAnalysis(repoPath)
        .catch(err => {
          console.warn('CryptoAnalysis scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if (promises.length > 0) {
    const results = await Promise.allSettled(promises);
    for (const result of results) {
      if (result.status === 'fulfilled') {
        allAssets.push(...result.value);
      }
    }
  }

  if (allAssets.length > 0) {
    console.log(`External tools: found ${allAssets.length} total crypto assets`);
  }

  return allAssets;
}

/**
 * Deduplicate assets from external tools against existing CBOM assets.
 *
 * An external finding is considered a duplicate if there's already an asset with:
 *   - Same normalised algorithm name
 *   - Same file (or within ±5 lines)
 *
 * When a duplicate is found, the external tool's finding enriches the existing
 * asset (higher confidence, additional context) rather than creating a new one.
 */
export function deduplicateExternalAssets(
  existingAssets: CryptoAsset[],
  externalAssets: CryptoAsset[],
): CryptoAsset[] {
  const newAssets: CryptoAsset[] = [];

  for (const extAsset of externalAssets) {
    const extName = normaliseAlgorithmName(extAsset.name).toLowerCase();
    const extFile = extAsset.location?.fileName ?? '';
    const extLine = extAsset.location?.lineNumber ?? 0;

    // Check for duplicate
    const duplicate = existingAssets.find(existing => {
      const existName = normaliseAlgorithmName(existing.name).toLowerCase();
      const existFile = existing.location?.fileName ?? '';
      const existLine = existing.location?.lineNumber ?? 0;

      return (
        existName === extName &&
        existFile === extFile &&
        Math.abs(existLine - extLine) <= 5
      );
    });

    if (duplicate) {
      // Enrich existing asset with external tool data
      if (extAsset.description) {
        duplicate.description = (duplicate.description ?? '') +
          ` | External tool confirmation: ${extAsset.description}`;
      }
      // Boost confidence if we have a pqcVerdict
      if (duplicate.pqcVerdict && extAsset.pqcVerdict) {
        duplicate.pqcVerdict.confidence = Math.min(100,
          duplicate.pqcVerdict.confidence + 15);
        duplicate.pqcVerdict.reasons.push(
          `✓ Confirmed by ${extAsset.detectionSource} external tool analysis.`,
        );
      }
    } else {
      newAssets.push(extAsset);
    }
  }

  return newAssets;
}
