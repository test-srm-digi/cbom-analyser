/**
 * CBOM Builder — create, parse, and merge CycloneDX 1.7 CBOM documents.
 */
import { v4 as uuidv4 } from 'uuid';
import {
  CBOMDocument,
  CryptoAsset,
  AssetType,
  QuantumSafetyStatus,
  CBOMRepository,
} from '../../types';
import { enrichAssetWithPQCData } from '../pqcRiskEngine';
import { filterFalsePositives } from '../scanner/scannerUtils';

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * Create an empty CBOM document shell.
 */
export function createEmptyCBOM(
  componentName: string,
  componentVersion?: string,
  repository?: CBOMRepository,
): CBOMDocument {
  // When the scan path is "." or empty, derive a meaningful name from the
  // repository URL (e.g. "https://github.com/org/repo" → "repo") or fall back
  // to a generic label.
  let resolvedName = componentName;
  if (!resolvedName || resolvedName === '.') {
    if (repository?.url) {
      const urlSegments = repository.url.replace(/\/+$/, '').split('/');
      resolvedName = urlSegments[urlSegments.length - 1] || 'Unknown Project';
    } else {
      resolvedName = 'Unknown Project';
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${uuidv4()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'QuantumGuard',
          name: 'CBOM Hub',
          version: '1.0.0',
        },
      ],
      component: {
        name: resolvedName,
        version: componentVersion,
        type: 'application',
      },
      ...(repository ? { repository } : {}),
    },
    components: [],
    cryptoAssets: [],
    dependencies: [],
  };
}

// ─── Parse ───────────────────────────────────────────────────────────────────

/**
 * Parse and validate an uploaded CBOM JSON file.
 * Supports both standard CycloneDX 1.6/1.7 CBOM and custom formats.
 */
export function parseCBOMFile(jsonContent: string): CBOMDocument {
  let data = JSON.parse(jsonContent);

  // Unwrap API response wrapper: { success, cbom, readinessScore, ... }
  if (data.success !== undefined && data.cbom) {
    data = data.cbom;
  }

  // If it's already in our internal format
  if (data.bomFormat === 'CycloneDX' && data.cryptoAssets) {
    // Enrich each asset with PQC data
    data.cryptoAssets = data.cryptoAssets.map((asset: CryptoAsset) =>
      enrichAssetWithPQCData(asset)
    );
    // Remove false positives (e.g. HashMap misclassified as crypto hash)
    data.cryptoAssets = filterFalsePositives(data.cryptoAssets);
    return data as CBOMDocument;
  }

  // If it's a standard CycloneDX with components that have cryptoProperties
  if (data.bomFormat === 'CycloneDX' && data.components) {
    const cbom = createEmptyCBOM(
      data.metadata?.component?.name || 'Unknown',
      data.metadata?.component?.version
    );
    cbom.metadata = data.metadata || cbom.metadata;

    // Map components with crypto properties to our CryptoAsset format
    for (const component of data.components) {
      if (component.cryptoProperties || component['crypto-properties']) {
        const cryptoProps = component.cryptoProperties || component['crypto-properties'];

        // Extract location from evidence, converting absolute paths to relative
        let location: { fileName: string; lineNumber?: number } | undefined;
        const firstOccurrence = component.evidence?.occurrences?.[0];
        if (firstOccurrence) {
          let fileName = firstOccurrence.location || '';
          // Strip absolute path prefix to make it relative
          if (fileName.startsWith('/')) {
            // Try to find src/ or main/ in the path and use from there
            const srcIdx = fileName.indexOf('/src/');
            if (srcIdx >= 0) {
              fileName = fileName.substring(srcIdx + 1);
            } else {
              // Fallback: use just the filename
              fileName = fileName.split('/').slice(-3).join('/');
            }
          }
          location = {
            fileName,
            lineNumber: firstOccurrence.line,
          };
        }

        const asset: CryptoAsset = {
          id: component['bom-ref'] || uuidv4(),
          name: component.name,
          type: 'crypto-asset',
          version: component.version,
          description: component.description,
          cryptoProperties: {
            assetType: cryptoProps.assetType || cryptoProps['asset-type'] || AssetType.ALGORITHM,
            algorithmProperties: cryptoProps.algorithmProperties,
            protocolProperties: cryptoProps.protocolProperties,
          },
          location,
          quantumSafety: QuantumSafetyStatus.UNKNOWN,
        };
        cbom.cryptoAssets.push(enrichAssetWithPQCData(asset));
      }
    }

    cbom.components = data.components;
    cbom.dependencies = data.dependencies;
    // Remove false positives (e.g. HashMap misclassified as crypto hash)
    cbom.cryptoAssets = filterFalsePositives(cbom.cryptoAssets);
    return cbom;
  }

  throw new Error('Invalid CBOM format. Expected CycloneDX CBOM JSON (1.6 or 1.7).');
}

// ─── Merge ───────────────────────────────────────────────────────────────────

/**
 * Merge network scan assets into an existing CBOM.
 */
export function mergeCBOMs(baseCBOM: CBOMDocument, ...additionalAssets: CryptoAsset[]): CBOMDocument {
  return {
    ...baseCBOM,
    cryptoAssets: [...baseCBOM.cryptoAssets, ...additionalAssets],
    metadata: {
      ...baseCBOM.metadata,
      timestamp: new Date().toISOString(),
    },
  };
}
