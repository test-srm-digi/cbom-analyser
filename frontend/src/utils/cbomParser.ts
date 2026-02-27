/**
 * Shared CBOM parsing utilities.
 *
 * Used by App.tsx (upload / sample data) and CbomDetailPage (import detail).
 * Centralises CycloneDX → internal model conversion so every page gets
 * consistent crypto-asset counts and quantum-safety classifications.
 */
import type {
  CBOMDocument,
  QuantumReadinessScore,
  ComplianceSummary,
  CryptoAsset,
} from '../types';

/* ── Helpers ──────────────────────────────────────────────── */

function buildDoc(data: any): CBOMDocument {
  return {
    bomFormat: data.bomFormat || 'CycloneDX',
    specVersion: data.specVersion || '1.7',
    serialNumber: data.serialNumber,
    version: data.version || 1,
    metadata: data.metadata || { timestamp: new Date().toISOString() },
    components: data.components || [],
    cryptoAssets: data.cryptoAssets || [],
    dependencies: data.dependencies,
    thirdPartyLibraries: data.thirdPartyLibraries,
  };
}

/**
 * Resolve the quantum-safety status from a component / crypto-properties
 * object.  Mirrors the backend `analyzeCbom` logic so the frontend
 * produces identical numbers.
 */
function resolveQuantumSafety(
  comp: Record<string, any>,
  cp: Record<string, any> | undefined,
): CryptoAsset['quantumSafety'] {
  const raw =
    comp.quantumSafety ??
    comp['quantum-safety'] ??
    cp?.quantumSafety ??
    cp?.['quantum-safety'] ??
    'unknown';

  switch (raw) {
    case 'quantum-safe':
      return 'quantum-safe' as any;
    case 'not-quantum-safe':
      return 'not-quantum-safe' as any;
    case 'conditional':
      return 'conditional' as any;
    default:
      return 'unknown' as any;
  }
}

/* ── Public API ───────────────────────────────────────────── */

export interface ParsedCbom {
  doc: CBOMDocument;
  readinessScore: QuantumReadinessScore;
  compliance: ComplianceSummary;
}

/**
 * Parse a raw JSON string (either a CycloneDX CBOM or a wrapped
 * `{ success, cbom, readinessScore, compliance }` envelope) and
 * return a fully-resolved internal model with correct quantum-safety
 * counts.
 *
 * @param jsonText  The raw JSON string.
 * @param source    Label shown in the compliance summary
 *                  (e.g. "CBOM Import Analysis").
 */
export function parseCbomJson(
  jsonText: string,
  source = 'CBOM Import Analysis',
): ParsedCbom {
  let data = JSON.parse(jsonText);

  /* Handle wrapped response format from /api/upload */
  if (data.success !== undefined && data.cbom) {
    const wrappedScore = data.readinessScore;
    const wrappedCompliance = data.compliance;
    data = data.cbom;
    if (wrappedScore && wrappedCompliance) {
      return {
        doc: buildDoc(data),
        readinessScore: wrappedScore,
        compliance: wrappedCompliance,
      };
    }
  }

  const doc = buildDoc(data);

  /* ── Extract crypto assets from components when needed ──── */
  if (doc.cryptoAssets.length === 0 && doc.components.length > 0) {
    for (const comp of doc.components as any[]) {
      const cp = comp.cryptoProperties || comp['crypto-properties'];
      if (cp) {
        doc.cryptoAssets.push({
          id: comp['bom-ref'] || crypto.randomUUID(),
          name: comp.name,
          type: comp.type || 'crypto-asset',
          cryptoProperties: {
            assetType: cp.assetType || cp['asset-type'] || 'algorithm',
            algorithmProperties: cp.algorithmProperties,
          },
          location: comp.evidence?.occurrences?.[0]
            ? {
                fileName: comp.evidence.occurrences[0].location || '',
                lineNumber: comp.evidence.occurrences[0].line,
              }
            : undefined,
          quantumSafety: resolveQuantumSafety(comp, cp),
        } as CryptoAsset);
      }
    }
  }

  /* ── Compute scores ──────────────────────────────────────── */
  const total = doc.cryptoAssets.length;
  const safe = doc.cryptoAssets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const notSafe = doc.cryptoAssets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
  const conditional = doc.cryptoAssets.filter((a) => a.quantumSafety === 'conditional').length;
  const unknown = doc.cryptoAssets.filter((a) => a.quantumSafety === 'unknown').length;

  const readinessScore: QuantumReadinessScore = {
    // Match backend: safe=1.0, conditional=0.5 (REVIEW_NEEDED), unknown=0.5
    score: total > 0 ? Math.round(((safe + conditional * 0.5 + unknown * 0.5) / total) * 100) : 100,
    totalAssets: total,
    quantumSafe: safe,
    notQuantumSafe: notSafe,
    conditional,
    unknown,
  };

  const compliance: ComplianceSummary = {
    isCompliant: notSafe === 0,
    policy: 'NIST Post-Quantum Cryptography',
    source,
    totalAssets: total,
    compliantAssets: safe,
    nonCompliantAssets: notSafe,
    unknownAssets: unknown,
  };

  return { doc, readinessScore, compliance };
}
