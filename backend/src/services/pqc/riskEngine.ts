/**
 * PQC Risk Engine — Business Logic
 *
 * Classifies cryptographic algorithms by quantum safety,
 * enriches assets with PQC data, and computes readiness/compliance.
 */
import {
  QuantumSafetyStatus,
  ComplianceStatus,
  CryptoAsset,
  QuantumReadinessScore,
  ComplianceSummary,
  PQCReadinessVerdict,
} from '../../types';
import type { AlgorithmProfile } from './types';
import { ALGORITHM_DATABASE } from './algorithmDatabase';

// ─── Classification ──────────────────────────────────────────────────────────

/**
 * Classify the quantum safety of an algorithm by name.
 */
export function classifyAlgorithm(algorithmName: string): AlgorithmProfile {
  const normalized = algorithmName.toUpperCase().trim();
  // Also create a version with dashes removed for fuzzy matching
  const noDashes = normalized.replace(/-/g, '');

  // Exact match
  if (ALGORITHM_DATABASE[algorithmName]) {
    return ALGORITHM_DATABASE[algorithmName];
  }

  // Case-insensitive match
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (key.toUpperCase() === normalized) {
      return profile;
    }
  }

  // Dash-insensitive match (e.g., "SHA256" matches "SHA-256", "AES128-GCM" matches "AES-128")
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (key.toUpperCase().replace(/-/g, '') === noDashes) {
      return profile;
    }
  }

  // Partial match (e.g., "RSA-OAEP" matches "RSA")
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (normalized.includes(key.toUpperCase()) || key.toUpperCase().includes(normalized)) {
      return profile;
    }
  }

  return {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    notes: 'Algorithm not found in classification database',
  };
}

// ─── Asset Enrichment ────────────────────────────────────────────────────────

/**
 * Enrich a crypto asset with PQC risk data.
 *
 * BC-Provider reclassification (Phase 1C): Entries marked `isInformational` in the
 * ALGORITHM_DATABASE are treated as audit-trail metadata, not actionable findings.
 * They get a special REVIEW_NEEDED verdict with low confidence (10) and a clear
 * note that actual algorithms are classified separately.
 */
export function enrichAssetWithPQCData(asset: CryptoAsset): CryptoAsset {
  // ── Normalize bare-number algorithm names ──
  // sonar-cryptography sometimes extracts key sizes as algorithm names (e.g. "3072"
  // from `rsaKeyGen.initialize(3072)`). Rename these to something meaningful.
  let normalizedAsset = asset;
  if (/^\d{3,5}$/.test(asset.name)) {
    const keySize = parseInt(asset.name, 10);
    const functions = asset.cryptoProperties?.algorithmProperties?.cryptoFunctions ?? [];
    const hasKeygen = functions.some((f: string) => f.toLowerCase() === 'keygen');
    // Infer algorithm from context: key size + keygen → likely RSA key generation
    let inferredName: string;
    if (keySize >= 1024 && keySize <= 16384 && (keySize & (keySize - 1)) === 0 || [3072, 7680, 15360].includes(keySize)) {
      // Common RSA key sizes: 1024, 2048, 3072, 4096, 7680, 8192, 15360, 16384
      inferredName = `RSA-${keySize}`;
    } else if (keySize >= 128 && keySize <= 521) {
      // Likely EC curve size (P-256 = 256, P-384 = 384, P-521 = 521) or symmetric key
      if (keySize === 256 || keySize === 384 || keySize === 521) {
        inferredName = `EC-${keySize}`;
      } else {
        inferredName = `AES-${keySize}`;
      }
    } else {
      inferredName = `RSA-${keySize}`;
    }
    normalizedAsset = {
      ...asset,
      name: inferredName,
      description: asset.description
        ? asset.description
        : `Key size ${keySize}-bit detected${hasKeygen ? ' in key generation' : ''}. Originally reported as bare number "${asset.name}".`,
    };
  }

  const profile = classifyAlgorithm(normalizedAsset.name);

  // ── Phase 1C: BC-Provider / JCE-Registration / Library reclassification ──
  if (profile.isInformational) {
    // Always override pqcVerdict for informational assets — force low confidence (10)
    // to prevent scanner-generated confidence: 40 from inflating their importance.
    const pqcVerdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 10,
      reasons: [
        `${normalizedAsset.name} is informational — this is a provider/framework/library registration, not an algorithm.`,
        'The actual cryptographic algorithms used through this provider are detected and classified as separate findings.',
        ...(profile.notes ? [profile.notes] : []),
        ...(normalizedAsset.description ? [`\u{1F50D} ${normalizedAsset.description}`] : []),
      ],
      recommendation: 'No direct action needed. Review the individual algorithm classifications that use this provider/library.',
    };

    return {
      ...normalizedAsset,
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      pqcVerdict,
      complianceStatus: ComplianceStatus.COMPLIANT,  // Informational entries are not compliance violations
      description: normalizedAsset.description
        ? (normalizedAsset.description.startsWith('[INFORMATIONAL]')
          ? normalizedAsset.description
          : `[INFORMATIONAL] ${normalizedAsset.description}`)
        : `[INFORMATIONAL] ${normalizedAsset.name} — provider/library reference, not an algorithm. See individual algorithm findings.`,
    };
  }

  // Build a pqcVerdict for definitively classified assets so the frontend always has verdict data
  let pqcVerdict = normalizedAsset.pqcVerdict;
  if (!pqcVerdict && profile.quantumSafety !== QuantumSafetyStatus.UNKNOWN) {
    if (profile.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          `${normalizedAsset.name} is classified as not quantum-safe.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(normalizedAsset.description ? [`\u{1F50D} ${normalizedAsset.description}`] : []),
        ],
        recommendation: profile.recommendedPQC
          ? `Replace with ${profile.recommendedPQC}.`
          : 'Migrate to a NIST-approved post-quantum algorithm.',
      };
    } else if (profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons: [
          `${normalizedAsset.name} is classified as quantum-safe.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(normalizedAsset.description ? [`\u{1F50D} ${normalizedAsset.description}`] : []),
        ],
        recommendation: 'No migration needed.',
      };
    } else if (profile.quantumSafety === QuantumSafetyStatus.CONDITIONAL) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 40,
        reasons: [
          `${normalizedAsset.name} quantum safety is conditional on configuration/parameters.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(normalizedAsset.description ? [`\u{1F50D} ${normalizedAsset.description}`] : []),
        ],
        recommendation: profile.recommendedPQC
          ? `Consider ${profile.recommendedPQC} if current parameters are insufficient.`
          : 'Review parameters and configuration for quantum safety.',
      };
    }
  }

  // Respect quantumSafety if it was already promoted/demoted by the parameter
  // analyzer (i.e. not UNKNOWN and different from the DB's generic classification).
  const effectiveSafety =
    normalizedAsset.quantumSafety !== QuantumSafetyStatus.UNKNOWN &&
    normalizedAsset.quantumSafety !== QuantumSafetyStatus.CONDITIONAL &&
    normalizedAsset.quantumSafety !== profile.quantumSafety
      ? normalizedAsset.quantumSafety
      : profile.quantumSafety;

  return {
    ...normalizedAsset,
    quantumSafety: effectiveSafety,
    recommendedPQC: profile.recommendedPQC,
    pqcVerdict,
    complianceStatus: effectiveSafety === QuantumSafetyStatus.QUANTUM_SAFE
      ? ComplianceStatus.COMPLIANT
      : effectiveSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE
        ? ComplianceStatus.NOT_COMPLIANT
        : effectiveSafety === QuantumSafetyStatus.CONDITIONAL
          ? ComplianceStatus.COMPLIANT   // Conditional assets are compliant but flagged for review
          : ComplianceStatus.UNKNOWN,
  };
}

// ─── Verdict Sync ────────────────────────────────────────────────────────────

/**
 * Safety-net sync: ensure quantumSafety is consistent with pqcVerdict.
 * Call this AFTER all analysis (parameter analyzer, cross-file enrichment)
 * to catch any ordering/overwrite issues.
 */
export function syncQuantumSafetyWithVerdict(assets: CryptoAsset[]): CryptoAsset[] {
  return assets.map(asset => {
    const v = asset.pqcVerdict;
    if (!v) return asset;

    let expected: QuantumSafetyStatus | null = null;
    if (v.verdict === PQCReadinessVerdict.PQC_READY && v.confidence >= 70) {
      expected = QuantumSafetyStatus.QUANTUM_SAFE;
    } else if (v.verdict === PQCReadinessVerdict.NOT_PQC_READY && v.confidence >= 50) {
      expected = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
    }

    if (expected && asset.quantumSafety !== expected) {
      return {
        ...asset,
        quantumSafety: expected,
        complianceStatus: expected === QuantumSafetyStatus.QUANTUM_SAFE
          ? ComplianceStatus.COMPLIANT
          : ComplianceStatus.NOT_COMPLIANT,
      };
    }
    return asset;
  });
}

// ─── Readiness Score ─────────────────────────────────────────────────────────

/**
 * Calculate the Quantum Readiness Score for a set of crypto assets.
 * Score is 0-100 where 100 = all assets are quantum-safe.
 *
 * Informational assets (provider/library registrations) are excluded from
 * the score calculation since they don't represent actual algorithms.
 *
 * If assets have a pqcVerdict, that verdict is used for more precise scoring:
 *   PQC_READY     → 1.0  (not just the flat 0.75 for conditional)
 *   NOT_PQC_READY → 0.0
 *   REVIEW_NEEDED → 0.5
 */
export function calculateReadinessScore(assets: CryptoAsset[]): QuantumReadinessScore {
  // Filter out informational assets for scoring (they are not actionable)
  const actionableAssets = filterInformationalAssets(assets);
  const total = actionableAssets.length;
  if (total === 0) {
    return { score: 100, totalAssets: 0, quantumSafe: 0, notQuantumSafe: 0, conditional: 0, unknown: 0 };
  }

  const quantumSafe = actionableAssets.filter(a => a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE).length;
  const notQuantumSafe = actionableAssets.filter(a => a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE).length;
  const conditional = actionableAssets.filter(a => a.quantumSafety === QuantumSafetyStatus.CONDITIONAL).length;
  const unknown = actionableAssets.filter(a => a.quantumSafety === QuantumSafetyStatus.UNKNOWN).length;

  // Verdict-aware scoring
  let weightedSum = quantumSafe; // safe = 1.0 each
  // unknown = 0.5 each
  weightedSum += unknown * 0.5;

  // Conditional assets: use their pqcVerdict if available for precise scoring
  for (const asset of actionableAssets) {
    if (asset.quantumSafety === QuantumSafetyStatus.CONDITIONAL) {
      if (asset.pqcVerdict) {
        switch (asset.pqcVerdict.verdict) {
          case PQCReadinessVerdict.PQC_READY:
            weightedSum += 1.0;
            break;
          case PQCReadinessVerdict.NOT_PQC_READY:
            weightedSum += 0.0;
            break;
          case PQCReadinessVerdict.REVIEW_NEEDED:
            weightedSum += 0.5;
            break;
        }
      } else {
        weightedSum += 0.75; // legacy flat weight for unanalyzed conditional
      }
    }
  }

  const score = Math.round((weightedSum / total) * 100);

  return { score, totalAssets: total, quantumSafe, notQuantumSafe, conditional, unknown };
}

// ─── Compliance ──────────────────────────────────────────────────────────────

/**
 * Check compliance against NIST PQC policy.
 * Informational assets are excluded from compliance checking.
 */
export function checkNISTPQCCompliance(assets: CryptoAsset[]): ComplianceSummary {
  const actionable = filterInformationalAssets(assets);
  const compliantAssets = actionable.filter(a => a.complianceStatus === ComplianceStatus.COMPLIANT).length;
  const nonCompliantAssets = actionable.filter(a => a.complianceStatus === ComplianceStatus.NOT_COMPLIANT).length;
  const unknownAssets = actionable.filter(a =>
    a.complianceStatus === ComplianceStatus.UNKNOWN || !a.complianceStatus
  ).length;

  return {
    isCompliant: nonCompliantAssets === 0,
    policy: 'NIST Post-Quantum Cryptography',
    source: 'Basic Local Compliance Service',
    totalAssets: actionable.length,
    compliantAssets,
    nonCompliantAssets,
    unknownAssets,
  };
}

// ─── PQC Helpers ─────────────────────────────────────────────────────────────

/**
 * Get all known PQC algorithm names.
 */
export function getPQCAlgorithms(): string[] {
  return Object.entries(ALGORITHM_DATABASE)
    .filter(([_, profile]) => profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE)
    .map(([name]) => name);
}

// ─── Informational Asset Helpers (Phase 1C) ─────────────────────────────────

/**
 * Check if a crypto asset is informational (provider registration, not an algorithm).
 * Informational assets should be excluded from compliance/readiness counts
 * but preserved in the CBOM for audit trail.
 */
export function isInformationalAsset(asset: CryptoAsset): boolean {
  const profile = classifyAlgorithm(asset.name);
  return profile.isInformational === true;
}

/**
 * Filter out informational assets from a list (for counting/scoring purposes).
 */
export function filterInformationalAssets(assets: CryptoAsset[]): CryptoAsset[] {
  return assets.filter(a => !isInformationalAsset(a));
}
