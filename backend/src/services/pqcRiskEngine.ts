/**
 * PQC (Post-Quantum Cryptography) Risk Engine
 *
 * Classifies cryptographic algorithms by quantum safety and
 * recommends NIST-approved PQC replacements.
 */
import {
  QuantumSafetyStatus,
  ComplianceStatus,
  CryptoAsset,
  QuantumReadinessScore,
  ComplianceSummary,
} from '../types';

// ─── Quantum Safety Classification Database ──────────────────────────────────

interface AlgorithmProfile {
  quantumSafety: QuantumSafetyStatus;
  recommendedPQC?: string;
  notes?: string;
  minSafeKeyLength?: number;
}

const ALGORITHM_DATABASE: Record<string, AlgorithmProfile> = {
  // Asymmetric – ALL quantum-vulnerable
  'RSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-2048': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber-768)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-4096': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber-1024)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-204800': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'ECC': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'ECDSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'ECDH': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'EC-SECP': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'ED25519': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'Ed25519': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'DSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'EDDSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'DH': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'SSL': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC KEM',
  },

  // Symmetric – Generally quantum-resistant but need larger keys
  'AES': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant with 256-bit keys (Grover halves effective key length)',
    minSafeKeyLength: 256,
  },
  'AES-128': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256',
    notes: 'Effectively 64-bit security with Grover\'s algorithm',
  },
  'AES-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit effective security with Grover\'s algorithm',
  },
  'KEY:AES': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'AES key material',
  },
  'CHACHA20': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant with 256-bit keys',
  },

  // Hash functions
  'SHA-1': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'SHA-3-256 or SHA-256',
    notes: 'Classically broken, not just quantum-vulnerable',
  },
  'SHA-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit collision resistance with Grover\'s algorithm',
  },
  'SHA-384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA-512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA-3': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'HMACSHA256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'HMACSHA384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'HMACSHA512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'MD5': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'SHA-3-256',
    notes: 'Classically broken',
  },

  // Key-related
  'KEY:RSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'KEY:HMAC': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'KEY:RAW': {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
  },
  'RAW': {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
  },

  // PQC algorithms – NIST approved
  'ML-KEM': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 203 – Key Encapsulation Mechanism (formerly Kyber)',
  },
  'ML-DSA': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 204 – Digital Signature Algorithm (formerly Dilithium)',
  },
  'SLH-DSA': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 205 – Stateless Hash-Based Digital Signature (formerly SPHINCS+)',
  },
  'FALCON': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST selected PQC signature scheme',
  },

  // TLS protocols
  'TLSv1.0': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Deprecated protocol',
  },
  'TLSv1.1': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Deprecated protocol',
  },
  'TLSv1.2': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Acceptable but not quantum-safe',
  },
  'TLSv1.3': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with ML-KEM hybrid',
    notes: 'Best current standard but key exchange is not PQC yet',
  },
};

// ─── Risk Engine Functions ───────────────────────────────────────────────────

/**
 * Classify the quantum safety of an algorithm by name.
 */
export function classifyAlgorithm(algorithmName: string): AlgorithmProfile {
  const normalized = algorithmName.toUpperCase().trim();

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

/**
 * Enrich a crypto asset with PQC risk data.
 */
export function enrichAssetWithPQCData(asset: CryptoAsset): CryptoAsset {
  const profile = classifyAlgorithm(asset.name);

  return {
    ...asset,
    quantumSafety: profile.quantumSafety,
    recommendedPQC: profile.recommendedPQC,
    complianceStatus: profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE
      ? ComplianceStatus.COMPLIANT
      : profile.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE
        ? ComplianceStatus.NOT_COMPLIANT
        : ComplianceStatus.UNKNOWN,
  };
}

/**
 * Calculate the Quantum Readiness Score for a set of crypto assets.
 * Score is 0-100 where 100 = all assets are quantum-safe.
 */
export function calculateReadinessScore(assets: CryptoAsset[]): QuantumReadinessScore {
  const total = assets.length;
  if (total === 0) {
    return { score: 100, totalAssets: 0, quantumSafe: 0, notQuantumSafe: 0, unknown: 0 };
  }

  const quantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE).length;
  const notQuantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE).length;
  const unknown = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.UNKNOWN).length;

  // Score: safe assets count fully, unknown count as half
  const score = Math.round(((quantumSafe + unknown * 0.5) / total) * 100);

  return { score, totalAssets: total, quantumSafe, notQuantumSafe, unknown };
}

/**
 * Check compliance against NIST PQC policy.
 */
export function checkNISTPQCCompliance(assets: CryptoAsset[]): ComplianceSummary {
  const compliantAssets = assets.filter(a => a.complianceStatus === ComplianceStatus.COMPLIANT).length;
  const nonCompliantAssets = assets.filter(a => a.complianceStatus === ComplianceStatus.NOT_COMPLIANT).length;
  const unknownAssets = assets.filter(a =>
    a.complianceStatus === ComplianceStatus.UNKNOWN || !a.complianceStatus
  ).length;

  return {
    isCompliant: nonCompliantAssets === 0,
    policy: 'NIST Post-Quantum Cryptography',
    source: 'Basic Local Compliance Service',
    totalAssets: assets.length,
    compliantAssets,
    nonCompliantAssets,
    unknownAssets,
  };
}

/**
 * Get all known PQC algorithm names.
 */
export function getPQCAlgorithms(): string[] {
  return Object.entries(ALGORITHM_DATABASE)
    .filter(([_, profile]) => profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE)
    .map(([name]) => name);
}

export { ALGORITHM_DATABASE };
