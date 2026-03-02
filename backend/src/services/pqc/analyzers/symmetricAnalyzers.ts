/**
 * Symmetric Cipher Analyzers
 *
 * Parameter extraction & PQC verdict for:
 * AES, generic block ciphers (Twofish, Serpent, Camellia), generic Cipher.
 */
import { PQCReadinessVerdict, PQCVerdictDetail } from '../../../types';

/**
 * Analyze AES usage by extracting key size.
 */
export function analyzeAES(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // If name already contains key size
  const nameKeySize = assetName.match(/AES[- ]?(\d+)/i);
  if (nameKeySize) {
    const bits = parseInt(nameKeySize[1], 10);
    params.keyBits = bits;

    if (bits >= 256) {
      reasons.push(`AES-${bits} — 128-bit effective security with Grover's algorithm ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: 'AES-256 is quantum-safe. No action needed.',
      };
    } else {
      reasons.push(`AES-${bits} — Grover's reduces to ${bits / 2}-bit effective security`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 90,
        reasons,
        parameters: params,
        recommendation: `Migrate from AES-${bits} to AES-256 for post-quantum security.`,
      };
    }
  }

  // Extract key size from context
  const keySizeMatch = context.match(
    /KeyGenerator\.getInstance\s*\(\s*"AES"\s*\)[^;]*\.init\s*\(\s*(\d+)/
  ) || context.match(
    /new\s+SecretKeySpec\s*\([^,]+,\s*(\d+)/
  ) || context.match(
    /(?:keySize|KEY_SIZE|keyLength)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /aes-(\d+)/i
  );

  if (keySizeMatch) {
    const bits = parseInt(keySizeMatch[1], 10);
    params.keyBits = bits;

    if (bits >= 256) {
      reasons.push(`AES key size ${bits}-bit ≥ 256 — quantum-safe ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 90,
        reasons,
        parameters: params,
        recommendation: 'AES-256 is quantum-safe. No action needed.',
      };
    } else {
      reasons.push(`AES key size ${bits}-bit — Grover's reduces to ${bits / 2}-bit`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 85,
        reasons,
        parameters: params,
        recommendation: `Upgrade to AES-256 for post-quantum margin.`,
      };
    }
  }

  reasons.push('Could not determine AES key size from source context');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Verify AES key size is 256-bit. If using AES-128, migrate to AES-256.',
  };
}

/**
 * Analyze a generic block cipher (Twofish, Serpent, Camellia) for key size.
 */
export function analyzeGenericBlockCipher(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const keySizeMatch = context.match(
    /(?:keySize|KEY_SIZE|keyLength|key_?length|key_?bits)\s*[=:]\s*(\d+)/i
  ) || context.match(
    new RegExp(`${assetName}[- /]?(128|192|256)`, 'i')
  );

  if (keySizeMatch) {
    const bits = parseInt(keySizeMatch[1], 10);
    params.keyBits = bits;

    if (bits >= 256) {
      reasons.push(`${assetName} with ${bits}-bit key — Grover's reduces to ${bits / 2}-bit effective, still quantum-safe ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 85,
        reasons,
        parameters: params,
        recommendation: `${assetName}-${bits} is quantum-safe. No migration needed.`,
      };
    } else {
      reasons.push(`${assetName} with ${bits}-bit key — Grover's reduces to ${bits / 2}-bit effective`);
      return {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 70,
        reasons,
        parameters: params,
        recommendation: `Consider upgrading to ${assetName}-256 or AES-256 for post-quantum margin.`,
      };
    }
  }

  reasons.push(`${assetName} detected — symmetric cipher. Quantum-safe with 256-bit key but key size unknown.`);
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 50,
    reasons,
    parameters: params,
    recommendation: `Verify ${assetName} uses a 256-bit key. Consider standardizing on AES-256.`,
  };
}

/**
 * Analyze generic "Cipher" detections.
 */
export function analyzeGenericCipher(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const cipherMatch = context.match(
    /Cipher\.getInstance\s*\(\s*['"]([^'"]+)['"]/
  ) || context.match(
    /['"](?:AES|DES|Blowfish|ChaCha20|RC\d|Twofish|Camellia|IDEA)(?:[/_-]\w+)?['"]/i
  );

  if (cipherMatch) {
    const cipher = cipherMatch[1] || cipherMatch[0].replace(/['"]/g, '');
    params.cipher = cipher;
    const upper = cipher.toUpperCase();

    if (upper.includes('AES') && upper.includes('256')) {
      reasons.push(`Cipher resolved to AES-256 — quantum-safe ✓`);
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 90, reasons, parameters: params, recommendation: 'AES-256 is quantum-safe.' };
    }
    if (upper.includes('CHACHA20')) {
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 90, reasons: ['ChaCha20 — quantum-safe ✓'], parameters: params, recommendation: 'ChaCha20 is quantum-safe.' };
    }
    if (upper.includes('DES') || upper.includes('RC4') || upper.includes('BLOWFISH')) {
      return { verdict: PQCReadinessVerdict.NOT_PQC_READY, confidence: 85, reasons: [`Cipher "${cipher}" — weak/broken ✗`], parameters: params, recommendation: 'Replace with AES-256-GCM.' };
    }
  }

  reasons.push('Generic "Cipher" detected — could not resolve to a specific algorithm.');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 30,
    reasons,
    parameters: params,
    recommendation: 'Identify the specific cipher algorithm. AES-256/ChaCha20 → safe; DES/RC4 → not safe.',
  };
}
