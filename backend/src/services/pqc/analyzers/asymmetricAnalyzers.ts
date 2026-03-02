/**
 * Asymmetric / Key-Exchange Analyzers
 *
 * Parameter extraction & PQC verdict for:
 * KeyPairGenerator, Digital Signature, KeyAgreement, KeyGenerator.
 */
import { PQCReadinessVerdict, PQCVerdictDetail } from '../../../types';

/**
 * Analyze KeyPairGenerator to determine algorithm.
 */
export function analyzeKeyPairGenerator(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const algMatch = context.match(
    /KeyPairGenerator\.getInstance\s*\(\s*"([^"]+)"/
  );

  if (algMatch) {
    const alg = algMatch[1].toUpperCase();
    params.algorithm = algMatch[1];

    if (alg === 'RSA' || alg === 'DSA') {
      reasons.push(`KeyPairGenerator for ${algMatch[1]} — vulnerable to Shor's algorithm ✗`);

      const sizeMatch = context.match(/initialize\s*\(\s*(\d+)/);
      if (sizeMatch) {
        params.keyBits = parseInt(sizeMatch[1], 10);
        reasons.push(`Key size: ${sizeMatch[1]}-bit (irrelevant against Shor's — all sizes vulnerable)`);
      }

      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: `Replace ${algMatch[1]} with ML-KEM (Kyber) for key encapsulation or ML-DSA (Dilithium) for signatures.`,
      };
    }

    if (alg === 'EC' || alg.includes('ECDSA') || alg.includes('ECDH')) {
      reasons.push(`KeyPairGenerator for ${algMatch[1]} — elliptic curve, vulnerable to Shor's algorithm ✗`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: `Replace ${algMatch[1]} with ML-DSA (Dilithium) for signatures or ML-KEM (Kyber) for key agreement.`,
      };
    }

    if (alg.includes('ML-KEM') || alg.includes('KYBER') || alg.includes('ML-DSA') || alg.includes('DILITHIUM')) {
      reasons.push(`KeyPairGenerator for ${algMatch[1]} — NIST PQC standard ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: 'PQC algorithm detected. No action needed.',
      };
    }
  }

  reasons.push('Could not determine KeyPairGenerator algorithm — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Check the algorithm passed to KeyPairGenerator.getInstance(). RSA/EC → vulnerable; ML-KEM/ML-DSA → safe.',
  };
}

/**
 * Analyze Digital-Signature (Signature.getInstance) to determine algorithm.
 */
export function analyzeDigitalSignature(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const algMatch = context.match(
    /Signature\.getInstance\s*\(\s*"([^"]+)"/
  );

  if (algMatch) {
    const sigAlg = algMatch[1];
    params.signatureAlgorithm = sigAlg;
    const upper = sigAlg.toUpperCase();

    if (upper.includes('RSA') || upper.includes('ECDSA') || upper.includes('DSA') || upper.includes('ED25519')) {
      reasons.push(`Signature algorithm "${sigAlg}" — classical, vulnerable to Shor's algorithm ✗`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: `Replace "${sigAlg}" with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+).`,
      };
    }

    if (upper.includes('ML-DSA') || upper.includes('DILITHIUM') || upper.includes('SLH-DSA') || upper.includes('SPHINCS') || upper.includes('FALCON')) {
      reasons.push(`Signature algorithm "${sigAlg}" — NIST PQC standard ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: 'PQC signature detected. No action needed.',
      };
    }
  }

  reasons.push('Could not determine signature algorithm — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Check the algorithm passed to Signature.getInstance(). RSA/ECDSA → vulnerable; ML-DSA → safe.',
  };
}

/**
 * Analyze Java KeyAgreement usage.
 */
export function analyzeKeyAgreement(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const algMatch = context.match(
    /KeyAgreement\.getInstance\s*\(\s*['"]([^'"]+)['"]/
  );

  if (algMatch) {
    const alg = algMatch[1];
    params.algorithm = alg;
    const upper = alg.toUpperCase();

    if (upper.includes('DH') || upper.includes('ECDH') || upper.includes('X25519') || upper.includes('X448')) {
      reasons.push(`KeyAgreement for "${alg}" — classical key exchange, vulnerable to Shor's algorithm ✗`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: `Replace ${alg} key agreement with ML-KEM (Kyber) or hybrid ML-KEM+ECDH.`,
      };
    }

    if (upper.includes('ML-KEM') || upper.includes('KYBER')) {
      reasons.push(`KeyAgreement for "${alg}" — NIST PQC standard ✓`);
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 95, reasons, parameters: params, recommendation: 'PQC key agreement. No action needed.' };
    }
  }

  reasons.push('Could not determine KeyAgreement algorithm — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Check KeyAgreement.getInstance() algorithm. DH/ECDH → vulnerable; ML-KEM → safe.',
  };
}

/**
 * Analyze Java KeyGenerator usage.
 */
export function analyzeKeyGenerator(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const algMatch = context.match(
    /KeyGenerator\.getInstance\s*\(\s*['"]([^'"]+)['"]/
  );

  if (algMatch) {
    const alg = algMatch[1];
    params.algorithm = alg;
    const upper = alg.toUpperCase();

    if (upper === 'AES' || upper.includes('AES')) {
      const sizeMatch = context.match(/\.init\s*\(\s*(\d+)/);
      if (sizeMatch) {
        const bits = parseInt(sizeMatch[1], 10);
        params.keyBits = bits;
        if (bits >= 256) {
          reasons.push(`KeyGenerator for AES with ${bits}-bit key — quantum-safe ✓`);
          return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 90, reasons, parameters: params, recommendation: 'AES-256 is quantum-safe.' };
        } else {
          reasons.push(`KeyGenerator for AES with ${bits}-bit key — Grover's halves effective security`);
          return { verdict: PQCReadinessVerdict.NOT_PQC_READY, confidence: 85, reasons, parameters: params, recommendation: 'Upgrade to AES-256 (KeyGenerator.init(256)).' };
        }
      }
      reasons.push('KeyGenerator for AES — quantum-safe with 256-bit key, verify key size');
      return { verdict: PQCReadinessVerdict.REVIEW_NEEDED, confidence: 60, reasons, parameters: params, recommendation: 'Verify KeyGenerator.init() uses 256-bit key size.' };
    }

    if (upper.includes('HMAC') || upper.includes('CHACHA')) {
      reasons.push(`KeyGenerator for "${alg}" — symmetric, quantum-safe ✓`);
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 85, reasons, parameters: params, recommendation: 'Symmetric key generation is quantum-safe.' };
    }

    if (upper.includes('DES')) {
      reasons.push(`KeyGenerator for "${alg}" — classically weak, not quantum-safe ✗`);
      return { verdict: PQCReadinessVerdict.NOT_PQC_READY, confidence: 95, reasons, parameters: params, recommendation: 'Replace DES with AES-256.' };
    }
  }

  reasons.push('Could not determine KeyGenerator algorithm — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Check KeyGenerator.getInstance() algorithm and key size.',
  };
}
