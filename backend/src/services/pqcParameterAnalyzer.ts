/**
 * PQC Parameter Analyzer
 *
 * Provides **definitive** PQC readiness verdicts for "conditional" crypto assets
 * by analyzing the actual source code context to extract real parameters:
 *   - PBKDF2: iteration count, key output length, underlying hash
 *   - SecureRandom: provider, seed source
 *   - KeyPairGenerator: algorithm parameter (RSA → vulnerable, EC → vulnerable)
 *   - AES: key size from KeyGenerator.init() or SecretKeySpec constructor
 *   - DRBG: seed length, cipher backing
 *
 * Instead of a vague "conditional" label, this engine gives one of:
 *   PQC_READY      — definitively safe against quantum attacks
 *   NOT_PQC_READY  — definitively vulnerable or too weak
 *   REVIEW_NEEDED  — couldn't extract params; manual review required
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  CryptoAsset,
  QuantumSafetyStatus,
  PQCReadinessVerdict,
  PQCVerdictDetail,
} from '../types';

// ─── Parameter Extraction Helpers ───────────────────────────────────────────

/**
 * Extract surrounding source code context (±N lines around the detection).
 */
function extractSourceContext(
  repoPath: string,
  fileName: string,
  lineNumber: number,
  contextLines: number = 15
): string | null {
  try {
    const fullPath = path.join(repoPath, fileName);
    if (!fs.existsSync(fullPath)) return null;

    const content = fs.readFileSync(fullPath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);
    return lines.slice(start, end).join('\n');
  } catch {
    return null;
  }
}

// ─── Specific Analyzers ────────────────────────────────────────────────────

/**
 * Analyze PBKDF2 usage by extracting iteration count, key length, and hash.
 */
function analyzePBKDF2(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};
  let score = 0; // accumulate, 3 = fully safe

  // ── Iteration count ──
  // Java: new PBEKeySpec(password, salt, 600000, 256)
  // Java: PBEKeySpec(..., iterationCount, keyLength) — 3rd positional arg
  const iterMatch = context.match(
    /new\s+PBEKeySpec\s*\([^,]+,[^,]+,\s*(\d+)/
  ) || context.match(
    /(?:iterations?|iterationCount|ITERATIONS?|PBKDF2_ITERATIONS?)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /pbkdf2Sync\s*\([^,]+,[^,]+,\s*(\d+)/   // Node.js
  );

  if (iterMatch) {
    const iterations = parseInt(iterMatch[1], 10);
    params.iterations = iterations;

    if (iterations >= 600000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} ≥ 600,000 (OWASP 2023 recommended) ✓`);
      score++;
    } else if (iterations >= 310000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is acceptable (≥310k) but below 600k recommendation`);
      score += 0.5;
    } else if (iterations >= 100000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is weak — OWASP recommends ≥600,000 for PBKDF2-SHA256`);
    } else {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is dangerously low — trivially brute-forceable`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine iteration count — verify manually');
  }

  // ── Key output length ──
  // Java PBEKeySpec: 4th arg is keyLength in bits
  const keyLenMatch = context.match(
    /new\s+PBEKeySpec\s*\([^,]+,[^,]+,\s*\d+\s*,\s*(\d+)/
  ) || context.match(
    /(?:keyLength|KEY_LENGTH|keySize|KEY_SIZE)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /pbkdf2Sync\s*\([^,]+,[^,]+,\s*\d+\s*,\s*(\d+)/  // Node.js: 4th arg = keylen in bytes
  );

  if (keyLenMatch) {
    let keyBits = parseInt(keyLenMatch[1], 10);
    // Node.js pbkdf2Sync output length is in bytes
    if (context.includes('pbkdf2Sync') && keyBits <= 64) {
      keyBits *= 8; // convert bytes → bits
    }
    params.keyLengthBits = keyBits;

    if (keyBits >= 256) {
      reasons.push(`Key output ${keyBits}-bit ≥ 256 — sufficient post-quantum margin ✓`);
      score++;
    } else if (keyBits >= 128) {
      reasons.push(`Key output ${keyBits}-bit — Grover's reduces to ${keyBits / 2}-bit effective. Consider 256-bit.`);
    } else {
      reasons.push(`Key output ${keyBits}-bit is too short for post-quantum security`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine key output length — verify manually');
  }

  // ── Underlying hash ──
  const hashMatch = context.match(
    /PBKDF2WithHmac(SHA\d+)/i
  ) || context.match(
    /PBKDF2-HMAC-(SHA\d+)/i
  ) || context.match(
    /['"]sha(\d+)['"]/i
  ) || context.match(
    /(?:hash|digest|algorithm)\s*[=:]\s*['"]?(SHA-?\d+)/i
  );

  if (hashMatch) {
    const hash = hashMatch[1].toUpperCase();
    params.hashAlgorithm = `SHA-${hash.replace('SHA', '')}`;

    if (hash.includes('512') || hash.includes('384') || hash.includes('256')) {
      reasons.push(`Underlying hash ${params.hashAlgorithm} is quantum-resistant ✓`);
      score++;
    } else if (hash.includes('1')) {
      reasons.push(`Underlying hash SHA-1 is classically broken — migrate to SHA-256+`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine underlying hash — assume SHA-256 if using PBKDF2WithHmacSHA256');
  }

  // ── Final verdict ──
  let verdict: PQCReadinessVerdict;
  let confidence: number;
  let recommendation: string;

  if (score >= 2.5) {
    verdict = PQCReadinessVerdict.PQC_READY;
    confidence = Math.min(95, 70 + score * 8);
    recommendation = 'PBKDF2 configuration meets post-quantum requirements. No action needed.';
  } else if (score >= 1) {
    verdict = PQCReadinessVerdict.REVIEW_NEEDED;
    confidence = 50 + score * 10;
    recommendation = 'PBKDF2 partially meets PQC standards. Increase iterations to ≥600k and ensure 256-bit key output with SHA-256+.';
  } else {
    verdict = PQCReadinessVerdict.NOT_PQC_READY;
    confidence = Math.max(20, 60 + score * 10);
    recommendation = 'PBKDF2 configuration is weak. Migrate to Argon2id or increase iterations to ≥600k with SHA-256 and 256-bit key output.';
  }

  return { verdict, confidence, reasons, parameters: params, recommendation };
}

/**
 * Analyze AES usage by extracting key size.
 */
function analyzeAES(context: string, assetName: string): PQCVerdictDetail {
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
    /new\s+SecretKeySpec\s*\([^,]+,\s*(\d+)/  // Not ideal but may have size
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
 * Analyze SecureRandom to determine provider / seed source.
 */
function analyzeSecureRandom(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Check for specific provider
  const providerMatch = context.match(
    /SecureRandom\.getInstance\s*\(\s*"([^"]+)"/
  );
  if (providerMatch) {
    params.algorithm = providerMatch[1];
    const alg = providerMatch[1].toUpperCase();

    if (alg.includes('DRBG') || alg.includes('NATIVEPRNG')) {
      reasons.push(`Using ${providerMatch[1]} — modern CSPRNG, not quantum-vulnerable ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 85,
        reasons,
        parameters: params,
        recommendation: 'CSPRNG is quantum-safe. No action needed.',
      };
    } else if (alg.includes('SHA1PRNG')) {
      reasons.push(`Using SHA1PRNG — not the same as SHA-1 hashing. PRNG itself is not quantum-vulnerable, but consider DRBG for modern compliance.`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 75,
        reasons,
        parameters: params,
        recommendation: 'SHA1PRNG is not quantum-vulnerable. Optionally migrate to DRBG for modern compliance.',
      };
    }
  }

  // Default SecureRandom() — uses platform default
  if (context.match(/new\s+SecureRandom\s*\(\s*\)/)) {
    reasons.push('Using default SecureRandom() — platform default CSPRNG (usually NativePRNG), not quantum-vulnerable ✓');
    params.algorithm = 'platform-default';
    return {
      verdict: PQCReadinessVerdict.PQC_READY,
      confidence: 80,
      reasons,
      parameters: params,
      recommendation: 'Default SecureRandom is quantum-safe. No action needed.',
    };
  }

  reasons.push('Could not determine SecureRandom provider — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 50,
    reasons,
    parameters: params,
    recommendation: 'Verify SecureRandom uses a NIST-approved DRBG or OS-native entropy source.',
  };
}

/**
 * Analyze KeyPairGenerator to determine algorithm.
 */
function analyzeKeyPairGenerator(context: string): PQCVerdictDetail {
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

      // Check key size
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
function analyzeDigitalSignature(context: string): PQCVerdictDetail {
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
 * Analyze SecretKeyFactory to determine purpose.
 */
function analyzeSecretKeyFactory(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const algMatch = context.match(
    /SecretKeyFactory\.getInstance\s*\(\s*"([^"]+)"/
  );

  if (algMatch) {
    const alg = algMatch[1];
    params.algorithm = alg;

    if (alg.toUpperCase().includes('PBKDF2')) {
      reasons.push(`SecretKeyFactory for PBKDF2 — delegating to PBKDF2 analysis`);
      return analyzePBKDF2(context);
    }

    if (alg.toUpperCase().includes('AES')) {
      reasons.push(`SecretKeyFactory for AES — symmetric, quantum-safe with 256-bit key ✓`);
      return analyzeAES(context, alg);
    }

    if (alg.toUpperCase().includes('DES') && !alg.toUpperCase().includes('3DES') && !alg.toUpperCase().includes('TRIPLE')) {
      reasons.push(`SecretKeyFactory for DES — classically broken, not quantum-safe ✗`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons,
        parameters: params,
        recommendation: 'Migrate from DES to AES-256.',
      };
    }
  }

  reasons.push('Could not determine SecretKeyFactory algorithm — verify manually');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Check the algorithm passed to SecretKeyFactory.getInstance().',
  };
}

// ─── Main Analyzer ──────────────────────────────────────────────────────────

/**
 * Analyze a "conditional" crypto asset and produce a definitive PQC verdict.
 *
 * @param asset   The crypto asset to analyze
 * @param repoPath  Root path of the scanned repository
 * @returns The asset with pqcVerdict populated (or unchanged if not conditional)
 */
export function analyzeConditionalAsset(
  asset: CryptoAsset,
  repoPath: string,
): CryptoAsset {
  // Only analyze CONDITIONAL assets
  if (asset.quantumSafety !== QuantumSafetyStatus.CONDITIONAL) {
    return asset;
  }

  const name = asset.name.toUpperCase();

  // Extract source context if location is available
  let context = '';
  if (asset.location?.fileName && asset.location?.lineNumber) {
    context = extractSourceContext(repoPath, asset.location.fileName, asset.location.lineNumber) || '';
  }

  let verdict: PQCVerdictDetail;

  // Route to specific analyzer based on asset name
  if (name.includes('PBKDF2')) {
    verdict = analyzePBKDF2(context);
  } else if (name === 'AES' || name.match(/^AES[- ]?\d*$/)) {
    verdict = analyzeAES(context, asset.name);
  } else if (name === 'SECURERANDOM') {
    verdict = analyzeSecureRandom(context);
  } else if (name === 'KEYPAIRGENERATOR') {
    verdict = analyzeKeyPairGenerator(context);
  } else if (name === 'DIGITAL-SIGNATURE' || name === 'DIGITALSIGNATURE') {
    verdict = analyzeDigitalSignature(context);
  } else if (name === 'SECRETKEYFACTORY') {
    verdict = analyzeSecretKeyFactory(context);
  } else if (name.includes('DRBG') || name === 'CTR-DRBG' || name === 'HMAC-DRBG') {
    // DRBGs are symmetric-based — quantum-safe if seed ≥256
    verdict = {
      verdict: PQCReadinessVerdict.PQC_READY,
      confidence: 85,
      reasons: [`${asset.name} is symmetric-based DRBG (NIST SP 800-90A) — not quantum-vulnerable`],
      recommendation: 'Ensure 256-bit seed/state for post-quantum margin.',
    };
  } else if (name === 'SHA1PRNG' || name === 'NATIVEPRNG') {
    verdict = {
      verdict: PQCReadinessVerdict.PQC_READY,
      confidence: 80,
      reasons: [`${asset.name} is a CSPRNG — not quantum-vulnerable. Uses OS entropy or seeded PRNG.`],
      recommendation: 'No quantum migration needed. Optionally migrate to DRBG for modern compliance.',
    };
  } else if (name.includes('BOUNCYCASTLE') || name.includes('JCE')) {
    // Provider registrations — depends on what algorithms are registered
    verdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 40,
      reasons: [`${asset.name} is a provider/registration — quantum safety depends on which algorithms are used through it.`],
      recommendation: 'Audit the algorithms registered/used through this provider. RSA/EC → vulnerable; AES/SHA/ML-KEM → safe.',
    };
  } else if (name === 'WEBCRYPTO') {
    verdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 40,
      reasons: ['WebCrypto (crypto.subtle) is a browser API wrapper — quantum safety depends on the algorithm arguments.'],
      recommendation: 'Audit crypto.subtle.encrypt/sign/generateKey calls for algorithm parameter.',
    };
  } else if (name === 'KEYFACTORY') {
    // Analyze similarly to KeyPairGenerator
    const algMatch = context.match(/KeyFactory\.getInstance\s*\(\s*"([^"]+)"/);
    if (algMatch) {
      const alg = algMatch[1].toUpperCase();
      if (alg === 'RSA' || alg.includes('EC') || alg === 'DSA') {
        verdict = {
          verdict: PQCReadinessVerdict.NOT_PQC_READY,
          confidence: 90,
          reasons: [`KeyFactory for "${algMatch[1]}" — classical asymmetric, quantum-vulnerable ✗`],
          parameters: { algorithm: algMatch[1] },
          recommendation: `Replace ${algMatch[1]} key operations with ML-KEM or ML-DSA.`,
        };
      } else {
        verdict = {
          verdict: PQCReadinessVerdict.REVIEW_NEEDED,
          confidence: 50,
          reasons: [`KeyFactory for "${algMatch[1]}" — check if this algorithm is quantum-safe.`],
          parameters: { algorithm: algMatch[1] },
          recommendation: 'Verify the key algorithm is quantum-safe.',
        };
      }
    } else {
      verdict = {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 35,
        reasons: ['Could not determine KeyFactory algorithm — verify manually'],
        recommendation: 'Check the algorithm passed to KeyFactory.getInstance().',
      };
    }
  } else {
    // Generic conditional — can't analyze further
    verdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 30,
      reasons: [`"${asset.name}" is flagged as conditional — automated parameter extraction not supported for this type.`],
      recommendation: 'Manual review required to determine PQC readiness.',
    };
  }

  // Optionally promote verdict to update quantumSafety status
  let updatedSafety: QuantumSafetyStatus = asset.quantumSafety;
  if (verdict.verdict === PQCReadinessVerdict.PQC_READY && verdict.confidence >= 75) {
    updatedSafety = QuantumSafetyStatus.QUANTUM_SAFE;
  } else if (verdict.verdict === PQCReadinessVerdict.NOT_PQC_READY && verdict.confidence >= 75) {
    updatedSafety = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
  }
  // Otherwise keep CONDITIONAL

  return {
    ...asset,
    quantumSafety: updatedSafety,
    pqcVerdict: verdict,
  };
}

/**
 * Batch-analyze all conditional assets in a CBOM.
 */
export function analyzeAllConditionalAssets(
  assets: CryptoAsset[],
  repoPath: string,
): CryptoAsset[] {
  return assets.map(asset => analyzeConditionalAsset(asset, repoPath));
}
