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

// ─── Additional Analyzers ───────────────────────────────────────────────────

/**
 * Analyze WebCrypto (crypto.subtle) to determine algorithms used.
 */
function analyzeWebCrypto(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Look for algorithm names in crypto.subtle calls
  const algPatterns = [
    /crypto\.subtle\.\w+\s*\(\s*\{\s*name\s*:\s*['"]([^'"]+)['"]/g,
    /algorithm\s*[=:]\s*\{\s*name\s*:\s*['"]([^'"]+)['"]/g,
    /['"](?:AES-(?:GCM|CBC|CTR|KW)|RSA-(?:OAEP|PSS)|ECDSA|ECDH|HMAC|PBKDF2|SHA-\d+|Ed25519|X25519)['"]/gi,
  ];

  const foundAlgs = new Set<string>();
  for (const pat of algPatterns) {
    let m;
    while ((m = pat.exec(context)) !== null) {
      foundAlgs.add(m[1] || m[0].replace(/['"]/g, ''));
    }
  }

  if (foundAlgs.size > 0) {
    const algs = [...foundAlgs];
    params.algorithms = algs.join(', ');

    const hasVulnerable = algs.some(a => {
      const u = a.toUpperCase();
      return u.includes('RSA') || u.includes('ECDSA') || u.includes('ECDH') || u === 'ED25519' || u === 'X25519';
    });
    const hasSafe = algs.some(a => {
      const u = a.toUpperCase();
      return u.includes('AES') || u.includes('HMAC') || u.includes('SHA');
    });

    if (hasVulnerable) {
      reasons.push(`WebCrypto uses quantum-vulnerable algorithm(s): ${algs.filter(a => /RSA|ECDSA|ECDH|ED25519|X25519/i.test(a)).join(', ')} ✗`);
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 85,
        reasons,
        parameters: params,
        recommendation: 'Replace RSA/ECDSA/ECDH in WebCrypto calls with quantum-safe alternatives when browser support is available.',
      };
    }

    if (hasSafe) {
      reasons.push(`WebCrypto uses quantum-safe algorithm(s): ${algs.join(', ')} ✓`);
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 80,
        reasons,
        parameters: params,
        recommendation: 'No migration needed for symmetric/hash operations.',
      };
    }
  }

  reasons.push('WebCrypto (crypto.subtle) detected but could not determine algorithm parameters from source context.');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Audit crypto.subtle.encrypt/sign/generateKey calls for algorithm parameter.',
  };
}

/**
 * Analyze bcrypt password hashing.
 */
function analyzeBcrypt(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Extract cost/rounds parameter
  const costMatch = context.match(
    /(?:cost|rounds|log_?rounds|BCRYPT_COST|BCRYPT_ROUNDS|bcrypt\.hash\w*\s*\([^,]+,\s*)(\d+)/i
  ) || context.match(
    /gensalt\s*\(\s*(\d+)/i
  ) || context.match(
    /\$2[aby]?\$(\d+)\$/
  );

  if (costMatch) {
    const cost = parseInt(costMatch[1], 10);
    params.cost = cost;

    if (cost >= 12) {
      reasons.push(`bcrypt cost factor ${cost} ≥ 12 — adequate post-quantum margin ✓`);
      reasons.push('bcrypt is memory-hard and not directly broken by quantum computers. Grover\'s halves effective work; cost 12 → 2^11 work with quantum, still expensive.');
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 80,
        reasons,
        parameters: params,
        recommendation: 'bcrypt with cost ≥12 provides adequate post-quantum margin. Consider Argon2id for new deployments.',
      };
    } else {
      reasons.push(`bcrypt cost factor ${cost} < 12 — insufficient post-quantum margin`);
      return {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 60,
        reasons,
        parameters: params,
        recommendation: `Increase bcrypt cost from ${cost} to ≥12. Consider migrating to Argon2id.`,
      };
    }
  }

  reasons.push('bcrypt detected but could not determine cost factor.');
  reasons.push('bcrypt is not directly broken by quantum computers (symmetric-based KDF).');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 50,
    reasons,
    parameters: params,
    recommendation: 'Verify bcrypt cost factor is ≥12. Consider Argon2id for new deployments.',
  };
}

/**
 * Analyze Argon2 (i/d/id) password hashing.
 */
function analyzeArgon2(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Determine variant
  const variant = assetName.toLowerCase().includes('argon2id') ? 'Argon2id'
    : assetName.toLowerCase().includes('argon2d') ? 'Argon2d'
    : assetName.toLowerCase().includes('argon2i') ? 'Argon2i'
    : 'Argon2';
  params.variant = variant;

  // Extract memory parameter
  const memMatch = context.match(
    /(?:memory|memoryCost|memory_cost|MEMORY|m_cost)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /Argon2\w*\s*\([^)]*?(\d{4,})/  // large numeric arg likely = memory in KiB
  );

  if (memMatch) {
    const memKiB = parseInt(memMatch[1], 10);
    params.memoryKiB = memKiB;
    if (memKiB >= 65536) { // ≥64 MiB
      reasons.push(`Memory parameter ${memKiB} KiB (${Math.round(memKiB / 1024)} MiB) ≥ 64 MiB ✓`);
    } else {
      reasons.push(`Memory parameter ${memKiB} KiB (${Math.round(memKiB / 1024)} MiB) < 64 MiB — consider increasing`);
    }
  }

  // Extract iterations/time cost
  const iterMatch = context.match(
    /(?:iterations?|timeCost|time_cost|t_cost|ITERATIONS?)\s*[=:]\s*(\d+)/i
  );
  if (iterMatch) {
    const iters = parseInt(iterMatch[1], 10);
    params.iterations = iters;
    if (iters >= 3) {
      reasons.push(`Time cost ${iters} ≥ 3 ✓`);
    } else {
      reasons.push(`Time cost ${iters} < 3 — increase for better security`);
    }
  }

  reasons.push(`${variant} is a memory-hard KDF — not directly broken by quantum computers.`);
  reasons.push('Quantum computers cannot efficiently attack memory-hard functions (no quantum speedup for memory-bound operations).');

  return {
    verdict: PQCReadinessVerdict.PQC_READY,
    confidence: 80,
    reasons,
    parameters: params,
    recommendation: `${variant} is quantum-resistant. Ensure ≥64 MiB memory, ≥3 iterations, ≥32-byte output for post-quantum margin.`,
  };
}

/**
 * Analyze a generic block cipher (Twofish, Serpent, Camellia) for key size.
 */
function analyzeGenericBlockCipher(context: string, assetName: string): PQCVerdictDetail {
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
 * Analyze OpenSSL EVP_* wrapper calls.
 */
function analyzeEVP(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Extract cipher/algorithm from EVP calls
  const cipherMatch = context.match(
    /EVP_(?:aes|des|chacha|camellia|bf|rc[24]|idea|cast5)_(\d+)_(\w+)/i
  ) || context.match(
    /EVP_(?:Encrypt|Decrypt|Cipher)Init(?:_ex)?\s*\([^,]*,\s*EVP_(\w+)\s*\(\)/
  ) || context.match(
    /EVP_get_cipherbyname\s*\(\s*["']([^"']+)["']\)/
  );

  if (cipherMatch) {
    const cipher = cipherMatch[1] || cipherMatch[0];
    params.cipher = cipher;
    const upper = cipher.toUpperCase();

    if (upper.includes('AES') && (upper.includes('256') || upper.includes('AES_256'))) {
      reasons.push(`EVP uses AES-256 — quantum-safe ✓`);
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 90, reasons, parameters: params, recommendation: 'AES-256 is quantum-safe.' };
    }
    if (upper.includes('CHACHA20')) {
      reasons.push(`EVP uses ChaCha20 — quantum-safe ✓`);
      return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 90, reasons, parameters: params, recommendation: 'ChaCha20 is quantum-safe.' };
    }
    if (upper.includes('DES') || upper.includes('RC4') || upper.includes('BF')) {
      reasons.push(`EVP uses weak/broken cipher: ${cipher} ✗`);
      return { verdict: PQCReadinessVerdict.NOT_PQC_READY, confidence: 90, reasons, parameters: params, recommendation: 'Replace with EVP_aes_256_gcm.' };
    }
  }

  // Check for digest in EVP_Digest / EVP_Sign
  if (assetName.toUpperCase().includes('SIGN') || assetName.toUpperCase().includes('DIGEST')) {
    const digestMatch = context.match(/EVP_(sha\d+|md5|sha3_\d+)/i);
    if (digestMatch) {
      params.digest = digestMatch[1];
    }
  }

  reasons.push(`${assetName} (OpenSSL EVP API) detected — quantum safety depends on the underlying algorithm.`);
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 40,
    reasons,
    parameters: params,
    recommendation: 'Audit EVP_EncryptInit_ex / EVP_DigestSignInit calls for the cipher/digest algorithm parameter.',
  };
}

/**
 * Analyze Java KeyAgreement usage.
 */
function analyzeKeyAgreement(context: string): PQCVerdictDetail {
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
function analyzeKeyGenerator(context: string): PQCVerdictDetail {
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
      // Check key size
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

/**
 * Analyze generic "Hash" / "Digest" detections.
 */
function analyzeGenericHash(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Try to extract the actual hash algorithm from context
  const hashPatterns = [
    /MessageDigest\.getInstance\s*\(\s*['"]([^'"]+)['"]/i,
    /(?:hash|digest|algorithm)\s*[=:]\s*['"]?(SHA-?\d+|MD5|BLAKE\d*|RIPEMD-?\d*|Whirlpool|SHA3-\d+)/i,
    /hashlib\.\s*(sha\d+|md5|blake\d*|sha3_\d+)/i,  // Python
    /crypto\.createHash\s*\(\s*['"]([^'"]+)['"]/i,  // Node.js
    /Digest::(\w+)/i,  // Ruby
    /'(sha256|sha384|sha512|sha1|md5|sha3)'/i,
  ];

  for (const pat of hashPatterns) {
    const m = context.match(pat);
    if (m) {
      const hash = m[1].toUpperCase().replace(/-/g, '');
      params.hashAlgorithm = m[1];

      if (hash.includes('SHA256') || hash.includes('SHA384') || hash.includes('SHA512') ||
          hash.includes('SHA3') || hash.includes('BLAKE')) {
        reasons.push(`Resolved generic "${assetName}" to ${m[1]} — quantum-resistant ✓`);
        return {
          verdict: PQCReadinessVerdict.PQC_READY,
          confidence: 85,
          reasons,
          parameters: params,
          recommendation: `${m[1]} is quantum-resistant. No migration needed.`,
        };
      }

      if (hash === 'MD5' || hash === 'SHA1') {
        reasons.push(`Resolved generic "${assetName}" to ${m[1]} — classically broken ✗`);
        return {
          verdict: PQCReadinessVerdict.NOT_PQC_READY,
          confidence: 90,
          reasons,
          parameters: params,
          recommendation: `Replace ${m[1]} with SHA-256 or SHA-3-256.`,
        };
      }

      reasons.push(`Resolved generic "${assetName}" to ${m[1]} — verify if quantum-safe.`);
      return {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 55,
        reasons,
        parameters: params,
        recommendation: `Verify ${m[1]} is quantum-resistant (SHA-256+ is safe; MD5/SHA-1 is broken).`,
      };
    }
  }

  reasons.push(`Generic "${assetName}" detected — could not resolve to a specific hash algorithm from source context.`);
  reasons.push('Most modern hash functions (SHA-256, SHA-3) are quantum-resistant. MD5/SHA-1 are classically broken.');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 35,
    reasons,
    parameters: params,
    recommendation: 'Identify the specific hash algorithm. SHA-256+ is quantum-safe; MD5/SHA-1 should be replaced.',
  };
}

/**
 * Analyze generic "Cipher" detections.
 */
function analyzeGenericCipher(context: string): PQCVerdictDetail {
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

/**
 * Analyze generic "KDF" detections.
 */
function analyzeGenericKDF(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  // Try to identify specific KDF
  if (context.match(/PBKDF2|pbkdf2/)) {
    reasons.push('Resolved generic KDF to PBKDF2 — delegating to PBKDF2 analyzer.');
    return analyzePBKDF2(context);
  }
  if (context.match(/[Aa]rgon2/)) {
    reasons.push('Resolved generic KDF to Argon2.');
    return analyzeArgon2(context, 'Argon2');
  }
  if (context.match(/bcrypt/i)) {
    reasons.push('Resolved generic KDF to bcrypt.');
    return analyzeBcrypt(context);
  }
  if (context.match(/scrypt/i)) {
    reasons.push('Resolved generic KDF to scrypt.');
    return analyzeScrypt(context);
  }
  if (context.match(/HKDF|hkdf/)) {
    reasons.push('Resolved generic KDF to HKDF — quantum-safe ✓');
    return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 85, reasons, parameters: params, recommendation: 'HKDF is quantum-resistant.' };
  }

  reasons.push('Generic KDF detected — symmetric-based KDFs are not directly quantum-vulnerable.');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 45,
    reasons,
    parameters: params,
    recommendation: 'Identify the specific KDF. PBKDF2/Argon2/bcrypt/scrypt are not directly quantum-vulnerable with adequate parameters.',
  };
}

/**
 * Analyze scrypt KDF.
 */
function analyzeScrypt(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const costMatch = context.match(
    /(?:cost|N|scryptN|SCRYPT_N|cpuCost)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /scrypt\s*\([^,]*,\s*[^,]*,\s*(\d+)/
  );

  if (costMatch) {
    const N = parseInt(costMatch[1], 10);
    params.costN = N;
    const log2N = Math.log2(N);
    reasons.push(`scrypt cost N=${N} (2^${log2N.toFixed(0)})`);
  }

  reasons.push('scrypt is a memory-hard KDF — not directly broken by quantum computers.');
  reasons.push('Quantum computers cannot efficiently attack memory-hard functions.');

  return {
    verdict: PQCReadinessVerdict.PQC_READY,
    confidence: 78,
    reasons,
    parameters: params,
    recommendation: 'scrypt is quantum-resistant. Ensure sufficient cost parameters (N≥2^15, r≥8, p≥1) for post-quantum margin.',
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
    verdict = analyzeWebCrypto(context);
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
  } else if (name === 'X.509' || name === 'X509' || name.includes('CERTIFICATE')) {
    // X.509 / certificate analysis — quantum safety depends on the signature algorithm
    const sigPatterns = [
      // Java / BouncyCastle patterns
      /SHA\d*\s*with\s*(RSA|ECDSA|DSA|ED25519|ED448)/i,
      /Signature\.getInstance\s*\(\s*"([^"]+)"/,
      /sigAlgName\s*[=:]\s*"?([A-Za-z0-9_-]+)"?/i,
      /signatureAlgorithm\s*[=:]\s*"?([A-Za-z0-9_-]+)"?/i,
      /(ML-DSA|SLH-DSA|Dilithium|SPHINCS|Falcon)/i,
      /(SHA256withRSA|SHA384withECDSA|SHA512withRSA|SHA256withECDSA|SHA1withRSA|MD5withRSA)/i,
    ];

    let foundSigAlg: string | null = null;
    for (const pat of sigPatterns) {
      const m = context.match(pat);
      if (m) {
        foundSigAlg = m[1] || m[0];
        break;
      }
    }

    if (foundSigAlg) {
      const upper = foundSigAlg.toUpperCase();
      if (upper.includes('ML-DSA') || upper.includes('SLH-DSA') || upper.includes('DILITHIUM') || upper.includes('SPHINCS') || upper.includes('FALCON')) {
        verdict = {
          verdict: PQCReadinessVerdict.PQC_READY,
          confidence: 90,
          reasons: [`X.509 certificate uses post-quantum signature algorithm: ${foundSigAlg} ✓`],
          parameters: { signatureAlgorithm: foundSigAlg },
          recommendation: 'Post-quantum certificate — no migration needed.',
        };
      } else if (upper.includes('RSA') || upper.includes('ECDSA') || upper.includes('DSA') || upper.includes('ED25519') || upper.includes('ED448')) {
        verdict = {
          verdict: PQCReadinessVerdict.NOT_PQC_READY,
          confidence: 90,
          reasons: [`X.509 certificate uses classical signature algorithm: ${foundSigAlg} — quantum-vulnerable ✗`],
          parameters: { signatureAlgorithm: foundSigAlg },
          recommendation: `Migrate certificate signing from ${foundSigAlg} to ML-DSA-65 or SLH-DSA for post-quantum safety.`,
        };
      } else {
        verdict = {
          verdict: PQCReadinessVerdict.REVIEW_NEEDED,
          confidence: 55,
          reasons: [`X.509 certificate uses signature algorithm: ${foundSigAlg} — verify if quantum-safe.`],
          parameters: { signatureAlgorithm: foundSigAlg },
          recommendation: `Verify whether ${foundSigAlg} is quantum-safe. If classical (RSA/EC), migrate to ML-DSA.`,
        };
      }
    } else if (asset.detectionSource === 'dependency') {
      // Dependency-sourced X.509 — no source context available
      verdict = {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 70,
        reasons: [
          'X.509 certificates detected via dependency (likely BouncyCastle/OpenSSL).',
          'Most deployed X.509 certificates use RSA or ECDSA signatures, which are quantum-vulnerable.',
        ],
        recommendation: 'Audit certificate chains for signature algorithms. Plan migration to ML-DSA/SLH-DSA certificates when CA support is available.',
      };
    } else {
      verdict = {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 45,
        reasons: ['X.509 certificate detected but could not determine the signature algorithm from source context.'],
        recommendation: 'Check the certificate signature algorithm. RSA/ECDSA → quantum-vulnerable; ML-DSA/SLH-DSA → quantum-safe.',
      };
    }
  } else if (name === 'TLS' || name === 'SSL' || name === 'DTLS') {
    // TLS/SSL protocol analysis
    const versionPatterns = [
      /TLSv?(1\.3|1\.2|1\.1|1\.0)/i,
      /SSLv?(3|2)/i,
      /setProtocol\s*\(\s*"([^"]+)"/,
      /sslProtocol\s*[=:]\s*"?([A-Za-z0-9.]+)"?/i,
    ];

    let foundVersion: string | null = null;
    for (const pat of versionPatterns) {
      const m = context.match(pat);
      if (m) {
        foundVersion = m[1] || m[0];
        break;
      }
    }

    // TLS key exchange is the quantum-vulnerable part (RSA/ECDHE)
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 75,
      reasons: [
        `${asset.name} protocol detected${foundVersion ? ' (version ' + foundVersion + ')' : ''}.`,
        'TLS key exchange (RSA/ECDHE) is quantum-vulnerable. TLS 1.3 supports hybrid PQ key exchange (ML-KEM) but requires server/client updates.',
      ],
      parameters: foundVersion ? { version: foundVersion } : undefined,
      recommendation: 'Plan migration to TLS 1.3 with hybrid ML-KEM key exchange. Monitor RFC 9180 (HPKE) and draft-ietf-tls-hybrid-design.',
    };
  } else if (name === 'TSP' || name.includes('TIMESTAMP')) {
    // Time Stamp Protocol — relies on PKI signatures
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 75,
      reasons: [
        'TSP (Time Stamp Protocol, RFC 3161) relies on PKI signatures for timestamp tokens.',
        'Current TSP implementations use RSA/ECDSA signatures, which are quantum-vulnerable.',
      ],
      recommendation: 'When TSA providers support PQ signatures (ML-DSA), update TSP configuration. Monitor IETF post-quantum PKI timeline.',
    };
  } else if (name === 'CMS' || name === 'PKCS7') {
    // Cryptographic Message Syntax — depends on underlying algorithms
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 70,
      reasons: [
        'CMS/PKCS#7 typically uses RSA/ECDSA for signatures and RSA/ECDH for key transport — both quantum-vulnerable.',
      ],
      recommendation: 'Migrate CMS operations to use ML-DSA for signatures and ML-KEM for key encapsulation.',
    };
  } else if (name === 'OCSP') {
    // Online Certificate Status Protocol — relies on PKI
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 75,
      reasons: [
        'OCSP relies on PKI signatures for certificate revocation responses.',
        'OCSP responders typically sign with RSA/ECDSA — quantum-vulnerable.',
      ],
      recommendation: 'OCSP quantum safety depends on PKI migration. Plan for ML-DSA-signed OCSP responses when CA infrastructure supports it.',
    };
  } else if (name === 'BCRYPT') {
    verdict = analyzeBcrypt(context);
  } else if (name.includes('ARGON2')) {
    verdict = analyzeArgon2(context, asset.name);
  } else if (name === 'TWOFISH' || name === 'SERPENT' || name === 'CAMELLIA') {
    verdict = analyzeGenericBlockCipher(context, asset.name);
  } else if (name.startsWith('EVP')) {
    verdict = analyzeEVP(context, asset.name);
  } else if (name === 'KEYAGREEMENT') {
    verdict = analyzeKeyAgreement(context);
  } else if (name === 'KEYGENERATOR') {
    verdict = analyzeKeyGenerator(context);
  } else if (name === 'HASH' || name === 'DIGEST') {
    verdict = analyzeGenericHash(context, asset.name);
  } else if (name === 'CIPHER') {
    verdict = analyzeGenericCipher(context);
  } else if (name === 'KDF') {
    verdict = analyzeGenericKDF(context);
  } else if (name === 'BLOWFISH') {
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 80,
      reasons: [
        'Blowfish has a 64-bit block size (birthday attack risk at 2^32 blocks).',
        'Maximum 448-bit key — Grover\'s halves effective strength. 64-bit block is the real weakness.',
      ],
      recommendation: 'Replace Blowfish with AES-256-GCM. Blowfish is obsolete regardless of quantum.',
    };
  } else if (name === 'SCRYPT' || name === 'SCRYPT') {
    verdict = analyzeScrypt(context);
  } else {
    // Generic conditional — can't analyze further
    verdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 30,
      reasons: [`"${asset.name}" is flagged as conditional — automated parameter extraction not supported for this type.`],
      recommendation: 'Manual review required to determine PQC readiness.',
    };
  }

  // Promote/demote quantumSafety based on the analyzer's definitive verdict.
  // Thresholds are intentionally lower than 100% because the analyzer is the
  // *most specific* signal — even 50-60% confidence from it outweighs the DB's
  // generic "conditional" classification.
  let updatedSafety: QuantumSafetyStatus = asset.quantumSafety;
  if (verdict.verdict === PQCReadinessVerdict.PQC_READY && verdict.confidence >= 70) {
    updatedSafety = QuantumSafetyStatus.QUANTUM_SAFE;
  } else if (verdict.verdict === PQCReadinessVerdict.NOT_PQC_READY && verdict.confidence >= 50) {
    updatedSafety = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
  }
  // REVIEW_NEEDED stays CONDITIONAL

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
