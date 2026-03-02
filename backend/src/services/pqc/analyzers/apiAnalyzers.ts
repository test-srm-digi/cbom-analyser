/**
 * Crypto API / Wrapper Analyzers
 *
 * Parameter extraction & PQC verdict for:
 * SecureRandom, WebCrypto, OpenSSL EVP, SecretKeyFactory, Hash/Digest.
 */
import { PQCReadinessVerdict, PQCVerdictDetail } from '../../../types';
import { analyzePBKDF2 } from './kdfAnalyzers';
import { analyzeAES } from './symmetricAnalyzers';

/**
 * Analyze SecureRandom to determine provider / seed source.
 */
export function analyzeSecureRandom(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

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
 * Analyze WebCrypto (crypto.subtle) to determine algorithms used.
 */
export function analyzeWebCrypto(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

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
 * Analyze OpenSSL EVP_* wrapper calls.
 */
export function analyzeEVP(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

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
 * Analyze SecretKeyFactory to determine purpose.
 */
export function analyzeSecretKeyFactory(context: string): PQCVerdictDetail {
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

/**
 * Analyze generic "Hash" / "Digest" detections.
 */
export function analyzeGenericHash(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const hashPatterns = [
    /MessageDigest\.getInstance\s*\(\s*['"]([^'"]+)['"]/i,
    /(?:hash|digest|algorithm)\s*[=:]\s*['"]?(SHA-?\d+|MD5|BLAKE\d*|RIPEMD-?\d*|Whirlpool|SHA3-\d+)/i,
    /hashlib\.\s*(sha\d+|md5|blake\d*|sha3_\d+)/i,
    /crypto\.createHash\s*\(\s*['"]([^'"]+)['"]/i,
    /Digest::(\w+)/i,
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
