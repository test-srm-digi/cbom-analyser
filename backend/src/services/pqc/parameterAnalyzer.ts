/**
 * PQC Parameter Analyzer — Main Router
 *
 * Routes "conditional" crypto assets to specific analyzers that inspect
 * source code context to produce definitive PQC verdicts.
 */
import {
  CryptoAsset,
  QuantumSafetyStatus,
  PQCReadinessVerdict,
  PQCVerdictDetail,
} from '../../types';

import {
  extractSourceContext,
  analyzePBKDF2,
  analyzeAES,
  analyzeSecureRandom,
  analyzeKeyPairGenerator,
  analyzeDigitalSignature,
  analyzeSecretKeyFactory,
  analyzeWebCrypto,
  analyzeBcrypt,
  analyzeArgon2,
  analyzeGenericBlockCipher,
  analyzeEVP,
  analyzeKeyAgreement,
  analyzeKeyGenerator,
  analyzeGenericHash,
  analyzeGenericCipher,
  analyzeGenericKDF,
  analyzeScrypt,
} from './analyzers';

/**
 * Analyze a "conditional" crypto asset and produce a definitive PQC verdict.
 *
 * @param asset     The crypto asset to analyze
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
    verdict = {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 40,
      reasons: [`${asset.name} is a provider/registration — quantum safety depends on which algorithms are used through it.`],
      recommendation: 'Audit the algorithms registered/used through this provider. RSA/EC → vulnerable; AES/SHA/ML-KEM → safe.',
    };
  } else if (name === 'WEBCRYPTO') {
    verdict = analyzeWebCrypto(context);
  } else if (name === 'KEYFACTORY') {
    verdict = analyzeKeyFactory(context, asset);
  } else if (name === 'X.509' || name === 'X509' || name.includes('CERTIFICATE')) {
    verdict = analyzeX509(context, asset);
  } else if (name === 'TLS' || name === 'SSL' || name === 'DTLS') {
    verdict = analyzeTLS(context, asset);
  } else if (name === 'TSP' || name.includes('TIMESTAMP')) {
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
    verdict = {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 70,
      reasons: [
        'CMS/PKCS#7 typically uses RSA/ECDSA for signatures and RSA/ECDH for key transport — both quantum-vulnerable.',
      ],
      recommendation: 'Migrate CMS operations to use ML-DSA for signatures and ML-KEM for key encapsulation.',
    };
  } else if (name === 'OCSP') {
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
  let updatedSafety: QuantumSafetyStatus = asset.quantumSafety;
  if (verdict.verdict === PQCReadinessVerdict.PQC_READY && verdict.confidence >= 70) {
    updatedSafety = QuantumSafetyStatus.QUANTUM_SAFE;
  } else if (verdict.verdict === PQCReadinessVerdict.NOT_PQC_READY && verdict.confidence >= 50) {
    updatedSafety = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
  }

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

// ─── Inline helpers for complex routing cases ────────────────────────────────

function analyzeKeyFactory(context: string, asset: CryptoAsset): PQCVerdictDetail {
  const algMatch = context.match(/KeyFactory\.getInstance\s*\(\s*"([^"]+)"/);
  if (algMatch) {
    const alg = algMatch[1].toUpperCase();
    if (alg === 'RSA' || alg.includes('EC') || alg === 'DSA') {
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 90,
        reasons: [`KeyFactory for "${algMatch[1]}" — classical asymmetric, quantum-vulnerable ✗`],
        parameters: { algorithm: algMatch[1] },
        recommendation: `Replace ${algMatch[1]} key operations with ML-KEM or ML-DSA.`,
      };
    }
    return {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 50,
      reasons: [`KeyFactory for "${algMatch[1]}" — check if this algorithm is quantum-safe.`],
      parameters: { algorithm: algMatch[1] },
      recommendation: 'Verify the key algorithm is quantum-safe.',
    };
  }
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 35,
    reasons: ['Could not determine KeyFactory algorithm — verify manually'],
    recommendation: 'Check the algorithm passed to KeyFactory.getInstance().',
  };
}

function analyzeX509(context: string, asset: CryptoAsset): PQCVerdictDetail {
  const sigPatterns = [
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
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 90,
        reasons: [`X.509 certificate uses post-quantum signature algorithm: ${foundSigAlg} ✓`],
        parameters: { signatureAlgorithm: foundSigAlg },
        recommendation: 'Post-quantum certificate — no migration needed.',
      };
    }
    if (upper.includes('RSA') || upper.includes('ECDSA') || upper.includes('DSA') || upper.includes('ED25519') || upper.includes('ED448')) {
      return {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 90,
        reasons: [`X.509 certificate uses classical signature algorithm: ${foundSigAlg} — quantum-vulnerable ✗`],
        parameters: { signatureAlgorithm: foundSigAlg },
        recommendation: `Migrate certificate signing from ${foundSigAlg} to ML-DSA-65 or SLH-DSA for post-quantum safety.`,
      };
    }
    return {
      verdict: PQCReadinessVerdict.REVIEW_NEEDED,
      confidence: 55,
      reasons: [`X.509 certificate uses signature algorithm: ${foundSigAlg} — verify if quantum-safe.`],
      parameters: { signatureAlgorithm: foundSigAlg },
      recommendation: `Verify whether ${foundSigAlg} is quantum-safe. If classical (RSA/EC), migrate to ML-DSA.`,
    };
  }

  if (asset.detectionSource === 'dependency') {
    return {
      verdict: PQCReadinessVerdict.NOT_PQC_READY,
      confidence: 70,
      reasons: [
        'X.509 certificates detected via dependency (likely BouncyCastle/OpenSSL).',
        'Most deployed X.509 certificates use RSA or ECDSA signatures, which are quantum-vulnerable.',
      ],
      recommendation: 'Audit certificate chains for signature algorithms. Plan migration to ML-DSA/SLH-DSA certificates when CA support is available.',
    };
  }

  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 45,
    reasons: ['X.509 certificate detected but could not determine the signature algorithm from source context.'],
    recommendation: 'Check the certificate signature algorithm. RSA/ECDSA → quantum-vulnerable; ML-DSA/SLH-DSA → quantum-safe.',
  };
}

function analyzeTLS(context: string, asset: CryptoAsset): PQCVerdictDetail {
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

  return {
    verdict: PQCReadinessVerdict.NOT_PQC_READY,
    confidence: 75,
    reasons: [
      `${asset.name} protocol detected${foundVersion ? ' (version ' + foundVersion + ')' : ''}.`,
      'TLS key exchange (RSA/ECDHE) is quantum-vulnerable. TLS 1.3 supports hybrid PQ key exchange (ML-KEM) but requires server/client updates.',
    ],
    parameters: foundVersion ? { version: foundVersion } : undefined,
    recommendation: 'Plan migration to TLS 1.3 with hybrid ML-KEM key exchange. Monitor RFC 9180 (HPKE) and draft-ietf-tls-hybrid-design.',
  };
}
