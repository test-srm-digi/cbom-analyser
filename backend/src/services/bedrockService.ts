/**
 * AWS Bedrock AI Service — Quantum-safe migration suggestions
 */

interface BedrockSuggestionRequest {
  algorithmName: string;
  primitive?: string;
  keyLength?: number;
  fileName?: string;
  lineNumber?: number;
  quantumSafety: string;
  recommendedPQC?: string;
  // CycloneDX 1.6 fields
  assetType?: string;
  detectionSource?: string;
  description?: string;
  mode?: string;
  curve?: string;
  pqcVerdict?: {
    verdict: string;
    confidence: number;
    reasons: string[];
    parameters?: Record<string, string | number | boolean>;
    recommendation?: string;
  };
}

interface BedrockSuggestionResponse {
  suggestedFix: string;
  confidence: 'high' | 'medium' | 'low';
  codeSnippet?: string;
}

const BEDROCK_ENDPOINT = process.env.VITE_BEDROCK_API_ENDPOINT
  || 'https://bedrock-runtime.us-east-1.amazonaws.com';
const BEDROCK_TOKEN = process.env.AWS_BEARER_TOKEN_BEDROCK || '';
const MODEL_ID = 'anthropic.claude-3-sonnet-20240229-v1:0';

function buildPrompt(asset: BedrockSuggestionRequest): string {
  const pqcSection = asset.pqcVerdict
    ? `\n\nPQC Verdict (pre-analyzed):
- Verdict: ${asset.pqcVerdict.verdict}
- Confidence: ${asset.pqcVerdict.confidence}%
- Reasons: ${asset.pqcVerdict.reasons.join('; ')}
- Parameters: ${asset.pqcVerdict.parameters ? JSON.stringify(asset.pqcVerdict.parameters) : 'none'}
- Existing Recommendation: ${asset.pqcVerdict.recommendation || 'none'}`
    : '';

  return `You are a cryptography migration expert. Given this cryptographic asset found in a codebase, provide a concise, actionable suggested fix to make it quantum-safe.

Asset Details:
- Algorithm: ${asset.algorithmName}
- Asset Type: ${asset.assetType || 'algorithm'}
- Primitive: ${asset.primitive || 'unknown'}${asset.mode ? ` (mode: ${asset.mode})` : ''}${asset.curve ? ` (curve: ${asset.curve})` : ''}
- Key Length: ${asset.keyLength ? `${asset.keyLength}-bit` : 'unknown'}
- File: ${asset.fileName || 'unknown'}${asset.lineNumber ? `:${asset.lineNumber}` : ''}
- Quantum Safety: ${asset.quantumSafety}
- Detection Source: ${asset.detectionSource || 'unknown'}
- Recommended PQC: ${asset.recommendedPQC || 'not specified'}${asset.description ? `\n- Description: ${asset.description}` : ''}${pqcSection}

IMPORTANT: Use the PQC verdict data above (if present) to inform your suggestion. Tailor your fix to the specific asset type:
- For "algorithm": suggest a drop-in PQC replacement algorithm
- For "protocol": suggest protocol version/config upgrades (e.g., TLS 1.3 + ML-KEM hybrid)
- For "certificate": suggest certificate algorithm migration path
- For "private-key" / "secret-key": suggest key type migration and rotation strategy
- For "related-crypto-material" (salt, IV, nonce, shared-secret): suggest parameter hardening if needed

Respond with ONLY a JSON object (no markdown, no backticks):
{
  "suggestedFix": "A 1-2 sentence actionable migration instruction",
  "confidence": "high|medium|low",
  "codeSnippet": "Optional short code example showing the replacement, or null"
}`;
}

/**
 * Call AWS Bedrock to get an AI-powered migration suggestion.
 */
export async function getAISuggestion(
  asset: BedrockSuggestionRequest
): Promise<BedrockSuggestionResponse> {
  if (!BEDROCK_TOKEN) {
    return generateFallbackSuggestion(asset);
  }

  try {
    const response = await fetch(
      `${BEDROCK_ENDPOINT}/model/${MODEL_ID}/invoke`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${BEDROCK_TOKEN}`,
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          anthropic_version: 'bedrock-2023-05-31',
          max_tokens: 300,
          messages: [{ role: 'user', content: buildPrompt(asset) }],
        }),
      }
    );

    if (!response.ok) {
      console.warn(`Bedrock API returned ${response.status}, using fallback`);
      return generateFallbackSuggestion(asset);
    }

    const data = await response.json() as { content?: { text?: string }[] };
    const text = data?.content?.[0]?.text || '';
    const parsed = JSON.parse(text);

    return {
      suggestedFix: parsed.suggestedFix || 'No suggestion available',
      confidence: parsed.confidence || 'low',
      codeSnippet: parsed.codeSnippet || undefined,
    };
  } catch (error) {
    console.warn('Bedrock AI failed, using fallback:', (error as Error).message);
    return generateFallbackSuggestion(asset);
  }
}

/**
 * Fallback: generate a suggestion from the static PQC database
 * when Bedrock is unavailable.
 */
function generateFallbackSuggestion(
  asset: BedrockSuggestionRequest
): BedrockSuggestionResponse {
  const { algorithmName, recommendedPQC, primitive, quantumSafety, assetType, pqcVerdict, mode, curve } = asset;

  // ── If pqcVerdict has a recommendation, prefer it ──────────────────
  if (pqcVerdict?.recommendation && pqcVerdict.verdict !== 'pqc-ready') {
    const verdictConfidence: 'high' | 'medium' | 'low' =
      pqcVerdict.confidence >= 90 ? 'high' : pqcVerdict.confidence >= 70 ? 'medium' : 'low';

    const snippets: Record<string, string> = {
      'ml-kem': `// Replace ${algorithmName} with ML-KEM (Kyber)\n// Java: BouncyCastle KyberKEMExtractor\n// Python: pqcrypto.kem.kyber768`,
      'ml-dsa': `// Replace ${algorithmName} with ML-DSA (Dilithium)\n// Java: BouncyCastle DilithiumSigner\n// Python: pqcrypto.sign.dilithium2`,
      'aes-256': `// Upgrade to AES-256-GCM (256-bit key)\n// Java: Cipher.getInstance("AES/GCM/NoPadding")\n// Avoid CBC mode; prefer authenticated encryption`,
    };
    const matchedSnippet = Object.entries(snippets).find(([k]) =>
      pqcVerdict.recommendation!.toLowerCase().includes(k)
    );

    return {
      suggestedFix: pqcVerdict.recommendation,
      confidence: verdictConfidence,
      codeSnippet: matchedSnippet?.[1],
    };
  }

  // ── Handle by asset type (CycloneDX 1.6) ──────────────────────────
  if (assetType === 'protocol') {
    if (algorithmName.includes('SSL') || algorithmName.includes('TLSv1.0') || algorithmName.includes('TLSv1.1')) {
      return {
        suggestedFix: `${algorithmName} is deprecated and insecure. Upgrade to TLS 1.3 with hybrid PQC key exchange (X25519+ML-KEM-768).`,
        confidence: 'high',
        codeSnippet: `// Disable legacy protocols:\n// Java: SSLContext.getInstance("TLSv1.3")\n// OpenSSL: ssl_conf_cmd MinProtocol TLSv1.3\n// Enable hybrid PQC KEM when server supports it`,
      };
    }
    if (algorithmName.includes('TLSv1.3')) {
      return {
        suggestedFix: `TLS 1.3 symmetric ciphers are quantum-safe, but the ECDHE key exchange is not. Enable hybrid PQC key exchange (ML-KEM + X25519) when your TLS stack supports it.`,
        confidence: 'medium',
        codeSnippet: `// Enable hybrid PQC key exchange:\n// OpenSSL 3.5+: set groups to x25519_mlkem768\n// BoringSSL: SSL_CTX_set1_curves_list(ctx, "X25519Kyber768Draft00")`,
      };
    }
    return {
      suggestedFix: `Review protocol ${algorithmName} configuration. Ensure TLS 1.3 is used with PQC-capable cipher suites.`,
      confidence: 'low',
    };
  }

  if (assetType === 'certificate') {
    return {
      suggestedFix: `Certificate using ${algorithmName} needs migration to a PQC signature algorithm. Plan certificate re-issuance with ML-DSA (Dilithium) or hybrid certificates (e.g., X.509 with composite signatures).`,
      confidence: 'medium',
      codeSnippet: `// Certificate migration path:\n// 1. Generate ML-DSA keypair: KeyPairGenerator.getInstance("Dilithium", "BC")\n// 2. Create CSR with PQC algorithm\n// 3. Re-issue certificate from CA with PQC support\n// 4. Deploy hybrid cert for backward compatibility`,
    };
  }

  if (assetType === 'private-key') {
    return {
      suggestedFix: `Private key ${algorithmName} is quantum-vulnerable. Generate a new PQC keypair (${recommendedPQC || 'ML-DSA / ML-KEM'}) and rotate credentials. Securely destroy the old private key after migration.`,
      confidence: 'high',
      codeSnippet: `// Key rotation steps:\n// 1. Generate PQC keypair: KeyPairGenerator.getInstance("Dilithium", "BC")\n// 2. Update key store with new keypair\n// 3. Re-sign/re-encrypt dependent artifacts\n// 4. Revoke and destroy old key material`,
    };
  }

  if (assetType === 'secret-key') {
    const keyLen = asset.keyLength || 0;
    if (keyLen >= 256) {
      return {
        suggestedFix: `${algorithmName} (${keyLen}-bit) is quantum-safe. No migration needed. Ensure the key is stored securely and rotated periodically.`,
        confidence: 'high',
      };
    }
    return {
      suggestedFix: `Upgrade ${algorithmName} to 256-bit key length for post-quantum security. Grover's algorithm halves the effective security of symmetric keys.`,
      confidence: 'medium',
      codeSnippet: `// Generate 256-bit secret key:\n// Java: KeyGenerator.getInstance("AES").init(256)\n// Python: os.urandom(32)`,
    };
  }

  if (assetType === 'related-crypto-material') {
    return {
      suggestedFix: `${algorithmName} is a cryptographic parameter, not an algorithm. Ensure the parent algorithm using this material is quantum-safe. ${asset.keyLength && asset.keyLength < 128 ? 'Consider increasing the bit length for added security margin.' : 'Current parameters appear adequate.'}`,
      confidence: 'medium',
    };
  }

  // ── Algorithm-level analysis (original logic, enhanced) ────────────
  if (quantumSafety === 'quantum-safe') {
    return {
      suggestedFix: `${algorithmName} is already quantum-safe. No migration needed.`,
      confidence: 'high',
    };
  }

  if (quantumSafety === 'conditional') {
    const algoLower = algorithmName.toLowerCase();
    const isWebCrypto = algoLower.includes('webcrypto') || algoLower.includes('subtle');
    const isJCE = algorithmName.startsWith('JCE-') || algorithmName === 'KeyPairGenerator' || algorithmName === 'KeyFactory';
    const isBC = algoLower.includes('bouncy') || algoLower.includes('bouncycastle');
    const isPBKDF = algoLower.includes('pbkdf');
    const isSig = algoLower.includes('signature') || algoLower === 'digital-signature';
    const isSecretKey = algorithmName === 'SecretKeyFactory';
    const isAES128 = algoLower.includes('aes') && (asset.keyLength === 128 || algoLower.includes('128'));
    const isTLS = algoLower.includes('tls');

    if (isAES128) {
      return {
        suggestedFix: `AES-128${mode ? `-${mode}` : ''} provides only 64-bit quantum security (Grover's). Upgrade to AES-256-GCM for post-quantum safety.`,
        confidence: 'medium',
        codeSnippet: `// Upgrade AES-128 to AES-256-GCM:\n// Java: Cipher.getInstance("AES/GCM/NoPadding") with 256-bit key\n// Python: from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n//         key = AESGCM.generate_key(bit_length=256)`,
      };
    }

    if (isTLS) {
      return {
        suggestedFix: `${algorithmName} uses quantum-safe symmetric ciphers, but ECDHE key exchange is vulnerable. Enable hybrid PQC key exchange (ML-KEM + X25519).`,
        confidence: 'medium',
        codeSnippet: `// Enable hybrid PQC key exchange:\n// OpenSSL 3.5+: set groups to x25519_mlkem768\n// BoringSSL: SSL_CTX_set1_curves_list(ctx, "X25519Kyber768Draft00")`,
      };
    }

    const snippet = isWebCrypto
      ? `// Audit crypto.subtle calls for algorithm choice:\n// SAFE:       crypto.subtle.encrypt({ name: 'AES-GCM' }, key, data)\n// VULNERABLE: crypto.subtle.generateKey({ name: 'RSA-OAEP', ... })\n// Migrate RSA/ECDSA/ECDH to PQC hybrids when WebCrypto adds support`
      : isBC
      ? `// BouncyCastle provides both safe and vulnerable algorithms:\n// VULNERABLE: KeyPairGenerator.getInstance("RSA", "BC")\n// SAFE:       Cipher.getInstance("AES/GCM/NoPadding", "BC")\n// PQC-READY:  KeyPairGenerator.getInstance("Dilithium", "BC")\n// Audit all BC algorithm usages in your codebase`
      : isPBKDF
      ? `// PBKDF2 hardening for post-quantum margin:\n// Use >=600,000 iterations and derive 256-bit keys:\n// SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")\n// PBEKeySpec(password, salt, 600_000, 256)`
      : isSig
      ? `// Audit Signature.getInstance() algorithm parameter:\n// VULNERABLE: Signature.getInstance("SHA256withRSA")\n// VULNERABLE: Signature.getInstance("SHA256withECDSA")\n// PQC-SAFE:   Signature.getInstance("Dilithium", "BC")\n// PQC-SAFE:   Signature.getInstance("SPHINCS+", "BC")`
      : isSecretKey || isJCE
      ? `// Audit JCE factory getInstance() argument:\n// VULNERABLE: KeyFactory.getInstance("RSA")\n// SAFE:       SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")\n// PQC:        KeyPairGenerator.getInstance("Dilithium", "BC")`
      : `// Verify SecureRandom provider:\n// Java: SecureRandom.getInstance("DRBG",\n//   DrbgParameters.instantiation(256, RESEED_ONLY, null))\n// This ensures a NIST-approved DRBG with 256-bit security`;

    return {
      suggestedFix: `${algorithmName} is not directly quantum-vulnerable — it's a crypto API wrapper/utility, not an algorithm itself. Quantum safety depends on which algorithms are used through it. Audit usage to ensure underlying algorithms are quantum-safe (AES-256, SHA-256+, ML-KEM, ML-DSA). No urgent migration needed for the API itself.`,
      confidence: 'medium',
      codeSnippet: snippet,
    };
  }

  if (recommendedPQC) {
    const snippets: Record<string, string> = {
      'ml-kem': `// Replace ${algorithmName} with ML-KEM (Kyber)\n// Java: BouncyCastle KyberKEMExtractor\n// Python: pqcrypto.kem.kyber768`,
      'ml-dsa': `// Replace ${algorithmName} with ML-DSA (Dilithium)\n// Java: BouncyCastle DilithiumSigner\n// Python: pqcrypto.sign.dilithium2`,
      'aes-256': `// Upgrade to AES-256 (min 256-bit key)\n// Java: Cipher.getInstance("AES/GCM/NoPadding")`,
      'sha-3': `// Replace with SHA-3-256\n// Java: MessageDigest.getInstance("SHA3-256")\n// Python: hashlib.sha3_256()`,
    };

    const matchedKey = Object.keys(snippets).find(k =>
      recommendedPQC.toLowerCase().includes(k)
    );

    const extra = curve ? ` (curve: ${curve})` : mode ? ` (mode: ${mode})` : '';

    return {
      suggestedFix: `Replace ${algorithmName}${extra} with ${recommendedPQC}. ${
        primitive === 'pke' || primitive === 'keygen' || primitive === 'key-encapsulation'
          ? 'Migrate key exchange to NIST-approved post-quantum KEM.'
          : primitive === 'signature'
            ? 'Migrate signatures to NIST-approved PQC scheme.'
            : primitive === 'key-agreement'
              ? 'Replace key agreement with ML-KEM key encapsulation.'
              : 'Upgrade per NIST SP 800-208 guidelines.'
      }`,
      confidence: 'medium',
      codeSnippet: matchedKey ? snippets[matchedKey] : undefined,
    };
  }

  return {
    suggestedFix: `${algorithmName} may be quantum-vulnerable. Review NIST PQC standards for a suitable replacement.`,
    confidence: 'low',
  };
}
