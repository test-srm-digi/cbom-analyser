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
  return `You are a cryptography migration expert. Given this cryptographic asset found in a codebase, provide a concise, actionable suggested fix to make it quantum-safe.

Asset Details:
- Algorithm: ${asset.algorithmName}
- Primitive: ${asset.primitive || 'unknown'}
- Key Length: ${asset.keyLength ? `${asset.keyLength}-bit` : 'unknown'}
- File: ${asset.fileName || 'unknown'}${asset.lineNumber ? `:${asset.lineNumber}` : ''}
- Quantum Safety: ${asset.quantumSafety}
- Recommended PQC: ${asset.recommendedPQC || 'not specified'}

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
  const { algorithmName, recommendedPQC, primitive, quantumSafety } = asset;

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

    const snippet = isWebCrypto
      ? `// Audit crypto.subtle calls for algorithm choice:\n// SAFE:       crypto.subtle.encrypt({ name: 'AES-GCM' }, key, data)\n// VULNERABLE: crypto.subtle.generateKey({ name: 'RSA-OAEP', ... })\n// Migrate RSA/ECDSA/ECDH to PQC hybrids when WebCrypto adds support`
      : isBC
      ? `// BouncyCastle provides both safe and vulnerable algorithms:\n// VULNERABLE: KeyPairGenerator.getInstance("RSA", "BC")\n// SAFE:       Cipher.getInstance("AES/GCM/NoPadding", "BC")\n// PQC-READY:  KeyPairGenerator.getInstance("Dilithium", "BC")\n// Audit all BC algorithm usages in your codebase`
      : isPBKDF
      ? `// PBKDF2 hardening for post-quantum margin:\n// Use ≥600,000 iterations and derive 256-bit keys:\n// SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")\n// PBEKeySpec(password, salt, 600_000, 256)`
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

    return {
      suggestedFix: `Replace ${algorithmName} with ${recommendedPQC}. ${
        primitive === 'pke' || primitive === 'keygen'
          ? 'Migrate key exchange to NIST-approved post-quantum KEM.'
          : primitive === 'signature'
            ? 'Migrate signatures to NIST-approved PQC scheme.'
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
