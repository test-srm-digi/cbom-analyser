/**
 * WebCrypto PQC-Aware Utilities
 *
 * Demonstrates WebCrypto (crypto.subtle) usage with both classical algorithms
 * and emerging PQC APIs. Browser PQC support is evolving — Chrome/Edge have
 * experimental support for X25519-ML-KEM-768 hybrid key exchange.
 *
 * Expected CBOM result:
 *   - WebCrypto → NOT_QUANTUM_SAFE (ECDSA, RSA-OAEP used)
 *   - ECDSA → NOT_QUANTUM_SAFE
 *   - RSA-OAEP → NOT_QUANTUM_SAFE (via importKey)
 *   - AES-GCM → QUANTUM_SAFE (256-bit)
 *   - SHA-256 → QUANTUM_SAFE
 *   - ECDH → NOT_QUANTUM_SAFE
 */

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Key Generation ────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * Generate ECDSA P-256 key pair via crypto.subtle — NOT quantum-safe.
 */
export async function generateECDSAKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

/**
 * Generate ECDSA P-384 key pair — NOT quantum-safe.
 */
export async function generateECDSAP384KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify']
  );
}

/**
 * Generate RSA-OAEP 2048-bit key pair — NOT quantum-safe.
 */
export async function generateRSAOAEPKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate RSA-PSS 4096-bit key pair — NOT quantum-safe.
 */
export async function generateRSAPSSKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-512',
    },
    true,
    ['sign', 'verify']
  );
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto AES (quantum-safe symmetric) ──────────────────
// ════════════════════════════════════════════════════════════════

/**
 * Generate AES-256-GCM key — QUANTUM_SAFE.
 */
export async function generateAES256Key(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * AES-GCM encryption with crypto.subtle.
 */
export async function encryptAESGCM(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
}

/**
 * AES-GCM decryption with crypto.subtle.
 */
export async function decryptAESGCM(key: CryptoKey, iv: Uint8Array, ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Hashing ────────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * SHA-256 digest — QUANTUM_SAFE.
 */
export async function hashSHA256(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', data);
}

/**
 * SHA-384 digest — QUANTUM_SAFE.
 */
export async function hashSHA384(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-384', data);
}

/**
 * SHA-512 digest — QUANTUM_SAFE.
 */
export async function hashSHA512(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-512', data);
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Signatures ─────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * ECDSA sign with P-256 — NOT quantum-safe.
 */
export async function signECDSA(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );
}

/**
 * ECDSA verify with P-256 — NOT quantum-safe.
 */
export async function verifyECDSA(publicKey: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signature,
    data
  );
}

/**
 * RSA-PSS sign — NOT quantum-safe.
 */
export async function signRSAPSS(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    privateKey,
    data
  );
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Key Exchange ───────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * ECDH key exchange via crypto.subtle — NOT quantum-safe.
 */
export async function deriveECDHKey(privKey: CryptoKey, pubKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: pubKey },
    privKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Key Import/Export ──────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * Import RSA-OAEP public key — NOT quantum-safe.
 */
export async function importRSAPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

/**
 * Import ECDSA public key — NOT quantum-safe.
 */
export async function importECDSAPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

/**
 * Import HMAC key for SHA-256 — QUANTUM_SAFE.
 */
export async function importHMACKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * HMAC-SHA256 sign — QUANTUM_SAFE.
 */
export async function signHMAC(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.sign('HMAC', key, data);
}

// ════════════════════════════════════════════════════════════════
// ── WebCrypto Key Derivation ────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * PBKDF2 key derivation — quantum-safe KDF.
 */
export async function deriveKeyPBKDF2(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * HKDF key derivation — quantum-safe KDF.
 */
export async function deriveKeyHKDF(ikm: ArrayBuffer, salt: Uint8Array, info: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
