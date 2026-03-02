/**
 * node-forge Crypto Utilities
 *
 * Demonstrates the node-forge library usage for cryptographic operations.
 * node-forge is a popular npm package for working with TLS, PKI, and crypto
 * entirely in JavaScript.
 *
 * Expected CBOM result:
 *   - node-forge → NOT_QUANTUM_SAFE (RSA, SHA-1, SHA-256 used)
 *   - RSA → NOT_QUANTUM_SAFE
 *   - SHA-256, SHA-512 → QUANTUM_SAFE (hash)
 *   - SHA-1, MD5 → NOT_QUANTUM_SAFE (weak hash)
 *   - AES-CBC → context dependent (128-bit = NOT_QUANTUM_SAFE)
 *   - X.509 → NOT_QUANTUM_SAFE (RSA cert)
 *   - TLS → depends on version
 */

import * as forge from 'node-forge';

// ════════════════════════════════════════════════════════════════
// ── Hashing with node-forge ──────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * SHA-256 hash using forge.md.sha256.
 */
export function hashSHA256(data: string): string {
  const md = forge.md.sha256.create();
  md.update(data);
  return md.digest().toHex();
}

/**
 * SHA-512 hash using forge.md.sha512.
 */
export function hashSHA512(data: string): string {
  const md = forge.md.sha512.create();
  md.update(data);
  return md.digest().toHex();
}

/**
 * SHA-1 hash — WEAK, NOT quantum-safe even classically.
 */
export function hashSHA1(data: string): string {
  const md = forge.md.sha1.create();
  md.update(data);
  return md.digest().toHex();
}

/**
 * MD5 hash — WEAK, completely broken.
 */
export function hashMD5(data: string): string {
  const md = forge.md.md5.create();
  md.update(data);
  return md.digest().toHex();
}

// ════════════════════════════════════════════════════════════════
// ── HMAC with node-forge ─────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * HMAC-SHA256 using node-forge.
 */
export function hmacSHA256(key: string, data: string): string {
  const hmac = forge.hmac.create();
  hmac.start('sha256', key);
  hmac.update(data);
  return hmac.digest().toHex();
}

// ════════════════════════════════════════════════════════════════
// ── RSA with node-forge ──────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * RSA-2048 key pair generation — NOT quantum-safe.
 */
export function generateRSAKeyPair(): forge.pki.rsa.KeyPair {
  return forge.pki.rsa.generateKeyPair(2048);
}

/**
 * RSA-4096 key pair generation — still NOT quantum-safe.
 */
export function generateRSA4096KeyPair(): forge.pki.rsa.KeyPair {
  return forge.pki.rsa.generateKeyPair(4096);
}

/**
 * RSA encryption using the generated key pair.
 */
export function rsaEncrypt(publicKey: forge.pki.rsa.PublicKey, plaintext: string): string {
  const encrypted = publicKey.encrypt(plaintext, 'RSA-OAEP');
  return forge.util.encode64(encrypted);
}

// ════════════════════════════════════════════════════════════════
// ── AES encryption with node-forge ──────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * AES-CBC encryption using forge.cipher.createCipher.
 */
export function encryptAESCBC(key: string, data: string): string {
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  const iv = forge.random.getBytesSync(16);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(data));
  cipher.finish();
  return forge.util.encode64(cipher.output.getBytes());
}

/**
 * AES-GCM encryption.
 */
export function encryptAESGCM(key: string, data: string): { encrypted: string; tag: string } {
  const cipher = forge.cipher.createCipher('AES-GCM', key);
  const iv = forge.random.getBytesSync(12);
  cipher.start({ iv, tagLength: 128 });
  cipher.update(forge.util.createBuffer(data));
  cipher.finish();
  return {
    encrypted: forge.util.encode64(cipher.output.getBytes()),
    tag: forge.util.encode64(cipher.mode.tag.getBytes()),
  };
}

// ════════════════════════════════════════════════════════════════
// ── X.509 certificates with node-forge ──────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * Self-signed X.509 certificate with RSA-2048 (NOT quantum-safe).
 */
export function createSelfSignedCert(): { cert: forge.pki.Certificate; privateKey: forge.pki.rsa.PrivateKey } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';

  const attrs = [
    { name: 'commonName', value: 'node-forge Test' },
    { name: 'organizationName', value: 'CBOM Analyser' },
    { name: 'countryName', value: 'US' },
  ];
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  // Sign with SHA-256 + RSA — NOT quantum-safe
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return { cert, privateKey: keys.privateKey };
}

/**
 * Load X.509 certificate from PEM.
 */
export function loadCertFromPEM(pem: string): forge.pki.Certificate {
  return forge.pki.certificateFromPem(pem);
}

// ════════════════════════════════════════════════════════════════
// ── TLS with node-forge ──────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/**
 * Create a TLS connection using node-forge.
 */
export function createTLSConnection(caStore: forge.pki.CAStore): forge.tls.Connection {
  return forge.tls.createConnection({
    server: false,
    caStore,
    verify: (connection, verified, depth, certs) => {
      // Custom verification logic
      return verified;
    },
    connected: (connection) => {
      console.log('TLS connection established');
    },
  } as any);
}
