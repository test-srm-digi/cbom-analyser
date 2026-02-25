/**
 * Demo Node.js crypto utilities for CBOM scanner detection.
 * Covers ALL CycloneDX 1.6 asset types:
 *   algorithm, protocol, certificate, related-crypto-material, private-key, secret-key
 */

import * as crypto from 'crypto';
import * as tls from 'tls';
import * as fs from 'fs';

// ── Hashing (algorithm) ─────────────────────────────────────────

export function hashSHA256(data: string): string {
  // algorithm: SHA-256 — quantum-safe
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function hashSHA384(data: string): string {
  // algorithm: SHA-384 — quantum-safe
  return crypto.createHash('sha384').update(data).digest('hex');
}

export function hashSHA512(data: string): string {
  // algorithm: SHA-512 — quantum-safe
  return crypto.createHash('sha512').update(data).digest('hex');
}

export function hashSHA1(data: string): string {
  // WARNING: SHA-1 is deprecated — collision attacks practical since 2017
  return crypto.createHash('sha1').update(data).digest('hex');
}

export function hashMD5(data: string): string {
  // WARNING: MD5 is cryptographically broken — never use for security
  return crypto.createHash('md5').update(data).digest('hex');
}

// ── HMAC (algorithm) ────────────────────────────────────────────

export function hmacSHA256(key: string, message: string): string {
  // algorithm: HMAC-SHA256 — quantum-safe MAC
  return crypto.createHmac('sha256', key).update(message).digest('hex');
}

export function hmacSHA512(key: string, message: string): string {
  // algorithm: HMAC-SHA512 — quantum-safe MAC
  return crypto.createHmac('sha512', key).update(message).digest('hex');
}

// ── Symmetric Encryption / AES (algorithm + related-crypto-material) ──

export function encryptAES256GCM(plaintext: string, key: Buffer): { iv: string; encrypted: string; tag: string } {
  // related-crypto-material: 96-bit nonce for GCM
  const iv = crypto.randomBytes(12);
  // algorithm: AES-256-GCM — quantum-safe authenticated encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return { iv: iv.toString('hex'), encrypted, tag };
}

export function decryptAES256GCM(encrypted: string, key: Buffer, iv: string, tag: string): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export function encryptAES128CBC(plaintext: string, key: Buffer): { iv: string; encrypted: string } {
  // related-crypto-material: 128-bit IV for CBC mode
  const iv = crypto.randomBytes(16);
  // WARNING: AES-128-CBC — no authentication, smaller key, migrate to AES-256-GCM
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encrypted };
}

// ── RSA Key Generation (algorithm + private-key) ────────────────

export function generateRSAKeyPair() {
  // WARNING: RSA-2048 is NOT quantum-safe — migrate to ML-KEM (Kyber)
  // private-key: RSA private key in PKCS#8 PEM format
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

export function generateRSA4096KeyPair() {
  // WARNING: RSA-4096 — larger key but still NOT quantum-safe
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ── Elliptic Curve Keys (algorithm + private-key) ───────────────

export function generateECKeyPairP256() {
  // WARNING: ECDSA P-256 is NOT quantum-safe — migrate to ML-DSA (Dilithium)
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

export function generateECKeyPairP384() {
  // WARNING: ECDSA P-384 — NOT quantum-safe
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ── Digital Signatures (algorithm) ──────────────────────────────

export function signData(data: string, privateKey: string): string {
  // algorithm: RSA/ECDSA signature with SHA-256
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  return signer.sign(privateKey, 'hex');
}

export function verifySignature(data: string, signature: string, publicKey: string): boolean {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(data);
  return verifier.verify(publicKey, signature, 'hex');
}

// ── Key Derivation (algorithm + related-crypto-material) ────────

export function deriveKeyPBKDF2(password: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  // related-crypto-material: 128-bit salt
  const derivedSalt = salt ?? crypto.randomBytes(16);
  // algorithm: PBKDF2 with SHA-256 — quantum-safe key derivation
  const key = crypto.pbkdf2Sync(password, derivedSalt, 600_000, 32, 'sha256');
  return { key, salt: derivedSalt };
}

export function deriveKeyScrypt(password: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  // related-crypto-material: salt for scrypt
  const derivedSalt = salt ?? crypto.randomBytes(16);
  // algorithm: scrypt — memory-hard key derivation, quantum-safe
  const key = crypto.scryptSync(password, derivedSalt, 32);
  return { key, salt: derivedSalt };
}

// ── Key Exchange (algorithm) ────────────────────────────────────

export function diffieHellmanExchange() {
  // WARNING: DH key exchange is NOT quantum-safe
  const alice = crypto.createDiffieHellman(2048);
  alice.generateKeys();

  const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
  bob.generateKeys();

  // related-crypto-material: shared secret
  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  return { aliceSecret, bobSecret, match: aliceSecret.equals(bobSecret) };
}

export function ecdhKeyExchange() {
  // WARNING: ECDH secp256k1 is NOT quantum-safe
  const alice = crypto.createECDH('secp256k1');
  alice.generateKeys();

  const bob = crypto.createECDH('secp256k1');
  bob.generateKeys();

  // related-crypto-material: ECDH shared secret
  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  return { aliceSecret, bobSecret, match: aliceSecret.equals(bobSecret) };
}

// ── Random / Related Crypto Material ────────────────────────────

export function generateSecureToken(length: number = 32): string {
  // related-crypto-material: cryptographically secure random bytes
  return crypto.randomBytes(length).toString('hex');
}

export function generateSalt(length: number = 16): Buffer {
  // related-crypto-material: random salt for KDF
  return crypto.randomBytes(length);
}

export function generateNonce(length: number = 12): Buffer {
  // related-crypto-material: nonce for AES-GCM
  return crypto.randomBytes(length);
}

// ── Secret Key Construction (secret-key) ────────────────────────

export function buildAESKeyFromSecret(sharedSecret: Buffer): Buffer {
  // secret-key: Derive AES-256 key from shared secret via SHA-256
  return crypto.createHash('sha256').update(sharedSecret).digest();
}

// ── TLS / SSL Configuration (protocol) ──────────────────────────

export function createTLSSecureContext(certPath: string, keyPath: string): tls.SecureContext {
  // protocol: TLS 1.2+ — symmetric ciphers quantum-safe,
  // but ECDHE/RSA key exchange is NOT quantum-safe
  return tls.createSecureContext({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    minVersion: 'TLSv1.2',
  });
}

export function createMutualTLSContext(
  certPath: string,
  keyPath: string,
  caPath: string,
): tls.SecureContext {
  // protocol: Mutual TLS with client certificate authentication
  return tls.createSecureContext({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    ca: fs.readFileSync(caPath),
    minVersion: 'TLSv1.2',
  });
}

// ── Certificate Operations (certificate) ────────────────────────

export function loadCertificate(certPath: string): string {
  // certificate: Load X.509 PEM certificate from disk
  return fs.readFileSync(certPath, 'utf-8');
}

export function getCertificateInfo(certPem: string): crypto.X509Certificate {
  // certificate: Parse X.509 certificate for inspection
  return new crypto.X509Certificate(certPem);
}

export function verifyCertificateChain(cert: crypto.X509Certificate, ca: crypto.X509Certificate): boolean {
  // certificate: Verify certificate was issued by the CA
  return cert.checkIssued(ca);
}

// ── WebCrypto / SubtleCrypto (algorithm) ────────────────────────

export async function webCryptoEncryptAES(
  plaintext: string,
  key: CryptoKey,
): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
  // algorithm: AES-256-GCM via Web Crypto API (SubtleCrypto)
  const iv = crypto.randomBytes(12);
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded,
  );
  return { iv, ciphertext };
}

export async function webCryptoGenerateKey(): Promise<CryptoKey> {
  // algorithm: AES-256-GCM key generation via SubtleCrypto
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function webCryptoDigest(data: string): Promise<ArrayBuffer> {
  // algorithm: SHA-256 via SubtleCrypto
  const encoded = new TextEncoder().encode(data);
  return crypto.subtle.digest('SHA-256', encoded);
}

// ── Private Key Operations (private-key) ────────────────────────

export function loadPrivateKey(keyPath: string): string {
  // private-key: Load PEM private key from disk
  return fs.readFileSync(keyPath, 'utf-8');
}

export function exportPrivateKeyDER(privateKeyPem: string): Buffer {
  // private-key: Convert PEM to DER format
  const keyObj = crypto.createPrivateKey(privateKeyPem);
  return keyObj.export({ type: 'pkcs8', format: 'der' }) as Buffer;
}

// ── Full Workflow ───────────────────────────────────────────────

export function secureMessageWorkflow(message: string) {
  // 1. Generate RSA key pair (algorithm + private-key)
  const { publicKey, privateKey } = generateRSAKeyPair();

  // 2. Derive AES key from password (algorithm + related-crypto-material)
  const { key: aesKey, salt } = deriveKeyPBKDF2('demo-passphrase');

  // 3. Hash the message (algorithm)
  const messageHash = hashSHA256(message);

  // 4. Encrypt with AES-256-GCM (algorithm + related-crypto-material)
  const { iv, encrypted, tag } = encryptAES256GCM(message, aesKey);

  // 5. Sign the encrypted data (algorithm)
  const signature = signData(encrypted, privateKey);

  // 6. Create HMAC of the whole package (algorithm)
  const mac = hmacSHA256(aesKey.toString('hex'), encrypted + iv + tag);

  return {
    messageHash,
    salt: salt.toString('hex'),
    iv,
    encrypted,
    tag,
    signature,
    mac,
    publicKey,
  };
}
