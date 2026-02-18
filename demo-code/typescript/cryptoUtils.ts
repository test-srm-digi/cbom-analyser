/**
 * Demo Node.js crypto utilities for CBOM scanner detection.
 * Showcases various cryptographic patterns using the built-in crypto module.
 */

import * as crypto from 'crypto';

// ── Hashing ──────────────────────────────────────────────────────

export function hashSHA256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function hashSHA512(data: string): string {
  return crypto.createHash('sha512').update(data).digest('hex');
}

export function hashSHA1(data: string): string {
  // WARNING: SHA-1 is deprecated for security use
  return crypto.createHash('sha1').update(data).digest('hex');
}

export function hashMD5(data: string): string {
  // WARNING: MD5 is broken, never use for security
  return crypto.createHash('md5').update(data).digest('hex');
}

// ── HMAC ─────────────────────────────────────────────────────────

export function hmacSHA256(key: string, message: string): string {
  return crypto.createHmac('sha256', key).update(message).digest('hex');
}

export function hmacSHA512(key: string, message: string): string {
  return crypto.createHmac('sha512', key).update(message).digest('hex');
}

// ── Symmetric Encryption (AES) ──────────────────────────────────

export function encryptAES256(plaintext: string, key: Buffer): { iv: string; encrypted: string; tag: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return { iv: iv.toString('hex'), encrypted, tag };
}

export function decryptAES256(encrypted: string, key: Buffer, iv: string, tag: string): string {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export function encryptAES128(plaintext: string, key: Buffer): { iv: string; encrypted: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encrypted };
}

// ── Asymmetric Keys (RSA) ───────────────────────────────────────

export function generateRSAKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ── Elliptic Curve Keys ─────────────────────────────────────────

export function generateECKeyPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// ── Digital Signatures ──────────────────────────────────────────

export function signData(data: string, privateKey: string): string {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  return signer.sign(privateKey, 'hex');
}

// ── Key Derivation ──────────────────────────────────────────────

export function deriveKeyPBKDF2(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

export function deriveKeyScrypt(password: string, salt: Buffer): Buffer {
  return crypto.scryptSync(password, salt, 32);
}

// ── Key Exchange ────────────────────────────────────────────────

export function diffieHellmanExchange() {
  const alice = crypto.createDiffieHellman(2048);
  alice.generateKeys();

  const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  return { aliceSecret, bobSecret, match: aliceSecret.equals(bobSecret) };
}

export function ecdhKeyExchange() {
  const alice = crypto.createECDH('secp256k1');
  alice.generateKeys();

  const bob = crypto.createECDH('secp256k1');
  bob.generateKeys();

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  return { aliceSecret, bobSecret, match: aliceSecret.equals(bobSecret) };
}

// ── Random Number Generation ────────────────────────────────────

export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

// ── Full Workflow ───────────────────────────────────────────────

export function secureMessageWorkflow(message: string) {
  // 1. Generate RSA key pair
  const { publicKey, privateKey } = generateRSAKeyPair();

  // 2. Generate random AES key
  const aesKey = crypto.randomBytes(32);

  // 3. Hash the message
  const messageHash = hashSHA256(message);

  // 4. Encrypt with AES-256-GCM
  const { iv, encrypted, tag } = encryptAES256(message, aesKey);

  // 5. Sign the encrypted data
  const signature = signData(encrypted, privateKey);

  // 6. Create HMAC of the whole package
  const mac = hmacSHA256(aesKey.toString('hex'), encrypted + iv + tag);

  return {
    messageHash,
    iv,
    encrypted,
    tag,
    signature,
    mac,
    publicKey,
  };
}
