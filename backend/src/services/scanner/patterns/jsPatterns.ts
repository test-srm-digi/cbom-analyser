/**
 * JavaScript / TypeScript Crypto Patterns
 *
 * Node.js crypto module, WebCrypto (crypto.subtle), TLS, and popular npm packages.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const jsPatterns: CryptoPattern[] = [
  // ── Node.js crypto module ──
  { pattern: /crypto\.createHash\s*\(\s*['"]([^'"]+)['"]\s*\)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /crypto\.createCipheriv\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /crypto\.createDecipheriv\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, extractAlgorithm: true },
  { pattern: /crypto\.generateKeyPairSync\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-KeyPair', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /crypto\.generateKeyPair\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-KeyPair', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /crypto\.createSign\s*\(\s*['"]([^'"]+)['"]\s*\)/g, algorithm: 'Unknown-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
  { pattern: /crypto\.createVerify\s*\(\s*['"]([^'"]+)['"]\s*\)/g, algorithm: 'Unknown-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, extractAlgorithm: true },
  { pattern: /crypto\.createHmac\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
  { pattern: /crypto\.randomBytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.pbkdf2Sync\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.pbkdf2\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.scryptSync\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.scrypt\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.createDiffieHellman\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /crypto\.createECDH\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /crypto\.hkdfSync\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.hkdf\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.generateKeySync\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Key', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },

  // ── WebCrypto ──
  { pattern: /new\s+SubtleCrypto|crypto\.subtle\./g, algorithm: 'WebCrypto', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },

  // ── TLS ──
  { pattern: /tls\.createSecureContext\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.connect\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /https\.createServer\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ── Popular npm crypto libraries ──
  // bcrypt / bcryptjs
  { pattern: /require\s*\(\s*['"]bcrypt(?:js)?['"]\s*\)/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /from\s+['"]bcrypt(?:js)?['"]/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // jsonwebtoken / jose
  { pattern: /require\s*\(\s*['"]jsonwebtoken['"]\s*\)/g, algorithm: 'JWT', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+['"]jose['"]/g, algorithm: 'JWT', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  // tweetnacl / libsodium-wrappers
  { pattern: /require\s*\(\s*['"]tweetnacl['"]\s*\)/g, algorithm: 'NaCl', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+['"]tweetnacl['"]/g, algorithm: 'NaCl', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /require\s*\(\s*['"]libsodium-wrappers['"]\s*\)/g, algorithm: 'libsodium', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+['"]libsodium-wrappers['"]/g, algorithm: 'libsodium', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  // argon2
  { pattern: /require\s*\(\s*['"]argon2['"]\s*\)/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /from\s+['"]argon2['"]/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
];
