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

  // ════════════════════════════════════════════════════════════════════════
  // ── Additional popular npm crypto libraries ─────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // crypto-js (very popular browser/node crypto)
  { pattern: /require\s*\(\s*['"]crypto-js['"]\s*\)/g, algorithm: 'CryptoJS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+['"]crypto-js['"]/g, algorithm: 'CryptoJS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoJS\.AES\./g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoJS\.DES\./g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoJS\.TripleDES\./g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoJS\.SHA256\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoJS\.SHA384\s*\(/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoJS\.SHA512\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoJS\.SHA1\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoJS\.MD5\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoJS\.HmacSHA256\s*\(/g, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /CryptoJS\.PBKDF2\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /CryptoJS\.Rabbit\./g, algorithm: 'Rabbit', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoJS\.RC4\./g, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // node-forge
  { pattern: /require\s*\(\s*['"]node-forge['"]\s*\)/g, algorithm: 'node-forge', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /from\s+['"]node-forge['"]/g, algorithm: 'node-forge', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /forge\.cipher\.createCipher\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /forge\.md\.sha256\.create\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /forge\.md\.sha512\.create\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /forge\.md\.sha1\.create\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /forge\.md\.md5\.create\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /forge\.pki\.rsa\.generateKeyPair\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /forge\.pki\.certificateFromPem\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /forge\.tls\.createConnection\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /forge\.hmac\.create\s*\(/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // elliptic (popular ECC library)
  { pattern: /require\s*\(\s*['"]elliptic['"]\s*\)/g, algorithm: 'Elliptic-Curves', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+['"]elliptic['"]/g, algorithm: 'Elliptic-Curves', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+(?:EC|EdDSA)\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'EC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },

  // noble cryptography (@noble/hashes, @noble/curves, @noble/ed25519)
  { pattern: /from\s+['"]@noble\/hashes/g, algorithm: 'noble-hashes', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /from\s+['"]@noble\/curves/g, algorithm: 'noble-curves', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+['"]@noble\/ed25519['"]/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+['"]@noble\/secp256k1['"]/g, algorithm: 'secp256k1', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // node-rsa
  { pattern: /require\s*\(\s*['"]node-rsa['"]\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+['"]node-rsa['"]/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },

  // openpgp
  { pattern: /require\s*\(\s*['"]openpgp['"]\s*\)/g, algorithm: 'OpenPGP', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+['"]openpgp['"]/g, algorithm: 'OpenPGP', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // ssh2
  { pattern: /require\s*\(\s*['"]ssh2['"]\s*\)/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /from\s+['"]ssh2['"]/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ════════════════════════════════════════════════════════════════════════
  // ── Additional Node.js crypto module APIs ───────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /crypto\.createSecretKey\s*\(/g, algorithm: 'SecretKey', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.SECRET_KEY },
  { pattern: /crypto\.createPrivateKey\s*\(/g, algorithm: 'PrivateKey', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PRIVATE_KEY },
  { pattern: /crypto\.createPublicKey\s*\(/g, algorithm: 'PublicKey', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.PUBLIC_KEY },
  { pattern: /crypto\.sign\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
  { pattern: /crypto\.verify\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, extractAlgorithm: true },
  { pattern: /crypto\.generatePrime\s*\(/g, algorithm: 'Prime-Generation', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto\.X509Certificate\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /crypto\.diffieHellman\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /crypto\.getRandomValues\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── PQC: JS/TS post-quantum packages ────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /require\s*\(\s*['"]crystals-kyber['"]\s*\)/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /from\s+['"]crystals-kyber['"]/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /require\s*\(\s*['"]pqc['"]\s*\)/g, algorithm: 'PQC', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /from\s+['"]pqc['"]/g, algorithm: 'PQC', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /require\s*\(\s*['"]liboqs['"]\s*\)/g, algorithm: 'liboqs', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /from\s+['"]liboqs['"]/g, algorithm: 'liboqs', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
];
