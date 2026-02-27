/**
 * Python Crypto Patterns
 *
 * hashlib, PyCrypto/PyCryptodome, cryptography.hazmat, ssl, and nacl patterns.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const pythonPatterns: CryptoPattern[] = [
  // ── hashlib ──
  { pattern: /hashlib\.sha256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha1/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.md5/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha384/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha512/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha3_256/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha3_384/g, algorithm: 'SHA3-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.sha3_512/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.blake2[bs]/g, algorithm: 'BLAKE2', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.new\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /hashlib\.pbkdf2_hmac\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ── PyCrypto / PyCryptodome ──
  { pattern: /from\s+Crypto\.Cipher\s+import\s+AES/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.Cipher\s+import\s+DES/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.Cipher\s+import\s+DES3/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.Cipher\s+import\s+Blowfish/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.Cipher\s+import\s+ChaCha20/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.Cipher\s+import\s+Salsa20/g, algorithm: 'Salsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+Crypto\.PublicKey\s+import\s+RSA/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /from\s+Crypto\.PublicKey\s+import\s+ECC/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+Crypto\.PublicKey\s+import\s+DSA/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+Crypto\.Signature\s+import\s+pkcs1_15/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+Crypto\.Signature\s+import\s+pss/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+Crypto\.Signature\s+import\s+DSS/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+Crypto\.Hash\s+import\s+(\w+)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /from\s+Crypto\.Protocol\.KDF\s+import\s+(\w+)/g, algorithm: 'KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /from\s+Crypto\.Random\s+import\s+get_random_bytes/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /RSA\.generate/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },

  // ── cryptography (hazmat) ──
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\brsa\b/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bec\b/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bed25519\b/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bed448\b/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bx25519\b/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bx448\b/g, algorithm: 'X448', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bdh\b/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /from\s+cryptography\.hazmat.*\s+import.*\bdsa\b/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+cryptography\.hazmat\.primitives\.ciphers\s+import\s+Cipher/g, algorithm: 'Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+cryptography\.hazmat\.primitives\.ciphers\.algorithms\s+import\s+(\w+)/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /from\s+cryptography\.hazmat\.primitives\s+import\s+hashes/g, algorithm: 'Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /from\s+cryptography\.hazmat\.primitives\.kdf\.\w+\s+import\s+(\w+)/g, algorithm: 'KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /from\s+cryptography\.hazmat\.primitives\s+import\s+hmac/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /from\s+cryptography\.hazmat\.primitives\s+import\s+cmac/g, algorithm: 'CMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /from\s+cryptography\s+import\s+x509/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /from\s+cryptography\.x509/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /from\s+cryptography\.fernet\s+import\s+Fernet/g, algorithm: 'Fernet', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // ── PyNaCl / libsodium Python bindings ──
  { pattern: /from\s+nacl\.signing\s+import/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+nacl\.public\s+import/g, algorithm: 'Curve25519-XSalsa20', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+nacl\.secret\s+import/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /from\s+nacl\.hash\s+import/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /from\s+nacl\.utils\s+import\s+random/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ── ssl ──
  { pattern: /ssl\.create_default_context\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /ssl\.SSLContext\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /ssl\.PROTOCOL_TLS/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ── secrets module ──
  { pattern: /secrets\.token_bytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /secrets\.token_hex\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /secrets\.token_urlsafe\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ── bcrypt / argon2 / scrypt (password hashing) ──
  { pattern: /import\s+bcrypt/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /bcrypt\.hashpw\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /import\s+argon2/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /from\s+cryptography\.hazmat\.primitives\.kdf\.scrypt/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
];
