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

  // ════════════════════════════════════════════════════════════════════════
  // ── PQC: liboqs-python, pqcrypto, oqs bindings ─────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // liboqs-python
  { pattern: /import\s+oqs/g, algorithm: 'liboqs', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /oqs\.KeyEncapsulation\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
  { pattern: /oqs\.Signature\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'PQC-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },

  // pqcrypto package
  { pattern: /from\s+pqcrypto\.sign\s+import\s+(\w+)/g, algorithm: 'PQC-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
  { pattern: /from\s+pqcrypto\.kem\s+import\s+(\w+)/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },

  // Specific PQC algorithm name matches in Python
  { pattern: /['"](?:Kyber|ML-KEM|MLKEM)[\w-]*['"]/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /['"](?:Dilithium|ML-DSA|MLDSA)[\w-]*['"]/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /['"](?:SPHINCS|SLH-DSA|SLHDSA)[\w+\-]*['"]/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /['"](?:Falcon)[\w-]*['"]/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /['"](?:FrodoKEM|BIKE|HQC|Classic-McEliece|NTRU)[\w-]*['"]/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // ════════════════════════════════════════════════════════════════════════
  // ── Additional hazmat specifics ─────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // hazmat cipher algorithm instantiations
  { pattern: /algorithms\.AES\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /algorithms\.TripleDES\s*\(/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /algorithms\.ChaCha20\s*\(/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /algorithms\.Camellia\s*\(/g, algorithm: 'Camellia', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /algorithms\.SM4\s*\(/g, algorithm: 'SM4', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // hazmat cipher mode instantiations
  { pattern: /modes\.CBC\s*\(/g, algorithm: 'CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /modes\.GCM\s*\(/g, algorithm: 'GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /modes\.CTR\s*\(/g, algorithm: 'CTR', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /modes\.CFB\s*\(/g, algorithm: 'CFB', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /modes\.OFB\s*\(/g, algorithm: 'OFB', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /modes\.XTS\s*\(/g, algorithm: 'XTS', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // hazmat RSA padding
  { pattern: /padding\.OAEP\s*\(/g, algorithm: 'RSA-OAEP', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /padding\.PSS\s*\(/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /padding\.PKCS1v15\s*\(/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },

  // hazmat ECDH class
  { pattern: /ec\.ECDH\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // hazmat named curves
  { pattern: /ec\.SECP256R1\s*\(/g, algorithm: 'P-256', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ec\.SECP384R1\s*\(/g, algorithm: 'P-384', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ec\.SECP521R1\s*\(/g, algorithm: 'P-521', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },

  // cryptography MultiFernet
  { pattern: /from\s+cryptography\.fernet\s+import\s+MultiFernet/g, algorithm: 'MultiFernet', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // cryptography serialization
  { pattern: /from\s+cryptography\.hazmat\.primitives\s+import\s+serialization/g, algorithm: 'Key-Serialization', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL },
  { pattern: /serialization\.load_pem_private_key\s*\(/g, algorithm: 'PEM-Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY },
  { pattern: /serialization\.load_der_private_key\s*\(/g, algorithm: 'DER-Private-Key', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY },

  // SHAKE variants
  { pattern: /hashlib\.shake_128/g, algorithm: 'SHAKE-128', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /hashlib\.shake_256/g, algorithm: 'SHAKE-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // paramiko / SSH
  { pattern: /import\s+paramiko/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /from\s+paramiko/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // PyJWT / python-jose
  { pattern: /import\s+jwt/g, algorithm: 'JWT', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /from\s+jose\s+import/g, algorithm: 'JWT', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // Key size extraction (RSA.generate(2048), etc.)
  { pattern: /RSA\.generate\s*\(\s*(\d{3,5})/g, algorithm: 'RSA-KeySize', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /rsa\.generate_private_key\s*\([^,]*,\s*(\d{3,5})/g, algorithm: 'RSA-KeySize', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
];
