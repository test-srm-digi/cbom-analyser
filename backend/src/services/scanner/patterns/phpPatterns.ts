/**
 * PHP Crypto Patterns
 *
 * OpenSSL extension, hash / hash_hmac, sodium, password_hash,
 * mcrypt (deprecated), phpseclib, and common PHP crypto patterns.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const phpPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── OpenSSL extension ───────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Symmetric encrypt / decrypt
  { pattern: /openssl_encrypt\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /openssl_decrypt\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, extractAlgorithm: true },
  // Generic openssl_encrypt / openssl_decrypt (variable cipher)
  { pattern: /openssl_encrypt\s*\(/g, algorithm: 'OpenSSL-Encrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /openssl_decrypt\s*\(/g, algorithm: 'OpenSSL-Decrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },

  // Digest
  { pattern: /openssl_digest\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /openssl_digest\s*\(/g, algorithm: 'OpenSSL-Digest', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, scanContext: true },

  // Signing / verification
  { pattern: /openssl_sign\s*\(/g, algorithm: 'OpenSSL-Sign', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /openssl_verify\s*\(/g, algorithm: 'OpenSSL-Verify', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },

  // Key generation
  { pattern: /openssl_pkey_new\s*\(/g, algorithm: 'OpenSSL-KeyGen', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, scanContext: true },
  { pattern: /openssl_pkey_export\s*\(/g, algorithm: 'OpenSSL-KeyExport', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /openssl_pkey_get_private\s*\(/g, algorithm: 'OpenSSL-PrivateKey', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /openssl_pkey_get_public\s*\(/g, algorithm: 'OpenSSL-PublicKey', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.OTHER },

  // Key type constants
  { pattern: /OPENSSL_KEYTYPE_RSA/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /OPENSSL_KEYTYPE_EC/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /OPENSSL_KEYTYPE_DSA/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /OPENSSL_KEYTYPE_DH/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // Public key encrypt / decrypt
  { pattern: /openssl_public_encrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /openssl_private_decrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /openssl_private_encrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /openssl_public_decrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.VERIFY },

  // Seal / open (envelope encryption)
  { pattern: /openssl_seal\s*\(/g, algorithm: 'RSA+Symmetric', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /openssl_open\s*\(/g, algorithm: 'RSA+Symmetric', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },

  // CSR / X.509
  { pattern: /openssl_csr_new\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_csr_sign\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_x509_parse\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_x509_read\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_x509_verify\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_x509_checkpurpose\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_pkcs12_export\s*\(/g, algorithm: 'PKCS12', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_pkcs12_read\s*\(/g, algorithm: 'PKCS12', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_pkcs7_sign\s*\(/g, algorithm: 'PKCS7', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl_pkcs7_encrypt\s*\(/g, algorithm: 'PKCS7', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT, assetType: AssetType.CERTIFICATE },

  // DH key exchange
  { pattern: /openssl_dh_compute_key\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // Cipher method helpers
  { pattern: /openssl_cipher_iv_length\s*\(/g, algorithm: 'OpenSSL-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /openssl_get_cipher_methods\s*\(/g, algorithm: 'OpenSSL-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /openssl_get_md_methods\s*\(/g, algorithm: 'OpenSSL-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.OTHER },

  // Random
  { pattern: /openssl_random_pseudo_bytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── hash / hash_hmac / hash_pbkdf2 ─────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // hash('sha256', $data)
  { pattern: /\bhash\s*\(\s*['"]sha256['"]/gi, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha384['"]/gi, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha512['"]/gi, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha1['"]/gi, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]md5['"]/gi, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha3-256['"]/gi, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha3-384['"]/gi, algorithm: 'SHA3-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]sha3-512['"]/gi, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]ripemd160['"]/gi, algorithm: 'RIPEMD-160', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bhash\s*\(\s*['"]whirlpool['"]/gi, algorithm: 'Whirlpool', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // hash with variable algorithm
  { pattern: /\bhash\s*\(\s*\$/g, algorithm: 'Hash-Variable', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, scanContext: true },

  // hash_hmac('sha256', $data, $key)
  { pattern: /hash_hmac\s*\(\s*['"]sha256['"]/gi, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /hash_hmac\s*\(\s*['"]sha384['"]/gi, algorithm: 'HMAC-SHA384', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /hash_hmac\s*\(\s*['"]sha512['"]/gi, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /hash_hmac\s*\(\s*['"]sha1['"]/gi, algorithm: 'HMAC-SHA1', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /hash_hmac\s*\(\s*['"]md5['"]/gi, algorithm: 'HMAC-MD5', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // hash_pbkdf2
  { pattern: /hash_pbkdf2\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  // hash_hkdf
  { pattern: /hash_hkdf\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  // hash_equals
  { pattern: /hash_equals\s*\(/g, algorithm: 'Constant-Time-Compare', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

  // Convenience functions
  { pattern: /\bmd5\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bsha1\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bcrc32\s*\(/g, algorithm: 'CRC32', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // ════════════════════════════════════════════════════════════════════════
  // ── password_hash / password_verify ─────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /password_hash\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION, scanContext: true },
  { pattern: /password_verify\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /password_needs_rehash\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /PASSWORD_BCRYPT/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /PASSWORD_ARGON2I/g, algorithm: 'Argon2i', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /PASSWORD_ARGON2ID/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /PASSWORD_DEFAULT/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // ════════════════════════════════════════════════════════════════════════
  // ── sodium extension (libsodium) ────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Symmetric
  { pattern: /sodium_crypto_secretbox\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_secretbox_open\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /sodium_crypto_secretbox_keygen\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.KEYGEN },

  // AEAD
  { pattern: /sodium_crypto_aead_aes256gcm_encrypt\s*\(/g, algorithm: 'AES-256-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_aead_aes256gcm_decrypt\s*\(/g, algorithm: 'AES-256-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /sodium_crypto_aead_chacha20poly1305_encrypt\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_aead_chacha20poly1305_decrypt\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /sodium_crypto_aead_xchacha20poly1305_ietf_encrypt\s*\(/g, algorithm: 'XChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_aead_xchacha20poly1305_ietf_decrypt\s*\(/g, algorithm: 'XChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },

  // Public-key
  { pattern: /sodium_crypto_box\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_box_open\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /sodium_crypto_box_keypair\s*\(/g, algorithm: 'Curve25519', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /sodium_crypto_box_seal\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_box_seal_open\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },

  // Signatures
  { pattern: /sodium_crypto_sign\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /sodium_crypto_sign_open\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /sodium_crypto_sign_detached\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /sodium_crypto_sign_verify_detached\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /sodium_crypto_sign_keypair\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },

  // Hashing
  { pattern: /sodium_crypto_generichash\s*\(/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sodium_crypto_shorthash\s*\(/g, algorithm: 'SipHash-2-4', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // Password hashing
  { pattern: /sodium_crypto_pwhash\s*\(/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /sodium_crypto_pwhash_str\s*\(/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sodium_crypto_pwhash_str_verify\s*\(/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sodium_crypto_pwhash_scryptsalsa208sha256\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // Key exchange
  { pattern: /sodium_crypto_kx_keypair\s*\(/g, algorithm: 'X25519-BLAKE2b', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /sodium_crypto_kx_client_session_keys\s*\(/g, algorithm: 'X25519-BLAKE2b', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /sodium_crypto_kx_server_session_keys\s*\(/g, algorithm: 'X25519-BLAKE2b', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /sodium_crypto_scalarmult\s*\(/g, algorithm: 'Curve25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // Auth (MAC)
  { pattern: /sodium_crypto_auth\s*\(/g, algorithm: 'HMAC-SHA512/256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /sodium_crypto_auth_verify\s*\(/g, algorithm: 'HMAC-SHA512/256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // Stream cipher
  { pattern: /sodium_crypto_stream_xchacha20\s*\(/g, algorithm: 'XChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodium_crypto_stream_xor\s*\(/g, algorithm: 'XSalsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // Key derivation
  { pattern: /sodium_crypto_kdf_derive_from_key\s*\(/g, algorithm: 'BLAKE2b-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /sodium_crypto_kdf_keygen\s*\(/g, algorithm: 'BLAKE2b-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // Random
  { pattern: /random_bytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /random_int\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── mcrypt (deprecated but still found in legacy code) ──────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /mcrypt_encrypt\s*\(/g, algorithm: 'mcrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /mcrypt_decrypt\s*\(/g, algorithm: 'mcrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },
  { pattern: /mcrypt_create_iv\s*\(/g, algorithm: 'mcrypt', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /mcrypt_module_open\s*\(/g, algorithm: 'mcrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /MCRYPT_RIJNDAEL_128/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /MCRYPT_RIJNDAEL_256/g, algorithm: 'Rijndael-256', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /MCRYPT_BLOWFISH/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /MCRYPT_TWOFISH/g, algorithm: 'Twofish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /MCRYPT_3DES/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /MCRYPT_DES/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // ════════════════════════════════════════════════════════════════════════
  // ── phpseclib (pure PHP crypto library) ─────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?RSA/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?AES/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?DES/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?TripleDES/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?Blowfish/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?Hash/g, algorithm: 'Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, scanContext: true },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?EC/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Crypt\\)?DSA/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+(?:\\?phpseclib\d?\\Net\\)?SSH2/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /new\s+(?:\\?phpseclib\d?\\File\\)?X509/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ════════════════════════════════════════════════════════════════════════
  // ── Defuse / PHP-Encryption ─────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /Crypto::encrypt\s*\(/g, algorithm: 'AES-256-CTR+HMAC', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /Crypto::decrypt\s*\(/g, algorithm: 'AES-256-CTR+HMAC', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /KeyFactory::createNewRandomKey\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── Common cipher string literals in OpenSSL context ────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /['"]aes-256-gcm['"]/gi, algorithm: 'AES-256-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]aes-256-cbc['"]/gi, algorithm: 'AES-256-CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]aes-128-gcm['"]/gi, algorithm: 'AES-128-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]aes-128-cbc['"]/gi, algorithm: 'AES-128-CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]aes-192-cbc['"]/gi, algorithm: 'AES-192-CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]bf-cbc['"]/gi, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]des-ede3-cbc['"]/gi, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]chacha20-poly1305['"]/gi, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /['"]rc4['"]/gi, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
];
