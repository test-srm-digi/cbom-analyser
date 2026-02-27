/**
 * C / C++ Crypto Patterns
 *
 * OpenSSL (EVP, legacy), Botan, libsodium, Crypto++, Windows CNG/BCrypt,
 * GnuTLS, wolfSSL, and mbedTLS detection patterns.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const cppPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── OpenSSL: EVP high-level API ─────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // EVP digest: EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)
  { pattern: /EVP_sha1\s*\(\s*\)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha224\s*\(\s*\)/g, algorithm: 'SHA-224', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha256\s*\(\s*\)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha384\s*\(\s*\)/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha512\s*\(\s*\)/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha3_256\s*\(\s*\)/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha3_384\s*\(\s*\)/g, algorithm: 'SHA3-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_sha3_512\s*\(\s*\)/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_md5\s*\(\s*\)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_blake2b512\s*\(\s*\)/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /EVP_blake2s256\s*\(\s*\)/g, algorithm: 'BLAKE2s', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // Generic EVP_DigestInit with string algorithm name
  { pattern: /EVP_DigestInit(?:_ex)?\s*\([^,]+,\s*EVP_(\w+)\s*\(\)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  // EVP_MD_fetch(NULL, "SHA256", NULL)
  { pattern: /EVP_MD_fetch\s*\([^,]*,\s*"([^"]+)"/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },

  // EVP symmetric ciphers
  { pattern: /EVP_aes_128_(?:gcm|cbc|ecb|ctr|cfb|ofb|ccm|xts|wrap)\s*\(\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_aes_192_(?:gcm|cbc|ecb|ctr|cfb|ofb|ccm|xts|wrap)\s*\(\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_aes_256_(?:gcm|cbc|ecb|ctr|cfb|ofb|ccm|xts|wrap)\s*\(\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_des_ede3_(?:cbc|ecb|cfb|ofb)\s*\(\s*\)/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_des_(?:cbc|ecb|cfb|ofb)\s*\(\s*\)/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_chacha20_poly1305\s*\(\s*\)/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_chacha20\s*\(\s*\)/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_rc4\s*\(\s*\)/g, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_camellia_\d+_\w+\s*\(\s*\)/g, algorithm: 'Camellia', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_aria_\d+_\w+\s*\(\s*\)/g, algorithm: 'ARIA', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /EVP_sm4_\w+\s*\(\s*\)/g, algorithm: 'SM4', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  // EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)
  { pattern: /EVP_CIPHER_fetch\s*\([^,]*,\s*"([^"]+)"/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },

  // EVP encryption/decryption init (catch-all for dynamic cipher selection)
  { pattern: /EVP_EncryptInit(?:_ex)?\s*\(/g, algorithm: 'EVP-Encrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /EVP_DecryptInit(?:_ex)?\s*\(/g, algorithm: 'EVP-Decrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },

  // EVP PKEY (asymmetric): RSA, EC, DH, Ed25519, X25519
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_ED25519/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_ED448/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_X25519/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_X448/g, algorithm: 'X448', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_DH/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /EVP_PKEY_keygen\s*\(/g, algorithm: 'EVP-KeyGen', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, scanContext: true },
  { pattern: /EVP_PKEY_sign\s*\(/g, algorithm: 'EVP-Sign', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /EVP_PKEY_verify\s*\(/g, algorithm: 'EVP-Verify', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },
  { pattern: /EVP_PKEY_derive\s*\(/g, algorithm: 'EVP-KeyDerive', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, scanContext: true },

  // EVP MAC
  { pattern: /EVP_MAC_fetch\s*\([^,]*,\s*"([^"]+)"/g, algorithm: 'Unknown-MAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },

  // EVP KDF
  { pattern: /EVP_KDF_fetch\s*\([^,]*,\s*"([^"]+)"/g, algorithm: 'Unknown-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },

  // ── OpenSSL: Legacy RSA/EC/DH APIs (deprecated but still common) ────
  { pattern: /RSA_generate_key(?:_ex)?\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /RSA_public_encrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /RSA_private_decrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /RSA_sign\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /RSA_verify\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /EC_KEY_new_by_curve_name\s*\(\s*NID_(\w+)/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /EC_KEY_generate_key\s*\(/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ECDSA_sign\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ECDSA_verify\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /DH_generate_parameters(?:_ex)?\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /DH_generate_key\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /DH_compute_key\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // Legacy hash functions
  { pattern: /\bSHA1\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bSHA256\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bSHA384\s*\(/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bSHA512\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /\bMD5\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // Legacy HMAC
  { pattern: /\bHMAC\s*\(\s*EVP_(\w+)\s*\(\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },

  // Legacy AES direct calls
  { pattern: /AES_set_encrypt_key\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /AES_set_decrypt_key\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /AES_cbc_encrypt\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // ── OpenSSL: SSL/TLS ────────────────────────────────────────────────
  { pattern: /SSL_CTX_new\s*\(\s*(\w+)\s*\(\s*\)\s*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /SSL_CTX_new\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /TLS_client_method\s*\(\s*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /TLS_server_method\s*\(\s*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /SSL_CTX_set_cipher_list\s*\([^,]+,\s*"([^"]+)"/g, algorithm: 'TLS-CipherSuite', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /SSL_CTX_set_ciphersuites\s*\([^,]+,\s*"([^"]+)"/g, algorithm: 'TLS1.3-CipherSuite', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },

  // ── OpenSSL: X.509 ──────────────────────────────────────────────────
  { pattern: /X509_new\s*\(\s*\)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /X509_sign\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, assetType: AssetType.CERTIFICATE, scanContext: true },
  { pattern: /X509_verify\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, assetType: AssetType.CERTIFICATE },
  { pattern: /PEM_read_X509\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /d2i_X509\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ── OpenSSL: Random ─────────────────────────────────────────────────
  { pattern: /RAND_bytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /RAND_priv_bytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ── OpenSSL: PKCS / PBKDF ──────────────────────────────────────────
  { pattern: /PKCS5_PBKDF2_HMAC\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /EVP_PBE_scrypt\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ── OpenSSL: includes (detect OpenSSL usage even without API calls) ─
  { pattern: /#include\s+<openssl\/evp\.h>/g, algorithm: 'OpenSSL-EVP', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /#include\s+<openssl\/ssl\.h>/g, algorithm: 'OpenSSL-TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, scanContext: true },
  { pattern: /#include\s+<openssl\/rsa\.h>/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /#include\s+<openssl\/ec\.h>/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.OTHER, scanContext: true },

  // ════════════════════════════════════════════════════════════════════════
  // ── libsodium ───────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /crypto_secretbox_easy\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /crypto_secretbox_open_easy\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /crypto_box_easy\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /crypto_box_open_easy\s*\(/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /crypto_box_keypair\s*\(/g, algorithm: 'Curve25519', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto_sign_keypair\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto_sign_detached\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /crypto_sign_verify_detached\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /crypto_sign\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /crypto_aead_aes256gcm_encrypt\s*\(/g, algorithm: 'AES-256-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /crypto_aead_chacha20poly1305_encrypt\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /crypto_aead_xchacha20poly1305_ietf_encrypt\s*\(/g, algorithm: 'XChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /crypto_generichash\s*\(/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto_hash_sha256\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto_hash_sha512\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto_auth\s*\(/g, algorithm: 'HMAC-SHA512/256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /crypto_kdf_derive_from_key\s*\(/g, algorithm: 'BLAKE2b-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto_pwhash\s*\(/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /crypto_scalarmult\s*\(/g, algorithm: 'Curve25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /crypto_kx_keypair\s*\(/g, algorithm: 'X25519-BLAKE2b', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /randombytes_buf\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── Botan (C++) ─────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /Botan::HashFunction::create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /Botan::Cipher_Mode::create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /Botan::PK_Encryptor_EME/g, algorithm: 'RSA-OAEP', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /Botan::PK_Signer/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /Botan::PK_Verifier/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },
  { pattern: /Botan::PK_Key_Agreement/g, algorithm: 'KeyAgreement', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, scanContext: true },
  { pattern: /Botan::AutoSeeded_RNG/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /Botan::TLS::Client/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /Botan::TLS::Server/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /Botan::X509_Certificate/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /Botan::PBKDF::create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /Botan::MessageAuthenticationCode::create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-MAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
  // Botan PQC
  { pattern: /Botan::Dilithium_PrivateKey/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /Botan::Kyber_PrivateKey/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /Botan::SPHINCS_Plus_PrivateKey/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // ════════════════════════════════════════════════════════════════════════
  // ── Crypto++ (cryptopp) ─────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /CryptoPP::SHA256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoPP::SHA1/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoPP::SHA384/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoPP::SHA512/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoPP::MD5/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /CryptoPP::AES/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::DES/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::DES_EDE3/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::Blowfish/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::RSA/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::RSAES_OAEP_SHA_Encryptor/g, algorithm: 'RSA-OAEP', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::ECDSA/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /CryptoPP::ECDH/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /CryptoPP::DiffieHellman/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /CryptoPP::HMAC</g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /CryptoPP::AutoSeededRandomPool/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /CryptoPP::GCM</g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::CCM</g, algorithm: 'AES-CCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::ChaCha20Poly1305/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /CryptoPP::ed25519/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /CryptoPP::x25519/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // ════════════════════════════════════════════════════════════════════════
  // ── Windows CNG / BCrypt ────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /BCryptOpenAlgorithmProvider\s*\([^,]*,\s*(?:BCRYPT_(\w+)_ALGORITHM|L"(\w+)")/g, algorithm: 'BCrypt-Algorithm', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, extractAlgorithm: true },
  { pattern: /BCryptEncrypt\s*\(/g, algorithm: 'BCrypt-Encrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /BCryptDecrypt\s*\(/g, algorithm: 'BCrypt-Decrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },
  { pattern: /BCryptSignHash\s*\(/g, algorithm: 'BCrypt-Sign', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /BCryptVerifySignature\s*\(/g, algorithm: 'BCrypt-Verify', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },
  { pattern: /BCryptGenerateKeyPair\s*\(/g, algorithm: 'BCrypt-KeyGen', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, scanContext: true },
  { pattern: /BCryptGenRandom\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /BCryptHash\s*\(/g, algorithm: 'BCrypt-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, scanContext: true },
  { pattern: /BCryptDeriveKeyPBKDF2\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /BCRYPT_AES_ALGORITHM/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /BCRYPT_RSA_ALGORITHM/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /BCRYPT_ECDSA_ALGORITHM/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /BCRYPT_ECDH_ALGORITHM/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /BCRYPT_SHA256_ALGORITHM/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /BCRYPT_SHA384_ALGORITHM/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /BCRYPT_SHA512_ALGORITHM/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // ════════════════════════════════════════════════════════════════════════
  // ── wolfSSL ─────────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /wc_AesGcmEncrypt\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /wc_AesCbcEncrypt\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /wc_RsaPublicEncrypt\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /wc_MakeRsaKey\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /wc_ecc_make_key\s*\(/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /wc_Sha256Hash\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /wc_ed25519_make_key\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /wc_curve25519_make_key\s*\(/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /wolfSSL_CTX_new\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ════════════════════════════════════════════════════════════════════════
  // ── mbedTLS ─────────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /mbedtls_md\s*\(\s*mbedtls_md_info_from_type\s*\(\s*MBEDTLS_MD_(\w+)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /mbedtls_aes_crypt_(?:cbc|ecb|ctr|cfb128)\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /mbedtls_gcm_crypt_and_tag\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /mbedtls_rsa_gen_key\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /mbedtls_ecdsa_genkey\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /mbedtls_pk_sign\s*\(/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /mbedtls_ssl_config_defaults\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /mbedtls_x509_crt_parse\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /mbedtls_ctr_drbg_seed\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /mbedtls_entropy_func/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── GnuTLS ──────────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /gnutls_hash_fast\s*\(\s*GNUTLS_DIG_(\w+)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /gnutls_cipher_init\s*\(\s*[^,]*,\s*GNUTLS_CIPHER_(\w+)/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /gnutls_init\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /gnutls_x509_crt_init\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /gnutls_privkey_sign_data\s*\(/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
];
