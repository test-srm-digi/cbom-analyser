/**
 * Rust Crypto Patterns
 *
 * Detection patterns for Rust cryptographic libraries:
 * - ring (high-level, safe crypto)
 * - RustCrypto (modular: aes, sha2, rsa, ed25519-dalek, x25519-dalek, etc.)
 * - rustls (TLS)
 * - openssl crate
 * - sodiumoxide / libsodium-sys
 * - snow (Noise Protocol)
 * - orion (safe, easy-to-use crypto)
 * - PQC: pqcrypto, oqs crates
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const rustPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── ring crate ──────────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Hash / digest
  { pattern: /ring::digest::(?:digest|SHA256|SHA384|SHA512|SHA1_FOR_LEGACY_USE_ONLY)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: false },
  { pattern: /ring::digest::SHA256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /ring::digest::SHA384/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /ring::digest::SHA512/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /ring::digest::SHA1_FOR_LEGACY_USE_ONLY/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // HMAC
  { pattern: /ring::hmac::(?:sign|verify|Key::new|Context::with_key)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /ring::hmac::HMAC_SHA256/g, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /ring::hmac::HMAC_SHA384/g, algorithm: 'HMAC-SHA384', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /ring::hmac::HMAC_SHA512/g, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // AEAD
  { pattern: /ring::aead::(?:AES_128_GCM|AES_256_GCM)/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /ring::aead::CHACHA20_POLY1305/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /ring::aead::(?:SealingKey|OpeningKey|LessSafeKey|UnboundKey)/g, algorithm: 'AEAD', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },

  // Signatures
  { pattern: /ring::signature::(?:Ed25519KeyPair|ED25519)/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ring::signature::ECDSA_P256_SHA256_(?:ASN1|FIXED)/g, algorithm: 'ECDSA-P256', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ring::signature::ECDSA_P384_SHA384_(?:ASN1|FIXED)/g, algorithm: 'ECDSA-P384', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ring::signature::RSA_PKCS1_SHA(?:256|384|512)/g, algorithm: 'RSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ring::signature::RSA_PSS_SHA(?:256|384|512)/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // Key agreement
  { pattern: /ring::agreement::(?:agree_ephemeral|EphemeralPrivateKey)/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ring::agreement::X25519/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ring::agreement::ECDH_P256/g, algorithm: 'ECDH-P256', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ring::agreement::ECDH_P384/g, algorithm: 'ECDH-P384', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // KDF
  { pattern: /ring::hkdf::(?:Salt|Prk|HKDF_SHA256|HKDF_SHA384|HKDF_SHA512)/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ring::pbkdf2::(?:derive|verify|PBKDF2_HMAC_SHA256|PBKDF2_HMAC_SHA384|PBKDF2_HMAC_SHA512)/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // PRNG
  { pattern: /ring::rand::(?:SystemRandom|SecureRandom|generate)/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── RustCrypto ecosystem ────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Hash crates
  { pattern: /(?:use\s+)?sha2::(?:Sha256|Sha384|Sha512|Digest)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /(?:use\s+)?sha3::(?:Sha3_256|Sha3_384|Sha3_512|Keccak256|Digest)/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /(?:use\s+)?sha1::(?:Sha1|Digest)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /(?:use\s+)?md5::(?:Md5|Digest)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /(?:use\s+)?blake2::(?:Blake2b512|Blake2s256|Digest)/g, algorithm: 'BLAKE2', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /(?:use\s+)?blake3/g, algorithm: 'BLAKE3', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // Symmetric ciphers
  { pattern: /(?:use\s+)?aes::(?:Aes128|Aes192|Aes256|Aes128Enc|Aes256Enc)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?aes_gcm::(?:Aes128Gcm|Aes256Gcm|AesGcm)/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?aes_gcm_siv::(?:Aes128GcmSiv|Aes256GcmSiv)/g, algorithm: 'AES-GCM-SIV', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?chacha20poly1305::(?:ChaCha20Poly1305|XChaCha20Poly1305)/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?chacha20::(?:ChaCha20|XChaCha20)/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?des::(?:Des|TdesEde3)/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?cbc::(?:Encryptor|Decryptor)/g, algorithm: 'CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?ctr::(?:Ctr32BE|Ctr64BE|Ctr128BE)/g, algorithm: 'CTR', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // MAC
  { pattern: /(?:use\s+)?hmac::(?:Hmac|Mac|SimpleHmac)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /(?:use\s+)?cmac::(?:Cmac|Mac)/g, algorithm: 'CMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /(?:use\s+)?poly1305::(?:Poly1305|Tag)/g, algorithm: 'Poly1305', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // Asymmetric / signatures
  { pattern: /(?:use\s+)?rsa::(?:RsaPrivateKey|RsaPublicKey|Pkcs1v15(?:Encrypt|Sign)|Oaep|Pss)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /(?:use\s+)?ed25519_dalek::(?:SigningKey|VerifyingKey|Signature|Signer|Verifier)/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?ed448_goldilocks/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?p256::(?:ecdsa|SecretKey|PublicKey|EncodedPoint)/g, algorithm: 'ECDSA-P256', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?p384::(?:ecdsa|SecretKey|PublicKey)/g, algorithm: 'ECDSA-P384', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?k256::(?:ecdsa|SecretKey|PublicKey)/g, algorithm: 'ECDSA-secp256k1', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?ecdsa::(?:SigningKey|VerifyingKey|Signature|DerSignature)/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /(?:use\s+)?dsa::(?:SigningKey|VerifyingKey)/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // Key exchange
  { pattern: /(?:use\s+)?x25519_dalek::(?:EphemeralSecret|PublicKey|StaticSecret|SharedSecret)/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /(?:use\s+)?x448/g, algorithm: 'X448', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /(?:use\s+)?diffie_hellman|(?:use\s+)?dh/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // KDF
  { pattern: /(?:use\s+)?hkdf::(?:Hkdf|HkdfExtract)/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /(?:use\s+)?pbkdf2/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /(?:use\s+)?scrypt::(?:scrypt|Scrypt|Params)/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /(?:use\s+)?argon2::(?:Argon2|Algorithm|Params|PasswordHash)/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /(?:use\s+)?bcrypt/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // PRNG
  { pattern: /(?:use\s+)?rand::(?:thread_rng|rngs::OsRng|Rng|CryptoRng|RngCore)/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /OsRng\.fill_bytes|OsRng\.try_fill_bytes/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── rustls (TLS) ────────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /(?:use\s+)?rustls::(?:ClientConfig|ServerConfig|ClientConnection|ServerConnection)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /rustls::version::TLS12/g, algorithm: 'TLS 1.2', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /rustls::version::TLS13/g, algorithm: 'TLS 1.3', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /rustls::cipher_suite::/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ════════════════════════════════════════════════════════════════════════
  // ── OpenSSL crate ───────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /openssl::symm::(?:Cipher|Crypter|encrypt|decrypt)/g, algorithm: 'OpenSSL-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /openssl::hash::(?:hash|Hasher|MessageDigest)/g, algorithm: 'OpenSSL-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /openssl::sign::(?:Signer|Verifier)/g, algorithm: 'OpenSSL-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /openssl::pkey::(?:PKey|Private|Public|Id)/g, algorithm: 'OpenSSL-PKI', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /openssl::rsa::(?:Rsa|Padding)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /openssl::ec::(?:EcKey|EcGroup|EcPoint)/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /openssl::ssl::(?:SslConnector|SslAcceptor|SslMethod|SslContext)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /openssl::x509::(?:X509|X509Req|X509Name)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /openssl::derive::Deriver/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /openssl::rand::rand_bytes/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── sodiumoxide / libsodium-sys ─────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /sodiumoxide::crypto::secretbox/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodiumoxide::crypto::box_/g, algorithm: 'Curve25519-XSalsa20-Poly1305', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodiumoxide::crypto::sign/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /sodiumoxide::crypto::hash/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sodiumoxide::crypto::auth/g, algorithm: 'HMAC-SHA512-256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /sodiumoxide::crypto::aead/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodiumoxide::crypto::scalarmult/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /sodiumoxide::crypto::pwhash/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /sodiumoxide::crypto::kdf/g, algorithm: 'BLAKE2b-KDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /sodiumoxide::crypto::stream/g, algorithm: 'XSalsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /sodiumoxide::crypto::generichash/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sodiumoxide::randombytes/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── snow (Noise Protocol) ───────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /snow::(?:Builder|HandshakeState|TransportState)/g, algorithm: 'Noise Protocol', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, assetType: AssetType.PROTOCOL },
  { pattern: /snow::params::NoiseParams/g, algorithm: 'Noise Protocol', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, assetType: AssetType.PROTOCOL },

  // ════════════════════════════════════════════════════════════════════════
  // ── orion (safe crypto) ─────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /orion::aead::(?:seal|open|SecretKey)/g, algorithm: 'XChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /orion::hash::(?:digest|Digest)/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /orion::auth::(?:authenticate|Tag)/g, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /orion::kdf::(?:derive_key|Salt)/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /orion::pwhash::(?:hash_password|PasswordHash)/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── PQC: pqcrypto crate ─────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /pqcrypto::sign::dilithium(?:2|3|5)/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /pqcrypto::sign::sphincsplus/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /pqcrypto::sign::falcon(?:512|1024)/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /pqcrypto::kem::kyber(?:512|768|1024)/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /pqcrypto::kem::(?:firesaber|lightsaber|saber)/g, algorithm: 'SABER', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /pqcrypto::kem::(?:mceliece|classicmceliece)/g, algorithm: 'Classic-McEliece', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /pqcrypto::kem::(?:hqc|bike|frodo)/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /pqcrypto_(?:dilithium|kyber|sphincsplus|falcon|ntru|mceliece)/g, algorithm: 'PQC', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

  // oqs crate (liboqs Rust binding)
  { pattern: /oqs::(?:sig|kem)/g, algorithm: 'liboqs', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /oqs::sig::Algorithm::(?:Dilithium2|Dilithium3|Dilithium5|MlDsa44|MlDsa65|MlDsa87)/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /oqs::sig::Algorithm::(?:Falcon512|Falcon1024|FalconPadded512|FalconPadded1024)/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /oqs::sig::Algorithm::(?:SphincsSha2128f|SphincsSha2128s|SphincsSha2192f|SlhDsa)/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /oqs::kem::Algorithm::(?:Kyber512|Kyber768|Kyber1024|MlKem512|MlKem768|MlKem1024)/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /oqs::kem::Algorithm::(?:Bike|Hqc|FrodoKem|ClassicMcEliece)/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // ════════════════════════════════════════════════════════════════════════
  // ── Certificates & PEM ──────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /(?:use\s+)?x509_parser::(?:parse_x509_certificate|X509Certificate|TbsCertificate)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /(?:use\s+)?rcgen::(?:Certificate|CertificateParams|KeyPair|DnType)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /(?:use\s+)?pem::(?:parse|encode|Pem)/g, algorithm: 'PEM', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL },
  { pattern: /(?:use\s+)?pkcs8::(?:DecodePrivateKey|EncodePrivateKey|PrivateKeyInfo)/g, algorithm: 'PKCS8', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY },
  { pattern: /(?:use\s+)?pkcs1::(?:DecodeRsaPrivateKey|RsaPrivateKey)/g, algorithm: 'PKCS1', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PRIVATE_KEY },

  // ════════════════════════════════════════════════════════════════════════
  // ── Cargo.toml dependency detection ─────────────────────────────────────
  // (useful when scanning Cargo.toml alongside .rs files)
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /ring\s*=\s*"/g, algorithm: 'ring', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /rustls\s*=\s*"/g, algorithm: 'rustls', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /openssl\s*=\s*"/g, algorithm: 'OpenSSL', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
];
