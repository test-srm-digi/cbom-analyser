// ring_crypto.rs
//
// Demonstrates the `ring` Rust crate usage for cryptographic operations.
// ring is a high-performance, safe crypto library focused on FIPS-approved algorithms.
//
// Expected CBOM result:
//   - ring → NOT_QUANTUM_SAFE (RSA, ECDSA, X25519 used — all classical)
//   - SHA-256, SHA-384, SHA-512 → QUANTUM_SAFE (hash)
//   - HMAC-SHA256, HMAC-SHA512 → QUANTUM_SAFE
//   - AES-256-GCM → QUANTUM_SAFE (symmetric, 256-bit key)
//   - AES-128-GCM → NOT_QUANTUM_SAFE (symmetric, 128-bit key — halved by Grover's)
//   - ChaCha20-Poly1305 → QUANTUM_SAFE
//   - Ed25519 → NOT_QUANTUM_SAFE (ECC)
//   - ECDSA-P256, ECDSA-P384 → NOT_QUANTUM_SAFE (ECC)
//   - RSA → NOT_QUANTUM_SAFE
//   - X25519 → NOT_QUANTUM_SAFE (ECC)

use ring::digest;
use ring::hmac;
use ring::aead;
use ring::signature;
use ring::agreement;
use ring::rand;

// ════════════════════════════════════════════════════════════════
// ── Hashing with ring::digest ────────────────────────────────
// ════════════════════════════════════════════════════════════════

/// SHA-256 digest — quantum-safe hash.
pub fn hash_sha256(data: &[u8]) -> digest::Digest {
    ring::digest::digest(&digest::SHA256, data)
}

/// SHA-384 digest — quantum-safe hash.
pub fn hash_sha384(data: &[u8]) -> digest::Digest {
    ring::digest::digest(&digest::SHA384, data)
}

/// SHA-512 digest — quantum-safe hash.
pub fn hash_sha512(data: &[u8]) -> digest::Digest {
    ring::digest::digest(&digest::SHA512, data)
}

/// SHA-1 — LEGACY ONLY, NOT quantum-safe.
pub fn hash_sha1_legacy(data: &[u8]) -> digest::Digest {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
}

// ════════════════════════════════════════════════════════════════
// ── HMAC with ring::hmac ─────────────────────────────────────
// ════════════════════════════════════════════════════════════════

/// HMAC-SHA256 message authentication.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> hmac::Tag {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&key, data)
}

/// HMAC-SHA384 message authentication.
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> hmac::Tag {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, key);
    ring::hmac::sign(&key, data)
}

/// HMAC-SHA512 message authentication.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> hmac::Tag {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
    ring::hmac::sign(&key, data)
}

/// HMAC-SHA256 verification.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    ring::hmac::verify(&key, data, tag).is_ok()
}

// ════════════════════════════════════════════════════════════════
// ── Authenticated Encryption with ring::aead ────────────────
// ════════════════════════════════════════════════════════════════

/// AES-256-GCM encryption — quantum-safe (256-bit symmetric key).
pub fn encrypt_aes256_gcm(
    key_bytes: &[u8; 32],
    nonce: &[u8; 12],
    data: &mut Vec<u8>,
) -> Result<(), ring::error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), data)?;
    Ok(())
}

/// AES-128-GCM encryption — NOT quantum-safe (128-bit → 64-bit under Grover's).
pub fn encrypt_aes128_gcm(
    key_bytes: &[u8; 16],
    nonce: &[u8; 12],
    data: &mut Vec<u8>,
) -> Result<(), ring::error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&ring::aead::AES_128_GCM, key_bytes)?;
    let opening_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;
    opening_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), data)?;
    Ok(())
}

/// ChaCha20-Poly1305 encryption — quantum-safe (256-bit key).
pub fn encrypt_chacha20(
    key_bytes: &[u8; 32],
    nonce: &[u8; 12],
    data: &mut Vec<u8>,
) -> Result<(), ring::error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, key_bytes)?;
    let sealing_key = aead::SealingKey::new(unbound_key, OneNonceSequence(Some(
        aead::Nonce::try_assume_unique_for_key(nonce)?
    )));
    Ok(())
}

// ════════════════════════════════════════════════════════════════
// ── Digital Signatures with ring::signature ──────────────────
// ════════════════════════════════════════════════════════════════

/// Ed25519 key pair generation and signing — NOT quantum-safe (ECC).
pub fn sign_ed25519(data: &[u8]) -> Result<(signature::Ed25519KeyPair, Vec<u8>), Box<dyn std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?;
    let sig = key_pair.sign(data);
    Ok((key_pair, sig.as_ref().to_vec()))
}

/// ECDSA P-256 signature — NOT quantum-safe (ECC).
pub fn verify_ecdsa_p256(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let public_key = signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        public_key,
    );
    public_key.verify(message, sig).is_ok()
}

/// ECDSA P-384 signature — NOT quantum-safe (ECC).
pub fn verify_ecdsa_p384(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let public_key = signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P384_SHA384_ASN1,
        public_key,
    );
    public_key.verify(message, sig).is_ok()
}

/// RSA PKCS1 SHA-256 signature verification — NOT quantum-safe.
pub fn verify_rsa_pkcs1(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let public_key = signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_SHA256,
        public_key,
    );
    public_key.verify(message, sig).is_ok()
}

/// RSA PSS SHA-512 signature verification — NOT quantum-safe.
pub fn verify_rsa_pss(
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let public_key = signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PSS_SHA512,
        public_key,
    );
    public_key.verify(message, sig).is_ok()
}

// ════════════════════════════════════════════════════════════════
// ── Key Agreement with ring::agreement ──────────────────────
// ════════════════════════════════════════════════════════════════

/// X25519 key exchange — NOT quantum-safe (ECC).
pub fn key_exchange_x25519() -> Result<Vec<u8>, ring::error::Unspecified> {
    let rng = rand::SystemRandom::new();
    let my_private_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;

    // In a real protocol, we'd receive the peer's public key
    // For demo, we do agree_ephemeral with our own key (would not work in practice)
    ring::agreement::agree_ephemeral(
        my_private_key,
        &agreement::UnparsedPublicKey::new(&ring::agreement::X25519, my_public_key.as_ref()),
        |shared_secret| {
            Ok(shared_secret.to_vec())
        },
    )
}

// ════════════════════════════════════════════════════════════════
// ── PQC via pqcrypto crate (Rust PQC ecosystem) ─────────────
// ════════════════════════════════════════════════════════════════

// The pqcrypto crate family provides PQC algorithms for Rust:
//   - pqcrypto-kyber: ML-KEM
//   - pqcrypto-dilithium: ML-DSA
//   - pqcrypto-sphincsplus: SLH-DSA
//   - pqcrypto-falcon: Falcon signatures

use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincsshake128fsimple;

/// ML-KEM-768 key encapsulation — QUANTUM_SAFE.
pub fn mlkem_keygen() -> (kyber768::PublicKey, kyber768::SecretKey) {
    pqcrypto_kyber::kyber768::keypair()
}

/// ML-KEM-768 encapsulation.
pub fn mlkem_encapsulate(pk: &kyber768::PublicKey) -> (kyber768::SharedSecret, kyber768::Ciphertext) {
    pqcrypto_kyber::kyber768::encapsulate(pk)
}

/// ML-DSA-65 (Dilithium3) signing — QUANTUM_SAFE.
pub fn mldsa_sign(sk: &dilithium3::SecretKey, message: &[u8]) -> dilithium3::SignedMessage {
    pqcrypto_dilithium::dilithium3::sign(message, sk)
}

/// SLH-DSA (SPHINCS+) signing — QUANTUM_SAFE.
pub fn slhdsa_keygen() -> (sphincsshake128fsimple::PublicKey, sphincsshake128fsimple::SecretKey) {
    pqcrypto_sphincsplus::sphincsshake128fsimple::keypair()
}

// ── Helper for AEAD nonce sequence ──
struct OneNonceSequence(Option<aead::Nonce>);

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
