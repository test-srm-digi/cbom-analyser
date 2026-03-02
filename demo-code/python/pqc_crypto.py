"""
PQC Crypto Utilities (Python)

Demonstrates Post-Quantum Cryptography in Python using:
  - oqs (liboqs-python): Open Quantum Safe library
  - pqcrypto: Python PQC bindings
  - Standard library for comparison

Expected CBOM result:
  - ML-KEM → QUANTUM_SAFE (via oqs.KeyEncapsulation)
  - ML-DSA → QUANTUM_SAFE (via oqs.Signature)
  - SHA-256 → QUANTUM_SAFE (hash)
  - RSA → NOT_QUANTUM_SAFE (classical comparison)
"""

import hashlib
import hmac
import os
from typing import Tuple

# ════════════════════════════════════════════════════════════════
# ── PQC via Open Quantum Safe (liboqs-python) ────────────────
# ════════════════════════════════════════════════════════════════

import oqs

def mlkem_keygen() -> Tuple[bytes, bytes]:
    """ML-KEM-768 key generation — QUANTUM_SAFE."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key


def mlkem_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """ML-KEM-768 key encapsulation — QUANTUM_SAFE."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def mlkem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """ML-KEM-768 key decapsulation — QUANTUM_SAFE."""
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key)
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


def mldsa_keygen() -> Tuple[bytes, bytes]:
    """ML-DSA-65 key generation — QUANTUM_SAFE."""
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return public_key, secret_key


def mldsa_sign(secret_key: bytes, message: bytes) -> bytes:
    """ML-DSA-65 digital signature — QUANTUM_SAFE."""
    sig = oqs.Signature("ML-DSA-65", secret_key)
    signature = sig.sign(message)
    return signature


def mldsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """ML-DSA-65 signature verification — QUANTUM_SAFE."""
    sig = oqs.Signature("ML-DSA-65")
    return sig.verify(message, signature, public_key)


def slhdsa_keygen() -> Tuple[bytes, bytes]:
    """SLH-DSA-SHA2-128s key generation — QUANTUM_SAFE (SPHINCS+)."""
    sig = oqs.Signature("SLH-DSA-SHA2-128s")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return public_key, secret_key


def falcon_keygen() -> Tuple[bytes, bytes]:
    """Falcon-512 key generation — QUANTUM_SAFE."""
    sig = oqs.Signature("Falcon-512")
    public_key = sig.generate_keypair()
    return public_key, sig.export_secret_key()


# ════════════════════════════════════════════════════════════════
# ── Quantum-safe hashing (standard library) ──────────────────
# ════════════════════════════════════════════════════════════════

def hash_sha3_256(data: bytes) -> bytes:
    """SHA3-256 — quantum-safe hash function."""
    return hashlib.sha3_256(data).digest()


def hash_sha3_512(data: bytes) -> bytes:
    """SHA3-512 — quantum-safe hash function."""
    return hashlib.sha3_512(data).digest()


def hash_sha256(data: bytes) -> bytes:
    """SHA-256 — quantum-safe (Grover's at 128-bit)."""
    return hashlib.sha256(data).digest()


def hash_sha512(data: bytes) -> bytes:
    """SHA-512 — quantum-safe (Grover's at 256-bit)."""
    return hashlib.sha512(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 — quantum-safe MAC."""
    return hmac.new(key, data, hashlib.sha256).digest()


# ════════════════════════════════════════════════════════════════
# ── Hybrid PQC + Classical (migration pattern) ───────────────
# ════════════════════════════════════════════════════════════════

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
import datetime


def hybrid_key_exchange() -> dict:
    """
    Hybrid key exchange: classical ECDH + ML-KEM.

    During the NIST PQC transition period, combining classical and PQC
    key exchange provides security against both classical and quantum attackers.
    """
    # Classical: ECDSA P-256 key pair (NOT quantum-safe)
    ec_private_key = ec.generate_private_key(ec.SECP256R1())
    ec_public_key = ec_private_key.public_key()

    # PQC: ML-KEM-1024 key pair (QUANTUM_SAFE)
    kem = oqs.KeyEncapsulation("ML-KEM-1024")
    pqc_public_key = kem.generate_keypair()
    pqc_secret_key = kem.export_secret_key()

    return {
        "classical_public": ec_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "pqc_public": pqc_public_key,
    }


def create_rsa_cert():
    """
    Create self-signed X.509 certificate with RSA — NOT quantum-safe.
    (Classical comparison for migration analysis.)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = Name([
        NameAttribute(NameOID.COMMON_NAME, "Classical RSA Cert"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "CBOM Analyser"),
    ])

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert
