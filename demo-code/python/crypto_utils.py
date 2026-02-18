"""
Demo cryptographic utilities for CBOM scanner detection.
Demonstrates various Python crypto patterns.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


# ── Hashing ──────────────────────────────────────────────────────

def hash_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of input data."""
    return hashlib.sha256(data).hexdigest()


def hash_sha1(data: bytes) -> str:
    """WARNING: SHA-1 is deprecated. Use SHA-256 or SHA-3."""
    return hashlib.sha1(data).hexdigest()


def hash_md5(data: bytes) -> str:
    """WARNING: MD5 is broken. Never use for security."""
    return hashlib.md5(data).hexdigest()


def hash_password(password: str, salt: bytes = None) -> tuple:
    """Hash a password with SHA-256 and a random salt."""
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.sha256(salt + password.encode()).hexdigest()
    return key, salt


# ── Symmetric Encryption (AES via PyCryptodome) ─────────────────

def encrypt_aes(plaintext: bytes, key: bytes) -> tuple:
    """Encrypt data using AES-256-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag


def decrypt_aes(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ── Asymmetric Keys (RSA) ───────────────────────────────────────

def generate_rsa_keypair_cryptography(key_size: int = 2048):
    """Generate RSA key pair using the cryptography library."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def generate_rsa_keypair_pycrypto(key_size: int = 2048):
    """Generate RSA key pair using PyCryptodome."""
    key = RSA.generate(key_size)
    return key, key.publickey()


# ── Elliptic Curve (ECDSA) ──────────────────────────────────────

def generate_ec_keypair():
    """Generate an ECDSA key pair using NIST P-256 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def sign_ecdsa(data: bytes, private_key) -> bytes:
    """Sign data using ECDSA with SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa(data: bytes, signature: bytes, public_key) -> bool:
    """Verify an ECDSA signature."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ── HMAC ─────────────────────────────────────────────────────────

def compute_hmac(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ── Full Workflow Example ────────────────────────────────────────

def secure_message_exchange(message: str):
    """Demo: encrypt, sign, and hash a message."""
    # Generate keys
    rsa_priv, rsa_pub = generate_rsa_keypair_cryptography(4096)
    ec_priv, ec_pub = generate_ec_keypair()
    aes_key = os.urandom(32)

    # Hash the message
    msg_hash = hash_sha256(message.encode())

    # Encrypt with AES
    nonce, ciphertext, tag = encrypt_aes(message.encode(), aes_key)

    # Sign with ECDSA
    signature = sign_ecdsa(ciphertext, ec_priv)

    return {
        "hash": msg_hash,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "signature": signature.hex(),
    }


if __name__ == "__main__":
    result = secure_message_exchange("Hello, quantum-safe world!")
    print("Secure message exchange result:")
    for k, v in result.items():
        print(f"  {k}: {v[:40]}...")
