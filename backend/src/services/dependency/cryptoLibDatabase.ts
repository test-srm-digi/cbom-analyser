/**
 * Known Crypto Library Databases
 *
 * Databases of known cryptographic libraries for each package manager ecosystem.
 * Used by the dependency scanner to classify third-party dependencies.
 */
import { QuantumSafetyStatus } from '../../types';
import type { KnownCryptoLib } from './types';

// ─── Maven / Gradle (groupId:artifactId prefix match) ──────────────────────

export const MAVEN_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'org.bouncycastle:bcprov': {
    name: 'BouncyCastle Provider',
    algorithms: ['RSA', 'ECDSA', 'AES', 'SHA-256', 'SHA-512', 'PBKDF2', 'Ed25519', 'ML-KEM', 'ML-DSA'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Comprehensive JCE/JCA provider — supports both classical and PQC algorithms',
  },
  'org.bouncycastle:bcpkix': {
    name: 'BouncyCastle PKIX',
    algorithms: ['X.509', 'CMS', 'OCSP', 'TSP', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PKI utilities — certificates, CMS, OCSP. Uses classical signatures.',
  },
  'org.bouncycastle:bcpg': {
    name: 'BouncyCastle OpenPGP',
    algorithms: ['RSA', 'DSA', 'ElGamal', 'AES', 'CAST5'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'OpenPGP implementation — classical asymmetric crypto',
  },
  'org.bouncycastle:bcfips': {
    name: 'BouncyCastle FIPS',
    algorithms: ['AES', 'SHA-256', 'RSA', 'ECDSA', 'HMAC', 'DRBG'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'FIPS 140-2 certified provider',
  },
  'org.bouncycastle:bcpqc': {
    name: 'BouncyCastle PQC',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON', 'SPHINCS+', 'BIKE', 'HQC'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-Quantum Cryptography implementations',
  },
  'com.google.crypto.tink:tink': {
    name: 'Google Tink',
    algorithms: ['AES-GCM', 'AES-EAX', 'AES-CTR-HMAC', 'ECDSA', 'Ed25519', 'RSA-SSA-PKCS1', 'HKDF'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Google Tink crypto library — modern API, classical algorithms',
  },
  'org.conscrypt:conscrypt': {
    name: 'Conscrypt',
    algorithms: ['TLSv1.3', 'TLSv1.2', 'AES-GCM', 'ChaCha20-Poly1305', 'ECDHE', 'RSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Java Security Provider backed by BoringSSL — modern TLS, classical KEM',
  },
  'javax.xml.crypto:': {
    name: 'XML Digital Signatures',
    algorithms: ['RSA', 'DSA', 'ECDSA', 'SHA-256', 'HMAC-SHA256'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'XML-DSIG — classical signature algorithms',
  },
  'com.nimbusds:nimbus-jose-jwt': {
    name: 'Nimbus JOSE+JWT',
    algorithms: ['RSA', 'ECDSA', 'AES', 'HMAC-SHA256', 'Ed25519'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE/JWT/JWS/JWE library — classical crypto',
  },
  'io.jsonwebtoken:jjwt': {
    name: 'JJWT (Java JWT)',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA', 'Ed25519'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JSON Web Token library — classical signatures',
  },
  'org.apache.commons:commons-crypto': {
    name: 'Apache Commons Crypto',
    algorithms: ['AES', 'AES-CTR', 'AES-CBC'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Optimized AES with OpenSSL native binding — symmetric only',
  },
  'org.springframework.security:spring-security-crypto': {
    name: 'Spring Security Crypto',
    algorithms: ['PBKDF2', 'BCrypt', 'SCrypt', 'AES-GCM', 'Argon2'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Spring password encoders + encryption utilities',
  },
  'org.springframework.security:spring-security': {
    name: 'Spring Security',
    algorithms: ['RSA', 'ECDSA', 'AES', 'BCrypt', 'PBKDF2', 'TLSv1.2', 'TLSv1.3'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Full Spring Security framework — uses classical key exchange/signatures',
  },
  'commons-codec:commons-codec': {
    name: 'Apache Commons Codec',
    algorithms: ['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'HMAC-SHA1'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Hash + encoding utility — watch for MD5/SHA-1 usage',
  },
  'com.google.guava:guava': {
    name: 'Google Guava',
    algorithms: ['SHA-256', 'SHA-512', 'MD5'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Contains Hashing utility class (CRC32/Murmur3 are non-crypto and excluded)',
  },
  'org.jasypt:jasypt': {
    name: 'Jasypt',
    algorithms: ['PBKDF2', 'AES', 'DES', '3DES', 'MD5'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Java Simplified Encryption — often uses weak defaults (DES, PBE)',
  },
  'de.mkammerer:argon2-jvm': {
    name: 'Argon2 JVM',
    algorithms: ['Argon2id', 'Argon2i', 'Argon2d'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing — quantum-resistant KDF',
  },
};

// ─── npm (package name) ─────────────────────────────────────────────────────

export const NPM_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'crypto-js': {
    name: 'CryptoJS',
    algorithms: ['AES', 'DES', '3DES', 'SHA-256', 'SHA-1', 'MD5', 'HMAC', 'PBKDF2', 'Rabbit', 'RC4'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'JavaScript crypto library — includes weak algorithms (DES, MD5, RC4)',
  },
  'node-forge': {
    name: 'Node Forge',
    algorithms: ['RSA', 'AES', 'DES', '3DES', 'SHA-256', 'MD5', 'HMAC', 'PBKDF2', 'X.509', 'TLS'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Pure JS TLS/PKI — classical asymmetric',
  },
  'tweetnacl': {
    name: 'TweetNaCl',
    algorithms: ['Curve25519', 'Ed25519', 'XSalsa20', 'Poly1305'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'NaCl-compatible library — classical ECC',
  },
  'libsodium-wrappers': {
    name: 'libsodium',
    algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'AES-256-GCM', 'Argon2id', 'BLAKE2b'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Sodium (libsodium) — modern crypto, but classical KEM/signatures',
  },
  'sodium-native': {
    name: 'sodium-native',
    algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Native libsodium bindings',
  },
  'jsonwebtoken': {
    name: 'jsonwebtoken',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JWT library — classical signatures',
  },
  'jose': {
    name: 'jose',
    algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES-GCM', 'HMAC'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE/JWT/JWK library — classical crypto',
  },
  'bcrypt': {
    name: 'bcrypt',
    algorithms: ['BCrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'BCrypt password hashing — quantum-resistant KDF',
  },
  'argon2': {
    name: 'argon2',
    algorithms: ['Argon2id', 'Argon2i', 'Argon2d'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing — quantum-resistant KDF',
  },
  'scrypt': {
    name: 'scrypt',
    algorithms: ['scrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'scrypt KDF — quantum-resistant',
  },
  'elliptic': {
    name: 'elliptic',
    algorithms: ['ECDSA', 'ECDH', 'Ed25519', 'secp256k1'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'EC cryptography — quantum-vulnerable',
  },
  'openpgp': {
    name: 'OpenPGP.js',
    algorithms: ['RSA', 'ECDSA', 'ECDH', 'AES', 'SHA-256'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'OpenPGP implementation — classical asymmetric',
  },
  '@noble/curves': {
    name: '@noble/curves',
    algorithms: ['secp256k1', 'Ed25519', 'Ed448', 'P-256', 'P-384'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Noble curves — high-quality EC, but quantum-vulnerable',
  },
  '@noble/hashes': {
    name: '@noble/hashes',
    algorithms: ['SHA-256', 'SHA-512', 'SHA-3', 'BLAKE2', 'BLAKE3', 'RIPEMD-160'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Noble hashes — hash-only, quantum-resistant',
  },
  'pqcrypto': {
    name: 'pqcrypto',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-quantum crypto for Node.js',
  },
  'crystals-kyber': {
    name: 'crystals-kyber',
    algorithms: ['ML-KEM'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'CRYSTALS-Kyber (ML-KEM) implementation',
  },
};

// ─── pip (package name) ─────────────────────────────────────────────────────

export const PIP_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'cryptography': {
    name: 'cryptography',
    algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES', 'ChaCha20', 'SHA-256', 'HMAC', 'X.509', 'HKDF', 'PBKDF2'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python cryptography library — comprehensive, classical',
  },
  'pycryptodome': {
    name: 'PyCryptodome',
    algorithms: ['RSA', 'AES', 'DES', '3DES', 'ChaCha20', 'SHA-256', 'HMAC', 'PBKDF2', 'scrypt'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PyCryptodome — drop-in PyCrypto replacement',
  },
  'pycryptodomex': {
    name: 'PyCryptodomex',
    algorithms: ['RSA', 'AES', 'DES', 'SHA-256', 'HMAC'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PyCryptodomex — side-by-side installable PyCryptodome',
  },
  'pynacl': {
    name: 'PyNaCl',
    algorithms: ['Curve25519', 'Ed25519', 'XSalsa20-Poly1305', 'BLAKE2b'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python binding to libsodium — classical ECC',
  },
  'pyopenssl': {
    name: 'pyOpenSSL',
    algorithms: ['RSA', 'ECDSA', 'TLS', 'X.509', 'AES'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python OpenSSL wrapper',
  },
  'pyjwt': {
    name: 'PyJWT',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JSON Web Token library',
  },
  'python-jose': {
    name: 'python-jose',
    algorithms: ['RSA', 'ECDSA', 'HMAC', 'AES'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE implementation for Python',
  },
  'passlib': {
    name: 'passlib',
    algorithms: ['BCrypt', 'SCrypt', 'Argon2', 'PBKDF2', 'SHA-512-Crypt'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Password hashing — mix of strong and legacy schemes',
  },
  'bcrypt': {
    name: 'bcrypt (Python)',
    algorithms: ['BCrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'BCrypt password hashing',
  },
  'argon2-cffi': {
    name: 'argon2-cffi',
    algorithms: ['Argon2id', 'Argon2i'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing',
  },
  'pqcrypto': {
    name: 'pqcrypto (Python)',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'SPHINCS+'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-quantum crypto for Python',
  },
  'oqs': {
    name: 'liboqs-python',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Open Quantum Safe liboqs Python wrapper',
  },
};

// ─── Go (module path prefix) ────────────────────────────────────────────────

export const GO_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'golang.org/x/crypto': {
    name: 'golang.org/x/crypto',
    algorithms: ['ChaCha20-Poly1305', 'Curve25519', 'Ed25519', 'Argon2', 'BCrypt', 'scrypt', 'SSH', 'HKDF'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Go extended crypto — classical ECC + modern KDFs',
  },
  'github.com/cloudflare/circl': {
    name: 'Cloudflare CIRCL',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'X25519', 'Ed448', 'HPKE'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Cloudflare cryptographic library — includes PQC',
  },
  'github.com/open-quantum-safe/liboqs-go': {
    name: 'liboqs-go',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Open Quantum Safe Go bindings',
  },
};
