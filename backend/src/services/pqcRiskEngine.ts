/**
 * PQC (Post-Quantum Cryptography) Risk Engine
 *
 * Classifies cryptographic algorithms by quantum safety and
 * recommends NIST-approved PQC replacements.
 */
import {
  QuantumSafetyStatus,
  ComplianceStatus,
  CryptoAsset,
  QuantumReadinessScore,
  ComplianceSummary,
  PQCReadinessVerdict,
} from '../types';

// ─── Quantum Safety Classification Database ──────────────────────────────────

interface AlgorithmProfile {
  quantumSafety: QuantumSafetyStatus;
  recommendedPQC?: string;
  notes?: string;
  minSafeKeyLength?: number;
}

const ALGORITHM_DATABASE: Record<string, AlgorithmProfile> = {
  // Asymmetric – ALL quantum-vulnerable
  'RSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-2048': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber-768)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-4096': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber-1024)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'RSA-204800': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'ECC': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
    notes: 'Broken by Shor\'s algorithm',
  },
  'ECDSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'ECDH': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'EC-SECP': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'ED25519': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'Ed25519': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'DSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'EDDSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
  },
  'DH': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'SSL': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC KEM',
  },

  // Symmetric – Generally quantum-resistant but need larger keys
  'AES': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant with 256-bit keys (Grover halves effective key length)',
    minSafeKeyLength: 256,
  },
  'AES-128': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256',
    notes: 'Effectively 64-bit security with Grover\'s algorithm',
  },
  'AES-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit effective security with Grover\'s algorithm',
  },
  // sonar-cryptography output names
  'AES128-GCM': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256-GCM',
    notes: 'AES-128 in GCM mode — effectively 64-bit security with Grover\'s algorithm',
  },
  'AES256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit effective security with Grover\'s algorithm',
  },
  'AES256-GCM': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'AES-256 in GCM mode — quantum-resistant',
  },
  'AES128': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256',
    notes: 'Effectively 64-bit security with Grover\'s algorithm',
  },
  'KEY:AES': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'AES key material',
  },
  'CHACHA20': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant with 256-bit keys',
  },

  // Hash functions
  'SHA-1': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'SHA-3-256 or SHA-256',
    notes: 'Classically broken, not just quantum-vulnerable',
  },
  'SHA-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit collision resistance with Grover\'s algorithm',
  },
  // sonar-cryptography uses dash-less names
  'SHA256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: '128-bit collision resistance with Grover\'s algorithm',
  },
  'SHA384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA-384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA-512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA-3': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Quantum-resistant',
  },
  'SHA3-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SHA-3 with 256-bit output — quantum-resistant (128-bit collision resistance with Grover\'s).',
  },
  'SHA3-384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SHA-3 with 384-bit output — quantum-resistant.',
  },
  'SHA3-512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SHA-3 with 512-bit output — quantum-resistant.',
  },
  'SHAKE128': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SHA-3 extendable output function — quantum-resistant at 128-bit security level.',
  },
  'SHAKE256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SHA-3 extendable output function — quantum-resistant at 256-bit security level.',
  },
  'HMACSHA256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  // sonar-cryptography hyphenated HMAC names
  'HMAC-SHA256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'HMAC with SHA-256 — quantum-resistant',
  },
  'HMAC-SHA384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'HMAC-SHA512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'HMACSHA384': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'HMACSHA512': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'MD5': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'SHA-3-256',
    notes: 'Classically broken',
  },

  // Key-related
  'KEY:RSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
  },
  'KEY:HMAC': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
  },
  'KEY:RAW': {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
  },
  'RAW': {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
  },

  // PQC algorithms – NIST approved (and common aliases)
  'ML-KEM': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 203 – Key Encapsulation Mechanism (formerly Kyber)',
  },
  'ML-DSA': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 204 – Digital Signature Algorithm (formerly Dilithium)',
  },
  'Dilithium': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Lattice-based digital signature — standardized as ML-DSA (NIST FIPS 204).',
  },
  'CRYSTALS-Dilithium': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'CRYSTALS-Dilithium — standardized as ML-DSA (NIST FIPS 204).',
  },
  'SLH-DSA': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST FIPS 205 – Stateless Hash-Based Digital Signature (formerly SPHINCS+)',
  },
  'SPHINCS+': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Stateless hash-based PQC signature — standardized as SLH-DSA (NIST FIPS 205).',
  },
  'FALCON': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'NIST selected PQC signature scheme',
  },
  'Kyber': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Lattice-based KEM — standardized as ML-KEM (NIST FIPS 203).',
  },
  'CRYSTALS-Kyber': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'CRYSTALS-Kyber — standardized as ML-KEM (NIST FIPS 203).',
  },
  'FrodoKEM': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Conservative lattice-based KEM — not NIST-selected but considered quantum-safe.',
  },
  'BIKE': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Code-based KEM (NIST round 4 alternate) — considered quantum-safe.',
  },
  'HQC': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Hamming Quasi-Cyclic KEM (NIST round 4) — considered quantum-safe.',
  },
  'XMSS': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'eXtended Merkle Signature Scheme (RFC 8391) — stateful hash-based signature, quantum-safe.',
  },
  'LMS': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Leighton-Micali Signature (RFC 8554) — stateful hash-based signature, quantum-safe.',
  },

  // PRNGs / CSPRNGs — Not directly quantum-vulnerable, but context-dependent
  'SecureRandom': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java CSPRNG utility — not an algorithm itself. Quantum safety depends on the underlying provider (SHA1PRNG, NativePRNG, DRBG). Review provider configuration.',
  },
  'DRBG': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'NIST SP 800-90A DRBG — symmetric-based, no direct quantum vulnerability. Ensure 256-bit seed/state for post-quantum margin.',
  },
  'HMAC-DRBG': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'HMAC-based DRBG — no direct quantum vulnerability. Verify underlying HMAC uses SHA-256+ for post-quantum security.',
  },
  'CTR-DRBG': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Counter-mode DRBG — no direct quantum vulnerability. Ensure AES-256 block cipher for post-quantum margin.',
  },
  'SHA1PRNG': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Sun SHA1PRNG — PRNG seeded from OS entropy, not the same as SHA-1 hashing. Not quantum-vulnerable but consider migrating to DRBG for modern compliance.',
  },
  'NativePRNG': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'OS-native PRNG (/dev/urandom) — no quantum vulnerability. Quality depends on OS entropy source.',
  },

  // Crypto API wrappers — not algorithms themselves, safety depends on usage
  'WebCrypto': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'W3C Web Cryptography API (crypto.subtle) — a browser API wrapper, not an algorithm. Quantum safety depends on which algorithms are used through it (e.g. RSA → vulnerable, AES-256 → safe). Audit actual algorithm parameters.',
  },
  'KeyPairGenerator': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java JCE KeyPairGenerator utility — not an algorithm itself. Quantum safety depends on the algorithm parameter (e.g. RSA → vulnerable, EC → vulnerable). Check getInstance() argument.',
  },
  'JCE-Signature-Registration': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'JCE Signature provider registration — indicates a custom/BouncyCastle provider. Quantum safety depends on the registered algorithm. Review provider source.',
  },
  'JCE-KeyPairGen-Registration': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'JCE KeyPairGenerator provider registration — indicates a custom/BouncyCastle provider. Quantum safety depends on the registered key generation algorithm.',
  },
  'JCE-Digest-Registration': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'JCE MessageDigest provider registration — indicates a custom/BouncyCastle digest provider. Most hash algorithms are not directly quantum-vulnerable at 256-bit+.',
  },
  'BouncyCastle-Provider': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'BouncyCastle JCE/JCA security provider — not an algorithm itself. Provides both quantum-safe (AES, SHA-256, ML-KEM, ML-DSA) and vulnerable (RSA, EC) implementations. Audit which algorithms are used through this provider.',
  },
  'PBKDF2': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Password-Based Key Derivation Function 2 (RFC 8018) — HMAC-based, not directly broken by quantum computers. Grover\'s gives quadratic speedup; use sufficient iteration count (≥600k) and derive 256-bit keys for post-quantum margin.',
  },
  'PBKDF2-HMAC-SHA256': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'PBKDF2 with HMAC-SHA256 — not directly broken by quantum computers. Use ≥600k iterations and 256-bit key output for post-quantum margin.',
  },
  'PBKDF2-HMAC-SHA512': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'PBKDF2 with HMAC-SHA512 — not directly broken by quantum computers.',
  },
  'KeyFactory': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java JCE KeyFactory utility — converts key specs/encodings, not an algorithm itself. Quantum safety depends on the key type (RSA/EC → vulnerable, AES → safe). Check getInstance() argument.',
  },
  'Digital-Signature': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Generic digital signature operation (Signature.getInstance) — not a specific algorithm. Quantum safety depends on the signature scheme (RSA/ECDSA → vulnerable, ML-DSA/SLH-DSA → safe). Audit the algorithm parameter.',
  },
  'SecretKeyFactory': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java JCE SecretKeyFactory utility — generates symmetric/KDF secret keys. Quantum safety depends on the algorithm (PBKDF2/AES → conditional, DES → insecure). Check getInstance() argument.',
  },

  // TLS protocols
  'TLSv1.0': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Deprecated protocol',
  },
  'TLSv1.1': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Deprecated protocol',
  },
  'TLSv1.2': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with PQC hybrid',
    notes: 'Acceptable but not quantum-safe',
  },
  'TLSv1.3': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with ML-KEM hybrid',
    notes: 'Best current standard but key exchange is not PQC yet',
  },
  'TLS': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TLS 1.3 with ML-KEM hybrid',
    notes: 'TLS protocol — current key exchange mechanisms are vulnerable to quantum attacks. Migrate to PQC hybrid.',
  },

  // Additional algorithms that may be extracted by the improved scanner
  'Diffie-Hellman': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'Classical Diffie-Hellman — vulnerable to Shor\'s algorithm. Migrate to ML-KEM.',
  },
  'DES': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    notes: 'DES is cryptographically broken regardless of quantum. Replace with AES-256.',
  },
  'DESede': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    notes: 'Triple DES (3DES) — weak key length, deprecated. Replace with AES-256.',
  },
  'CSPRNG': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Cryptographically Secure PRNG — quantum computers don\'t break randomness generation.',
  },
  'scrypt': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'scrypt KDF — not directly broken by quantum computers. Use sufficient cost parameters for post-quantum margin.',
  },
  'X.509': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'X.509 certificate format — quantum safety depends on the signature algorithm used (RSA → vulnerable, ML-DSA → safe).',
  },
  'HMAC': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Generic HMAC — quantum computers reduce effective key strength by half (Grover). Use ≥256-bit keys for post-quantum safety.',
  },
  'RC4': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    notes: 'RC4 is cryptographically broken. Replace immediately with AES-256.',
  },
  'Blowfish': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Blowfish has 64-bit block size (birthday attack risk). Replace with AES-256.',
  },
  'ChaCha20': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'ChaCha20 (256-bit key) is considered quantum-safe against Grover\'s attack.',
  },
  'ChaCha20-Poly1305': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'ChaCha20-Poly1305 AEAD — quantum-safe with 256-bit symmetric key.',
  },
  'EC': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber) / ML-DSA (Dilithium)',
    notes: 'Elliptic Curve cryptography is vulnerable to Shor\'s algorithm.',
  },
  'GCM': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'GCM mode with AES-256 is quantum-safe.',
  },
  'TSP': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'TSP with ML-DSA signatures',
    notes: 'Time Stamp Protocol (RFC 3161) relies on PKI signatures (RSA/ECDSA) — quantum-vulnerable.',
  },
  'CMS': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'CMS with ML-DSA/ML-KEM',
    notes: 'Cryptographic Message Syntax uses RSA/ECDSA signatures and RSA/ECDH key transport — quantum-vulnerable.',
  },
  'OCSP': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'OCSP with ML-DSA signed responses',
    notes: 'Online Certificate Status Protocol relies on PKI signatures — quantum-vulnerable.',
  },
  'CAST5': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256',
    notes: 'CAST5 has 64-bit block size and max 128-bit key. Deprecated — replace with AES-256.',
  },
  'ElGamal': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'ElGamal encryption is based on discrete logarithm problem — broken by Shor\'s algorithm.',
  },
  'MessageDigest': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java MessageDigest wrapper — quantum safety depends on the actual hash algorithm parameter. SHA-256+ is safe; MD5/SHA-1 are classically broken.',
  },
  'NONE': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    notes: 'NONE digest used in raw signature operations (e.g. NONEwithRSA). The signature scheme itself determines quantum safety.',
  },
  'NONEwithRSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
    notes: 'Raw RSA signature (no hash) — quantum-vulnerable via Shor\'s algorithm.',
  },
  'NONEwithECDSA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
    notes: 'Raw ECDSA signature (no hash) — quantum-vulnerable via Shor\'s algorithm.',
  },

  // ─── Additional Algorithms (resolving "unknown" classifications) ────────

  // Key Derivation Functions — not directly quantum-vulnerable (symmetric-based)
  'Argon2': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Argon2 memory-hard KDF — not directly broken by quantum computers. Grover\'s gives quadratic speedup on brute-force but memory-hardness mitigates. Use sufficient parameters (Argon2id, ≥64 MiB, ≥3 iterations).',
  },
  'Argon2i': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Argon2i (data-independent) KDF — not directly broken by quantum computers. Consider Argon2id for better side-channel resistance. Use ≥64 MiB memory, ≥3 iterations.',
  },
  'Argon2d': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Argon2d (data-dependent) KDF — not quantum-vulnerable but susceptible to side-channel attacks. Use Argon2id instead.',
  },
  'Argon2id': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Argon2id (hybrid) KDF — OWASP recommended password hashing. Not directly broken by quantum computers. Use ≥64 MiB memory, ≥3 iterations.',
  },
  'bcrypt': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'bcrypt password hashing — not directly broken by quantum computers. Grover\'s halves effective work factor; use cost ≥12 for post-quantum margin.',
  },

  // Symmetric ciphers
  'Twofish': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Twofish block cipher (128/192/256-bit keys). Quantum-safe with 256-bit key. Grover\'s halves effective security; verify key size ≥256 bits.',
  },
  'Rijndael': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Rijndael is the algorithm underlying AES. Quantum-safe with 256-bit key (Grover\'s halves to 128-bit effective).',
  },
  'Rijndael-256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Rijndael with 256-bit block size — quantum-safe with 256-bit key.',
  },
  'Serpent': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Serpent block cipher (AES finalist). Quantum-safe with 256-bit key.',
  },
  'Camellia': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Camellia block cipher (RFC 3713). Similar security profile to AES; quantum-safe with 256-bit key.',
  },
  'IDEA': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'AES-256',
    notes: 'IDEA has 128-bit key — Grover\'s reduces to 64-bit effective security. Replace with AES-256.',
  },

  // Key exchange / agreement
  'X25519': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'X25519 (Curve25519 ECDH) — elliptic curve key agreement, vulnerable to Shor\'s algorithm.',
  },
  'X448': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-KEM (Kyber)',
    notes: 'X448 (Curve448 ECDH) — elliptic curve key agreement, vulnerable to Shor\'s algorithm.',
  },
  'Ed448': {
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    recommendedPQC: 'ML-DSA (Dilithium)',
    notes: 'Ed448 (Edwards curve signature) — vulnerable to Shor\'s algorithm.',
  },
  'KeyAgreement': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java JCE KeyAgreement utility — not an algorithm itself. Quantum safety depends on the algorithm parameter (DH/ECDH → vulnerable, ML-KEM → safe). Check getInstance() argument.',
  },
  'KeyGenerator': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Java JCE KeyGenerator utility — generates symmetric keys. Quantum safety depends on the algorithm (AES-256 → safe, DES → insecure). Check getInstance() argument.',
  },

  // OpenSSL / crypto library wrappers
  'EVP-Encrypt': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'OpenSSL EVP encryption API wrapper — not an algorithm itself. Quantum safety depends on the cipher passed to EVP_EncryptInit_ex (AES-256 → safe, DES → insecure).',
  },
  'EVP-Decrypt': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'OpenSSL EVP decryption API wrapper — same considerations as EVP-Encrypt.',
  },
  'EVP-Sign': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'OpenSSL EVP signing API wrapper — quantum safety depends on the signature algorithm (RSA/EC → vulnerable).',
  },
  'EVP-Digest': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'OpenSSL EVP digest API wrapper — quantum safety depends on the hash algorithm (SHA-256+ → safe, MD5/SHA-1 → broken).',
  },

  // Generic / catch-all names from various CBOM generators
  'Hash': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Generic hash algorithm detected — quantum safety depends on the specific algorithm. SHA-256+ and SHA-3 are quantum-resistant; MD5 and SHA-1 are classically broken.',
  },
  'Digest': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Generic message digest — quantum safety depends on the specific hash algorithm. Review source for actual algorithm.',
  },
  'Cipher': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Generic cipher reference — quantum safety depends on the actual algorithm (AES-256 → safe, DES/RSA → not safe).',
  },
  'MAC': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Message Authentication Code — HMAC and CMAC with 256-bit keys are quantum-resistant.',
  },
  'KDF': {
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    notes: 'Generic Key Derivation Function — symmetric-based KDFs are not directly quantum-vulnerable. Review parameters.',
  },
  'HKDF': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'HMAC-based Key Derivation Function (RFC 5869) — symmetric-based, quantum-resistant.',
  },
  'HKDF-SHA256': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'HKDF with SHA-256 — quantum-resistant.',
  },
  'Poly1305': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'Poly1305 MAC — symmetric-based authenticator, quantum-resistant.',
  },
  'SipHash': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'SipHash PRF — keyed hash, quantum-resistant for authentication purposes.',
  },
  'BLAKE2': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'BLAKE2 hash function — quantum-resistant (≥128-bit post-quantum security).',
  },
  'BLAKE2b': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'BLAKE2b hash — quantum-resistant.',
  },
  'BLAKE2s': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'BLAKE2s hash — quantum-resistant.',
  },
  'BLAKE3': {
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    notes: 'BLAKE3 hash — quantum-resistant.',
  },
};

// ─── Risk Engine Functions ───────────────────────────────────────────────────

/**
 * Classify the quantum safety of an algorithm by name.
 */
export function classifyAlgorithm(algorithmName: string): AlgorithmProfile {
  const normalized = algorithmName.toUpperCase().trim();
  // Also create a version with dashes removed for fuzzy matching
  const noDashes = normalized.replace(/-/g, '');

  // Exact match
  if (ALGORITHM_DATABASE[algorithmName]) {
    return ALGORITHM_DATABASE[algorithmName];
  }

  // Case-insensitive match
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (key.toUpperCase() === normalized) {
      return profile;
    }
  }

  // Dash-insensitive match (e.g., "SHA256" matches "SHA-256", "AES128-GCM" matches "AES-128")
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (key.toUpperCase().replace(/-/g, '') === noDashes) {
      return profile;
    }
  }

  // Partial match (e.g., "RSA-OAEP" matches "RSA")
  for (const [key, profile] of Object.entries(ALGORITHM_DATABASE)) {
    if (normalized.includes(key.toUpperCase()) || key.toUpperCase().includes(normalized)) {
      return profile;
    }
  }

  return {
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    notes: 'Algorithm not found in classification database',
  };
}

/**
 * Enrich a crypto asset with PQC risk data.
 */
export function enrichAssetWithPQCData(asset: CryptoAsset): CryptoAsset {
  const profile = classifyAlgorithm(asset.name);

  // Build a pqcVerdict for definitively classified assets so the frontend always has verdict data
  let pqcVerdict = asset.pqcVerdict;
  if (!pqcVerdict && profile.quantumSafety !== QuantumSafetyStatus.UNKNOWN) {
    if (profile.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          `${asset.name} is classified as not quantum-safe.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(asset.description ? [`\u{1F50D} ${asset.description}`] : []),
        ],
        recommendation: profile.recommendedPQC
          ? `Replace with ${profile.recommendedPQC}.`
          : 'Migrate to a NIST-approved post-quantum algorithm.',
      };
    } else if (profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons: [
          `${asset.name} is classified as quantum-safe.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(asset.description ? [`\u{1F50D} ${asset.description}`] : []),
        ],
        recommendation: 'No migration needed.',
      };
    } else if (profile.quantumSafety === QuantumSafetyStatus.CONDITIONAL) {
      pqcVerdict = {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 40,
        reasons: [
          `${asset.name} quantum safety is conditional on configuration/parameters.`,
          ...(profile.notes ? [profile.notes] : []),
          ...(asset.description ? [`\u{1F50D} ${asset.description}`] : []),
        ],
        recommendation: profile.recommendedPQC
          ? `Consider ${profile.recommendedPQC} if current parameters are insufficient.`
          : 'Review parameters and configuration for quantum safety.',
      };
    }
  }

  // Respect quantumSafety if it was already promoted/demoted by the parameter
  // analyzer (i.e. not UNKNOWN and different from the DB's generic classification).
  const effectiveSafety =
    asset.quantumSafety !== QuantumSafetyStatus.UNKNOWN &&
    asset.quantumSafety !== QuantumSafetyStatus.CONDITIONAL &&
    asset.quantumSafety !== profile.quantumSafety
      ? asset.quantumSafety
      : profile.quantumSafety;

  return {
    ...asset,
    quantumSafety: effectiveSafety,
    recommendedPQC: profile.recommendedPQC,
    pqcVerdict,
    complianceStatus: effectiveSafety === QuantumSafetyStatus.QUANTUM_SAFE
      ? ComplianceStatus.COMPLIANT
      : effectiveSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE
        ? ComplianceStatus.NOT_COMPLIANT
        : effectiveSafety === QuantumSafetyStatus.CONDITIONAL
          ? ComplianceStatus.COMPLIANT   // Conditional assets are compliant but flagged for review
          : ComplianceStatus.UNKNOWN,
  };
}

/**
 * Safety-net sync: ensure quantumSafety is consistent with pqcVerdict.
 * Call this AFTER all analysis (parameter analyzer, cross-file enrichment)
 * to catch any ordering/overwrite issues.
 */
export function syncQuantumSafetyWithVerdict(assets: CryptoAsset[]): CryptoAsset[] {
  return assets.map(asset => {
    const v = asset.pqcVerdict;
    if (!v) return asset;

    let expected: QuantumSafetyStatus | null = null;
    if (v.verdict === PQCReadinessVerdict.PQC_READY && v.confidence >= 70) {
      expected = QuantumSafetyStatus.QUANTUM_SAFE;
    } else if (v.verdict === PQCReadinessVerdict.NOT_PQC_READY && v.confidence >= 50) {
      expected = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
    }

    if (expected && asset.quantumSafety !== expected) {
      return {
        ...asset,
        quantumSafety: expected,
        complianceStatus: expected === QuantumSafetyStatus.QUANTUM_SAFE
          ? ComplianceStatus.COMPLIANT
          : ComplianceStatus.NOT_COMPLIANT,
      };
    }
    return asset;
  });
}

/**
 * Calculate the Quantum Readiness Score for a set of crypto assets.
 * Score is 0-100 where 100 = all assets are quantum-safe.
 *
 * If assets have a pqcVerdict, that verdict is used for more precise scoring:
 *   PQC_READY     → 1.0  (not just the flat 0.75 for conditional)
 *   NOT_PQC_READY → 0.0
 *   REVIEW_NEEDED → 0.5
 */
export function calculateReadinessScore(assets: CryptoAsset[]): QuantumReadinessScore {
  const total = assets.length;
  if (total === 0) {
    return { score: 100, totalAssets: 0, quantumSafe: 0, notQuantumSafe: 0, conditional: 0, unknown: 0 };
  }

  const quantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE).length;
  const notQuantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE).length;
  const conditional = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.CONDITIONAL).length;
  const unknown = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.UNKNOWN).length;

  // Verdict-aware scoring
  let weightedSum = quantumSafe; // safe = 1.0 each
  // unknown = 0.5 each
  weightedSum += unknown * 0.5;

  // Conditional assets: use their pqcVerdict if available for precise scoring
  for (const asset of assets) {
    if (asset.quantumSafety === QuantumSafetyStatus.CONDITIONAL) {
      if (asset.pqcVerdict) {
        switch (asset.pqcVerdict.verdict) {
          case PQCReadinessVerdict.PQC_READY:
            weightedSum += 1.0;
            break;
          case PQCReadinessVerdict.NOT_PQC_READY:
            weightedSum += 0.0;
            break;
          case PQCReadinessVerdict.REVIEW_NEEDED:
            weightedSum += 0.5;
            break;
        }
      } else {
        weightedSum += 0.75; // legacy flat weight for unanalyzed conditional
      }
    }
  }

  const score = Math.round((weightedSum / total) * 100);

  return { score, totalAssets: total, quantumSafe, notQuantumSafe, conditional, unknown };
}

/**
 * Check compliance against NIST PQC policy.
 */
export function checkNISTPQCCompliance(assets: CryptoAsset[]): ComplianceSummary {
  const compliantAssets = assets.filter(a => a.complianceStatus === ComplianceStatus.COMPLIANT).length;
  const nonCompliantAssets = assets.filter(a => a.complianceStatus === ComplianceStatus.NOT_COMPLIANT).length;
  const unknownAssets = assets.filter(a =>
    a.complianceStatus === ComplianceStatus.UNKNOWN || !a.complianceStatus
  ).length;

  return {
    isCompliant: nonCompliantAssets === 0,
    policy: 'NIST Post-Quantum Cryptography',
    source: 'Basic Local Compliance Service',
    totalAssets: assets.length,
    compliantAssets,
    nonCompliantAssets,
    unknownAssets,
  };
}

/**
 * Get all known PQC algorithm names.
 */
export function getPQCAlgorithms(): string[] {
  return Object.entries(ALGORITHM_DATABASE)
    .filter(([_, profile]) => profile.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE)
    .map(([name]) => name);
}

export { ALGORITHM_DATABASE };
