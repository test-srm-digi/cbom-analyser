/**
 * Sample CBOM data mimicking a Keycloak-like project scan.
 * Demonstrates all CycloneDX 1.6 features including pqcVerdict,
 * detectionSource, thirdPartyLibraries, and extended asset types.
 */
import {
  CBOMDocument,
  QuantumSafetyStatus,
  ComplianceStatus,
  CryptoPrimitive,
  CryptoFunction,
  PQCReadinessVerdict,
} from './types';

export const SAMPLE_CBOM: CBOMDocument = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      { vendor: 'QuantumGuard', name: 'CBOM Hub', version: '2.0.0' },
      { vendor: 'IBM', name: 'sonar-cryptography', version: '1.4.0' },
    ],
    component: {
      name: 'keycloak/keycloak',
      version: 'main',
      type: 'application',
      group: 'github.com',
    },
  },
  components: [],
  cryptoAssets: [
    // ─── SHA-256 (quantum-safe hash) ───────────────────────────────────
    {
      id: 'asset-001',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'AbstractIdentityProvider.java', lineNumber: 118 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-002',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'KeycloakModelUtils.java', lineNumber: 150 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-003',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'PkceUtils.java', lineNumber: 49 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-004',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'SHA256PairwiseSubMapper.java', lineNumber: 88 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-005',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'TokenVerifier.java', lineNumber: 89 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-006',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'MutualTLSUtils.java', lineNumber: 138 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-007',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'OIDCLoginProtocol.java', lineNumber: 67 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-008',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'S256CodeChallenge.java', lineNumber: 23 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'regex',
    },

    // ─── SHA-384 ───────────────────────────────────────────────────────
    {
      id: 'asset-009',
      name: 'SHA-384',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'OIDCWellKnownProvider.java', lineNumber: 156 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── SHA-1 (deprecated, not quantum-safe) ─────────────────────────
    {
      id: 'asset-010',
      name: 'SHA-1',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.HASH,
          cryptoFunctions: [CryptoFunction.HASH_FUNCTION],
        },
      },
      location: { fileName: 'LegacyHashProvider.java', lineNumber: 45 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'SHA-3-256 or SHA-256',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── RSA-2048 (not PQC-ready) ─────────────────────────────────────
    {
      id: 'asset-011',
      name: 'RSA-2048',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.PKE,
          cryptoFunctions: [CryptoFunction.KEYGEN, CryptoFunction.ENCRYPT],
        },
      },
      location: { fileName: 'RSAKeyProvider.java', lineNumber: 78 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-KEM (Kyber-768)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          'RSA-2048 is vulnerable to Shor\'s algorithm on quantum computers',
          'Key size insufficient for post-quantum security',
        ],
        parameters: { keySize: 2048, algorithm: 'RSA', vulnerable: true },
        recommendation: 'Migrate to ML-KEM (Kyber-768) for key encapsulation or ML-DSA (Dilithium) for signatures',
      },
    },
    {
      id: 'asset-012',
      name: 'RSA-2048',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.PKE,
          cryptoFunctions: [CryptoFunction.SIGN],
        },
      },
      location: { fileName: 'JWSBuilder.java', lineNumber: 156 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-KEM (Kyber-768)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── RSA-4096 (not PQC-ready) ─────────────────────────────────────
    {
      id: 'asset-013',
      name: 'RSA-4096',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.PKE,
          cryptoFunctions: [CryptoFunction.ENCRYPT, CryptoFunction.SIGN],
        },
      },
      location: { fileName: 'RSACertificateUtils.java', lineNumber: 89 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 4096,
      recommendedPQC: 'ML-KEM (Kyber-1024)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          'RSA-4096 is vulnerable to Shor\'s algorithm regardless of key size',
          'Larger key only increases classical security, not quantum resistance',
        ],
        parameters: { keySize: 4096, algorithm: 'RSA', vulnerable: true },
        recommendation: 'Migrate to ML-KEM (Kyber-1024) for equivalent security level',
      },
    },

    // ─── Ed25519 (not PQC-ready) ──────────────────────────────────────
    {
      id: 'asset-014',
      name: 'Ed25519',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          cryptoFunctions: [CryptoFunction.SIGN, CryptoFunction.VERIFY],
        },
      },
      location: { fileName: 'Ed25519KeyPairProvider.java', lineNumber: 42 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          'Ed25519 relies on elliptic curve discrete logarithm problem',
          'Vulnerable to quantum attack via Shor\'s algorithm',
        ],
        parameters: { curve: 'Curve25519', algorithm: 'EdDSA' },
        recommendation: 'Replace with ML-DSA-65 (Dilithium) for digital signatures',
      },
    },
    {
      id: 'asset-015',
      name: 'Ed25519',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          cryptoFunctions: [CryptoFunction.KEYGEN],
        },
      },
      location: { fileName: 'Ed25519SignatureVerifier.java', lineNumber: 67 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── EC-P256 (ECDSA, not PQC-ready) ──────────────────────────────
    {
      id: 'asset-016',
      name: 'EC-P256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          curve: 'P-256',
          cryptoFunctions: [CryptoFunction.SIGN, CryptoFunction.VERIFY],
        },
      },
      location: { fileName: 'ECDSASignatureProvider.java', lineNumber: 34 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          'ECDSA with P-256 curve is vulnerable to Shor\'s algorithm',
          'All elliptic curve cryptography is quantum-vulnerable',
        ],
        parameters: { curve: 'P-256', algorithm: 'ECDSA' },
        recommendation: 'Migrate to ML-DSA-44 (Dilithium) for equivalent security',
      },
    },
    {
      id: 'asset-017',
      name: 'EC-P384',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          curve: 'P-384',
          cryptoFunctions: [CryptoFunction.KEYGEN],
        },
      },
      location: { fileName: 'ECKeyProvider.java', lineNumber: 89 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── ECDH (key agreement, not PQC-ready) ──────────────────────────
    {
      id: 'asset-018',
      name: 'ECDH-P256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.KEY_AGREEMENT,
          curve: 'P-256',
          cryptoFunctions: [CryptoFunction.KEY_EXCHANGE],
        },
      },
      location: { fileName: 'ECDHKeyAgreement.java', lineNumber: 56 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-KEM (Kyber-768)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 95,
        reasons: [
          'ECDH key agreement relies on elliptic curve discrete logarithm',
          'Quantum computers can solve ECDLP efficiently via Shor\'s algorithm',
        ],
        parameters: { curve: 'P-256', algorithm: 'ECDH' },
        recommendation: 'Replace with ML-KEM-768 (Kyber) for key encapsulation',
      },
    },

    // ─── AES-256-GCM (quantum-safe symmetric) ────────────────────────
    {
      id: 'asset-019',
      name: 'AES-256-GCM',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.AE,
          mode: 'GCM',
          cryptoFunctions: [CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT],
        },
      },
      location: { fileName: 'ContentEncryptionProvider.java', lineNumber: 92 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 95,
        reasons: [
          'AES-256 provides 128-bit security against Grover\'s algorithm',
          'Sufficient key length for post-quantum symmetric encryption',
        ],
        parameters: { keySize: 256, mode: 'GCM', algorithm: 'AES' },
        recommendation: 'No action needed -- AES-256 is quantum-safe',
      },
    },
    {
      id: 'asset-020',
      name: 'AES-256-GCM',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.AE,
          mode: 'GCM',
          cryptoFunctions: [CryptoFunction.ENCRYPT],
        },
      },
      location: { fileName: 'VaultEncryptor.java', lineNumber: 112 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── AES-128-CBC (conditional -- needs upgrade to 256) ───────────
    {
      id: 'asset-021',
      name: 'AES-128-CBC',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.BLOCK_CIPHER,
          mode: 'CBC',
          cryptoFunctions: [CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT],
        },
      },
      location: { fileName: 'JWETokenDecoder.java', lineNumber: 203 },
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      keyLength: 128,
      recommendedPQC: 'AES-256-GCM',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.NOT_PQC_READY,
        confidence: 90,
        reasons: [
          'AES-128 provides only 64-bit security against Grover\'s algorithm',
          'CBC mode lacks authenticated encryption guarantees',
        ],
        parameters: { keySize: 128, mode: 'CBC', algorithm: 'AES' },
        recommendation: 'Upgrade to AES-256-GCM for post-quantum symmetric security',
      },
    },

    // ─── HMAC (quantum-safe MAC) ──────────────────────────────────────
    {
      id: 'asset-022',
      name: 'HMACSHA256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.MAC,
          cryptoFunctions: [CryptoFunction.TAG],
        },
      },
      location: { fileName: 'HmacKeyProvider.java', lineNumber: 56 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-023',
      name: 'HMACSHA384',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.MAC,
          cryptoFunctions: [CryptoFunction.TAG],
        },
      },
      location: { fileName: 'HmacSignatureProvider.java', lineNumber: 78 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-024',
      name: 'HMACSHA512',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.MAC,
          cryptoFunctions: [CryptoFunction.TAG],
        },
      },
      location: { fileName: 'HmacSHA512Provider.java', lineNumber: 45 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'regex',
    },

    // ─── PBKDF2 (conditional, review key derivation) ─────────────────
    {
      id: 'asset-025',
      name: 'PBKDF2',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.KEY_DERIVATION,
          parameterSetIdentifier: 'PBKDF2WithHmacSHA256',
          cryptoFunctions: [CryptoFunction.KEYGEN],
        },
      },
      location: { fileName: 'Pbkdf2PasswordHashProvider.java', lineNumber: 72 },
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 85,
        reasons: [
          'PBKDF2 with HMAC-SHA256 is symmetric-based and quantum-resistant',
          'Ensure iteration count is >= 600,000 for NIST SP 800-132 compliance',
        ],
        parameters: { iterations: 600000, hashFunction: 'HMAC-SHA256' },
        recommendation: 'Maintain high iteration count; consider Argon2id for new deployments',
      },
    },

    // ─── DSA (not quantum-safe, deprecated) ──────────────────────────
    {
      id: 'asset-026',
      name: 'DSA',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          cryptoFunctions: [CryptoFunction.SIGN, CryptoFunction.VERIFY],
        },
      },
      location: { fileName: 'DSAKeyGenerator.java', lineNumber: 83 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'regex',
    },

    // ─── SecureRandom ─────────────────────────────────────────────────
    {
      id: 'asset-027',
      name: 'SecureRandom',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: CryptoPrimitive.OTHER,
          parameterSetIdentifier: 'NativePRNG',
          cryptoFunctions: [CryptoFunction.OTHER],
        },
      },
      location: { fileName: 'KeycloakModelUtils.java', lineNumber: 42 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 90,
        reasons: [
          'NativePRNG sources entropy from OS random device',
          'Quantum computers do not weaken properly-seeded CSPRNGs',
        ],
        parameters: { provider: 'NativePRNG', entropySource: '/dev/urandom' },
        recommendation: 'No action needed -- ensure adequate entropy seeding',
      },
    },

    // ─── TLS 1.3 (protocol, conditional) ─────────────────────────────
    {
      id: 'asset-028',
      name: 'TLSv1.3',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: 'TLSv1.3',
          cipherSuites: [
            { name: 'TLS_AES_256_GCM_SHA384', algorithms: ['AES-256-GCM', 'SHA-384'] },
            { name: 'TLS_CHACHA20_POLY1305_SHA256', algorithms: ['ChaCha20-Poly1305', 'SHA-256'] },
          ],
        },
      },
      location: { fileName: 'TLSClientConfigWrapper.java', lineNumber: 112 },
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      recommendedPQC: 'TLS 1.3 with ML-KEM hybrid key exchange',
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
      pqcVerdict: {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 80,
        reasons: [
          'TLS 1.3 symmetric ciphers are quantum-safe',
          'Key exchange (ECDHE) is vulnerable to quantum attack',
          'Hybrid PQC key exchange (ML-KEM + X25519) available but not yet configured',
        ],
        parameters: { version: 'TLSv1.3', keyExchange: 'ECDHE', cipherStrength: 'strong' },
        recommendation: 'Enable hybrid PQC key exchange (e.g., X25519+ML-KEM-768) when supported',
      },
    },

    // ─── TLS 1.2 (protocol, not quantum-safe) ────────────────────────
    {
      id: 'asset-029',
      name: 'TLSv1.2',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: 'TLSv1.2',
          cipherSuites: [
            { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', algorithms: ['ECDHE', 'RSA', 'AES-256-GCM', 'SHA-384'] },
          ],
        },
      },
      location: { fileName: 'DefaultHttpClientFactory.java', lineNumber: 78 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'Upgrade to TLS 1.3 with PQC KEM',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'network',
    },

    // ─── SSL (deprecated protocol) ───────────────────────────────────
    {
      id: 'asset-030',
      name: 'SSLv3',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'ssl',
          version: 'SSLv3',
        },
      },
      location: { fileName: 'SSLContextProvider.java', lineNumber: 29 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'TLS 1.3 with PQC KEM',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'regex',
    },

    // ─── X.509 Certificates ──────────────────────────────────────────
    {
      id: 'asset-031',
      name: 'X.509 RSA Certificate',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'certificate',
        algorithmProperties: {
          primitive: CryptoPrimitive.PKE,
          parameterSetIdentifier: 'SHA256withRSA',
          cryptoFunctions: [CryptoFunction.SIGN, CryptoFunction.VERIFY],
        },
      },
      location: { fileName: 'CertificateUtils.java', lineNumber: 145 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-DSA certificate',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'dependency',
    },
    {
      id: 'asset-032',
      name: 'X.509 ECDSA Certificate',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'certificate',
        algorithmProperties: {
          primitive: CryptoPrimitive.SIGNATURE,
          parameterSetIdentifier: 'SHA256withECDSA',
          curve: 'P-256',
          cryptoFunctions: [CryptoFunction.SIGN, CryptoFunction.VERIFY],
        },
      },
      location: { fileName: 'ECDSACertificateProvider.java', lineNumber: 67 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA certificate',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'dependency',
    },

    // ─── Related Crypto Material ─────────────────────────────────────
    {
      id: 'asset-033',
      name: 'PBKDF2 Salt',
      type: 'crypto-asset',
      description: '128-bit random salt for PBKDF2 password hashing',
      cryptoProperties: {
        assetType: 'related-crypto-material',
        algorithmProperties: {
          primitive: CryptoPrimitive.OTHER,
          parameterSetIdentifier: 'salt',
          cryptoFunctions: [CryptoFunction.OTHER],
        },
      },
      location: { fileName: 'Pbkdf2PasswordHashProvider.java', lineNumber: 85 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 128,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-034',
      name: 'AES-GCM Initialization Vector',
      type: 'crypto-asset',
      description: '96-bit initialization vector for AES-GCM encryption',
      cryptoProperties: {
        assetType: 'related-crypto-material',
        algorithmProperties: {
          primitive: CryptoPrimitive.OTHER,
          parameterSetIdentifier: 'initialization-vector',
          cryptoFunctions: [CryptoFunction.OTHER],
        },
      },
      location: { fileName: 'ContentEncryptionProvider.java', lineNumber: 68 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 96,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
    {
      id: 'asset-035',
      name: 'ECDH Shared Secret',
      type: 'crypto-asset',
      description: '256-bit shared secret derived from ECDH key agreement',
      cryptoProperties: {
        assetType: 'related-crypto-material',
        algorithmProperties: {
          primitive: CryptoPrimitive.KEY_AGREEMENT,
          parameterSetIdentifier: 'shared-secret',
          cryptoFunctions: [CryptoFunction.KEY_EXCHANGE],
        },
      },
      location: { fileName: 'ECDHKeyAgreement.java', lineNumber: 92 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'sonar',
    },

    // ─── Private Key ─────────────────────────────────────────────────
    {
      id: 'asset-036',
      name: 'RSA-2048 Private Key',
      type: 'crypto-asset',
      description: 'RSA-2048 private key for JWT signing',
      cryptoProperties: {
        assetType: 'private-key',
        algorithmProperties: {
          primitive: CryptoPrimitive.PKE,
          parameterSetIdentifier: 'RSA-2048',
          cryptoFunctions: [CryptoFunction.SIGN],
        },
      },
      location: { fileName: 'RSAKeyStore.java', lineNumber: 167 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-DSA (Dilithium) private key',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
      detectionSource: 'dependency',
    },

    // ─── Secret Key ──────────────────────────────────────────────────
    {
      id: 'asset-037',
      name: 'HMAC Signing Key',
      type: 'crypto-asset',
      description: 'HMAC-SHA256 secret key for token signing',
      cryptoProperties: {
        assetType: 'secret-key',
        algorithmProperties: {
          primitive: CryptoPrimitive.MAC,
          parameterSetIdentifier: 'HMAC-SHA256',
          cryptoFunctions: [CryptoFunction.TAG],
        },
      },
      location: { fileName: 'HmacKeyProvider.java', lineNumber: 34 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.COMPLIANT,
      detectionSource: 'sonar',
    },
  ],

  // ─── Dependency Graph with provides ────────────────────────────────
  dependencies: [
    {
      ref: 'org.bouncycastle:bcprov-jdk18on:1.78',
      dependsOn: ['asset-011', 'asset-013', 'asset-016', 'asset-018', 'asset-019'],
      provides: ['RSA', 'ECDSA', 'ECDH', 'AES-GCM', 'SHA-256', 'Ed25519'],
    },
    {
      ref: 'org.bouncycastle:bcpkix-jdk18on:1.78',
      dependsOn: ['asset-031', 'asset-032', 'asset-036'],
      provides: ['X.509', 'PKCS#8', 'CMS'],
    },
    {
      ref: 'com.nimbusds:nimbus-jose-jwt:9.37',
      dependsOn: ['asset-012', 'asset-020', 'asset-022', 'asset-037'],
      provides: ['JWS', 'JWE', 'JWT', 'HMAC'],
    },
    {
      ref: 'javax.crypto:javax.crypto-api',
      dependsOn: ['asset-019', 'asset-021', 'asset-022', 'asset-024'],
      provides: ['AES', 'HMAC', 'SecretKeyFactory'],
    },
    {
      ref: 'java.security:java.security-api',
      dependsOn: ['asset-001', 'asset-009', 'asset-010', 'asset-026', 'asset-027'],
      provides: ['MessageDigest', 'SecureRandom', 'KeyPairGenerator', 'Signature'],
    },
  ],

  // ─── Third-Party Crypto Libraries ──────────────────────────────────
  thirdPartyLibraries: [
    {
      name: 'Bouncy Castle Provider',
      groupId: 'org.bouncycastle',
      artifactId: 'bcprov-jdk18on',
      version: '1.78',
      packageManager: 'maven',
      cryptoAlgorithms: ['RSA', 'ECDSA', 'ECDH', 'AES', 'SHA-256', 'SHA-384', 'Ed25519', 'ChaCha20'],
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      isDirectDependency: true,
      depth: 0,
      dependencyPath: ['org.bouncycastle:bcprov-jdk18on:1.78'],
      manifestFile: 'pom.xml',
    },
    {
      name: 'Bouncy Castle PKIX',
      groupId: 'org.bouncycastle',
      artifactId: 'bcpkix-jdk18on',
      version: '1.78',
      packageManager: 'maven',
      cryptoAlgorithms: ['X.509', 'PKCS#8', 'CMS', 'OCSP'],
      quantumSafety: QuantumSafetyStatus.CONDITIONAL,
      isDirectDependency: true,
      depth: 0,
      dependencyPath: ['org.bouncycastle:bcpkix-jdk18on:1.78'],
      manifestFile: 'pom.xml',
    },
    {
      name: 'Nimbus JOSE+JWT',
      groupId: 'com.nimbusds',
      artifactId: 'nimbus-jose-jwt',
      version: '9.37',
      packageManager: 'maven',
      cryptoAlgorithms: ['RSA', 'ECDSA', 'HMAC-SHA256', 'AES-GCM', 'Ed25519'],
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      isDirectDependency: true,
      depth: 0,
      dependencyPath: ['com.nimbusds:nimbus-jose-jwt:9.37'],
      manifestFile: 'pom.xml',
    },
    {
      name: 'jBCrypt',
      groupId: 'org.mindrot',
      artifactId: 'jbcrypt',
      version: '0.4',
      packageManager: 'maven',
      cryptoAlgorithms: ['bcrypt', 'Blowfish'],
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      isDirectDependency: false,
      depth: 1,
      dependencyPath: ['org.keycloak:keycloak-server-spi', 'org.mindrot:jbcrypt:0.4'],
      manifestFile: 'pom.xml',
    },
  ],
};
