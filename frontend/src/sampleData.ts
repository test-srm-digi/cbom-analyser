/**
 * Sample CBOM data mimicking a Keycloak-like project scan.
 * Based on the IBM CBOMkit visualization example.
 */
import { CBOMDocument, QuantumSafetyStatus, ComplianceStatus } from './types';

export const SAMPLE_CBOM: CBOMDocument = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      { vendor: 'QuantumGuard', name: 'CBOM Hub', version: '1.0.0' },
      { vendor: 'CBOMkit', name: 'sonar-cryptography', version: '1.4.0' },
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
    // SHA-256 occurrences (most common)
    {
      id: 'asset-001',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'AbstractIdentityProvider.java', lineNumber: 118 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-002',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'KeycloakModelUtils.java', lineNumber: 150 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-003',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'MutualTLSUtils.java', lineNumber: 138 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-004',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'DockerKeyIdentifier.java', lineNumber: 37 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-005',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'Ed255192018Suite.java', lineNumber: 121 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-006',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'PkceUtils.java', lineNumber: 49 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-007',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'SHA256PairwiseSubMapper.java', lineNumber: 88 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-008',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'AbstractParEndpoint.java', lineNumber: 85 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-009',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'PKCEEnforcerExecutor.java', lineNumber: 230 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-010',
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'MtlsHoKTokenUtil.java', lineNumber: 114 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    // ED25519 (EdDSA signatures)
    {
      id: 'asset-011',
      name: 'Ed25519',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          cryptoFunctions: ['Sign' as any, 'Verify' as any],
        },
      },
      location: { fileName: 'Ed25519KeyPairProvider.java', lineNumber: 42 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    {
      id: 'asset-012',
      name: 'Ed25519',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'Ed25519SignatureVerifier.java', lineNumber: 67 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    {
      id: 'asset-013',
      name: 'Ed25519',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          cryptoFunctions: ['Sign' as any],
        },
      },
      location: { fileName: 'Ed255192018Suite.java', lineNumber: 55 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // RSA
    {
      id: 'asset-014',
      name: 'RSA-2048',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'pke' as any,
          cryptoFunctions: ['Keygen' as any, 'Encrypt' as any],
        },
      },
      location: { fileName: 'RSAKeyProvider.java', lineNumber: 78 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-KEM (Kyber-768)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    {
      id: 'asset-015',
      name: 'RSA-2048',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'pke' as any,
          cryptoFunctions: ['Sign' as any],
        },
      },
      location: { fileName: 'JWSBuilder.java', lineNumber: 156 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 2048,
      recommendedPQC: 'ML-KEM (Kyber-768)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // AES
    {
      id: 'asset-016',
      name: 'AES-128',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'block-cipher' as any,
          mode: 'GCM',
          cryptoFunctions: ['Encrypt' as any, 'Decrypt' as any],
        },
      },
      location: { fileName: 'AesKeyWrap.java', lineNumber: 44 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 128,
      recommendedPQC: 'AES-256',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    {
      id: 'asset-017',
      name: 'AES-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'block-cipher' as any,
          mode: 'GCM',
          cryptoFunctions: ['Encrypt' as any, 'Decrypt' as any],
        },
      },
      location: { fileName: 'ContentEncryptionProvider.java', lineNumber: 92 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-018',
      name: 'AES-128',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'block-cipher' as any,
          mode: 'CBC',
          cryptoFunctions: ['Encrypt' as any],
        },
      },
      location: { fileName: 'JWETokenDecoder.java', lineNumber: 203 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 128,
      recommendedPQC: 'AES-256',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // EC-SECP
    {
      id: 'asset-019',
      name: 'EC-SECP',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          curve: 'P-256',
          cryptoFunctions: ['Sign' as any, 'Verify' as any],
        },
      },
      location: { fileName: 'ECDSASignatureProvider.java', lineNumber: 34 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    {
      id: 'asset-020',
      name: 'EC-SECP',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          curve: 'P-384',
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'ECKeyProvider.java', lineNumber: 89 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // HMAC
    {
      id: 'asset-021',
      name: 'HMACSHA256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'mac' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'HmacKeyProvider.java', lineNumber: 56 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    {
      id: 'asset-022',
      name: 'HMACSHA384',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'mac' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'HmacSignatureProvider.java', lineNumber: 78 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    // KEY:AES
    {
      id: 'asset-023',
      name: 'KEY:AES',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'keygen' as any,
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'SecretKeyProvider.java', lineNumber: 44 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    // KEY:HMAC
    {
      id: 'asset-024',
      name: 'KEY:HMAC',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'keygen' as any,
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'HmacKeyResolver.java', lineNumber: 22 },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    },
    // KEY:RSA
    {
      id: 'asset-025',
      name: 'KEY:RSA',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'keygen' as any,
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'RSAKeyStore.java', lineNumber: 167 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-KEM (Kyber)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // RAW keys
    {
      id: 'asset-026',
      name: 'RAW',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'other' as any,
          cryptoFunctions: ['Other' as any],
        },
      },
      location: { fileName: 'MacSecretGenerator.java', lineNumber: 31 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      complianceStatus: ComplianceStatus.UNKNOWN,
    },
    {
      id: 'asset-027',
      name: 'KEY:RAW',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'other' as any,
          cryptoFunctions: ['Keygen' as any],
        },
      },
      location: { fileName: 'RawKeyProvider.java', lineNumber: 19 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      complianceStatus: ComplianceStatus.UNKNOWN,
    },
    // SHA-1 (deprecated)
    {
      id: 'asset-028',
      name: 'SHA-1',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: { fileName: 'LegacyHashProvider.java', lineNumber: 45 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'SHA-3-256 or SHA-256',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // EDDSA
    {
      id: 'asset-029',
      name: 'EDDSA',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          cryptoFunctions: ['Sign' as any],
        },
      },
      location: { fileName: 'EdDSASignatureProvider.java', lineNumber: 52 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // DSA
    {
      id: 'asset-030',
      name: 'DSA',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: 'signature' as any,
          cryptoFunctions: ['Sign' as any, 'Verify' as any],
        },
      },
      location: { fileName: 'DSAKeyGenerator.java', lineNumber: 83 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // SSL (deprecated)
    {
      id: 'asset-031',
      name: 'SSL',
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
    },
    // TLS
    {
      id: 'asset-032',
      name: 'TLSv1.3',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'protocol',
        protocolProperties: {
          type: 'tls',
          version: 'TLSv1.3',
          cipherSuites: [
            { name: 'TLS_AES_256_GCM_SHA384', algorithms: ['AES-256', 'GCM', 'SHA-384'] },
          ],
        },
      },
      location: { fileName: 'TLSClientConfigWrapper.java', lineNumber: 112 },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'TLS 1.3 with ML-KEM hybrid',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    },
    // More SHA-256 occurrences
    ...Array.from({ length: 10 }, (_, i) => ({
      id: `asset-${33 + i}`,
      name: 'SHA-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm' as const,
        algorithmProperties: {
          primitive: 'hash' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: {
        fileName: [
          'OIDCLoginProtocol.java', 'TokenVerifier.java', 'S256CodeChallenge.java',
          'AuthenticationManager.java', 'CookieHelper.java', 'OIDCWellKnownProvider.java',
          'SignatureProvider.java', 'JWSInput.java', 'CodeVerifierParser.java',
          'CryptoIntegrationTest.java',
        ][i],
        lineNumber: [67, 89, 23, 312, 45, 156, 78, 201, 34, 167][i],
      },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    })),
    // More RSA occurrences
    ...Array.from({ length: 4 }, (_, i) => ({
      id: `asset-${43 + i}`,
      name: 'RSA-204800' as string,
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm' as const,
        algorithmProperties: {
          primitive: 'pke' as any,
          cryptoFunctions: [['Encrypt', 'Sign', 'Keygen', 'Verify'][i] as any],
        },
      },
      location: {
        fileName: ['JWSRSAProvider.java', 'RSATokenVerifier.java', 'RSAKeyGenerator.java', 'RSACertificateUtils.java'][i],
        lineNumber: [134, 67, 45, 89][i],
      },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      keyLength: 4096,
      recommendedPQC: 'ML-KEM (Kyber-1024)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    })),
    // More AES entries
    ...Array.from({ length: 4 }, (_, i) => ({
      id: `asset-${47 + i}`,
      name: 'AES-256',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm' as const,
        algorithmProperties: {
          primitive: 'block-cipher' as any,
          mode: ['GCM', 'CBC', 'GCM', 'CTR'][i],
          cryptoFunctions: ['Encrypt' as any],
        },
      },
      location: {
        fileName: ['JWEAesGcmProvider.java', 'DefaultKeyManager.java', 'VaultEncryptor.java', 'SessionTokenEncoder.java'][i],
        lineNumber: [45, 78, 112, 56][i],
      },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      keyLength: 256,
      complianceStatus: ComplianceStatus.COMPLIANT,
    })),
    // EC additional
    ...Array.from({ length: 3 }, (_, i) => ({
      id: `asset-${51 + i}`,
      name: 'EC-SECP',
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm' as const,
        algorithmProperties: {
          primitive: 'signature' as any,
          curve: ['P-256', 'P-384', 'P-521'][i],
          cryptoFunctions: ['Sign' as any],
        },
      },
      location: {
        fileName: ['ECDSAProvider.java', 'EC384Provider.java', 'EC521Provider.java'][i],
        lineNumber: [34, 56, 78][i],
      },
      quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
      recommendedPQC: 'ML-DSA (Dilithium)',
      complianceStatus: ComplianceStatus.NOT_COMPLIANT,
    })),
    // HMAC additional
    ...Array.from({ length: 4 }, (_, i) => ({
      id: `asset-${54 + i}`,
      name: ['HMACSHA256', 'HMACSHA512', 'HMACSHA256', 'HMACSHA384'][i],
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: 'algorithm' as const,
        algorithmProperties: {
          primitive: 'mac' as any,
          cryptoFunctions: ['Hash Function' as any],
        },
      },
      location: {
        fileName: ['HmacTokenSigner.java', 'HmacSHA512Provider.java', 'MacSigner.java', 'HMAC384Verifier.java'][i],
        lineNumber: [23, 45, 67, 89][i],
      },
      quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
      complianceStatus: ComplianceStatus.COMPLIANT,
    })),
  ],
  dependencies: [
    { ref: 'org.bouncycastle:bcprov-jdk18on', dependsOn: ['RSA', 'ECC', 'AES', 'SHA-256'] },
    { ref: 'javax.crypto', dependsOn: ['AES', 'HMAC'] },
    { ref: 'java.security', dependsOn: ['SHA-256', 'RSA', 'DSA'] },
  ],
};
