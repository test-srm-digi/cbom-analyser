/**
 * Java Crypto Patterns
 *
 * JCE/JCA, BouncyCastle, SSL/TLS, X.509, and provider registration patterns.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const javaPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── JCE getInstance() with algorithm extraction from string arg ──────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /MessageDigest\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /Cipher\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /Signature\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
  { pattern: /KeyFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /KeyPairGenerator\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /KeyGenerator\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyGenerator', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /SecretKeyFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /KeyAgreement\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyAgreement', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
  { pattern: /Mac\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
  { pattern: /AlgorithmParameters\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'AlgorithmParameters', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, extractAlgorithm: true },
  // SecretKeySpec with algorithm arg
  { pattern: /new\s+SecretKeySpec\s*\([^,]+,\s*"([^"]+)"[^)]*\)/g, algorithm: 'SecretKeySpec', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.SECRET_KEY, extractAlgorithm: true },

  // ── JCE calls with variable arguments — capture variable name for resolution ──
  { pattern: /MessageDigest\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'MessageDigest', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, resolveVariable: true },
  { pattern: /Cipher\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, resolveVariable: true },
  { pattern: /Signature\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, resolveVariable: true },
  { pattern: /KeyFactory\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
  { pattern: /KeyPairGenerator\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
  { pattern: /SecretKeyFactory\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
  { pattern: /Mac\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, resolveVariable: true },

  // ── TLS / SSL (protocol asset type) ──
  { pattern: /SSLContext\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /SSLContext\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ── Certificates ──
  { pattern: /CertificateFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
  { pattern: /X509Certificate/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },
  { pattern: /X509TrustManager/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },

  // ── Misc JCE & BouncyCastle ──
  { pattern: /new\s+SecureRandom\s*\(/g, algorithm: 'SecureRandom', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+BouncyCastleProvider\s*\(/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /BouncyCastleProvider\.PROVIDER_NAME/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /Security\.(?:addProvider|insertProviderAt)\s*\(\s*new\s+BouncyCastleProvider/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },

  // ── JCE Provider registration patterns ──
  { pattern: /put\s*\(\s*"Signature\.([^"]+)"\s*,/g, algorithm: 'JCE-Signature-Registration', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
  { pattern: /put\s*\(\s*"KeyPairGenerator\.([^"]+)"\s*,/g, algorithm: 'JCE-KeyPairGen-Registration', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /put\s*\(\s*"MessageDigest\.([^"]+)"\s*,/g, algorithm: 'JCE-Digest-Registration', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  { pattern: /put\s*\(\s*"Cipher\.([^"]+)"\s*,/g, algorithm: 'JCE-Cipher-Registration', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /put\s*\(\s*"KeyAgreement\.([^"]+)"\s*,/g, algorithm: 'JCE-KeyAgreement-Registration', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
  { pattern: /put\s*\(\s*"Mac\.([^"]+)"\s*,/g, algorithm: 'JCE-Mac-Registration', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
];
