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

  // ════════════════════════════════════════════════════════════════════════
  // ── BouncyCastle deep engine detection (sonar-cryptography inspired) ──
  // ════════════════════════════════════════════════════════════════════════

  // BC low-level crypto engines
  { pattern: /new\s+AESEngine\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+AESFastEngine\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+RSAEngine\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+RSABlindedEngine\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+DESedeEngine\s*\(/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+DESEngine\s*\(/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+BlowfishEngine\s*\(/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+TwofishEngine\s*\(/g, algorithm: 'Twofish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+CamelliaEngine\s*\(/g, algorithm: 'Camellia', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+SerpentEngine\s*\(/g, algorithm: 'Serpent', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+CAST5Engine\s*\(/g, algorithm: 'CAST5', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+IDEA(?:Engine)?\s*\(/g, algorithm: 'IDEA', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+RC4Engine\s*\(/g, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+ChaCha7539Engine\s*\(/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+ChaChaEngine\s*\(/g, algorithm: 'ChaCha', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+Salsa20Engine\s*\(/g, algorithm: 'Salsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+SM4Engine\s*\(/g, algorithm: 'SM4', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+ARIAEngine\s*\(/g, algorithm: 'ARIA', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // BC AEAD wrappers
  { pattern: /new\s+GCMBlockCipher\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+CCMBlockCipher\s*\(/g, algorithm: 'AES-CCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+EAXBlockCipher\s*\(/g, algorithm: 'EAX', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+OCBBlockCipher\s*\(/g, algorithm: 'OCB', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+ChaCha20Poly1305\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },

  // BC block cipher modes
  { pattern: /new\s+CBCBlockCipher\s*\(/g, algorithm: 'CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+CTRBlockCipher\s*\(/g, algorithm: 'CTR', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+CFBBlockCipher\s*\(/g, algorithm: 'CFB', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+OFBBlockCipher\s*\(/g, algorithm: 'OFB', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // BC digests
  { pattern: /new\s+SHA256Digest\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA384Digest\s*\(/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA512Digest\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA1Digest\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA3Digest\s*\(/g, algorithm: 'SHA-3', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+MD5Digest\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+RIPEMD160Digest\s*\(/g, algorithm: 'RIPEMD-160', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+Blake2bDigest\s*\(/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+Blake2sDigest\s*\(/g, algorithm: 'BLAKE2s', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SM3Digest\s*\(/g, algorithm: 'SM3', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+WhirlpoolDigest\s*\(/g, algorithm: 'Whirlpool', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // BC MAC
  { pattern: /new\s+HMac\s*\(/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+CMac\s*\(/g, algorithm: 'CMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+GMac\s*\(/g, algorithm: 'GMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+Poly1305\s*\(/g, algorithm: 'Poly1305', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+SipHash\s*\(/g, algorithm: 'SipHash', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // BC signers
  { pattern: /new\s+RSADigestSigner\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+PSSSigner\s*\(/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+ECDSASigner\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+Ed25519Signer\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+Ed448Signer\s*\(/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+SM2Signer\s*\(/g, algorithm: 'SM2', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+DSADigestSigner\s*\(/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // BC key generators / key pair generators
  { pattern: /new\s+RSAKeyPairGenerator\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+ECKeyPairGenerator\s*\(/g, algorithm: 'EC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+Ed25519KeyPairGenerator\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+Ed448KeyPairGenerator\s*\(/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+X25519KeyPairGenerator\s*\(/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+X448KeyPairGenerator\s*\(/g, algorithm: 'X448', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEYGEN },

  // BC KDF
  { pattern: /new\s+PKCS5S2ParametersGenerator\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+HKDFBytesGenerator\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+SCrypt\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+Argon2BytesGenerator\s*\(/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── BouncyCastle PQC algorithms (NIST PQC winners + candidates) ──────
  // ════════════════════════════════════════════════════════════════════════

  // ML-KEM (Kyber)
  { pattern: /new\s+KyberKeyPairGenerator\s*\(/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+KyberKeyGenerationParameters\s*\(/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+KyberKEMGenerator\s*\(/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /new\s+KyberKEMExtractor\s*\(/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /KyberParameterSpec\.(?:kyber512|kyber768|kyber1024|ml_kem_512|ml_kem_768|ml_kem_1024)/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /MLKEMParameterSpec/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // ML-DSA (Dilithium)
  { pattern: /new\s+DilithiumKeyPairGenerator\s*\(/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+DilithiumSigner\s*\(/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /DilithiumParameterSpec\.(?:dilithium2|dilithium3|dilithium5|ml_dsa_44|ml_dsa_65|ml_dsa_87)/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /MLDSAParameterSpec/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // SLH-DSA (SPHINCS+)
  { pattern: /new\s+SPHINCSPlusKeyPairGenerator\s*\(/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+SPHINCSPlusSigner\s*\(/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /SPHINCSPlusParameterSpec/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /SLHDSAParameterSpec/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // Falcon
  { pattern: /new\s+FalconKeyPairGenerator\s*\(/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+FalconSigner\s*\(/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /FalconParameterSpec/g, algorithm: 'Falcon', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // XMSS / LMS (hash-based stateful signatures)
  { pattern: /new\s+XMSSKeyPairGenerator\s*\(/g, algorithm: 'XMSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+XMSSMTKeyPairGenerator\s*\(/g, algorithm: 'XMSS-MT', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+XMSSSigner\s*\(/g, algorithm: 'XMSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+LMSKeyPairGenerator\s*\(/g, algorithm: 'LMS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+LMSSigner\s*\(/g, algorithm: 'LMS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /new\s+HSSKeyPairGenerator\s*\(/g, algorithm: 'HSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },

  // FrodoKEM / BIKE / HQC / Classic McEliece (KEM candidates)
  { pattern: /new\s+FrodoKEMKeyPairGenerator\s*\(/g, algorithm: 'FrodoKEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+BIKEKeyPairGenerator\s*\(/g, algorithm: 'BIKE', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+HQCKeyPairGenerator\s*\(/g, algorithm: 'HQC', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+CMCEKeyPairGenerator\s*\(/g, algorithm: 'Classic-McEliece', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+NTRUKeyPairGenerator\s*\(/g, algorithm: 'NTRU', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── Key size extraction (complements sonar-cryptography enrichment) ────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /KeyPairGenerator\.getInstance\s*\([^)]+\)\s*;\s*\w+\.initialize\s*\(\s*(\d+)/g, algorithm: 'KeyPairGen-KeySize', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /\.initialize\s*\(\s*(\d{3,5})\s*[,)]/g, algorithm: 'KeySize', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },

  // ── Additional JCE APIs (JSSE / KeyStore) ──
  { pattern: /KeyStore\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyStore', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.RELATED_MATERIAL, extractAlgorithm: true },
  { pattern: /TrustManagerFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'TrustManagerFactory', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
  { pattern: /KeyManagerFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyManagerFactory', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },

  // ── javax.crypto.spec parameters (mode/padding/IV) ──
  { pattern: /new\s+GCMParameterSpec\s*\(/g, algorithm: 'GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+IvParameterSpec\s*\(/g, algorithm: 'IV-Parameter', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+PBEKeySpec\s*\(/g, algorithm: 'PBE', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+DHParameterSpec\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /new\s+ECGenParameterSpec\s*\(\s*"([^"]+)"/g, algorithm: 'EC-Curve', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
];
