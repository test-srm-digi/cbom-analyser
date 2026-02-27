/**
 * C# / .NET Crypto Patterns
 *
 * System.Security.Cryptography (modern + legacy), SslStream,
 * X509Certificate2, BouncyCastle .NET, and common NuGet packages.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const csharpPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — Hash algorithms ──────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /SHA256\.Create\s*\(\s*\)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA384\.Create\s*\(\s*\)/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA512\.Create\s*\(\s*\)/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA1\.Create\s*\(\s*\)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /MD5\.Create\s*\(\s*\)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA3_256\.(?:Create|HashData)\s*\(/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA3_384\.(?:Create|HashData)\s*\(/g, algorithm: 'SHA3-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA3_512\.(?:Create|HashData)\s*\(/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // Static one-shot hash methods (.NET 5+)
  { pattern: /SHA256\.HashData\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA384\.HashData\s*\(/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA512\.HashData\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /SHA1\.HashData\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /MD5\.HashData\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // HashAlgorithm.Create with string name
  { pattern: /HashAlgorithm\.Create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
  // new SHA256Managed / SHA512Managed (legacy)
  { pattern: /new\s+SHA256Managed\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA512Managed\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+SHA1Managed\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /new\s+MD5CryptoServiceProvider\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — Symmetric ciphers ────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /Aes\.Create\s*\(\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /AesGcm\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /AesCcm\s*\(/g, algorithm: 'AES-CCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+AesCryptoServiceProvider\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+AesManaged\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /TripleDES\.Create\s*\(\s*\)/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+TripleDESCryptoServiceProvider\s*\(/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /DES\.Create\s*\(\s*\)/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+DESCryptoServiceProvider\s*\(/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /RC2\.Create\s*\(\s*\)/g, algorithm: 'RC2', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+RC2CryptoServiceProvider\s*\(/g, algorithm: 'RC2', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /ChaCha20Poly1305\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  // SymmetricAlgorithm.Create with string
  { pattern: /SymmetricAlgorithm\.Create\s*\(\s*"([^"]+)"/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  // CreateEncryptor / CreateDecryptor
  { pattern: /\.CreateEncryptor\s*\(/g, algorithm: 'Symmetric-Encrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /\.CreateDecryptor\s*\(/g, algorithm: 'Symmetric-Decrypt', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },

  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — Asymmetric / PKI ─────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /RSA\.Create\s*\(\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /RSA\.Create\s*\(\s*\d+\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+RSACryptoServiceProvider\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+RSACng\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /\.Encrypt\s*\(\s*[^,]+,\s*RSAEncryptionPadding\.(\w+)\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
  { pattern: /\.Decrypt\s*\(\s*[^,]+,\s*RSAEncryptionPadding\.(\w+)\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT, extractAlgorithm: true },
  { pattern: /\.SignData\s*\(/g, algorithm: 'RSA-Sign', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /\.VerifyData\s*\(/g, algorithm: 'RSA-Verify', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },
  { pattern: /\.SignHash\s*\(/g, algorithm: 'Digital-Sign', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, scanContext: true },
  { pattern: /\.VerifyHash\s*\(/g, algorithm: 'Digital-Verify', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY, scanContext: true },

  // ECDsa
  { pattern: /ECDsa\.Create\s*\(\s*\)/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ECDsa\.Create\s*\(\s*ECCurve\.(\w+)\s*\)/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
  { pattern: /new\s+ECDsaCng\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  // ECDiffieHellman
  { pattern: /ECDiffieHellman\.Create\s*\(\s*\)/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ECDiffieHellman\.Create\s*\(\s*ECCurve\.(\w+)\s*\)/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
  { pattern: /new\s+ECDiffieHellmanCng\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  // DSA
  { pattern: /DSA\.Create\s*\(/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+DSACryptoServiceProvider\s*\(/g, algorithm: 'DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — MAC ──────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /new\s+HMACSHA256\s*\(/g, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+HMACSHA384\s*\(/g, algorithm: 'HMAC-SHA384', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+HMACSHA512\s*\(/g, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+HMACSHA1\s*\(/g, algorithm: 'HMAC-SHA1', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /new\s+HMACMD5\s*\(/g, algorithm: 'HMAC-MD5', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  // Static one-shot (.NET 5+)
  { pattern: /HMACSHA256\.HashData\s*\(/g, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /HMACSHA512\.HashData\s*\(/g, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — Key Derivation ───────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /new\s+Rfc2898DeriveBytes\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /Rfc2898DeriveBytes\.Pbkdf2\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+HKDF\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /HKDF\.DeriveKey\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /HKDF\.Extract\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /HKDF\.Expand\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+PasswordDeriveBytes\s*\(/g, algorithm: 'PBKDF1', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── System.Security.Cryptography — Random ───────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /RandomNumberGenerator\.(?:Create|GetBytes|Fill|GetInt32|GetNonZeroBytes)\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+RNGCryptoServiceProvider\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── X.509 / Certificates ────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /new\s+X509Certificate2\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /X509Store\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /X509Chain\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /CertificateRequest\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },

  // ════════════════════════════════════════════════════════════════════════
  // ── TLS / SSL ───────────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /new\s+SslStream\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /\.AuthenticateAsServer\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /\.AuthenticateAsClient\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /SslProtocols\.Tls12/g, algorithm: 'TLS 1.2', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /SslProtocols\.Tls13/g, algorithm: 'TLS 1.3', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /SslProtocols\.Tls11/g, algorithm: 'TLS 1.1', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /SslProtocols\.Ssl3/g, algorithm: 'SSL 3.0', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // ════════════════════════════════════════════════════════════════════════
  // ── Data Protection API (DPAPI) ─────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /ProtectedData\.Protect\s*\(/g, algorithm: 'DPAPI', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /ProtectedData\.Unprotect\s*\(/g, algorithm: 'DPAPI', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT },

  // ════════════════════════════════════════════════════════════════════════
  // ── ASP.NET Core Data Protection ────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /\.AddDataProtection\s*\(\s*\)/g, algorithm: 'AES-256-CBC+HMAC', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /IDataProtector/g, algorithm: 'DataProtection', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /\.Protect\s*\(/g, algorithm: 'DataProtection', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },

  // ════════════════════════════════════════════════════════════════════════
  // ── BouncyCastle .NET ───────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /using\s+Org\.BouncyCastle\.Crypto/g, algorithm: 'BouncyCastle', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /new\s+RsaKeyPairGenerator\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+ECKeyPairGenerator\s*\(/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /new\s+AesEngine\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /new\s+GcmBlockCipher\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },

  // ════════════════════════════════════════════════════════════════════════
  // ── Namespace / using statements ────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /using\s+System\.Security\.Cryptography;/g, algorithm: 'System.Security.Cryptography', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /using\s+System\.Net\.Security;/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, scanContext: true },
];
