/**
 * Go Crypto Patterns
 *
 * Go standard library crypto/* packages, golang.org/x/crypto,
 * and common third-party cryptographic libraries.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../../types';
import { CryptoPattern } from '../scannerTypes';

export const goPatterns: CryptoPattern[] = [
  // ════════════════════════════════════════════════════════════════════════
  // ── Go stdlib: crypto/* imports ─────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // Hash imports (detect usage via import path)
  { pattern: /"crypto\/sha256"/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /"crypto\/sha512"/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /"crypto\/sha1"/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /"crypto\/md5"/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // Hash function calls
  { pattern: /sha256\.New\s*\(\s*\)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha256\.Sum256\s*\(/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha512\.New\s*\(\s*\)/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha512\.Sum512\s*\(/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha512\.New384\s*\(\s*\)/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha1\.New\s*\(\s*\)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha1\.Sum\s*\(/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /md5\.New\s*\(\s*\)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /md5\.Sum\s*\(/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  // crypto.SHA256 etc. (used as hash identifier enum)
  { pattern: /crypto\.SHA256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.SHA384/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.SHA512/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.SHA1/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.MD5/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.SHA3_256/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /crypto\.SHA3_512/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // ── Symmetric ciphers ───────────────────────────────────────────────
  { pattern: /"crypto\/aes"/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"crypto\/des"/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /aes\.NewCipher\s*\(/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /des\.NewCipher\s*\(/g, algorithm: 'DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /des\.NewTripleDESCipher\s*\(/g, algorithm: '3DES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /cipher\.NewGCM\s*\(/g, algorithm: 'AES-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /cipher\.NewCBCEncrypter\s*\(/g, algorithm: 'AES-CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /cipher\.NewCBCDecrypter\s*\(/g, algorithm: 'AES-CBC', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /cipher\.NewCFBEncrypter\s*\(/g, algorithm: 'AES-CFB', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /cipher\.NewCFBDecrypter\s*\(/g, algorithm: 'AES-CFB', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /cipher\.NewCTR\s*\(/g, algorithm: 'AES-CTR', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /cipher\.NewOFB\s*\(/g, algorithm: 'AES-OFB', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /\.Seal\s*\(/g, algorithm: 'AEAD-Seal', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /\.Open\s*\(/g, algorithm: 'AEAD-Open', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT, scanContext: true },
  { pattern: /"crypto\/cipher"/g, algorithm: 'Block-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
  { pattern: /"crypto\/rc4"/g, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /rc4\.NewCipher\s*\(/g, algorithm: 'RC4', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // ── Asymmetric: RSA ─────────────────────────────────────────────────
  { pattern: /"crypto\/rsa"/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /rsa\.GenerateKey\s*\(/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /rsa\.EncryptPKCS1v15\s*\(/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /rsa\.DecryptPKCS1v15\s*\(/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /rsa\.EncryptOAEP\s*\(/g, algorithm: 'RSA-OAEP', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /rsa\.DecryptOAEP\s*\(/g, algorithm: 'RSA-OAEP', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /rsa\.SignPKCS1v15\s*\(/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /rsa\.VerifyPKCS1v15\s*\(/g, algorithm: 'RSA-PKCS1v15', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /rsa\.SignPSS\s*\(/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /rsa\.VerifyPSS\s*\(/g, algorithm: 'RSA-PSS', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },

  // ── Asymmetric: ECDSA ───────────────────────────────────────────────
  { pattern: /"crypto\/ecdsa"/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ecdsa\.GenerateKey\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ecdsa\.Sign\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ecdsa\.Verify\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },
  { pattern: /ecdsa\.SignASN1\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ecdsa\.VerifyASN1\s*\(/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },

  // ── Asymmetric: ECDH ────────────────────────────────────────────────
  { pattern: /"crypto\/ecdh"/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ecdh\.P256\s*\(\s*\)/g, algorithm: 'ECDH-P256', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ecdh\.P384\s*\(\s*\)/g, algorithm: 'ECDH-P384', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ecdh\.P521\s*\(\s*\)/g, algorithm: 'ECDH-P521', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /ecdh\.X25519\s*\(\s*\)/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // ── Asymmetric: Ed25519 ─────────────────────────────────────────────
  { pattern: /"crypto\/ed25519"/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ed25519\.GenerateKey\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /ed25519\.Sign\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /ed25519\.Verify\s*\(/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.VERIFY },

  // ── Elliptic curves ─────────────────────────────────────────────────
  { pattern: /"crypto\/elliptic"/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /elliptic\.P256\s*\(\s*\)/g, algorithm: 'P-256', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /elliptic\.P384\s*\(\s*\)/g, algorithm: 'P-384', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /elliptic\.P521\s*\(\s*\)/g, algorithm: 'P-521', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.OTHER },

  // ── HMAC ────────────────────────────────────────────────────────────
  { pattern: /"crypto\/hmac"/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /hmac\.New\s*\(/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, scanContext: true },
  { pattern: /hmac\.Equal\s*\(/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

  // ── TLS ─────────────────────────────────────────────────────────────
  { pattern: /"crypto\/tls"/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.Config\s*\{/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.Dial\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.Listen\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.NewListener\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.LoadX509KeyPair\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /MinVersion:\s*tls\.VersionTLS12/g, algorithm: 'TLS 1.2', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /MinVersion:\s*tls\.VersionTLS13/g, algorithm: 'TLS 1.3', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /MaxVersion:\s*tls\.VersionTLS10/g, algorithm: 'TLS 1.0', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /MaxVersion:\s*tls\.VersionTLS11/g, algorithm: 'TLS 1.1', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  // TLS cipher suites
  { pattern: /tls\.TLS_AES_128_GCM_SHA256/g, algorithm: 'TLS-AES-128-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.TLS_AES_256_GCM_SHA384/g, algorithm: 'TLS-AES-256-GCM', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.TLS_CHACHA20_POLY1305_SHA256/g, algorithm: 'TLS-ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.TLS_ECDHE_RSA_WITH_AES_\d+_GCM_SHA\d+/g, algorithm: 'TLS-ECDHE-RSA-AES-GCM', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.TLS_ECDHE_ECDSA_WITH_AES_\d+_GCM_SHA\d+/g, algorithm: 'TLS-ECDHE-ECDSA-AES-GCM', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, assetType: AssetType.PROTOCOL },

  // ── X.509 ───────────────────────────────────────────────────────────
  { pattern: /"crypto\/x509"/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.ParseCertificate\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.CreateCertificate\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },
  { pattern: /x509\.ParsePKCS8PrivateKey\s*\(/g, algorithm: 'PKCS8', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.MarshalPKCS8PrivateKey\s*\(/g, algorithm: 'PKCS8', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.ParsePKIXPublicKey\s*\(/g, algorithm: 'PKIX', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.NewCertPool\s*\(\s*\)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
  { pattern: /x509\.CertificateRequest/g, algorithm: 'X.509-CSR', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ── Random ──────────────────────────────────────────────────────────
  { pattern: /"crypto\/rand"/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /rand\.Read\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /rand\.Int\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /rand\.Prime\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },

  // ── Subtle (constant-time) ──────────────────────────────────────────
  { pattern: /"crypto\/subtle"/g, algorithm: 'Constant-Time', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /subtle\.ConstantTimeCompare\s*\(/g, algorithm: 'Constant-Time', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

  // ════════════════════════════════════════════════════════════════════════
  // ── golang.org/x/crypto ─────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════

  // ChaCha20-Poly1305
  { pattern: /"golang\.org\/x\/crypto\/chacha20poly1305"/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /chacha20poly1305\.New\s*\(/g, algorithm: 'ChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /chacha20poly1305\.NewX\s*\(/g, algorithm: 'XChaCha20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },

  // ChaCha20 stream cipher
  { pattern: /"golang\.org\/x\/crypto\/chacha20"/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /chacha20\.NewUnauthenticatedCipher\s*\(/g, algorithm: 'ChaCha20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // Curve25519
  { pattern: /"golang\.org\/x\/crypto\/curve25519"/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /curve25519\.ScalarMult\s*\(/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /curve25519\.ScalarBaseMult\s*\(/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /curve25519\.X25519\s*\(/g, algorithm: 'X25519', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },

  // Argon2
  { pattern: /"golang\.org\/x\/crypto\/argon2"/g, algorithm: 'Argon2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /argon2\.IDKey\s*\(/g, algorithm: 'Argon2id', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /argon2\.Key\s*\(/g, algorithm: 'Argon2i', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // bcrypt
  { pattern: /"golang\.org\/x\/crypto\/bcrypt"/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /bcrypt\.GenerateFromPassword\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /bcrypt\.CompareHashAndPassword\s*\(/g, algorithm: 'bcrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // scrypt
  { pattern: /"golang\.org\/x\/crypto\/scrypt"/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /scrypt\.Key\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // NaCl
  { pattern: /"golang\.org\/x\/crypto\/nacl\/secretbox"/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /secretbox\.Seal\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /secretbox\.Open\s*\(/g, algorithm: 'XSalsa20-Poly1305', primitive: CryptoPrimitive.AE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /"golang\.org\/x\/crypto\/nacl\/box"/g, algorithm: 'NaCl-Box', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /box\.Seal\s*\(/g, algorithm: 'NaCl-Box', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /box\.Open\s*\(/g, algorithm: 'NaCl-Box', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.DECRYPT },
  { pattern: /box\.GenerateKey\s*\(/g, algorithm: 'NaCl-Box', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /"golang\.org\/x\/crypto\/nacl\/sign"/g, algorithm: 'Ed25519', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // HKDF
  { pattern: /"golang\.org\/x\/crypto\/hkdf"/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /hkdf\.New\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /hkdf\.Extract\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /hkdf\.Expand\s*\(/g, algorithm: 'HKDF', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // PBKDF2
  { pattern: /"golang\.org\/x\/crypto\/pbkdf2"/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
  { pattern: /pbkdf2\.Key\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },

  // SHA-3
  { pattern: /"golang\.org\/x\/crypto\/sha3"/g, algorithm: 'SHA-3', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.New256\s*\(\s*\)/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.New384\s*\(\s*\)/g, algorithm: 'SHA3-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.New512\s*\(\s*\)/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.Sum256\s*\(/g, algorithm: 'SHA3-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.Sum512\s*\(/g, algorithm: 'SHA3-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.ShakeSum256\s*\(/g, algorithm: 'SHAKE256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /sha3\.NewShake256\s*\(\s*\)/g, algorithm: 'SHAKE256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // BLAKE2
  { pattern: /"golang\.org\/x\/crypto\/blake2b"/g, algorithm: 'BLAKE2b', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /blake2b\.New256\s*\(/g, algorithm: 'BLAKE2b-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /blake2b\.New512\s*\(/g, algorithm: 'BLAKE2b-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /"golang\.org\/x\/crypto\/blake2s"/g, algorithm: 'BLAKE2s', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
  { pattern: /blake2s\.New256\s*\(/g, algorithm: 'BLAKE2s-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },

  // Salsa20
  { pattern: /"golang\.org\/x\/crypto\/salsa20"/g, algorithm: 'Salsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /salsa20\.XORKeyStream\s*\(/g, algorithm: 'Salsa20', primitive: CryptoPrimitive.STREAM_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },

  // SSH
  { pattern: /"golang\.org\/x\/crypto\/ssh"/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /ssh\.Dial\s*\(/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /ssh\.NewServerConn\s*\(/g, algorithm: 'SSH', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // Ed448
  { pattern: /"golang\.org\/x\/crypto\/ed448"/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // OCSP
  { pattern: /"golang\.org\/x\/crypto\/ocsp"/g, algorithm: 'OCSP', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ════════════════════════════════════════════════════════════════════════
  // ── PEM / encoding ──────────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /"encoding\/pem"/g, algorithm: 'PEM', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
  { pattern: /pem\.Decode\s*\(/g, algorithm: 'PEM', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /pem\.Encode\s*\(/g, algorithm: 'PEM', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

  // ════════════════════════════════════════════════════════════════════════
  // ── Missing x/crypto packages ───────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /"golang\.org\/x\/crypto\/twofish"/g, algorithm: 'Twofish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/blowfish"/g, algorithm: 'Blowfish', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/cast5"/g, algorithm: 'CAST5', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/tea"/g, algorithm: 'TEA', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/xtea"/g, algorithm: 'XTEA', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/xts"/g, algorithm: 'XTS', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
  { pattern: /"golang\.org\/x\/crypto\/poly1305"/g, algorithm: 'Poly1305', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
  { pattern: /"golang\.org\/x\/crypto\/openpgp"/g, algorithm: 'OpenPGP', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /"golang\.org\/x\/crypto\/acme"/g, algorithm: 'ACME', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

  // Missing ecdh
  { pattern: /ecdh\.GenerateKey\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEYGEN },
  // Missing P-224 curve
  { pattern: /elliptic\.P224\s*\(/g, algorithm: 'P-224', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },

  // ════════════════════════════════════════════════════════════════════════
  // ── PQC: Cloudflare CIRCL ───────────────────────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /"github\.com\/cloudflare\/circl"/g, algorithm: 'CIRCL', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /"github\.com\/cloudflare\/circl\/kem\/kyber"/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /"github\.com\/cloudflare\/circl\/kem\/mlkem"/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /"github\.com\/cloudflare\/circl\/sign\/dilithium"/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /"github\.com\/cloudflare\/circl\/sign\/mldsa"/g, algorithm: 'ML-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /"github\.com\/cloudflare\/circl\/sign\/ed448"/g, algorithm: 'Ed448', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
  { pattern: /"github\.com\/cloudflare\/circl\/kem\/frodo"/g, algorithm: 'FrodoKEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /"github\.com\/cloudflare\/circl\/hpke"/g, algorithm: 'HPKE', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /"github\.com\/cloudflare\/circl\/pke\/kyber"/g, algorithm: 'ML-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /"github\.com\/cloudflare\/circl\/sign\/sphincs"/g, algorithm: 'SLH-DSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // ── Go PQC in go.mod / import path detection ──
  { pattern: /"github\.com\/open-quantum-safe\/liboqs-go"/g, algorithm: 'liboqs', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
  { pattern: /oqs\.KeyEncapsulation/g, algorithm: 'PQC-KEM', primitive: CryptoPrimitive.KEY_ENCAPSULATION, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
  { pattern: /oqs\.Signature/g, algorithm: 'PQC-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },

  // ════════════════════════════════════════════════════════════════════════
  // ── Additional TLS cipher suites / config ───────────────────────────────
  // ════════════════════════════════════════════════════════════════════════
  { pattern: /tls\.CipherSuiteName\s*\(/g, algorithm: 'TLS-CipherSuite', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  { pattern: /tls\.X509KeyPair\s*\(/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

  // ── Key size via RSA key generation ──
  { pattern: /rsa\.GenerateKey\s*\([^,]+,\s*(\d{3,5})\s*\)/g, algorithm: 'RSA-KeySize', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
];
