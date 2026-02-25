package com.quantumguard.demo;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

/**
 * Demo authentication module showcasing additional crypto patterns
 * for CBOM scanner detection — covers password hashing, token signing,
 * TLS setup, certificate pinning, key derivation with PBKDF2,
 * and related crypto materials (salt, IV, nonce).
 */
public class AuthenticationModule {

  private static final int PBKDF2_ITERATIONS = 600_000;
  private static final int SALT_LENGTH = 16;     // 128-bit salt
  private static final int KEY_LENGTH = 256;      // 256-bit derived key

  // ── Password Hashing with PBKDF2 (key-derivation + salt) ──────

  public byte[] hashPasswordSecure(char[] password) throws Exception {
    // related-crypto-material: Generate 128-bit random salt
    byte[] salt = new byte[SALT_LENGTH];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(salt);

    // algorithm: PBKDF2 key derivation (quantum-safe with sufficient iterations)
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH);
    SecretKey derivedKey = factory.generateSecret(spec);

    // Combine salt + derived key for storage
    byte[] result = new byte[salt.length + derivedKey.getEncoded().length];
    System.arraycopy(salt, 0, result, 0, salt.length);
    System.arraycopy(derivedKey.getEncoded(), 0, result, salt.length, derivedKey.getEncoded().length);
    return result;
  }

  public String legacyHashSHA256(String password) throws NoSuchAlgorithmException {
    // algorithm: SHA-256 hash (quantum-safe but NOT suitable for password storage alone)
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] hashedBytes = sha256.digest(password.getBytes());
    return bytesToHex(hashedBytes);
  }

  public String legacyHashMD5(String password) throws NoSuchAlgorithmException {
    // WARNING: MD5 is cryptographically broken — never use for passwords
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    byte[] hashedBytes = md5.digest(password.getBytes());
    return bytesToHex(hashedBytes);
  }

  // ── Token Signing (signature: ECDSA, RSA) ─────────────────────

  public byte[] signTokenECDSA(String payload, PrivateKey key) throws Exception {
    // WARNING: ECDSA is NOT quantum-safe — migrate to ML-DSA (Dilithium)
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(key);
    signer.update(payload.getBytes());
    return signer.sign();
  }

  public byte[] signTokenRSA(String payload, PrivateKey key) throws Exception {
    // WARNING: RSA signatures are NOT quantum-safe — migrate to ML-DSA
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(key);
    signer.update(payload.getBytes());
    return signer.sign();
  }

  public boolean verifyTokenRSA(String payload, byte[] sig, PublicKey key) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(key);
    verifier.update(payload.getBytes());
    return verifier.verify(sig);
  }

  // ── HMAC-based Token Authentication (mac) ─────────────────────

  public byte[] createHMACToken(byte[] data, SecretKey key) throws Exception {
    // algorithm: HMAC-SHA256 — quantum-safe MAC
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key);
    return mac.doFinal(data);
  }

  // ── Secure Channel Setup with AES-GCM (ae + related-crypto-material) ──

  public Cipher createSecureChannelCipher(SecretKey sessionKey) throws Exception {
    // AES-256-GCM — quantum-safe authenticated encryption
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    // related-crypto-material: 96-bit initialization vector
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmSpec);
    return cipher;
  }

  public Cipher createLegacyCBCCipher(SecretKey sessionKey) throws Exception {
    // WARNING: AES/CBC — no authentication, vulnerable to padding oracle
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
    return cipher;
  }

  // ── RSA Key Pair Generation (pke + private-key) ───────────────

  public KeyPair generateSessionKeyPairRSA2048() throws NoSuchAlgorithmException {
    // WARNING: RSA-2048 is NOT quantum-safe
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  public KeyPair generateSessionKeyPairRSA4096() throws NoSuchAlgorithmException {
    // WARNING: RSA-4096 — larger key but still NOT quantum-safe
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(4096);
    return generator.generateKeyPair();
  }

  // ── Secret Key Construction (secret-key) ──────────────────────

  public SecretKey deriveSessionKey(byte[] sharedSecret) {
    // secret-key: Constructing AES key from derived shared secret
    return new SecretKeySpec(sharedSecret, 0, 32, "AES");
  }

  // ── TLS/SSL Configuration (protocol) ──────────────────────────

  public SSLContext configureTLS13() throws Exception {
    // protocol: TLS 1.3 — symmetric ciphers are quantum-safe,
    // but ECDHE key exchange is vulnerable to Shor's algorithm
    SSLContext ctx = SSLContext.getInstance("TLSv1.3");
    ctx.init(null, null, new SecureRandom());
    return ctx;
  }

  public SSLContext configureTLS12WithClientAuth(
      KeyManagerFactory kmf, TrustManagerFactory tmf) throws Exception {
    // WARNING: TLS 1.2 — RSA/ECDHE key exchange is NOT quantum-safe
    SSLContext ctx = SSLContext.getInstance("TLSv1.2");
    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
    return ctx;
  }

  // ── Certificate Verification (certificate) ────────────────────

  public boolean verifyCertificateSignature(
      X509Certificate cert, PublicKey issuerKey) throws Exception {
    // certificate: X.509 RSA certificate signature verification
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(issuerKey);
    verifier.update(cert.getTBSCertificate());
    return verifier.verify(cert.getSignature());
  }

  public void validateCertificateChain(X509Certificate[] chain) throws Exception {
    // certificate: Full chain validation
    for (int i = 0; i < chain.length - 1; i++) {
      chain[i].verify(chain[i + 1].getPublicKey());
      chain[i].checkValidity();
    }
  }

  // ── Private Key Operations (private-key) ──────────────────────

  public PrivateKey loadPrivateKeyPKCS8(byte[] pkcs8Bytes) throws Exception {
    // private-key: Loading RSA private key from PKCS#8 DER encoding
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
    return kf.generatePrivate(spec);
  }

  // ── SecureRandom (CSPRNG) ─────────────────────────────────────

  public byte[] generateNonce(int length) {
    // related-crypto-material: nonce for replay protection
    SecureRandom sr = new SecureRandom();
    byte[] nonce = new byte[length];
    sr.nextBytes(nonce);
    return nonce;
  }

  // ── Utility ────────────────────────────────────────────────────

  private String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
