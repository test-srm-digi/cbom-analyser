package com.quantumguard.demo;

import java.security.*;
import javax.crypto.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Demo authentication module with additional crypto patterns
 * for CBOM scanner detection.
 */
public class AuthenticationModule {

  // ── Password Hashing ────────────────────────────────────────────

  public String hashPassword(String password) throws NoSuchAlgorithmException {
    // First pass: SHA-256 hash
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] hashedBytes = sha256.digest(password.getBytes());
    return bytesToHex(hashedBytes);
  }

  public String legacyHashPassword(String password) throws NoSuchAlgorithmException {
    // WARNING: MD5 should not be used for password hashing
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    byte[] hashedBytes = md5.digest(password.getBytes());
    return bytesToHex(hashedBytes);
  }

  // ── Token Signing ──────────────────────────────────────────────

  public byte[] generateSignedToken(String payload, PrivateKey key) throws Exception {
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(key);
    signer.update(payload.getBytes());
    return signer.sign();
  }

  // ── Secure Channel Setup ────────────────────────────────────────

  public Cipher createChannelCipher(SecretKey sessionKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
    return cipher;
  }

  public KeyPair generateSessionKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(4096);
    return generator.generateKeyPair();
  }

  // ── Certificate Verification ────────────────────────────────────

  public boolean verifyCertificateSignature(
      X509Certificate cert, PublicKey issuerKey) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(issuerKey);
    verifier.update(cert.getTBSCertificate());
    return verifier.verify(cert.getSignature());
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
