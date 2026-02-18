package com.quantumguard.demo;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

/**
 * Demo crypto service showcasing various cryptographic operations
 * that the CBOM scanner should detect.
 */
public class CryptoService {

  // ── Hashing ──────────────────────────────────────────────────────

  public byte[] hashWithSHA256(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return digest.digest(data);
  }

  public byte[] hashWithSHA1(byte[] data) throws NoSuchAlgorithmException {
    // WARNING: SHA-1 is deprecated, use SHA-256 or SHA-3 instead
    MessageDigest digest = MessageDigest.getInstance("SHA-1");
    return digest.digest(data);
  }

  public byte[] hashWithMD5(byte[] data) throws NoSuchAlgorithmException {
    // WARNING: MD5 is broken, never use for security purposes
    MessageDigest digest = MessageDigest.getInstance("MD5");
    return digest.digest(data);
  }

  // ── Symmetric Encryption (AES) ──────────────────────────────────

  public SecretKey generateAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    return keyGen.generateKey();
  }

  public byte[] encryptAES(byte[] plaintext, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(plaintext);
  }

  // ── Asymmetric Encryption (RSA) ─────────────────────────────────

  public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    return keyPairGen.generateKeyPair();
  }

  public byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(plaintext);
  }

  // ── Digital Signatures ──────────────────────────────────────────

  public byte[] signWithRSA(byte[] data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  public boolean verifyWithRSA(byte[] data, byte[] sig, PublicKey publicKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);
    signature.update(data);
    return signature.verify(sig);
  }

  public byte[] signWithECDSA(byte[] data, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  // ── Example: Encrypt-then-Sign workflow ─────────────────────────

  public String secureTransmit(String message) throws Exception {
    // 1. Generate session key
    SecretKey aesKey = generateAESKey();

    // 2. Encrypt the message
    byte[] ciphertext = encryptAES(message.getBytes(), aesKey);

    // 3. Generate RSA key pair for the session
    KeyPair rsaKeyPair = generateRSAKeyPair();

    // 4. Sign the ciphertext
    byte[] signature = signWithRSA(ciphertext, rsaKeyPair.getPrivate());

    // 5. Encrypt the AES key with RSA
    byte[] encryptedKey = encryptRSA(aesKey.getEncoded(), rsaKeyPair.getPublic());

    return Base64.getEncoder().encodeToString(ciphertext) + "."
         + Base64.getEncoder().encodeToString(signature) + "."
         + Base64.getEncoder().encodeToString(encryptedKey);
  }
}
