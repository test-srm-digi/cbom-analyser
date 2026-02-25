package com.quantumguard.demo;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.*;
import java.security.cert.*;
import java.io.*;
import java.util.Base64;

/**
 * Demo crypto service showcasing ALL cryptographic operations
 * that the CBOM scanner should detect — covers every CycloneDX 1.6
 * asset type: algorithm, protocol, certificate, related-crypto-material,
 * private-key, secret-key.
 */
public class CryptoService {

  // ── Hashing (algorithm: hash) ──────────────────────────────────

  public byte[] hashWithSHA256(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return digest.digest(data);
  }

  public byte[] hashWithSHA384(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-384");
    return digest.digest(data);
  }

  public byte[] hashWithSHA512(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    return digest.digest(data);
  }

  public byte[] hashWithSHA3(byte[] data) throws NoSuchAlgorithmException {
    // SHA-3 family — quantum-safe hash
    MessageDigest digest = MessageDigest.getInstance("SHA3-256");
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

  // ── Symmetric Encryption — AES (algorithm: block-cipher/ae) ────

  public SecretKey generateAES256Key() throws NoSuchAlgorithmException {
    // secret-key: AES-256 key generation
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    return keyGen.generateKey();
  }

  public byte[] encryptAES256GCM(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
    // AES-256-GCM — quantum-safe authenticated encryption
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // related-crypto-material: IV
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
    return cipher.doFinal(plaintext);
  }

  public byte[] encryptAES128CBC(byte[] plaintext, SecretKey key) throws Exception {
    // WARNING: AES-128-CBC — only 64-bit quantum security, upgrade to AES-256-GCM
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(plaintext);
  }

  public SecretKey createAESKeyFromBytes(byte[] rawKey) {
    // secret-key: constructing AES key from raw bytes
    return new SecretKeySpec(rawKey, "AES");
  }

  // ── HMAC (algorithm: mac) ──────────────────────────────────────

  public byte[] computeHMACSHA256(byte[] data, SecretKey key) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key);
    return mac.doFinal(data);
  }

  // ── Asymmetric Keys — RSA (algorithm: pke) ─────────────────────

  public KeyPair generateRSA2048KeyPair() throws NoSuchAlgorithmException {
    // WARNING: RSA-2048 is NOT quantum-safe — migrate to ML-KEM
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    return keyPairGen.generateKeyPair();
  }

  public KeyPair generateRSA4096KeyPair() throws NoSuchAlgorithmException {
    // WARNING: RSA-4096 is NOT quantum-safe — larger key != quantum-resistant
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(4096);
    return keyPairGen.generateKeyPair();
  }

  public byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(plaintext);
  }

  // ── Private Key Serialization (private-key asset type) ─────────

  public byte[] serializePrivateKey(PrivateKey privateKey) throws Exception {
    // private-key: Exporting RSA private key in PKCS#8 format
    return privateKey.getEncoded(); // PKCS#8 DER-encoded
  }

  public PrivateKey loadPrivateKey(byte[] pkcs8Bytes) throws Exception {
    // private-key: Loading RSA private key from PKCS#8
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
    return keyFactory.generatePrivate(keySpec);
  }

  // ── Digital Signatures (algorithm: signature) ──────────────────

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
    // WARNING: ECDSA is NOT quantum-safe — migrate to ML-DSA
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
  }

  // ── Key Derivation — PBKDF2 (algorithm: key-derivation) ───────

  public SecretKey deriveKeyPBKDF2(char[] password, byte[] salt, int iterations) throws Exception {
    // related-crypto-material: salt (should be >= 128-bit random)
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), "AES");
  }

  // ── Random Number Generation (algorithm: other/CSPRNG) ─────────

  public byte[] generateSecureRandomBytes(int length) {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return bytes;
  }

  public byte[] generateSalt() {
    // related-crypto-material: 128-bit salt for key derivation
    return generateSecureRandomBytes(16);
  }

  public byte[] generateGCMIV() {
    // related-crypto-material: 96-bit initialization vector for AES-GCM
    return generateSecureRandomBytes(12);
  }

  public byte[] generateNonce(int bytes) {
    // related-crypto-material: nonce for replay protection
    return generateSecureRandomBytes(bytes);
  }

  // ── TLS/SSL Protocol Configuration (protocol asset type) ──────

  public SSLContext createTLS13Context() throws Exception {
    // protocol: TLS 1.3 — symmetric ciphers quantum-safe, but ECDHE key exchange is not
    SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
    sslContext.init(null, null, new SecureRandom());
    return sslContext;
  }

  public SSLContext createTLS12Context(KeyManager[] km, TrustManager[] tm) throws Exception {
    // WARNING: TLS 1.2 key exchange is NOT quantum-safe
    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
    sslContext.init(km, tm, new SecureRandom());
    return sslContext;
  }

  // ── X.509 Certificate Operations (certificate asset type) ─────

  public boolean verifyCertificateChain(X509Certificate cert, PublicKey issuerKey) throws Exception {
    // certificate: X.509 RSA certificate verification
    cert.verify(issuerKey);
    return true;
  }

  public X509Certificate loadCertificateFromPEM(InputStream pemStream) throws Exception {
    // certificate: Loading X.509 from PEM
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(pemStream);
  }

  // ── Full Workflow: Encrypt-then-Sign ─────────────────────────────

  public String secureTransmit(String message) throws Exception {
    // 1. Generate 256-bit AES session key (secret-key)
    SecretKey aesKey = generateAES256Key();

    // 2. Generate 96-bit IV (related-crypto-material)
    byte[] iv = generateGCMIV();

    // 3. Encrypt the message with AES-256-GCM
    byte[] ciphertext = encryptAES256GCM(message.getBytes(), aesKey, iv);

    // 4. Generate RSA-2048 key pair for transport
    KeyPair rsaKeyPair = generateRSA2048KeyPair();

    // 5. Sign the ciphertext with RSA
    byte[] signature = signWithRSA(ciphertext, rsaKeyPair.getPrivate());

    // 6. Encrypt the AES key with RSA (key wrapping)
    byte[] encryptedKey = encryptRSA(aesKey.getEncoded(), rsaKeyPair.getPublic());

    // 7. Compute HMAC over the bundle
    byte[] hmac = computeHMACSHA256(ciphertext, aesKey);

    return Base64.getEncoder().encodeToString(ciphertext) + "."
         + Base64.getEncoder().encodeToString(signature) + "."
         + Base64.getEncoder().encodeToString(encryptedKey) + "."
         + Base64.getEncoder().encodeToString(iv) + "."
         + Base64.getEncoder().encodeToString(hmac);
  }
}
