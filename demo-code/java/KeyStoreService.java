package com.example.keystore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.asn1.x500.X500Name;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Date;

/**
 * KeyStore & PBE Service
 *
 * Demonstrates PKCS12 / JKS keystore operations and Password-Based Encryption (PBE).
 * These are typically classified as CONDITIONAL because the keystore format itself
 * doesn't determine quantum safety — the algorithms used within do.
 *
 * Expected CBOM result:
 *   - PKCS12 → NOT_QUANTUM_SAFE (stores RSA keys in this example)
 *   - JKS → NOT_QUANTUM_SAFE (stores RSA keys)
 *   - PBE → NOT_QUANTUM_SAFE (PBEWithSHA256And256BitAES uses SHA-256+AES, but key exchange is classical)
 *   - RSA → NOT_QUANTUM_SAFE
 *   - AES → QUANTUM_SAFE (256-bit)
 */
public class KeyStoreService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ════════════════════════════════════════════════════════════════
    // ── PKCS12 KeyStore operations ───────────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Create a PKCS12 keystore with an RSA key pair and self-signed cert.
     */
    public void createPKCS12KeyStore(String path, char[] password) throws Exception {
        // Create PKCS12 keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);

        // Generate RSA key pair for the keystore entry
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        // Self-signed cert for the key entry
        X500Name name = new X500Name("CN=KeyStore Test, O=CBOM Analyser");
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 365L * 86400000),
            name, keyPair.getPublic()
        );
        JcaContentSignerBuilder signer = new JcaContentSignerBuilder("SHA256WithRSA");
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate cert = converter.getCertificate(certBuilder.build(signer.build(keyPair.getPrivate())));

        // Store the key entry
        ks.setKeyEntry("my-key", keyPair.getPrivate(), password, new java.security.cert.Certificate[]{cert});

        // Save to file
        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password);
        }
    }

    /**
     * Load a PKCS12 keystore and extract the private key.
     */
    public PrivateKey loadPKCS12PrivateKey(String path, char[] password, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password);
        }
        return (PrivateKey) ks.getKey(alias, password);
    }

    // ════════════════════════════════════════════════════════════════
    // ── JKS KeyStore operations ──────────────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Create a JKS keystore using BouncyCastle.
     */
    public void createJKSKeyStore(String path, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, password);

        // RSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096);
        KeyPair keyPair = kpg.generateKeyPair();

        // Self-signed cert
        X500Name name = new X500Name("CN=JKS Test, O=CBOM Analyser");
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            name, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 365L * 86400000),
            name, keyPair.getPublic()
        );
        JcaContentSignerBuilder signer = new JcaContentSignerBuilder("SHA256WithRSA");
        signer.setProvider("BC");
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate cert = converter.getCertificate(certBuilder.build(signer.build(keyPair.getPrivate())));

        ks.setKeyEntry("jks-key", keyPair.getPrivate(), password, new java.security.cert.Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password);
        }
    }

    // ════════════════════════════════════════════════════════════════
    // ── Password-Based Encryption (PBE) ──────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * PBE with SHA-256 and AES-256 — password-based encryption.
     */
    public byte[] encryptPBE(char[] password, byte[] data) throws Exception {
        // Derive key from password using PBKDF2
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, 310000, 256);
        SecretKey tempKey = skf.generateSecret(keySpec);
        SecretKey secretKey = new SecretKeySpec(tempKey.getEncoded(), "AES");

        // Encrypt with AES-256-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * PBE using BouncyCastle direct PBE cipher.
     * PBEWithSHA256And256BitAES-CBC-BC — BC-specific PBE cipher.
     */
    public byte[] encryptPBEDirect(char[] password, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC", "BC");
        PBEKeySpec keySpec = new PBEKeySpec(password);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC", "BC");
        SecretKey key = skf.generateSecret(keySpec);

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 310000);

        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        return cipher.doFinal(data);
    }

    /**
     * PBE using older / weaker algorithm (for detection testing).
     * PBEWithMD5AndDES — weak, NOT quantum-safe.
     */
    public byte[] encryptPBEWeak(char[] password, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        PBEKeySpec keySpec = new PBEKeySpec(password);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = skf.generateSecret(keySpec);

        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 1000);

        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        return cipher.doFinal(data);
    }

    // ════════════════════════════════════════════════════════════════
    // ── PKCS8 Private Key operations ─────────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Export RSA private key in PKCS8 format.
     */
    public byte[] exportPKCS8(PrivateKey privateKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8Spec = kf.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        return pkcs8Spec.getEncoded();
    }

    /**
     * Import RSA private key from PKCS8 format.
     */
    public PrivateKey importPKCS8(byte[] pkcs8Bytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        return kf.generatePrivate(spec);
    }

    // ════════════════════════════════════════════════════════════════
    // ── JCEKS KeyStore (Java Cryptography Extension KeyStore) ────
    // ════════════════════════════════════════════════════════════════

    /**
     * Create JCEKS keystore — supports symmetric key storage.
     */
    public void createJCEKSKeyStore(String path, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(null, password);

        // Store AES-256 symmetric key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        ks.setKeyEntry("aes-key", aesKey, password, null);

        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password);
        }
    }
}
