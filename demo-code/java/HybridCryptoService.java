package com.example.hybrid;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;

/**
 * Hybrid Crypto Service — Mixed Classical + PQC
 *
 * This file demonstrates a REAL-WORLD migration scenario where classical
 * algorithms (RSA, ECDSA) are used alongside PQC algorithms (ML-KEM, ML-DSA).
 * This is the expected pattern during the NIST PQC transition period.
 *
 * Expected CBOM result:
 *   - BouncyCastle-Provider → NOT_QUANTUM_SAFE (worst-case: RSA and ECDSA present)
 *   - RSA → NOT_QUANTUM_SAFE
 *   - ECDSA → NOT_QUANTUM_SAFE
 *   - ML-KEM → QUANTUM_SAFE
 *   - ML-DSA → QUANTUM_SAFE
 *   - AES-256 → QUANTUM_SAFE (symmetric, 256-bit key)
 *   - SHA-256 → QUANTUM_SAFE (hash)
 */
public class HybridCryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ════════════════════════════════════════════════════════════════
    // ── Classical (NOT quantum-safe) — still in active use ────────
    // ════════════════════════════════════════════════════════════════

    /**
     * RSA-2048 key pair — classical, NOT quantum-safe.
     * Still used for backward compatibility during migration.
     */
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /**
     * RSA signature — classical, NOT quantum-safe.
     */
    public byte[] signWithRSA(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256WithRSA", "BC");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    /**
     * ECDSA P-256 key pair — classical, NOT quantum-safe.
     */
    public KeyPair generateECDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    /**
     * ECDSA signature — classical, NOT quantum-safe.
     */
    public byte[] signWithECDSA(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256WithECDSA", "BC");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // ════════════════════════════════════════════════════════════════
    // ── Post-Quantum (QUANTUM_SAFE) — migration targets ──────────
    // ════════════════════════════════════════════════════════════════

    /**
     * ML-KEM-768 key encapsulation — PQC, QUANTUM_SAFE.
     * Replaces RSA key exchange / ECDH in the quantum era.
     */
    public KeyPair generateMLKEMKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * ML-DSA-65 signature — PQC, QUANTUM_SAFE.
     * Replaces ECDSA / RSA signatures in the quantum era.
     */
    public byte[] signWithMLDSA(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("ML-DSA-65", "BC");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    /**
     * ML-DSA-65 key pair generation.
     */
    public KeyPair generateMLDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        return kpg.generateKeyPair();
    }

    // ════════════════════════════════════════════════════════════════
    // ── Quantum-safe symmetric primitives ────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * AES-256-GCM — quantum-safe symmetric encryption (Grover's halves key
     * strength, but 256-bit → 128-bit effective is still secure).
     */
    public byte[] encryptAES256GCM(byte[] data) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * SHA-256 hashing — quantum-safe hash (Grover's at 128-bit → still secure).
     */
    public byte[] hashSHA256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // ════════════════════════════════════════════════════════════════
    // ── Hybrid key exchange (classical + PQC combined) ───────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Hybrid approach: generate BOTH RSA and ML-KEM key pairs.
     * Real-world migration pattern — dual key exchange for safety.
     */
    public record HybridKeyBundle(KeyPair classicalKeyPair, KeyPair pqcKeyPair) {}

    public HybridKeyBundle generateHybridKeyBundle() throws Exception {
        // Classical (RSA-4096 for higher security during transition)
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaGen.initialize(4096);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();

        // PQC (ML-KEM-1024 for highest security)
        KeyPairGenerator mlkemGen = KeyPairGenerator.getInstance("ML-KEM-1024", "BC");
        KeyPair mlkemKeyPair = mlkemGen.generateKeyPair();

        return new HybridKeyBundle(rsaKeyPair, mlkemKeyPair);
    }

    /**
     * Hybrid signature: sign with BOTH ECDSA and ML-DSA.
     * Provides backward compatibility AND quantum safety.
     */
    public record HybridSignature(byte[] classicalSig, byte[] pqcSig) {}

    public HybridSignature signHybrid(PrivateKey ecKey, PrivateKey mldsaKey, byte[] data) throws Exception {
        // Classical signature
        Signature ecSig = Signature.getInstance("SHA256WithECDSA", "BC");
        ecSig.initSign(ecKey);
        ecSig.update(data);
        byte[] classicalSig = ecSig.sign();

        // PQC signature
        Signature pqcSig = Signature.getInstance("ML-DSA-87", "BC");
        pqcSig.initSign(mldsaKey);
        pqcSig.update(data);
        byte[] quantumSig = pqcSig.sign();

        return new HybridSignature(classicalSig, quantumSig);
    }
}
