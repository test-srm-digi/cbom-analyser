package com.example.pqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;

import javax.crypto.KEM;
import java.security.*;
import java.util.Arrays;

/**
 * BouncyCastle PQC-Only Service
 *
 * This file demonstrates PURE Post-Quantum Cryptography usage via BouncyCastle.
 * All algorithms used here are NIST PQC standards or candidates.
 *
 * Expected CBOM result:
 *   - BouncyCastle-Provider → QUANTUM_SAFE (only PQC algorithms in this file)
 *   - ML-KEM, ML-DSA, SLH-DSA, Falcon, XMSS, LMS, FrodoKEM, BIKE, HQC → QUANTUM_SAFE
 */
public class BouncyCastlePQCService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ════════════════════════════════════════════════════════════════
    // ── ML-KEM (FIPS 203) — formerly Kyber ─────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * ML-KEM-768 key encapsulation using JCE provider API.
     */
    public KeyPair generateMLKEMKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * ML-KEM-1024 (highest security level) using JCE.
     */
    public KeyPair generateMLKEM1024KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-1024", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * ML-KEM key encapsulation using low-level BC API.
     */
    public byte[] encapsulateMLKEM(KeyPair keyPair) throws Exception {
        KyberKeyPairGenerator kyberGen = new KyberKeyPairGenerator();
        // KEM using JCE (Java 21+)
        KEM kem = KEM.getInstance("ML-KEM-768", "BC");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        return encapsulated.encapsulation();
    }

    /**
     * ML-KEM decapsulation using low-level BC API.
     */
    public byte[] decapsulateMLKEM(PrivateKey privateKey, byte[] encapsulation) throws Exception {
        KyberKEMExtractor extractor = new KyberKEMExtractor(null);
        KEM kem = KEM.getInstance("ML-KEM-768", "BC");
        KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
        return decapsulator.decapsulate(encapsulation).key().getEncoded();
    }

    /**
     * ML-KEM-512 (lighter variant) parameterised key generation.
     */
    public KeyPair generateMLKEM512() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(KyberParameterSpec.ml_kem_512);
        return kpg.generateKeyPair();
    }

    // ════════════════════════════════════════════════════════════════
    // ── ML-DSA (FIPS 204) — formerly Dilithium ────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * ML-DSA-65 digital signature using JCE API.
     */
    public byte[] signWithMLDSA(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("ML-DSA-65", "BC");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * ML-DSA-65 signature verification.
     */
    public boolean verifyMLDSA(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("ML-DSA-65", "BC");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    /**
     * ML-DSA-87 key pair generation (highest security level).
     */
    public KeyPair generateMLDSA87KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * ML-DSA key pair using low-level BC API.
     */
    public void generateMLDSALowLevel() throws Exception {
        DilithiumKeyPairGenerator dilithiumGen = new DilithiumKeyPairGenerator();
        // Low-level keygen — no JCE wrapper
        DilithiumSigner dilithiumSigner = new DilithiumSigner();
    }

    /**
     * ML-DSA-44 (lightest security level) parameterised.
     */
    public KeyPair generateMLDSA44() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(DilithiumParameterSpec.ml_dsa_44);
        return kpg.generateKeyPair();
    }

    // ════════════════════════════════════════════════════════════════
    // ── SLH-DSA (FIPS 205) — formerly SPHINCS+ ────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * SLH-DSA signature using JCE API.
     */
    public byte[] signWithSLHDSA(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SLH-DSA-SHA2-128s", "BC");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * SLH-DSA key pair using low-level BC API.
     */
    public void generateSLHDSALowLevel() throws Exception {
        SPHINCSPlusKeyPairGenerator sphincsGen = new SPHINCSPlusKeyPairGenerator();
        SPHINCSPlusSigner sphincsSigner = new SPHINCSPlusSigner();
    }

    /**
     * SLH-DSA key pair generation using MLDSAParameterSpec / SLHDSAParameterSpec.
     */
    public KeyPair generateSLHDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        return kpg.generateKeyPair();
    }

    // ════════════════════════════════════════════════════════════════
    // ── Falcon (NIST round-3 alternate) ───────────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Falcon-512 digital signature.
     */
    public KeyPair generateFalconKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon-512", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * Falcon low-level BC API.
     */
    public void falconLowLevel() throws Exception {
        FalconKeyPairGenerator falconGen = new FalconKeyPairGenerator();
        FalconSigner falconSigner = new FalconSigner();
    }

    // ════════════════════════════════════════════════════════════════
    // ── Hash-based signatures: XMSS and LMS ──────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * XMSS key pair generation.
     */
    public KeyPair generateXMSSKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * XMSS low-level BC API.
     */
    public void xmssLowLevel() throws Exception {
        XMSSKeyPairGenerator xmssGen = new XMSSKeyPairGenerator();
        XMSSSigner xmssSigner = new XMSSSigner();
    }

    /**
     * LMS key pair generation.
     */
    public KeyPair generateLMSKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * LMS low-level BC API.
     */
    public void lmsLowLevel() throws Exception {
        LMSKeyPairGenerator lmsGen = new LMSKeyPairGenerator();
        LMSSigner lmsSigner = new LMSSigner();
    }

    // ════════════════════════════════════════════════════════════════
    // ── KEM Candidates: FrodoKEM, BIKE, HQC, McEliece, NTRU ─────
    // ════════════════════════════════════════════════════════════════

    /**
     * FrodoKEM key generation — conservative lattice KEM.
     */
    public void generateFrodoKEMKeyPair() throws Exception {
        FrodoKEMKeyPairGenerator frodoGen = new FrodoKEMKeyPairGenerator();
    }

    /**
     * BIKE key generation — code-based KEM.
     */
    public void generateBIKEKeyPair() throws Exception {
        BIKEKeyPairGenerator bikeGen = new BIKEKeyPairGenerator();
    }

    /**
     * HQC key generation — code-based KEM.
     */
    public void generateHQCKeyPair() throws Exception {
        HQCKeyPairGenerator hqcGen = new HQCKeyPairGenerator();
    }

    /**
     * Classic McEliece key generation — code-based KEM.
     */
    public void generateClassicMcElieceKeyPair() throws Exception {
        CMCEKeyPairGenerator cmceGen = new CMCEKeyPairGenerator();
    }

    /**
     * NTRU key generation — lattice KEM.
     */
    public void generateNTRUKeyPair() throws Exception {
        NTRUKeyPairGenerator ntruGen = new NTRUKeyPairGenerator();
    }

    // ════════════════════════════════════════════════════════════════
    // ── SHA-3 and AES-256 (quantum-safe symmetric/hash) ──────────
    // ════════════════════════════════════════════════════════════════

    /**
     * SHA3-256 hashing — quantum-safe hash.
     */
    public byte[] hashSHA3(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        return md.digest(data);
    }

    /**
     * AES-256 symmetric encryption — quantum-safe with 256-bit keys.
     */
    public byte[] encryptAES256(byte[] data) throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        javax.crypto.SecretKey key = kg.generateKey();
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
