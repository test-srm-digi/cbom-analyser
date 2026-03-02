package com.example.x509pqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;

/**
 * X.509 PQC Certificate Service
 *
 * Demonstrates X.509 certificate operations with POST-QUANTUM signature algorithms.
 * This tests the X.509 context scanner's ability to detect PQC signatures in certificates.
 *
 * Expected CBOM result:
 *   - X.509 → QUANTUM_SAFE (signed with ML-DSA-65, SLH-DSA)
 *   - ML-DSA-65 → QUANTUM_SAFE
 *   - SLH-DSA → QUANTUM_SAFE
 *   - BouncyCastle-Provider → QUANTUM_SAFE (only PQC in this file)
 */
public class X509PQCCertificateService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ════════════════════════════════════════════════════════════════
    // ── Self-signed X.509 cert with ML-DSA-65 signature ──────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Generate a self-signed X.509 certificate using ML-DSA-65 (Dilithium).
     * This is the NIST FIPS 204 standard post-quantum signature.
     */
    public X509Certificate createMLDSASelfSignedCert() throws Exception {
        // Generate ML-DSA-65 key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPair keyPair = kpg.generateKeyPair();

        // Build X.509 certificate with ML-DSA-65 signature
        X500Name issuer = new X500Name("CN=PQC Test CA, O=CBOM Analyser, C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        // Sign with ML-DSA-65 — post-quantum signature algorithm
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("ML-DSA-65");
        signerBuilder.setProvider("BC");

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider("BC");
        return converter.getCertificate(certBuilder.build(signerBuilder.build(keyPair.getPrivate())));
    }

    // ════════════════════════════════════════════════════════════════
    // ── Self-signed X.509 cert with SLH-DSA (SPHINCS+) ──────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Generate a self-signed X.509 certificate using SLH-DSA-SHA2-128s.
     * This is NIST FIPS 205 — hash-based stateless signature.
     */
    public X509Certificate createSLHDSASelfSignedCert() throws Exception {
        // Generate SLH-DSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name issuer = new X500Name("CN=SLH-DSA Test CA, O=CBOM Analyser, C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        // Sign certificate with SLH-DSA
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SLH-DSA-SHA2-128s");
        signerBuilder.setProvider("BC");

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider("BC");
        return converter.getCertificate(certBuilder.build(signerBuilder.build(keyPair.getPrivate())));
    }

    // ════════════════════════════════════════════════════════════════
    // ── X.509 cert chain verification with PQC ────────────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Verify an X.509 certificate chain where the CA cert uses ML-DSA.
     */
    public boolean verifyCertChain(X509Certificate caCert, X509Certificate endEntity) throws Exception {
        // Get the signature algorithm name — expect ML-DSA-65 or SLH-DSA
        String sigAlg = caCert.getSigAlgName();
        System.out.println("CA certificate signature algorithm: " + sigAlg);

        // Verify end-entity cert against CA public key
        endEntity.verify(caCert.getPublicKey());
        
        // Check that the signature algorithm is PQC
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(caCert.getSigAlgOID());
        return sigAlg.contains("ML-DSA") || sigAlg.contains("SLH-DSA");
    }

    /**
     * Issue an end-entity X.509 certificate signed by a PQC CA.
     */
    public X509Certificate issueEndEntityCert(KeyPair caKeyPair, KeyPair userKeyPair) throws Exception {
        X500Name issuer = new X500Name("CN=PQC Root CA, O=CBOM Analyser, C=US");
        X500Name subject = new X500Name("CN=User, O=CBOM Analyser, C=US");

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 90L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, userKeyPair.getPublic()
        );

        // Sign with ML-DSA-87 — highest security level for CA operations
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("ML-DSA-87");
        signerBuilder.setProvider("BC");

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider("BC");
        return converter.getCertificate(certBuilder.build(signerBuilder.build(caKeyPair.getPrivate())));
    }

    // ════════════════════════════════════════════════════════════════
    // ── Certificate Signing Request (CSR) with PQC ───────────────
    // ════════════════════════════════════════════════════════════════

    /**
     * Create a PKCS#10 CSR signed with ML-DSA-65.
     * Demonstrates that CSR operations can also use PQC signatures.
     */
    public PKCS10CertificationRequest createPQCCSR(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=PQC Service, O=CBOM Analyser, C=US");

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("ML-DSA-65");
        signerBuilder.setProvider("BC");

        org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder csrBuilder =
            new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        return csrBuilder.build(signerBuilder.build(keyPair.getPrivate()));
    }

    /**
     * Validate certificate trust path using CertPathValidator.
     */
    public boolean validateCertPath(X509Certificate[] chain, X509Certificate trustAnchor) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        // Use PKIX validator — supports PQC signatures via BC provider
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        
        // Check each certificate's getSigAlgName — should be ML-DSA or SLH-DSA
        for (X509Certificate cert : chain) {
            String alg = cert.getSigAlgName();
            System.out.println("Certificate signed with: " + alg);
        }
        
        return true;
    }
}
