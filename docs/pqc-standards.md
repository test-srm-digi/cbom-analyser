# PQC Standards & CycloneDX Reference

> Post-Quantum Cryptography fundamentals, the quantum threat, CycloneDX 1.7 CBOM specification, and quantum safety classification.

---

## Table of Contents

- [The Quantum Threat](#the-quantum-threat)
- [Why a CBOM?](#why-a-cbom)
- [Core Concepts & Terminology](#core-concepts--terminology)
- [CycloneDX 1.7 Standard](#cyclonedx-17-standard)
- [Quantum Safety Classification](#quantum-safety-classification)
- [Resources](#resources)

---

## The Quantum Threat

Quantum computers running **Shor's algorithm** will be able to break:

- **RSA** (all key sizes)
- **ECC / ECDSA / ECDH** (all curves)
- **DH** (Diffie-Hellman)
- **DSA**
- **Ed25519 / EdDSA**

Quantum computers running **Grover's algorithm** will halve the effective security of:

- **AES-128** → effectively 64-bit (breakable)
- **AES-256** → effectively 128-bit (still safe)
- **SHA-256** → effectively 128-bit collision resistance (still safe)

---

## Why a CBOM?

Most organisations have **no idea** what cryptography their software uses. A typical enterprise application might use 30–60 different crypto algorithms scattered across hundreds of files and 50+ dependencies. When quantum computers arrive, these organisations won't know:

1. **What** crypto they use
2. **Where** it's used in the codebase
3. **Which** algorithms are vulnerable
4. **What** to replace them with

A CBOM answers all four questions.

---

## Core Concepts & Terminology

| Term | Definition |
|------|-----------|
| **CBOM** | Cryptographic Bill of Materials — a machine-readable inventory of all cryptographic assets |
| **SBOM** | Software Bill of Materials — inventory of software dependencies, licenses, CVEs |
| **xBOM** | Unified SBOM + CBOM — links software components to crypto assets (see [xBOM docs](xbom.md)) |
| **CycloneDX** | An OWASP-backed open standard for BOMs with crypto-specific properties |
| **PQC** | Post-Quantum Cryptography — algorithms designed to resist quantum computer attacks |
| **ML-KEM (Kyber)** | NIST FIPS 203. Replaces RSA/ECDH for key encapsulation |
| **ML-DSA (Dilithium)** | NIST FIPS 204. Replaces RSA/ECDSA/Ed25519 for digital signatures |
| **SLH-DSA (SPHINCS+)** | NIST FIPS 205. Hash-based signature scheme |
| **FN-DSA (Falcon)** | NIST candidate. Lattice-based digital signature |
| **Quantum Safe** | An algorithm not known to be breakable by quantum computers |
| **Not Quantum Safe** | An algorithm that WILL be broken by a sufficiently powerful quantum computer |
| **Crypto Primitive** | The category: hash, block-cipher, signature, key-agreement, etc. |
| **Crypto Function** | The operation: Hash, Encrypt, Decrypt, Sign, Verify, Keygen, etc. |

---

## CycloneDX 1.7 Standard

This project implements the **CycloneDX 1.7** specification for Cryptographic Bill of Materials.

### Asset Types

| Asset Type | Description |
|-----------|-------------|
| `algorithm` | Cryptographic algorithm (AES, RSA, SHA-256, etc.) |
| `protocol` | Cryptographic protocol (TLS 1.2, SSH, etc.) |
| `certificate` | X.509 certificates and chains |
| `related-crypto-material` | Keys, salts, IVs, nonces, credentials |
| `private-key` | Private key material |
| `public-key` | Public key material |
| `secret-key` | Symmetric secret key |

### Crypto Properties

- `cryptoProperties.assetType` — algorithm, protocol, certificate, related-crypto-material
- `cryptoProperties.algorithmProperties` — primitive, mode, padding, curve, cryptoFunctions
- `cryptoProperties.protocolProperties` — TLS version and cipher suites

### Related Crypto Material Subtypes

| Type | Description |
|------|-------------|
| `salt` | Random salt for password hashing |
| `seed` | PRNG seed |
| `nonce` | Number used once |
| `iv` | Initialization vector |
| `shared-secret` | Diffie-Hellman shared secret |
| `credential` | Username / password credential |
| `password` | Password material |
| `key` | Generic key material |
| `ciphertext` | Encrypted data |
| `signature` | Digital signature value |
| `digest` | Hash digest output |
| `token` | Authentication token (JWT, API key) |
| `tag` | GCM authentication tag |
| `initialization-vector` | Full-name alias for IV |
| `private-key` / `public-key` / `secret-key` | Typed key material |
| `unknown` | Unclassified material |

### CBOM Document Structure

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-15T10:30:00Z",
    "tools": [...],
    "component": { "name": "my-app", "version": "1.0.0" },
    "repository": {
      "url": "https://github.com/org/repo",
      "branch": "main"
    }
  },
  "components": [],
  "cryptoAssets": [
    {
      "id": "uuid",
      "name": "AES-256",
      "type": "crypto-asset",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "parameterSetIdentifier": "256",
          "cryptoFunctions": ["encrypt", "decrypt"]
        }
      },
      "location": { "fileName": "src/Crypto.java", "lineNumber": 42 },
      "quantumSafety": "conditional",
      "pqcVerdict": {
        "verdict": "PQC_READY",
        "confidence": 90,
        "reasons": ["AES-256 provides sufficient post-quantum security margin"],
        "parameters": { "keySize": 256 },
        "recommendation": "No changes needed — AES-256 is PQC-safe."
      },
      "detectionSource": "sonar"
    }
  ],
  "dependencies": [
    {
      "ref": "maven:org.bouncycastle:bcprov-jdk18on",
      "dependsOn": [],
      "provides": ["algorithm:AES", "algorithm:RSA", "algorithm:ECDSA"]
    }
  ],
  "thirdPartyLibraries": [
    {
      "name": "bcprov-jdk18on",
      "groupId": "org.bouncycastle",
      "version": "1.78.1",
      "packageManager": "maven",
      "isDirect": true,
      "transitiveDepth": 0,
      "dependencyPath": ["bcprov-jdk18on"],
      "cryptoAlgorithms": ["AES", "RSA", "ECDSA", "SHA-256"],
      "quantumSafety": "conditional"
    }
  ]
}
```

---

## Quantum Safety Classification

| Status | Meaning |
|--------|---------|
| `quantum-safe` | Uses NIST-approved PQC algorithm or AES-256 |
| `not-quantum-safe` | Vulnerable to quantum attack (RSA, ECDSA, etc.) |
| `conditional` | Safety depends on parameters — analysed by PQC verdict system |
| `unknown` | Not enough information to classify |

The PQC Risk Engine evaluates each asset with 11 specialised analysers and assigns a verdict with confidence score. See [Scanning — PQC Readiness Verdicts](scanning.md#pqc-readiness-verdicts) for the full breakdown.

---

## Resources

- [CycloneDX 1.7 Specification](https://cyclonedx.org/docs/1.7/json/)
- [CycloneDX CBOM Guide](https://cyclonedx.org/capabilities/cbom/)
- [IBM sonar-cryptography](https://github.com/cbomkit/sonar-cryptography)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)

---

*Back to [README](../README.md) · See also [Scanning](scanning.md) · [xBOM](xbom.md)*
