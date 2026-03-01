# PQC Classification Analysis — Conditional & Unknown Assets

This document provides a comprehensive analysis of **why** certain crypto assets are classified as "conditional" or "unknown" in CBOM reports, what has been done to reduce them, and which cases are **irreducible** by design.

---

## Table of Contents

1. [Overview](#overview)
2. [Classification Pipeline](#classification-pipeline)
3. [Analysis by Application](#analysis-by-application)
4. [Resolved Unknowns (Now Classified)](#resolved-unknowns)
5. [Irreducible Conditionals](#irreducible-conditionals)
6. [Irreducible Unknowns](#irreducible-unknowns)
7. [PQCA / CBOMKit Tooling Comparison](#pqca--cbomkit-tooling-comparison)
8. [Recommendations](#recommendations)

---

## Overview

Across all analyzed CBOMs, crypto assets fall into four categories:

| Status | Meaning | Action |
|--------|---------|--------|
| **quantum-safe** | Definitively safe (AES-256, SHA-256, ML-KEM, ML-DSA) | None |
| **not-quantum-safe** | Definitively vulnerable (RSA, ECDSA, ECDH, DH) | Migrate to PQC |
| **conditional** | Safety depends on parameters/configuration | Review needed |
| **unknown** | Algorithm not recognized by classification engine | Add to database |

### Pre-Fix Counts (All Applications)

| Application | Total | QS | NQS | Conditional | Unknown |
|-------------|-------|----|-----|-------------|---------|
| cbom-analyser | 276 | 119 | 85 | 56 | 16 |
| dcone-document-manager | 217 | 35 | 32 | 150 | 0 |
| snowbird | 1231 | 67 | 79 | 1085 | 0 |
| snowbird-securesigning (latest) | 617 | 128 | 214 | 275 | 0 |
| snowbird-securesigning (older) | 1227 | 53 | 123 | 275 | 776 |

---

## Classification Pipeline

```
Source Code / Dependencies
        │
        ▼
┌─────────────────────┐
│  Pattern Scanner     │  Extracts crypto API usage (regex-based, 8 languages)
│  (scanner/*.ts)      │
└─────────┬───────────┘
          │ CryptoAsset[]
          ▼
┌─────────────────────┐
│  PQC Risk Engine     │  Looks up algorithm in ALGORITHM_DATABASE
│  (pqcRiskEngine.ts)  │  → quantum-safe / not-quantum-safe / conditional / unknown
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Parameter Analyzer  │  For CONDITIONAL assets: reads source context
│  (pqcParameterAnalyzer.ts)  (±15 lines around detection) to extract real
│                      │  parameters (key size, iterations, algorithm args)
│                      │  → Promotes to PQC_READY or NOT_PQC_READY
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Verdict Sync        │  Final consistency pass — ensures quantumSafety
│  (syncQuantumSafety) │  matches pqcVerdict (e.g., PQC_READY → quantum-safe)
└─────────────────────┘
```

### Why "Conditional" Persists

An asset stays **conditional** when:
1. It's in `ALGORITHM_DATABASE` as `CONDITIONAL` (e.g., X.509, PBKDF2, SecureRandom)
2. The Parameter Analyzer couldn't extract enough context to make a definitive verdict
3. The resulting `pqcVerdict` is `REVIEW_NEEDED` (stays conditional)

### Why "Unknown" Persists

An asset is **unknown** when:
1. Its name doesn't match ANY entry in `ALGORITHM_DATABASE`
2. No exact, case-insensitive, dash-insensitive, or partial match found
3. Falls through to the default: `quantumSafety: UNKNOWN`

---

## Analysis by Application

### cbom-analyser (Self-Scan)

**Conditionals (56):**
| Asset | Count | Why Conditional |
|-------|-------|-----------------|
| X.509 | 19x | Certificate format — safety depends on signature algorithm (RSA→vulnerable, ML-DSA→safe) |
| WebCrypto | 10x | Browser API wrapper — safety depends on algorithm arguments |
| SecureRandom | 8x | Java CSPRNG utility — safety depends on provider |
| PBKDF2 | 11x | KDF — safety depends on iterations, key length, hash |
| Digital-Signature | 2x | Generic signature — safety depends on algorithm |
| Blowfish | 2x | 64-bit block cipher — now promoted to NOT_PQC_READY by analyzer |
| bcrypt | 2x | KDF — safety depends on cost factor (now has analyzer) |
| scrypt | 2x | KDF — not quantum-vulnerable (now has analyzer) |

**Unknowns (16) — NOW FIXED:**
| Asset | Count | Was | Now | Fix Applied |
|-------|-------|-----|-----|-------------|
| Dilithium | 5x | unknown | **quantum-safe** | Added to ALGORITHM_DATABASE (alias for ML-DSA) |
| SHA3-256 | 3x | unknown | **quantum-safe** | Added SHA3-256/384/512 entries |
| Argon2i | 2x | unknown | **conditional** → PQC_READY (80%) | Added Argon2 family + analyzer |
| SPHINCS+ | 1x | unknown | **quantum-safe** | Added as alias for SLH-DSA |
| EVP-Encrypt | 1x | unknown | **conditional** | Added EVP family + analyzer |
| KeyAgreement | 1x | unknown | **conditional** | Added + analyzer |
| X25519 | 1x | unknown | **not-quantum-safe** | Added (ECDH variant, Shor's vulnerable) |
| Rijndael-256 | 1x | unknown | **quantum-safe** | Added (AES variant) |
| Twofish | 1x | unknown | **conditional** | Added + analyzer for key size |

### snowbird-securesigning (Older Run)

**Unknowns (776) — NOW FIXED:**
| Asset | Count | Was | Now | Fix Applied |
|-------|-------|-----|-----|-------------|
| Hash | 776x | unknown | **conditional** | Added `Hash` to DB + analyzer that resolves to specific hash |

**Conditionals (275):**
| Asset | Count | Why Conditional |
|-------|-------|-----------------|
| X.509 | 166x | Certificate format — see [Irreducible Conditionals](#irreducible-conditionals) |
| BouncyCastle-Provider | 107x | Security provider — see [Irreducible Conditionals](#irreducible-conditionals) |
| WebCrypto | 2x | API wrapper |

### dcone-document-manager

**Conditionals (150):**
| Asset | Count | Why Conditional |
|-------|-------|-----------------|
| X.509 | 149x | Certificate format — overwhelmingly from dependencies |
| MessageDigest | 1x | Java wrapper — depends on hash algorithm argument |

### snowbird

**Conditionals (1085):**
| Asset | Count | Why Conditional |
|-------|-------|-----------------|
| X.509 | 1015x | Certificate format — from dependency scanning |
| WebCrypto | 37x | API wrapper |
| BouncyCastle-Provider | 30x | Security provider |
| MessageDigest | 2x | Java wrapper |
| Digital-Signature | 1x | Generic signature |

---

## Resolved Unknowns

The following algorithms have been added to `ALGORITHM_DATABASE` in `pqcRiskEngine.ts`:

### PQC Algorithms (quantum-safe)
| Added Entry | Classification | Notes |
|-------------|---------------|-------|
| `Dilithium` | quantum-safe | Alias for ML-DSA (NIST FIPS 204) |
| `CRYSTALS-Dilithium` | quantum-safe | Full name alias |
| `SPHINCS+` | quantum-safe | Alias for SLH-DSA (NIST FIPS 205) |
| `Kyber` | quantum-safe | Alias for ML-KEM (NIST FIPS 203) |
| `CRYSTALS-Kyber` | quantum-safe | Full name alias |
| `FrodoKEM` | quantum-safe | Conservative lattice-based KEM |
| `BIKE` | quantum-safe | Code-based KEM (NIST round 4) |
| `HQC` | quantum-safe | NIST round 4 alternate |
| `XMSS` | quantum-safe | Stateful hash-based signature (RFC 8391) |
| `LMS` | quantum-safe | Stateful hash-based signature (RFC 8554) |

### Hash Functions (quantum-safe)
| Added Entry | Notes |
|-------------|-------|
| `SHA3-256` | SHA-3 family — quantum-resistant |
| `SHA3-384` | SHA-3 family |
| `SHA3-512` | SHA-3 family |
| `SHAKE128` | SHA-3 XOF |
| `SHAKE256` | SHA-3 XOF |
| `BLAKE2` / `BLAKE2b` / `BLAKE2s` | Modern hash — quantum-resistant |
| `BLAKE3` | Modern hash — quantum-resistant |
| `SipHash` | Keyed hash PRF |
| `Poly1305` | MAC — quantum-resistant |

### Symmetric / KDF (conditional with analyzer)
| Added Entry | Classification | Analyzer |
|-------------|---------------|----------|
| `Argon2` / `Argon2i` / `Argon2d` / `Argon2id` | conditional → PQC_READY | Extracts memory, time cost |
| `bcrypt` | conditional → PQC_READY (cost≥12) | Extracts cost factor |
| `Twofish` | conditional → depends on key size | Extracts key bits |
| `Serpent` | conditional | Key size analyzer |
| `Camellia` | conditional | Key size analyzer |
| `Rijndael` / `Rijndael-256` | quantum-safe | Direct classification |

### Key Exchange (not-quantum-safe)
| Added Entry | Classification | Notes |
|-------------|---------------|-------|
| `X25519` | not-quantum-safe | Curve25519 ECDH — Shor's vulnerable |
| `X448` | not-quantum-safe | Curve448 ECDH — Shor's vulnerable |
| `Ed448` | not-quantum-safe | Edwards curve signature |

### API Wrappers / Generic (conditional with analyzer)
| Added Entry | Analyzer Does |
|-------------|--------------|
| `EVP-Encrypt` / `EVP-Decrypt` / `EVP-Sign` / `EVP-Digest` | Extracts cipher/digest from OpenSSL EVP calls |
| `KeyAgreement` | Extracts algorithm from JCE KeyAgreement.getInstance() |
| `KeyGenerator` | Extracts algorithm + key size from JCE KeyGenerator |
| `Hash` / `Digest` | Resolves to specific hash via MessageDigest/hashlib/createHash |
| `Cipher` | Resolves via Cipher.getInstance() |
| `KDF` | Delegates to PBKDF2/Argon2/bcrypt/scrypt analyzers |
| `MAC` | quantum-safe (HMAC/CMAC symmetric-based) |
| `HKDF` / `HKDF-SHA256` | quantum-safe (symmetric KDF) |
| `IDEA` | not-quantum-safe (128-bit key max) |

---

## Irreducible Conditionals

These assets **cannot** be automatically resolved to quantum-safe or not-quantum-safe. They are **inherently conditional** because their quantum safety depends on runtime configuration, parameter choices, or external factors that static analysis cannot determine.

### 1. X.509 Certificates (from Dependencies)

**Count across apps:** ~1,350 total (1,015 + 166 + 149 + 19)

**Why irreducible:**
- X.509 is a **certificate format**, not an algorithm. Its quantum safety depends entirely on the **signature algorithm** used (RSA → vulnerable, ML-DSA → safe).
- When detected via **dependency scanning** (e.g., BouncyCastle JAR, OpenSSL library), there is **no source code context** to determine which signature algorithm is used.
- The actual certificates are generated at **runtime** or by external CAs — their algorithm is not in the source code.

**Current mitigation:**
- Dependency-sourced X.509: Classified `NOT_PQC_READY` at 70% confidence (most deployed certs use RSA/ECDSA)
- Source-code X.509: Parameter analyzer searches for `SHA256withRSA`, `ML-DSA`, etc. in surrounding context

**What would fix it:**
- **Runtime certificate inspection** (not static analysis) — examine actual cert chains
- **Network scanner integration** — the network/TLS scanner already does this for live endpoints
- External tools like **cbomkit/Mnemosyne** (certificate analysis engine) from the PQCA CBOM Kit

### 2. BouncyCastle-Provider (JCE Security Provider)

**Count:** ~137 total (107 + 30)

**Why irreducible:**
- BouncyCastle is a **provider**, not an algorithm. It contains both quantum-safe (AES, ML-KEM) and quantum-vulnerable (RSA, EC) implementations.
- A single `Security.addProvider(new BouncyCastleProvider())` registration makes ALL BouncyCastle algorithms available — the scanner detects the registration, not the usage.
- Which algorithms are actually **used** through the provider requires tracing `Cipher.getInstance()`, `Signature.getInstance()`, etc. calls — these are detected separately.

**Current mitigation:** `REVIEW_NEEDED` at 40% confidence. Points user to audit registered algorithms.

**What would fix it:** These detections are actually **informational** — they flag that BouncyCastle is present. The actual algorithm usages are captured by separate detections (RSA, AES, etc.). Consider filtering these from the asset count entirely.

### 3. WebCrypto (Browser API Wrapper)

**Count:** ~49 total (37 + 10 + 2)

**Why irreducible (sometimes):**
- WebCrypto `crypto.subtle` is an **API**, not an algorithm.
- When the algorithm argument is a **variable** (not a string literal), static regex can't resolve it:
  ```js
  const alg = getConfig('crypto.algorithm'); // runtime value
  crypto.subtle.encrypt({ name: alg }, key, data);
  ```
- When the algorithm **is** a string literal, the new analyzer can resolve it.

**Current mitigation:** New `analyzeWebCrypto()` analyzer extracts algorithm from `crypto.subtle.*({name: 'AES-GCM'...})` patterns. Falls back to `REVIEW_NEEDED` if argument is dynamic.

### 4. MessageDigest (Java Digest Wrapper)

**Count:** ~3 total

**Why irreducible (sometimes):**
- `MessageDigest.getInstance(algorithmVar)` where the algorithm is a variable.
- When it's a literal string like `MessageDigest.getInstance("SHA-256")`, the scanner detects SHA-256 directly.

### 5. PBKDF2 / SecureRandom / Digital-Signature (Partial Resolution)

These are **partially reducible**. The parameter analyzer resolves them when:
- Source code is available (not dependency-sourced)
- Parameters are literal values (not runtime variables)
- The detection has valid `location.fileName` and `location.lineNumber`

When these conditions aren't met, they stay `REVIEW_NEEDED` (conditional).

---

## Irreducible Unknowns

After the fixes applied above, the only remaining source of "unknown" classifications would be:

1. **Completely novel algorithm names** — e.g., proprietary or niche algorithms not in the 100+ entry database
2. **Obfuscated or generated identifiers** — algorithm names that don't match any known pattern
3. **Non-crypto false positives** — code patterns that match crypto regexes but aren't actually cryptographic

These are irreducible because they require human knowledge to classify. The `ALGORITHM_DATABASE` in `pqcRiskEngine.ts` can be extended as new algorithm names are encountered.

---

## PQCA / CBOMKit Tooling Comparison

The [PQCA CBOM Kit](https://github.com/PQCA/cbomkit) provides complementary tools:

| Component | What It Does | Our Equivalent | Gap |
|-----------|-------------|----------------|-----|
| **sonar-cryptography (Hyperion)** | SonarQube plugin — AST-based crypto detection | Pattern scanner (regex-based) | AST analysis resolves variables; regex can't |
| **cbomkit-lib** | CycloneDX CBOM library | Backend CBOM types + generation | Comparable |
| **cbomkit-action** | GitHub Action for CBOM generation | `action.yml` + `entrypoint.sh` | Comparable |
| **cbomkit / Coeus** | Policy compliance engine | `checkNISTPQCCompliance()` | Comparable |
| **cbomkit / Themis** | Algorithm classification | `ALGORITHM_DATABASE` + `classifyAlgorithm()` | Comparable |
| **cbomkit / Mnemosyne** | Certificate chain analysis | X.509 parameter analyzer | Mnemosyne does **runtime** cert inspection — our gap |
| **cbomkit-theia (Theia)** | CBOM visualization | Frontend dashboard | Comparable |

### Key Gaps

1. **AST-based detection vs Regex**: sonar-cryptography (Hyperion) uses SonarQube's AST analysis, which can resolve variables, follow data flow, and determine algorithm parameters that are assigned dynamically. Our regex-based scanner can only match literal string values.

2. **Runtime certificate analysis**: Mnemosyne inspects actual deployed certificates (chains, trust stores) to determine signature algorithms. Our scanner detects X.509 references in source/dependencies but can't inspect the actual certificate content.

3. **These are INHERENT limitations of static regex analysis** — not bugs. The remediation is either:
   - Integrate with sonar-cryptography for AST-level detection
   - Add Mnemosyne-style runtime certificate inspection
   - Both of which are out of scope for a regex-based scanner

---

## Recommendations

### For Users

1. **X.509 conditionals**: Run the **Network Scanner** on your deployed endpoints to get definitive TLS/certificate analysis. The network scanner examines actual certificate chains and cipher suites.

2. **BouncyCastle-Provider**: These are informational. Focus on the individual algorithm detections (RSA, AES, etc.) rather than the provider registration itself.

3. **WebCrypto / MessageDigest**: Review the flagged source locations. If the algorithm argument is a string literal, the analyzer should have resolved it. If it's dynamic, manual review is needed.

4. **PBKDF2 / bcrypt / scrypt**: The analyzer extracts parameters when available. If flagged as `REVIEW_NEEDED`, check the iteration count, key length, and cost factor manually.

### For Development

1. **AST Integration**: Consider integrating with SonarQube's sonar-cryptography for languages where regex-based detection is insufficient.

2. **Certificate Runtime Scanner**: Extend the network scanner to inspect certificate chains in trust stores (JKS, PKCS12) from the repository, not just live endpoints.

3. **Confidence Thresholds**: The parameter analyzer uses conservative thresholds (≥70% for PQC_READY, ≥50% for NOT_PQC_READY). These can be tuned based on organizational risk appetite.
