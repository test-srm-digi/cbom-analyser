# Scanning Guide

> How to scan source code, network endpoints, dependencies, and configuration files for cryptographic assets.

---

## Table of Contents

- [Scanning Approaches](#scanning-approaches)
  - [Approach 1: Built-In Regex Scanner](#approach-1-built-in-regex-scanner-easiest--no-setup)
  - [Approach 2: PQCA sonar-cryptography / Hyperion](#approach-2-pqca-sonar-cryptography--hyperion-most-accurate-for-java)
  - [Approach 3: Network TLS Scanner](#approach-3-network-tls-scanner-runtime-crypto-discovery)
  - [Approach 4: Full Pipeline](#approach-4-full-pipeline-recommended)
  - [Comparison Matrix](#comparison-matrix)
- [Certificate File Scanning](#certificate-file-scanning)
- [External Tool Integration](#external-tool-integration)
- [Variable Resolution & Context Scanning](#variable-resolution--context-scanning)
  - [Supported Languages & Libraries](#supported-languages--libraries)
  - [Scanner Module Architecture](#scanner-module-architecture)
  - [Variable-Argument Resolution](#variable-argument-resolution)
  - [Context Scanning](#context-scanning)
  - [Configuration & Artifact File Scanning](#configuration--artifact-file-scanning)
- [Third-Party Dependency Scanning](#third-party-dependency-scanning)
  - [How It Works — Step by Step](#how-it-works--step-by-step)
  - [Supported Manifest Files](#supported-manifest-files)
  - [Known Crypto Library Database](#known-crypto-library-database)
  - [Transitive Dependency Resolution](#transitive-dependency-resolution)
  - [From Library to CBOM Asset](#from-library-to-cbom-asset)
  - [Deduplication](#deduplication)
  - [Dashboard View](#dashboard-view)
- [PQC Readiness Verdicts](#pqc-readiness-verdicts)

---

## Scanning Approaches

### Approach 1: Built-In Regex Scanner (Easiest — No Setup)

Uses the QuantumGuard regex scanner that's built into this project. No external tools needed.

```bash
# Clone any GitHub repo
git clone https://github.com/spring-projects/spring-petclinic.git /tmp/petclinic

# Scan it (backend must be running on port 3001)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' \
  -o petclinic-cbom.json
```

| Pros | Cons |
|------|------|
| Zero setup — works out of the box | Pattern-based, may miss uncommon crypto APIs |
| Fast — scans 500 files in seconds | Doesn't analyze dependencies/transitive crypto |
| Covers 8 language ecosystems (Java, Python, JS/TS, C/C++, C#/.NET, Go, PHP, Rust) | No bytecode analysis |
| 1 000+ patterns including deep BouncyCastle, PQC algorithms, npm packages | |
| Scans config/artifact files (PEM certs, java.security, openssl.cnf, TLS configs) | |

### Approach 2: PQCA sonar-cryptography / Hyperion (Most Accurate for Java)

Uses SonarQube with the **sonar-cryptography** plugin (formerly IBM, now part of the [PQCA CBOM Kit](https://github.com/IBM/cbomkit)) for deep AST-based static analysis.
The plugin's detection engine (**Hyperion**) performs multi-stage analysis: AST parsing → detection rules → INode mapping → OID enrichment → CycloneDX 1.7 CBOM generation with precise algorithm detection, key sizes, and OIDs.

> **Related PQCA CBOM Kit components:**
> - **cbomkit-theia** — Go CLI for filesystem/container scanning (certificates, secrets, java.security, openssl.cnf, problematic CAs). Inspired our built-in config/artifact scanner.
> - **cbomkit-lib** — Standalone Java library for programmatic CBOM generation.
> - **cbomkit** — Full application with REST API, WebSocket scanning, and compliance evaluation.
> - **cbomkit-action** — GitHub Action wrapping cbomkit-lib in a Docker container.

> **GitHub Actions:** You can also enable sonar-cryptography in the GitHub
> Action by setting the `sonar-host-url` and `sonar-token` inputs — see
> [GitHub Actions Integration](github-actions.md).

**Quick Setup:**

```bash
# 1. Start SonarQube with the crypto plugin (already bundled)
docker compose -f docker-compose.sonarqube.yml up -d

# 2. Wait for SonarQube to start (~60s), then check:
curl -s http://localhost:9090/api/system/status
# Should return: {"status":"UP"}

# 3. Set your SONAR_TOKEN in .env (generate at http://localhost:9090)
#    Default login: admin / QuantumGuard2024@

# 4. Scan via the API (sonar-scanner must be on $PATH)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/your/java-project"}'
```

**Manual sonar-scanner run:**

```bash
# Install sonar-scanner CLI
brew install sonar-scanner   # macOS

# Create sonar-project.properties in your target project root
# (see sonar-project.properties.example for a template)

cd /path/to/your/java-project
sonar-scanner \
  -Dsonar.host.url=http://localhost:9090 \
  -Dsonar.token=YOUR_TOKEN \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=src

# The plugin generates cbom.json in the project root
cat cbom.json | python3 -m json.tool
```

**Supported languages:**
- Java (JCA 100%, BouncyCastle 100%)
- Python (pyca/cryptography 100%)
- Go (crypto stdlib 100%)

### Approach 3: Network TLS Scanner (Runtime Crypto Discovery)

Scan live endpoints to discover what cryptography is actually used at runtime.

```bash
# Scan a single endpoint
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}'
```

### Approach 4: Full Pipeline (Recommended)

For the most complete CBOM, use the **`/api/scan-code/full`** endpoint — it runs all scanners in sequence and produces a unified CBOM with definitive PQC verdicts:

```bash
# Single command — runs code scan + dependency scan + network scan + PQC analysis
curl -X POST http://localhost:3001/api/scan-code/full \
  -H "Content-Type: application/json" \
  -d '{
    "repoPath": "/tmp/your-app",
    "networkHosts": ["your-app.com", "api.your-app.com"]
  }' \
  -o full-cbom.json
```

This produces a CBOM that includes:
- All crypto assets from source code (sonar or regex) — 8 languages, 1 000+ patterns
- Crypto configuration & artifact detections (PEM certificates/keys, java.security, openssl.cnf, nginx/apache TLS config, SSH config, Spring/ASP.NET settings)
- **Certificate file parsing** — `.pem`, `.crt`, `.cer`, `.der` files parsed for signature algorithms, public key types, and key sizes
- Third-party crypto libraries discovered from manifest files (`pom.xml`, `package.json`, `requirements.txt`, `go.mod`, etc.)
- Known algorithms provided by each library (dependency graph with `provides` field)
- **External tool results** (if CodeQL, cbomkit-theia, or CryptoAnalysis are installed) — deduplicated and merged with regex findings
- Network TLS scan results (if `networkHosts` specified)
- **Definitive PQC verdicts** on conditional assets (PBKDF2 iteration counts, AES key sizes, SecureRandom providers, KeyPairGenerator algorithms, etc.)
- **Informational asset filtering** — BouncyCastle-Provider registrations marked as informational, excluded from risk counts

**Alternatively**, you can still combine scanners manually:

```bash
# Step 1: Scan source code
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/your-app"}' \
  -o your-app-cbom.json

# Step 2: Upload the CBOM
curl -X POST http://localhost:3001/api/upload/raw \
  -H "Content-Type: application/json" \
  -d @your-app-cbom.json
# Note the cbomId from the response

# Step 3: Merge network scan results
curl -X POST http://localhost:3001/api/scan-network/merge/urn:uuid:YOUR-CBOM-ID \
  -H "Content-Type: application/json" \
  -d '{"url": "your-app.com"}'
```

### Comparison Matrix

| Approach | Setup | Speed | Accuracy | Languages | Deps | Certs | External Tools | PQC Verdicts | Runtime Crypto |
|----------|-------|-------|----------|-----------|------|-------|----------------|-------------|----------------|
| **Regex Scanner** | None | Fast | Medium | Java, Python, JS/TS, C/C++, C#/.NET, Go, PHP, Rust + config files | No | No | No | No | No |
| **PQCA sonar-cryptography** | High | Slow | Very High | Java, Python, Go | No | No | N/A | No | No |
| **Network TLS Scanner** | None | Fast | High (TLS) | N/A | No | No | No | No | Yes |
| **Full Pipeline** | Low–High | Medium | Highest | All (8 languages + config/artifacts) | Yes | Yes | If installed | Yes | Yes |

---

## Certificate File Scanning

The full scan pipeline includes a dedicated **certificate file scanner** (`certificateFileScanner.ts`) that discovers and parses certificate files in the repository, extracting actual cryptographic details that turn generic "X.509 (conditional)" entries into definitive classifications.

### How It Works

1. **Discovery** — scans the repository for files matching `.pem`, `.crt`, `.cer`, `.der` extensions (excluding `node_modules`, `.git`, `target`, `build`, `dist`, `vendor`)
2. **PEM Parsing** — reads PEM files, splits multi-certificate bundles (multiple `-----BEGIN CERTIFICATE-----` blocks), and parses each using Node.js `crypto.X509Certificate`
3. **DER Parsing** — attempts binary DER parsing for `.der` files
4. **Key File Detection** — identifies private keys (`.key`, `*.pem` with `PRIVATE KEY` header) and public keys
5. **Keystore Detection** — discovers `.jks`, `.p12`, `.pfx`, `.keystore` files (listed as assets but requires password for deep parsing)

### Extracted Information

| Field | Source | Example |
|-------|--------|---------|
| **Signature Algorithm** | `X509Certificate.sigAlgName` | `SHA256withRSA`, `ECDSA-with-SHA384`, `ML-DSA-65` |
| **Public Key Algorithm** | `createPublicKey(cert.publicKey)` | `rsa`, `ec`, `ed25519`, `ml-dsa` |
| **Public Key Size** | `asymmetricKeySize` | `2048`, `256`, `384` |
| **Subject / Issuer** | Certificate fields | `CN=*.example.com` |
| **Validity** | `validFrom` / `validTo` | Expiry tracking |
| **Serial Number** | Certificate serial | Unique identifier |

### CBOM Integration

Each parsed certificate produces a `CryptoAsset` with:
- `detectionSource: 'certificate'`
- `cryptoProperties.assetType: 'certificate'`
- `CertificateProperties` including `signatureAlgorithm`, `subjectPublicKeyAlgorithm`, `certificateExpiry`
- PQC enrichment via `enrichAssetWithPQCData()` — turns "X.509" into "RSA-2048 (not-quantum-safe)" or "ML-DSA-65 (quantum-safe)"

### Example Output

A `.pem` certificate signed with SHA256withRSA and a 2048-bit key produces:
```json
{
  "name": "RSA-2048",
  "type": "crypto-asset",
  "detectionSource": "certificate",
  "quantumSafety": "not-quantum-safe",
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "signatureAlgorithm": "SHA256withRSA",
      "subjectPublicKeyAlgorithm": "RSA",
      "subjectPublicKeySize": 2048
    }
  },
  "location": { "fileName": "certs/server.pem" }
}
```

---

## External Tool Integration

The scanner supports optional integration with three external static analysis tools. These run as **subprocesses** — if a tool is not installed, it fails gracefully and returns no results.

### Supported Tools

| Tool | What It Does | Languages | Detection Source |
|------|-------------|-----------|-----------------|
| **CodeQL** | Data flow analysis with custom crypto queries | Java, JS, Python, Go, C/C++, C# | `codeql` |
| **cbomkit-theia** | Filesystem/container certificate & config scanning | N/A (file-based) | `cbomkit-theia` |
| **CryptoAnalysis** | CrySL-based typestate analysis for Java crypto APIs | Java | `cryptoanalysis` |

### Check Tool Availability

Before running scans, the pipeline calls `checkToolAvailability()` which tests whether each tool's CLI is accessible:
- `codeql --version`
- `cbomkit-theia --version`
- `java -jar CryptoAnalysis.jar --help`

### CodeQL Integration

When CodeQL is available, the scanner:

1. **Creates a CodeQL database** for the repository
2. **Runs custom `.ql` queries** that trace string values flowing into:
   - `MessageDigest.getInstance()` — resolves dynamic digest algorithm arguments
   - `Cipher.getInstance()` — resolves cipher transformation strings
   - `KeyGenerator.getInstance()` — resolves key generation algorithm arguments
   - `Signature.getInstance()` — resolves signature algorithm arguments
3. **Parses SARIF output** to extract resolved algorithm names with file locations
4. Each finding becomes a `CryptoAsset` with `detectionSource: 'codeql'`

### cbomkit-theia Integration

When cbomkit-theia is available:
- Runs `cbomkit-theia scan --format json <repoPath>`
- Parses the JSON output for certificate findings, java.security config, and OpenSSL config
- Each finding is converted to a `CryptoAsset` with `detectionSource: 'cbomkit-theia'`

### CryptoAnalysis Integration

When CryptoAnalysis is available:
- Runs `java -jar CryptoAnalysis.jar --appPath <repoPath> --reportFormat JSON`
- Parses the JSON report for crypto misuse findings with resolved arguments
- Each finding is converted to a `CryptoAsset` with `detectionSource: 'cryptoanalysis'`

### Deduplication with Regex Results

External tool findings are **deduplicated** against existing regex scanner results:
- If an external tool detects the same algorithm at the same file/line as a regex finding, the external result **enriches** the existing asset (boosts confidence) rather than creating a duplicate
- Novel findings (detected only by external tools) are added as new assets
- The `deduplicateExternalAssets()` function handles this merge logic

---

## Variable Resolution & Context Scanning

The regex scanner includes two advanced analysis capabilities that go beyond simple pattern matching.

### Supported Languages & Libraries

The built-in regex scanner ships with **1 000+ patterns** covering 8 language ecosystems plus configuration/artifact files:

| Language | File Extensions | Libraries / APIs Covered |
|----------|----------------|-------------------------|
| **Java** | `.java` | JCE (`MessageDigest`, `Cipher`, `Signature`, `KeyPairGenerator`, `Mac`, `KeyAgreement`, `SecretKeyFactory`), `SSLContext`, `X509Certificate`, `SecureRandom`, KeyStore/TrustManagerFactory/KeyManagerFactory, GCMParameterSpec/IvParameterSpec/PBEKeySpec/DHParameterSpec/ECGenParameterSpec, **BouncyCastle deep** — low-level engines (AESEngine, RSAEngine, DESedeEngine, BlowfishEngine, TwofishEngine, CamelliaEngine, SerpentEngine, CAST5, IDEA, RC4, ChaCha, Salsa20, SM4, ARIA), AEAD (GCM, CCM, EAX, OCB, ChaCha20Poly1305), block cipher modes (CBC, CTR, CFB, OFB), digests (SHA-256/384/512, SHA-1, SHA-3, MD5, RIPEMD-160, Blake2b/s, SM3, Whirlpool), MACs (HMac, CMac, GMac, Poly1305, SipHash), signers (RSADigestSigner, PSSSigner, ECDSASigner, Ed25519/448Signer, SM2Signer, DSADigestSigner), key generators (RSA/EC/Ed25519/Ed448/X25519/X448), KDF (PKCS5S2, HKDF, SCrypt, Argon2), **PQC** — ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon, XMSS/LMS/HSS, FrodoKEM, BIKE, HQC, CMCE, NTRU; key size extraction |
| **Python** | `.py` | `hashlib`, PyCrypto/PyCryptodome, `cryptography.hazmat` — cipher algorithms (AES, TripleDES, ChaCha20, Camellia, SM4), modes (CBC, GCM, CTR, CFB, OFB, XTS), RSA padding (OAEP, PSS, PKCS1v15), ECDH, named curves (P-256/384/521), MultiFernet, serialization, SHAKE-128/256, KDF (HKDF, PBKDF2, scrypt), RSA/EC/Ed25519/Ed448/X25519/X448/DH, X.509, Fernet; PyNaCl, `ssl`, `secrets`, `bcrypt`, `argon2`, `scrypt`, paramiko (SSH), PyJWT/jose, key size extraction; **PQC** — liboqs-python (`oqs.KeyEncapsulation`, `oqs.Signature`), pqcrypto package, ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon, FrodoKEM, BIKE, HQC, NTRU |
| **JavaScript / TypeScript** | `.js`, `.ts`, `.jsx`, `.tsx` | Node.js `crypto` (createHash, createCipher, createSign, ECDH, HKDF, scrypt, pbkdf2, generateKeyPair, createSecretKey, createPrivateKey, createPublicKey, sign, verify, generatePrime, X509Certificate, diffieHellman, getRandomValues), WebCrypto (`crypto.subtle`), TLS (`createSecureContext`, `https`); **npm packages** — crypto-js (AES, DES, 3DES, SHA-*, MD5, HMAC, PBKDF2, Rabbit, RC4), node-forge (cipher, md, pki, tls, hmac), elliptic (EC/EdDSA with curve extraction), @noble/hashes, @noble/curves, @noble/ed25519, @noble/secp256k1, node-rsa, openpgp, ssh2, bcrypt, jsonwebtoken, jose, tweetnacl, libsodium-wrappers, argon2; **PQC** — crystals-kyber, pqc, liboqs |
| **C / C++** | `.c`, `.cpp`, `.cxx`, `.cc`, `.h`, `.hpp`, `.hxx` | OpenSSL EVP + legacy APIs, libsodium, Botan (including PQC: Dilithium, Kyber, SPHINCS+), Crypto++, Windows CNG/BCrypt, wolfSSL, mbedTLS, GnuTLS |
| **C# / .NET** | `.cs` | `System.Security.Cryptography` (Create, Managed, CNG, CSP variants), HMAC, `Rfc2898DeriveBytes`, HKDF, `X509Certificate2`, `SslStream`, DPAPI, ASP.NET Core Data Protection, BouncyCastle .NET |
| **Go** | `.go` | `crypto/*` stdlib (`sha256`, `aes`, `rsa`, `ecdsa`, `ecdh`, `ed25519`, `hmac`, `tls`, `x509`, `rand`, `elliptic`, `cipher`), `golang.org/x/crypto` (`chacha20poly1305`, `argon2`, `bcrypt`, `scrypt`, `nacl`, `hkdf`, `pbkdf2`, `sha3`, `blake2b/s`, `ssh`, `curve25519`, `twofish`, `blowfish`, `cast5`, `tea`, `xtea`, `xts`, `poly1305`, `openpgp`, `acme`), **CIRCL PQC** (`kem/kyber`, `kem/mlkem`, `sign/dilithium`, `sign/mldsa`, `sign/ed448`, `kem/frodo`, `hpke`, `sign/sphincs`), liboqs-go (`oqs.KeyEncapsulation`, `oqs.Signature`), RSA key size extraction |
| **PHP** | `.php` | `openssl_*` (encrypt, sign, pkey, x509, pkcs), `hash`/`hash_hmac`/`hash_pbkdf2`, `password_hash` (bcrypt, argon2), `sodium_crypto_*` (secretbox, box, sign, aead, pwhash, kdf, kx), `mcrypt` (deprecated), phpseclib, Defuse PHP-Encryption |
| **Rust** | `.rs` | **ring** (digest, HMAC, AEAD, signatures, key agreement, KDF, PRNG), **RustCrypto** ecosystem (sha2, sha3, sha1, md5, blake2/3, aes, aes-gcm, chacha20poly1305, des, cbc/ctr modes, hmac/cmac/poly1305, rsa, ed25519-dalek, p256/p384/k256, ecdsa/dsa, x25519-dalek, hkdf/pbkdf2/scrypt/argon2/bcrypt, rand), **rustls** (TLS 1.2/1.3), **openssl** crate (symm, hash, sign, pkey, rsa, ec, ssl, x509), **sodiumoxide** (secretbox, box, sign, hash, auth, aead, scalarmult, pwhash, kdf, stream, generichash, randombytes), **snow** (Noise Protocol), **orion** (aead, hash, auth, kdf, pwhash), **PQC** — pqcrypto (dilithium, sphincsplus, falcon, kyber, saber, mceliece, hqc, bike, frodo), oqs crate (ML-DSA, ML-KEM, Falcon, SLH-DSA, BIKE, HQC, FrodoKEM, ClassicMcEliece), x509/rcgen/pem/pkcs8/pkcs1, Cargo.toml dependency detection |
| **Config / Artifacts** | `.pem`, `.crt`, `.key`, `.p12`, `.jks`, `.conf`, `.cnf`, `.security`, `.yml`, `.properties`, etc. | PEM-encoded certificates & private keys (X.509, RSA/EC/DSA/SSH/PKCS8), `java.security` (providers, disabled algorithms, keystore type, SecureRandom source), `openssl.cnf` (default_md, CipherString, MinProtocol/MaxProtocol, FIPS mode), Spring Boot `server.ssl.*`, ASP.NET `SslProtocols`, Nginx `ssl_protocols`/`ssl_ciphers`/`ssl_certificate`, Apache `SSLProtocol`/`SSLCipherSuite`, Docker/K8s TLS file refs, SSH config (`KexAlgorithms`, `Ciphers`, `MACs`) |

### Scanner Module Architecture

The scanner is organized into a modular structure under `backend/src/services/scanner/`:

```
scanner/
├── scannerTypes.ts          # CryptoPattern interface, file extension constants, skip patterns
├── scannerUtils.ts          # globToRegex, shouldExcludeFile, normaliseAlgorithmName, resolveVariableToAlgorithm (7 strategies)
├── contextScanners.ts       # scanWebCryptoContext, scanX509Context, scanNearbyContext
├── certificateFileScanner.ts # scanCertificateFiles, scanKeystoreFiles, discoverCertificateFiles
├── externalToolIntegration.ts # runExternalToolScans, checkToolAvailability, deduplicateExternalAssets
└── patterns/
    ├── index.ts             # Re-exports all patterns + combined allCryptoPatterns & allConfigPatterns arrays
    ├── javaPatterns.ts      # ~140 Java/JCE + deep BouncyCastle + PQC patterns
    ├── pythonPatterns.ts    # ~115 Python patterns (hazmat, PQC, paramiko, PyJWT)
    ├── jsPatterns.ts        # ~95 JavaScript/TypeScript patterns (crypto-js, node-forge, @noble, PQC)
    ├── cppPatterns.ts       # ~170 C/C++ patterns
    ├── csharpPatterns.ts    # ~100 C#/.NET patterns
    ├── goPatterns.ts        # ~165 Go patterns (x/crypto, CIRCL PQC, liboqs-go)
    ├── phpPatterns.ts       # ~130 PHP patterns
    ├── rustPatterns.ts      # ~170 Rust patterns (ring, RustCrypto, rustls, sodiumoxide, PQC)
    └── configPatterns.ts    # ~60 config/artifact patterns (PEM, java.security, openssl.cnf, TLS)
```

Each pattern file exports a `CryptoPattern[]` array. The `allCryptoPatterns` combined array is used by `scannerAggregator.ts` to drive the source code scan loop, while the separate `allConfigPatterns` array drives the configuration/artifact file scan phase.

### Variable-Argument Resolution

When the scanner encounters crypto API calls that use a **variable** instead of a string literal (e.g., `KeyPairGenerator.getInstance(algorithm)` instead of `getInstance("RSA")`), it attempts to **resolve the variable to an actual algorithm name** using **7 resolution strategies**.

**Resolution Strategies (in priority order):**

| # | Strategy | Description | Example |
|---|----------|-------------|--------|
| 1 | **Backward Search (100 lines)** | Scans up to 100 lines before the call site for `varName = "ALGORITHM"` assignments | `String algo = "RSA"; ... getInstance(algo)` |
| 2 | **Class-Level Constants** | Matches `static final`, `const`, `readonly` field declarations | `private static final String ALG = "AES";` |
| 3 | **Ternary / Conditional** | Extracts algorithm from ternary expressions assigned to the variable | `String alg = useNew ? "ML-KEM" : "RSA";` |
| 4 | **Enum / Switch-Case** | Detects enum constants or switch/case values near the variable | `case RSA: return "RSA"` |
| 5 | **Method Parameter → Call Site** | Traces method parameters to their call sites with positional argument matching | `void init(String alg) {...}` → `init("AES")` |
| 6 | **String Concatenation Root** | Extracts the root algorithm from concatenated strings | `"AES" + "/GCM/NoPadding"` → `AES` |
| 7 | **Cross-File Import** | Detects imported constants from other modules | `import { ALGORITHM } from './config'` |

**How it works:**

1. The scanner detects a variable-arg pattern like `KeyPairGenerator.getInstance(algo)`
2. It runs all 7 strategies in order, stopping at the first successful resolution
3. If resolved → the asset is named with the **actual algorithm** (e.g., `RSA`) and enriched with PQC data
4. If unresolved → the asset keeps a generic name with a description like *"Algorithm determined at runtime via variable `algo`"*

Additionally, `resolveVariableBackward()` provides a simpler backward search used by the PQC parameter analyzer when processing source context blocks.

**Supported variable patterns (Java):**
- `KeyPairGenerator.getInstance(variable)`
- `Cipher.getInstance(variable)`
- `MessageDigest.getInstance(variable)`
- `Signature.getInstance(variable)`
- `SecretKeyFactory.getInstance(variable)`
- `KeyAgreement.getInstance(variable)`
- `Mac.getInstance(variable)`

**Additional variable resolution:**
- **Go:** Traces function parameters and `var`/`:=` assignments to resolve algorithm names passed to `crypto/*` calls
- **Algorithm normalisation:** Handles OpenSSL cipher strings (e.g., `aes-256-gcm` → `AES`), Go import paths (e.g., `crypto/sha256` → `SHA-256`), and framework-specific naming conventions

### Context Scanning

For certain crypto patterns whose security depends on **how they're used**, the scanner examines surrounding source code to provide richer context.

**How it works:**

1. Patterns like `X509Certificate`, `X509TrustManager`, and `BouncyCastleProvider` trigger context scanning
2. The scanner reads ±30 lines around the detection site
3. It looks for `getInstance()` calls and signature algorithm references (e.g., `SHA256withRSA`, `ECDSA`)
4. The asset description is enriched, e.g.:
   > *"X.509 used alongside: SHA256withRSA, RSA. Review these algorithms for PQC readiness."*

**Context-scanned patterns:**

| Pattern | Detection | Context Gathered |
|---------|-----------|------------------|
| **X.509 Certificate** | `X509Certificate`, `X509TrustManager` | Nearby `getInstance()` calls, signature algorithms |
| **BouncyCastle Provider** | `new BouncyCastleProvider()`, `PROVIDER_NAME` | Nearby algorithm instantiations |

Additionally, the scanner performs **cross-file enrichment** for BouncyCastle-Provider assets: when a `BouncyCastleProvider` is detected via provider registration but no specific algorithm is found nearby, the scanner searches all other detected assets for BouncyCastle-specific low-level engine classes (e.g., `AESEngine`, `GCMBlockCipher`, `SHA256Digest`) and enriches the provider asset description with a summary of algorithms found elsewhere in the project.

This helps reviewers understand the **full cryptographic picture** around certificate and provider usage, even when the X.509 or provider reference itself doesn't name a specific algorithm.

### Configuration & Artifact File Scanning

Inspired by [cbomkit-theia](https://github.com/IBM/cbomkit)'s plugin architecture, the scanner includes a dedicated **configuration/artifact file scanning phase** that detects cryptographic settings in non-source-code files.

**How it works:**

1. After the source code scan completes, the scanner searches for configuration files by name and extension
2. Target files include: `java.security`, `openssl.cnf`, `application.properties`, `appsettings.json`, `nginx.conf`, `httpd.conf`, `sshd_config`, `Cargo.toml`, `go.sum`, plus files with extensions `.pem`, `.crt`, `.key`, `.p12`, `.jks`, `.cnf`, `.conf`, `.security`, etc.
3. Each file is scanned against `allConfigPatterns` (~60 dedicated patterns)
4. Binary files (DER certificates, JKS keystores) are automatically skipped
5. Detected items are added to the CBOM as first-class crypto assets with file location and description

**Detected configuration categories:**

| Category | What's Detected | Example Files |
|----------|----------------|---------------|
| **PEM Certificates & Keys** | X.509 certs, RSA/EC/DSA/PKCS8 private keys, public keys, CSRs, CRLs | `*.pem`, `*.crt`, `*.key` |
| **Java Security** | Security providers, disabled algorithms (TLS/certpath/JAR), keystore type, SecureRandom source | `java.security` |
| **OpenSSL Config** | Default digest/bits, cipher strings, min/max protocol, curves, FIPS mode | `openssl.cnf` |
| **Application Config** | TLS/SSL settings in application frameworks | `application.properties`, `application.yml`, `appsettings.json` |
| **Web Server TLS** | Protocol versions, cipher suites, certificate paths | `nginx.conf`, `httpd.conf`, `ssl.conf` |
| **SSH** | Key exchange algorithms, ciphers, MACs, host key algorithms | `sshd_config`, `ssh_config` |
| **Container/Orchestration** | TLS file references, certificate mounts | `Dockerfile`, `docker-compose.yml`, K8s manifests |

---

## Third-Party Dependency Scanning

The full scan pipeline (`POST /api/scan-code/full`) automatically discovers
cryptographic libraries declared in your project's dependency manifests,
resolves transitive dependencies where tools are available, and converts every
known algorithm into a first-class CBOM crypto-asset — all without touching
source code.

### How It Works — Step by Step

```
┌─────────────────────────────────────────────────────────────────┐
│  1. DISCOVER manifest files                                     │
│     find <repoPath> … -name "pom.xml" -o -name "package.json"  │
│     … skipping node_modules, .git, target, build, dist, vendor  │
├─────────────────────────────────────────────────────────────────┤
│  2. PARSE each manifest with an ecosystem-specific parser       │
│     parseMavenPom()  → pom.xml                                  │
│     parseGradleBuild() → build.gradle / build.gradle.kts        │
│     parsePackageJson() → package.json                           │
│     parseRequirementsTxt() → requirements.txt / requirements-*  │
│     parseSetupPy() → setup.py (install_requires)                │
│     parseGoMod() → go.mod                                       │
├─────────────────────────────────────────────────────────────────┤
│  3. MATCH against Known Crypto Library Database                 │
│     groupId:artifactId prefix match (Maven/Gradle)              │
│     exact package name match (npm, pip)                         │
│     module path prefix match (Go)                               │
├─────────────────────────────────────────────────────────────────┤
│  4. RESOLVE transitive dependencies (best-effort)               │
│     Maven  → mvn dependency:tree -DoutputType=text              │
│     npm    → npm ls --json --all (walks up to depth 5)          │
│     Others → manifest-level only (direct deps)                  │
├─────────────────────────────────────────────────────────────────┤
│  5. DEDUPLICATE by groupId:artifactId:packageManager            │
│     keep the entry with the lowest dependency depth             │
├─────────────────────────────────────────────────────────────────┤
│  6. CONVERT to CBOM CryptoAssets via cryptoLibToCBOMAssets()    │
│     each algorithm the library provides → separate crypto-asset │
│     enriched with PQC verdict + quantum safety status           │
└─────────────────────────────────────────────────────────────────┘
```

### Supported Manifest Files

| Ecosystem | Manifest File(s) | Parser | Transitive Resolution |
|-----------|------------------|--------|-----------------------|
| **Maven** | `pom.xml` | `parseMavenPom()` — extracts `<dependency>` blocks with `<groupId>`, `<artifactId>`, `<version>` | Yes — `mvn dependency:tree` (120 s timeout) |
| **Gradle** | `build.gradle` / `.kts` | `parseGradleBuild()` — matches `implementation`, `api`, `compileOnly`, `runtimeOnly`, `testImplementation` | Manifest-level only |
| **npm** | `package.json` | `parsePackageJson()` — reads `dependencies` + `devDependencies` via `JSON.parse` | Yes — `npm ls --json --all` (depth ≤ 5) |
| **pip** | `requirements.txt`, `requirements-*.txt` | `parseRequirementsTxt()` — handles `==`, `>=`, `~=` specifiers + comments/flags | Manifest-level only |
| **pip** | `setup.py` | `parseSetupPy()` — extracts from `install_requires=[…]` | Manifest-level only |
| **Go** | `go.mod` | `parseGoMod()` — parses `require` blocks + single require lines | Manifest-level only |

> Every parser records the **line number** in the manifest file where the
> dependency is declared, so the dashboard links directly to the right location.

### Known Crypto Library Database

The scanner ships a curated database of **50+ cryptographic libraries** across
four ecosystems. Each entry stores the library's display name, known
algorithms, quantum safety status, and a description.

**Maven / Gradle** — matched by `groupId:artifactId` prefix:

| Library | Key | Quantum Safety | Algorithms |
|---------|-----|---------------|------------|
| BouncyCastle Provider | `org.bouncycastle:bcprov` | Conditional | RSA, ECDSA, AES, SHA-256, Ed25519, ML-KEM, ML-DSA |
| BouncyCastle PKIX | `org.bouncycastle:bcpkix` | Not Quantum Safe | X.509, CMS, OCSP, RSA, ECDSA |
| BouncyCastle PQC | `org.bouncycastle:bcpqc` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA, FALCON, SPHINCS+ |
| BouncyCastle FIPS | `org.bouncycastle:bcfips` | Conditional | AES, SHA-256, RSA, ECDSA, HMAC, DRBG |
| Google Tink | `com.google.crypto.tink:tink` | Not Quantum Safe | AES-GCM, ECDSA, Ed25519, RSA-SSA-PKCS1 |
| Conscrypt | `org.conscrypt:conscrypt` | Not Quantum Safe | TLSv1.3, AES-GCM, ChaCha20-Poly1305, ECDHE |
| Nimbus JOSE+JWT | `com.nimbusds:nimbus-jose-jwt` | Not Quantum Safe | RSA, ECDSA, AES, Ed25519 |
| JJWT | `io.jsonwebtoken:jjwt` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| Apache Commons Crypto | `org.apache.commons:commons-crypto` | Quantum Safe | AES, AES-CTR, AES-CBC |
| Spring Security Crypto | `…:spring-security-crypto` | Conditional | PBKDF2, BCrypt, SCrypt, AES-GCM, Argon2 |
| Jasypt | `org.jasypt:jasypt` | Not Quantum Safe | PBKDF2, AES, DES, 3DES, MD5 |
| Argon2 JVM | `de.mkammerer:argon2-jvm` | Quantum Safe | Argon2id, Argon2i, Argon2d |

**npm** — matched by exact package name:

| Library | Package | Quantum Safety | Algorithms |
|---------|---------|---------------|------------|
| CryptoJS | `crypto-js` | Conditional | AES, DES, SHA-256, MD5, PBKDF2, RC4 |
| Node Forge | `node-forge` | Not Quantum Safe | RSA, AES, DES, X.509, TLS |
| TweetNaCl | `tweetnacl` | Not Quantum Safe | Curve25519, Ed25519, XSalsa20 |
| libsodium | `libsodium-wrappers` | Not Quantum Safe | X25519, Ed25519, ChaCha20-Poly1305, Argon2id |
| jsonwebtoken | `jsonwebtoken` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| jose | `jose` | Not Quantum Safe | RSA, ECDSA, Ed25519, AES-GCM |
| elliptic | `elliptic` | Not Quantum Safe | ECDSA, ECDH, secp256k1 |
| OpenPGP.js | `openpgp` | Not Quantum Safe | RSA, ECDSA, ECDH, AES |
| @noble/curves | `@noble/curves` | Not Quantum Safe | secp256k1, Ed25519, P-256, P-384 |
| @noble/hashes | `@noble/hashes` | Quantum Safe | SHA-256, SHA-3, BLAKE2, BLAKE3 |
| bcrypt | `bcrypt` | Quantum Safe | BCrypt |
| argon2 | `argon2` | Quantum Safe | Argon2id, Argon2i |
| pqcrypto | `pqcrypto` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA |
| crystals-kyber | `crystals-kyber` | Quantum Safe | ML-KEM |

**pip** — matched by normalized package name (underscore → hyphen):

| Library | Package | Quantum Safety | Algorithms |
|---------|---------|---------------|------------|
| cryptography | `cryptography` | Not Quantum Safe | RSA, ECDSA, AES, X.509, HKDF, PBKDF2 |
| PyCryptodome | `pycryptodome` | Not Quantum Safe | RSA, AES, DES, ChaCha20, scrypt |
| PyNaCl | `pynacl` | Not Quantum Safe | Curve25519, Ed25519, BLAKE2b |
| pyOpenSSL | `pyopenssl` | Not Quantum Safe | RSA, ECDSA, TLS, X.509 |
| PyJWT | `pyjwt` | Not Quantum Safe | HMAC-SHA256, RSA, ECDSA |
| passlib | `passlib` | Conditional | BCrypt, SCrypt, Argon2, PBKDF2 |
| bcrypt | `bcrypt` | Quantum Safe | BCrypt |
| argon2-cffi | `argon2-cffi` | Quantum Safe | Argon2id, Argon2i |
| pqcrypto | `pqcrypto` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA |
| liboqs-python | `oqs` | Quantum Safe | ML-KEM, ML-DSA, FALCON |

**Go** — matched by module path prefix:

| Library | Module | Quantum Safety | Algorithms |
|---------|--------|---------------|------------|
| golang.org/x/crypto | `golang.org/x/crypto` | Not Quantum Safe | ChaCha20-Poly1305, Ed25519, Argon2, BCrypt |
| Cloudflare CIRCL | `github.com/cloudflare/circl` | Quantum Safe | ML-KEM, ML-DSA, SLH-DSA, X25519, HPKE |
| liboqs-go | `github.com/open-quantum-safe/liboqs-go` | Quantum Safe | ML-KEM, ML-DSA, FALCON |

### Transitive Dependency Resolution

When available tooling exists on the runner, the scanner resolves dependencies
*beyond* the manifest file:

**Maven** — runs `mvn dependency:tree -DoutputType=text -q` (120 s timeout),
parses the indented tree output to calculate depth and identify crypto
libraries hidden behind non-crypto intermediaries.

**npm** — runs `npm ls --json --all` (60 s timeout), recursively walks the
dependency tree up to **depth 5** with cycle detection (`visited` set).

Both resolvers skip depth 0 entries (already captured by manifest parsing) and
tag results with `isDirectDependency: false` and the actual depth number.

> If Maven or npm are not installed (e.g. in the GitHub Action Docker image
> before a `build` step), transitive resolution fails silently and the scanner
> returns only direct dependencies.

### From Library to CBOM Asset

Each detected library is exploded into **one CryptoAsset per algorithm**. For
example, `node-forge` in `package.json` produces separate assets for RSA, AES,
DES, 3DES, SHA-256, MD5, HMAC, PBKDF2, X.509, and TLS — each with:

| Field | Value |
|-------|-------|
| `name` | The algorithm name (e.g. `RSA`) |
| `type` | `crypto-asset` |
| `cryptoProperties.assetType` | `algorithm`, `certificate`, or `protocol` |
| `location.fileName` | Manifest path (e.g. `package.json`) |
| `location.lineNumber` | Line where the dependency is declared |
| `provider` | Library display name (e.g. `Node Forge`) |
| `detectionSource` | `dependency` |
| `description` | "Provided by Node Forge v1.3.1 (npm: node-forge). Detected as a direct dependency in package.json:12." |
| `quantumSafety` | Enriched by `enrichAssetWithPQCData()` from the PQC Risk Engine |

### Deduplication

After all parsers + transitive resolvers run, the scanner deduplicates by
`groupId:artifactId:packageManager`. When duplicates exist (e.g. a library
appears both as a direct and transitive dependency), the entry with the
**lowest depth** wins, ensuring the most direct reference is kept.

### Dashboard View

The frontend displays a **Third-Party Crypto Libraries** section below the asset list, showing:
- Safety badge (Quantum Safe / Not Quantum Safe / Conditional / Unknown)
- Package manager badge (Maven, npm, pip, Go)
- Direct vs. transitive dependency indicator
- Transitive depth (how many hops from your direct dependencies)
- Expandable cards with dependency path and known algorithms
- Filter by package manager

---

## PQC Readiness Verdicts

For assets classified as **Conditional** (e.g., PBKDF2, AES, SecureRandom, KeyPairGenerator), the scanner now performs **smart parameter analysis** to deliver definitive PQC readiness verdicts instead of vague labels.

### How It Works

1. The scanner detects a conditional crypto usage (e.g., `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`)
2. It reads ±15 lines of surrounding source code
3. It extracts actual parameters (iteration count, key length, algorithm, provider)
4. It applies PQC-aware rules to emit a verdict with confidence score

### Verdict Types

| Verdict | Meaning | Example |
|---------|---------|--------|
| **PQC_READY** | Safe for the post-quantum era | AES-256, PBKDF2 ≥ 600k iterations + 256-bit key |
| **NOT_PQC_READY** | Vulnerable to quantum attack | RSA-2048 KeyPairGenerator, ECDSA Signature |
| **REVIEW_NEEDED** | Cannot determine automatically | Custom providers, runtime-selected algorithms |

### Analyzers

| Crypto Pattern | What's Extracted | Verdict Rules |
|---------------|-----------------|---------------|
| **PBKDF2** | Iteration count, key length, hash algorithm | ≥ 600k iterations + ≥ 256-bit key + SHA-256/512 → PQC_READY |
| **AES** | Key size (128/192/256) from constant or variable name | AES-256 → PQC_READY; AES-128 → NOT_PQC_READY |
| **SecureRandom** | Provider (NativePRNG, DRBG, SHA1PRNG, default) | DRBG/NativePRNG → PQC_READY; default → REVIEW_NEEDED |
| **KeyPairGenerator** | Algorithm (RSA, EC, ML-KEM, ML-DSA, etc.) | RSA/EC → NOT_PQC_READY; ML-KEM/ML-DSA → PQC_READY |
| **Signature** | Algorithm (SHA256withRSA, SHA384withECDSA, etc.) | RSA/ECDSA → NOT_PQC_READY; ML-DSA → PQC_READY |
| **SecretKeyFactory** | Delegates to PBKDF2 or AES analysis | Based on underlying algorithm |
| **X.509 Certificate** | Certificate type, signature algorithm, key usage | RSA/ECDSA-signed certs → NOT_PQC_READY; PQC-signed → PQC_READY |
| **TLS/SSL** | Protocol version, cipher suite | TLS 1.3 with PQC KEM → PQC_READY; legacy suites → NOT_PQC_READY |
| **TSP (Timestamping)** | Timestamp hash algorithm | SHA-256+ → REVIEW_NEEDED; SHA-1 → NOT_PQC_READY |
| **CMS/PKCS#7** | Signing algorithm, envelope encryption | RSA/ECDSA → NOT_PQC_READY |
| **OCSP** | Response signing algorithm | RSA/ECDSA → NOT_PQC_READY |

### Algorithm Database Entries

The scanner includes a comprehensive **ALGORITHM_DATABASE** with quantum safety classifications for 100+ algorithms. Recent additions include:

| Algorithm | Classification | Notes |
|-----------|---------------|-------|
| `CAST5` | NOT_QUANTUM_SAFE | Legacy 64-bit block cipher |
| `ElGamal` | NOT_QUANTUM_SAFE | Discrete logarithm-based |
| `MessageDigest` | CONDITIONAL | Java JCE wrapper — safety depends on underlying algorithm |
| `NONE` | NOT_QUANTUM_SAFE | Raw signature without digest — no cryptographic protection |
| `NONEwithRSA` | NOT_QUANTUM_SAFE | RSA signature without hashing |
| `NONEwithECDSA` | NOT_QUANTUM_SAFE | ECDSA signature without hashing |

Non-cryptographic hash functions (`CRC32`, `Murmur3`) are **excluded** from scanning results — they are checksums, not crypto primitives.

### Informational Asset Filtering

Some detected crypto assets are **informational** rather than actionable. The PQC Risk Engine marks these with `isInformational: true` and applies special handling:

| Asset | Why Informational |
|-------|-------------------|
| `BouncyCastle-Provider` | Provider registration, not algorithm usage — actual algorithms detected separately |
| `JCE-Signature-Registration` | Java JCE service registration boilerplate |
| `JCE-KeyPairGen-Registration` | Java JCE service registration boilerplate |
| `JCE-Digest-Registration` | Java JCE service registration boilerplate |

**Informational assets receive:**
- Confidence: **10** (minimal)
- PQC status: **COMPLIANT**
- Name prefix: **[INFORMATIONAL]**
- Excluded from risk scoring and conditional/unknown counts

Use `isInformationalAsset(asset)` to check or `filterInformationalAssets(assets)` to remove them from reports.

### Promotion Rules

- If verdict is `PQC_READY` or `NOT_PQC_READY` with **confidence ≥ 75%**, the asset's `quantumSafety` status is automatically promoted from `CONDITIONAL` to `QUANTUM_SAFE` or `NOT_QUANTUM_SAFE`
- Otherwise, the asset stays `CONDITIONAL` with the verdict attached for manual review

### Scoring Impact

Verdicts affect the readiness score:
- `PQC_READY` → weight 1.0 (full marks)
- `NOT_PQC_READY` → weight 0.0 (zero)
- `REVIEW_NEEDED` → weight 0.5 (partial)
- Unanalyzed conditional → weight 0.75 (legacy)

---

*Back to [README](../README.md) · See also [API Reference](api-reference.md) · [PQC Standards](pqc-standards.md)*
