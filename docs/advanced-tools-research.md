# Advanced Cryptographic Detection Tools — Research & Integration Guide

> **Purpose:** Catalog advanced cryptographic misuse/detection tools, evaluate their
> relevance for resolving hard CBOM classification cases (X.509 from dependencies,
> BouncyCastle-Provider, WebCrypto dynamic args, MessageDigest dynamic args), and
> document integration strategies.

---

## 1. Tool Catalog

### 1.1 CogniCrypt (CogniCryptSAST / CrySL)

| Attribute | Detail |
|-----------|--------|
| **Repository** | [CROSSINGTUD/CryptoAnalysis](https://github.com/CROSSINGTUD/CryptoAnalysis) |
| **Language** | Java (JCA, JCE, BouncyCastle, Tink) |
| **Type** | Static analysis — typestate + pointer analysis |
| **License** | EPL-2.0 |
| **Stars** | ~78 |
| **Latest** | v5.0.1 (Aug 2025) |
| **Framework** | Built on Soot, SootUp, and Opal static analysis frameworks |

**What it does:**
- Takes **CrySL rules** (a domain-specific language) that encode correct usage
  specifications for cryptographic APIs
- Performs context-sensitive, field-sensitive, flow-sensitive typestate and pointer analysis
- Detects: `ConstraintError`, `TypestateError`, `ImpreciseValueExtractionError`,
  `IncompleteOperationError`, `RequiredPredicateError`, `ForbiddenMethodError`
- Resolves **dynamic arguments** through data-flow analysis — exactly what's needed
  for `MessageDigest.getInstance(variable)` and `Cipher.getInstance(variable)`

**Relevance to our hard cases:**
- **BC-Provider (~107 assets):** CrySL has dedicated rules for BouncyCastle-JCA and
  BouncyCastle libraries. It can trace `Security.addProvider(new BouncyCastleProvider())`
  to actual algorithm usage via typestate analysis.
- **MessageDigest dynamic args:** CogniCrypt's data-flow engine tracks string values
  flowing into `MessageDigest.getInstance()`, `Cipher.getInstance()`, etc.
- **X.509 from dependencies:** When run on compiled JARs, CogniCrypt analyzes the
  full call graph including transitive dependencies.

**Integration approach:**
```bash
# GitHub Action integration (already supported)
- name: Run CogniCrypt
  uses: CROSSINGTUD/CryptoAnalysis@5.0.1
  with:
    appPath: "target/myapp.jar"
    basePath: "src/main/java"
    reportFormat: SARIF

# CLI integration
java -jar HeadlessJavaScanner-5.0.1-jar-with-dependencies.jar \
  --appPath target/myapp.jar \
  --rulesDir ./CrySL-Rules/ \
  --reportFormat SARIF \
  --reportPath ./output/
```

**Our integration:** Already scaffolded in `externalToolIntegration.ts` →
`runCryptoAnalysis()`. Parses SARIF output and maps errors to CryptoAsset entries.

---

### 1.2 CryptoGuard

| Attribute | Detail |
|-----------|--------|
| **Repository** | [CryptoGuardOSS/cryptoguard](https://github.com/CryptoGuardOSS/cryptoguard) |
| **Language** | Java (source, JAR, APK, .class files) |
| **Type** | Static analysis — program analysis for crypto misuse |
| **License** | GPL-3.0 |
| **Stars** | ~121 |
| **Latest** | v04.05.03 (2020, archived) |
| **Framework** | Soot-based analysis |

**What it does:**
- Scans Java source, JARs, APKs, and even individual .class files
- Detects 6 categories of misuse: weak algorithms, weak key sizes, predictable
  seeds, insecure modes, hardcoded credentials, bad TLS configurations
- Uses program slicing to trace variable values to crypto API call sites

**Relevance to our hard cases:**
- **MessageDigest dynamic args:** CryptoGuard's backward slicing can resolve variable
  values flowing into `MessageDigest.getInstance()` calls
- **KeyPairGenerator dynamic args:** Traces `initialize(keySize)` to resolve key sizes
- Complements CogniCrypt with different analysis approach (slicing vs typestate)

**Limitations:**
- Last updated 2020, Java 8 required for some scan modes
- No BouncyCastle-specific support beyond JCA bridge
- No CI/CD integration (standalone tool)

**Integration approach:**
```bash
java -jar cryptoguard.jar -in source -s /project/root -m D -o output.json
```
Output is JSON with `BugInstance` entries containing algorithm, location, and bug type.

---

### 1.3 Joern

| Attribute | Detail |
|-----------|--------|
| **Repository** | [joernio/joern](https://github.com/joernio/joern) |
| **Language** | C/C++, Java, JavaScript, Python, Kotlin, binary |
| **Type** | Code Property Graph (CPG) analysis platform |
| **License** | Apache-2.0 |
| **Stars** | ~3,000 |
| **Latest** | v4.0.492 (actively maintained, daily releases) |

**What it does:**
- Generates Code Property Graphs (CPGs) — a unified graph combining AST,
  control-flow, data-flow, and call graphs
- Provides a Scala-based query language for mining the CPG
- Supports cross-language analysis (crucial for polyglot projects)

**Relevance to our hard cases:**
- **WebCrypto dynamic args:** Joern's JavaScript CPG can trace `crypto.subtle.encrypt({name: algo})`
  backward through variable assignments and function parameters
- **MessageDigest dynamic args:** Java CPG + data-flow tracking resolves string
  constants flowing to `getInstance()` calls
- **X.509 from dependencies:** With bytecode analysis, Joern can build CPGs from
  compiled JARs including dependency code
- **Cross-language:** Can analyze Java + TypeScript + Python in a single scan

**Custom query for crypto detection:**
```scala
// Find all MessageDigest.getInstance() calls and resolve the algorithm argument
cpg.call.name("getInstance")
  .where(_.typeFullName(".*MessageDigest.*"))
  .argument(1)
  .reachableByFlows(cpg.literal)
  .l

// Find WebCrypto subtle.encrypt with algorithm parameter
cpg.call.name("encrypt")
  .where(_.receiver.code(".*subtle.*"))
  .argument(1)
  .code
  .l
```

**Integration approach:**
```bash
# Docker-based (recommended)
docker run --rm -v $(pwd):/app ghcr.io/joernio/joern \
  joern --script /app/crypto-queries.sc --params inputPath=/app

# Or via joern-cli
joern-parse /path/to/project
joern --script crypto-resolution.sc
```

**Our potential integration:** Could be added to `externalToolIntegration.ts` as a
new scanner. Output would be custom JSON from Joern scripts.

---

### 1.4 Binarly Transparency Platform

| Attribute | Detail |
|-----------|--------|
| **Website** | [binarly.io](https://binarly.io) |
| **Type** | Commercial platform — binary analysis + CBOM generation |
| **Focus** | Firmware, containers, software supply chain |
| **Patent** | U.S. Patent No. 12153686 for CBOM generation from binaries |

**Key capabilities (v2.7+):**
- **Cryptographic reachability analysis** — determines which crypto algorithms in
  a binary are actually reachable (used) vs. dead code
- **PQC compliance** — NIST IR 8547 compliance checking
- **Binary CBOM generation** — patented process for extracting CBOMs from binary
  executables (no source needed)
- **YARA integration** (v3.5) — custom detection rules for crypto patterns

**Relevance to our hard cases:**
- **X.509 from dependencies:** Binary analysis can discover certificates embedded
  in compiled dependencies without source access
- **Cryptographic reachability** — eliminates false positives from statically-linked
  libraries (e.g., OpenSSL) where not all algorithms are actually used
- Their approach of binary-level CBOM generation is complementary to our source-level
  scanning

**Integration approach:**
- API-based (commercial, requires license)
- Free tier via [Binary Risk Hunt](https://risk.binarly.io/) for individual scans
- Could export CBOM in CycloneDX format for import into our platform

---

### 1.5 CamBench

| Attribute | Detail |
|-----------|--------|
| **Repository** | [CROSSINGTUD/CamBench](https://github.com/CROSSINGTUD/CamBench) |
| **Type** | Benchmark suite (not a detection tool) |
| **License** | Apache-2.0 |
| **Paper** | arXiv:2204.06447 (MSR 2022 Registered Report) |

**What it is:**
- **CamBench_Real** — real-world Java applications with manually labeled usages
- **CamBench_Cap** — synthetic test cases covering analysis capabilities
- **CamBench_Cov** — heuristic for crypto API coverage measurement

**Relevance:** Not a scanner, but a **validation resource**. We can use CamBench_Real
to validate our scanner's accuracy on real apps and CamBench_Cap to test coverage
of our analyzers against known capabilities.

---

### 1.6 Frida

| Attribute | Detail |
|-----------|--------|
| **Website** | [frida.re](https://frida.re) |
| **Type** | Dynamic instrumentation toolkit |
| **Languages** | Any (hooks native functions at runtime) |
| **License** | Free software |
| **Platforms** | Windows, macOS, Linux, iOS, Android, FreeBSD, QNX |

**What it does:**
- Injects JavaScript scripts into running processes
- Can hook crypto API functions at runtime to intercept actual arguments
- No source code required — works on black-box binaries

**Relevance to our hard cases:**
- **WebCrypto dynamic args:** Could hook `crypto.subtle.*` in Node.js to capture
  actual algorithm parameters at runtime
- **MessageDigest dynamic args:** Hook `java.security.MessageDigest.getInstance()`
  to capture the actual string argument
- **BC-Provider:** Hook `Security.addProvider()` and subsequent crypto calls to
  trace actual usage
- **Runtime certificate analysis:** Hook TLS handshake to capture negotiated cipher suites

**Integration approach:**
```javascript
// Frida script for Java crypto hooking
Java.perform(function() {
  var MessageDigest = Java.use('java.security.MessageDigest');
  MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
    console.log('[MessageDigest] Algorithm: ' + algo);
    return this.getInstance(algo);
  };
});
```

**Limitations:**
- Requires running the application (dynamic analysis)
- Only captures code paths actually executed
- Not suitable for CI/CD static analysis workflows

---

### 1.7 CRYLOGGER

| Attribute | Detail |
|-----------|--------|
| **Type** | Dynamic analysis for Android crypto misuse detection |
| **Paper** | "Crylogger: Detecting Crypto Misuses Dynamically" (S&P 2021) |
| **Approach** | Instruments Android runtime to log crypto API calls |

**What it does:**
- Patches the Android runtime to intercept JCA API calls
- Logs algorithm, key size, IV, and all parameters at runtime
- Checks 26 crypto rules covering weak algorithms, short keys, ECB mode, etc.

**Relevance:** Similar to Frida but Android-specific and fully automated. Could be
a reference for our dynamic analysis approach if we add Android app scanning.

---

### 1.8 Additional Tools & Resources

| Tool | Type | Relevance |
|------|------|-----------|
| **YARA** | Pattern matching | Custom rules for detecting crypto patterns in binaries. Binarly uses this extensively. |
| **KLEE** | Symbolic execution | Can explore all paths through crypto code to find all possible algorithm arguments. Heavy but thorough. |
| **CryptoDeps** | Dependency analyzer | Maps crypto library dependencies in build files (Maven, Gradle, npm). |
| **semgrep** | Pattern matching | Custom rules for crypto API patterns across languages. Lighter than CodeQL. |
| **cbomkit-theia** | Container scanner | IBM's tool for scanning Docker images for crypto materials. Already integrated. |

---

## 2. Hard Case Resolution Strategies

### 2.1 X.509 from Dependencies (~166 conditional)

**Problem:** `X.509` appears as an algorithm name from BouncyCastle dependency JARs.
The actual signing/hash algorithm is inside the certificate, not in the code.

**Current resolution (implemented):**
- Phase 1A: `certificateFileScanner.ts` parses `.pem`, `.crt`, `.der` files in repo
  to extract actual signature algorithms (SHA256withRSA, ECDSA-SHA384, etc.)
- ALGORITHM_DATABASE entry for `X.509`: classified as `conditional` with note that
  certificate-specific algorithm resolution is needed

**Advanced resolution strategies:**
1. **CogniCrypt + CrySL rules** — Can trace X509Certificate usage to determine what
   operations are performed (signing, verification, key extraction)
2. **Joern CPG queries** — Cross-reference X509Certificate call sites with the actual
   algorithms used downstream: `cert.getSigAlgName()`, `cert.getPublicKey()`
3. **Binary analysis (Binarly)** — Extract embedded certificates from compiled JARs
4. **keytool / openssl integration** — Already scaffolded in externalToolIntegration.ts
   for extracting cert details from JKS/PKCS12 keystores

**Recommended next step:** Enhance parameter analyzer to detect `CertificateFactory.getInstance("X.509")`
patterns and extract the actual certificate operations from surrounding code context.

### 2.2 BouncyCastle-Provider (~107 conditional)

**Problem:** `BouncyCastle-Provider` appears when `Security.addProvider(new BouncyCastleProvider())`
is detected. This is a provider registration, not an algorithm.

**Current resolution (implemented):**
- Phase 1C: BC-Provider entries in ALGORITHM_DATABASE marked as `isInformational: true`
- `enrichAssetWithPQCData` gives these a special low-confidence (10) REVIEW_NEEDED verdict
- UI filters them from actionable statistics

**Advanced resolution strategies:**
1. **CogniCrypt with BC CrySL rules** — CROSSINGTUD/Crypto-API-Rules has dedicated
   `BouncyCastle-JCA` and `BouncyCastle` rule sets. These trace from provider registration
   to actual algorithm usage through the JCA bridge.
2. **Joern data-flow** — Query: find all `Cipher.getInstance(algo, "BC")` and
   `KeyGenerator.getInstance(algo, bcProvider)` calls that flow from the provider registration
3. **CodeQL** — Our existing CodeQL queries already handle this via taint tracking from
   `getInstance` arguments

**Recommended next step:** Link BC-Provider informational entries to the actual algorithm
assets found in the same file/class. The provider entry becomes a "parent" with actual
algorithms as "children" in the UI.

### 2.3 WebCrypto Dynamic Args (~1 conditional)

**Problem:** `crypto.subtle.encrypt({name: algo}, key, data)` where `algo` is a
variable determined at runtime.

**Current resolution (implemented):**
- `analyzeWebCrypto()` analyzer in pqcParameterAnalyzer.ts extracts algorithm from
  source context using regex patterns:
  - `{name: 'AES-GCM'}` or `{name: "RSA-OAEP"}`
  - `algorithm.name`, `algo.name` variable patterns
  - `subtle.generateKey`, `subtle.importKey`, `subtle.deriveKey` patterns

**Advanced resolution strategies:**
1. **Joern JavaScript CPG** — Build full data-flow graph for JavaScript/TypeScript,
   trace `algo` variable backward to its assignment or parameter source
2. **CodeQL JavaScript** — Similar data-flow analysis for QL-based resolution
3. **Frida runtime hooking** — If running in Node.js, hook `crypto.subtle.*` to
   capture actual arguments

**Recommended next step:** Enhance `analyzeWebCrypto()` with deeper variable resolution:
follow `const algo = ...` assignments in ±30 lines of context.

### 2.4 MessageDigest Dynamic Args (~40+ conditional)

**Problem:** `MessageDigest.getInstance(variable)` where the algorithm string comes
from a variable, method parameter, or configuration.

**Current resolution (implemented):**
- Enhanced variable resolution patterns in scanner code look for:
  - Direct string assignment: `String algo = "SHA-256"; ... getInstance(algo)`
  - Constant references: `getInstance(HASH_ALGORITHM)` → find `static final String HASH_ALGORITHM = "SHA-256"`
  - Method parameters: Track up one level to find actual arguments

**Advanced resolution strategies:**
1. **CogniCrypt** — Best tool for this. Its data-flow engine specifically tracks
   String values through JCA API calls. The CrySL rules encode allowed values.
2. **CryptoGuard** — Backward slicing resolves variable values to call sites
3. **CodeQL data-flow** — Already scaffolded in our CodeQL queries (`MessageDigestFlow`)
4. **Joern CPG** — `cpg.call.name("getInstance").argument(1).reachableByFlows(cpg.literal)`

**Recommended next step:** Our variable resolution covers ~60% of cases. For the remaining
~40%, run CogniCrypt or CodeQL as a secondary pass on the compiled JAR.

---

## 3. Integration Priority Matrix

| Tool | Effort | Impact | Priority | Status |
|------|--------|--------|----------|--------|
| CogniCrypt (SARIF) | Medium | High (resolves MessageDigest, BC-Provider) | **P1** | Scaffolded in `externalToolIntegration.ts` |
| CodeQL | Medium | High (resolves dynamic args across languages) | **P1** | Scaffolded in `externalToolIntegration.ts` |
| Joern | High | Very High (cross-language, deep analysis) | **P2** | Not yet scaffolded |
| cbomkit-theia | Low | Medium (container crypto scanning) | **P1** | Scaffolded in `externalToolIntegration.ts` |
| Frida | High | Medium (runtime-only, not CI/CD) | **P3** | Not applicable for static analysis |
| Binarly | Low | High (binary CBOM) | **P2** | Would require API integration |
| CryptoGuard | Medium | Medium (Java-only, archived) | **P3** | Not scaffolded |
| semgrep | Low | Medium (pattern matching) | **P2** | Easy to add custom rules |
| YARA | Low | Low (binary patterns only) | **P3** | Not applicable for source analysis |
| KLEE | Very High | Low (symbolic execution, niche) | **P4** | Not practical for CI/CD |
| CamBench | Low | Medium (validation only) | **P2** | Use for testing accuracy |

---

## 4. Existing Implementation Review

### What's Working (Verified)

| Feature | File | Status |
|---------|------|--------|
| Certificate file scanner (Phase 1A) | `certificateFileScanner.ts` (679 lines) | ✅ Scans .pem/.crt/.der files |
| External tool integration (Phase 2A/3) | `externalToolIntegration.ts` (829 lines) | ✅ CodeQL, cbomkit-theia, CryptoAnalysis |
| BC-Provider reclassification (Phase 1C) | `pqcRiskEngine.ts` | ✅ `isInformational` flag + override |
| PQC parameter analysis (17 analyzers) | `pqcParameterAnalyzer.ts` (1323 lines) | ✅ Context-aware resolution |
| 10-step aggregation pipeline | `scannerAggregator.ts` | ✅ Ordered: scan→cert→external→merge→analyze |
| Bare-number normalization | `pqcRiskEngine.ts` | ✅ "3072" → "RSA-3072" |
| ALGORITHM_DATABASE (40+ entries) | `pqcRiskEngine.ts` | ✅ Covers ring, PKCS12, PBE, curves, etc. |
| Informational asset filtering | `pqcRiskEngine.ts`, `cbomRoutes.ts` | ✅ Excluded from stats/compliance |

### 17 Parameter Analyzers

1. `analyzePBKDF2` — Iteration count, key length, hash extraction
2. `analyzeAES` — Key size detection (128/192/256)
3. `analyzeSecureRandom` — Provider/seed source analysis
4. `analyzeKeyPairGenerator` — Algorithm + key size from context
5. `analyzeDigitalSignature` — Signature algorithm resolution
6. `analyzeSecretKeyFactory` — PBE/KDF algorithm detection
7. `analyzeWebCrypto` — `crypto.subtle` algorithm extraction
8. `analyzeBcrypt` — Cost factor analysis
9. `analyzeArgon2` — Memory/time/parallelism parameters
10. `analyzeGenericBlockCipher` — Mode detection (CBC/GCM/ECB)
11. `analyzeEVP` — OpenSSL EVP_* function analysis
12. `analyzeKeyAgreement` — ECDH/DH/X25519 detection
13. `analyzeKeyGenerator` — Symmetric key generation analysis
14. `analyzeGenericHash` — Hash algorithm extraction
15. `analyzeGenericCipher` — Multi-language cipher detection
16. `analyzeGenericKDF` — KDF algorithm classification
17. `analyzeScrypt` — Scrypt parameter analysis

---

## 5. Recommended Roadmap

### Phase 4: Tool Integration (Next)

1. **Install CogniCrypt in CI** — Add `CROSSINGTUD/CryptoAnalysis@5.0.1` GitHub Action
   to the scanning workflow. Map SARIF results to our asset format.
2. **Install CodeQL** — Add `github/codeql-action` with custom crypto queries.
   Parse SARIF and merge with existing findings.
3. **Add Joern scaffolding** — Write crypto-specific Joern Scala scripts for the three
   main resolution queries (MessageDigest, Cipher, WebCrypto). Docker-based execution.

### Phase 5: Enhanced Resolution

1. **Parent-child linking** — Connect BC-Provider informational entries to actual
   algorithm assets in the same scope
2. **Certificate chain analysis** — Follow certificate chains to determine CA vs
   leaf certificate trust relationships
3. **Cross-file variable resolution** — Build a simple intra-project constant map
   for crypto-related string constants

### Phase 6: Benchmark & Validation

1. **CamBench validation** — Run our scanner against CamBench_Cap and CamBench_Real
   to measure precision, recall, and F1 score
2. **Snowbird regression suite** — Automate CBOM comparison between scanner versions
   to detect regressions in classification
