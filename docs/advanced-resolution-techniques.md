# Advanced Techniques for Resolving Irreducible Crypto Classifications

This document synthesizes research on advanced tools and techniques that can resolve the ~1,500 crypto assets currently classified as **conditional** or **unknown** by our regex-based scanner — cases documented as "irreducible" in [pqc-classification-analysis.md](pqc-classification-analysis.md).

---

## Table of Contents

1. [Problem Summary](#problem-summary)
2. [Tool & Technique Inventory](#tool--technique-inventory)
   - [CBOMKit Ecosystem (PQCA)](#1-cbomkit-ecosystem-pqca)
   - [CogniCryptSAST / CryptoAnalysis](#2-cognicryptsast--cryptoanalysis)
   - [CryptoGuard](#3-cryptoguard)
   - [CodeQL Crypto Queries](#4-codeql-crypto-queries)
   - [Joern CPG Platform](#5-joern-cpg-platform)
   - [Frida Dynamic Instrumentation](#6-frida-dynamic-instrumentation)
   - [YARA Binary Detection](#7-yara-binary-detection)
   - [Certificate File Parsing](#8-certificate-file-parsing-custom)
3. [Feasibility Matrix](#feasibility-matrix)
4. [Prioritized Implementation Plan](#prioritized-implementation-plan)
5. [Impact Estimates](#impact-estimates)
6. [Architecture for Integration](#architecture-for-integration)

---

## Problem Summary

Our current scanner uses **regex-based pattern matching** across 8 languages with 1,000+ patterns. This works well for literal API calls but fails for:

| Category | Count | Root Cause | Example |
|----------|-------|------------|---------|
| **X.509 from dependencies** | ~1,350 | No source context; certificate format, not algorithm | BouncyCastle JAR contains X.509 support |
| **BouncyCastle-Provider** | ~137 | Provider registration ≠ algorithm usage | `Security.addProvider(new BouncyCastleProvider())` |
| **WebCrypto with dynamic args** | ~49 | Variable argument, not string literal | `crypto.subtle.encrypt({name: alg}, ...)` |
| **MessageDigest with dynamic args** | ~3 | Variable argument | `MessageDigest.getInstance(algorithmVar)` |
| **Partial KDF/SecureRandom** | ~30 | Missing parameter context | PBKDF2 from dependencies |

**Total: ~1,569 assets** that static regex analysis cannot definitively classify.

---

## Tool & Technique Inventory

### 1. CBOMKit Ecosystem (PQCA)

> **Source:** [github.com/IBM/sonar-cryptography](https://github.com/IBM/sonar-cryptography) | [github.com/IBM/cbomkit](https://github.com/IBM/cbomkit) | [github.com/IBM/cbomkit-theia](https://github.com/IBM/cbomkit-theia)

#### sonar-cryptography (Hyperion) — AST-Based Detection

- **What it is:** SonarQube plugin that uses **AST and semantic analysis** (not regex) to detect cryptographic API usage
- **Languages:** Java (JCA 100%, BouncyCastle light-weight API 100%), Python (pyca/cryptography 100%), Go (crypto stdlib 100%)
- **Key capability:** Resolves variable values through SonarQube's data flow engine — directly addresses the "dynamic argument" problem
- **Output:** CycloneDX CBOM v1.6 with algorithms, keys, evidence (source locations), dependencies, OIDs, primitives, modes, padding
- **Architecture:** Modular detection rule system with translation/enrichment pipeline
- **Version:** v1.5.1 | 55 stars | Active development
- **License:** Apache 2.0

**Relevance to our problems:**
- ✅ Resolves `MessageDigest.getInstance(variable)` — AST traces variable assignments
- ✅ Resolves `crypto.subtle.encrypt({name: alg})` — for Python equivalent
- ✅ Distinguishes BouncyCastle provider registration from actual algorithm usage
- ⚠️ Requires SonarQube infrastructure
- ❌ Does not resolve X.509 from dependency scanning (no source to analyze)

#### cbomkit-theia — Container/Filesystem Crypto Scanner

- **What it is:** Go-based tool that detects crypto assets in **container images AND directories**
- **Key plugins:**
  - `certificates`: Searches filesystem for X.509 certificates, **extracts signature algorithms, public keys, and public key algorithms** → adds them to CBOM
  - `javasecurity`: Reads `java.security` config, `jdk.tls.disabledAlgorithms` — assigns confidence levels
  - `secrets`: gitleaks-based secret detection
  - `opensslconf`: OpenSSL configuration file parsing
  - `keys`: Private/public key file detection
- **Version:** Part of CBOMKit v2.2.0 | 80 stars

**Relevance to our problems:**
- ✅ **Directly solves X.509 unknowns** — parses `.pem`, `.crt`, `.der` files to extract actual signature algorithms (RSA-SHA256, ECDSA-P256, ML-DSA, etc.)
- ✅ Reads `java.security` to determine which providers and algorithms are actually enabled/disabled
- ✅ OpenSSL config parsing reveals configured cipher suites
- ⚠️ Written in Go; would need adaptation or subprocess integration

#### cbomkit-action — GitHub Action

- **What it is:** GitHub Action wrapper for the CBOMKit pipeline
- **Key flag:** `CBOMKIT_JAVA_REQUIRE_BUILD` — controls whether Java projects must be built before scanning
- **Useful for:** CI/CD integration, but we already have our own `action.yml`

---

### 2. CogniCryptSAST / CryptoAnalysis

> **Source:** [github.com/CROSSINGTUD/CryptoAnalysis](https://github.com/CROSSINGTUD/CryptoAnalysis)

- **What it is:** Context-sensitive, field-sensitive, flow-sensitive **typestate and pointer analysis** for Java JCA/JCE crypto APIs. Successor to CogniCrypt (Eclipse plugin, now unmaintained).
- **Key technology:** **CrySL rules** — a domain-specific language that encodes complete crypto API specifications:
  ```
  SPEC javax.crypto.Cipher
  OBJECTS
    java.lang.String trans;
    int encmode;
  EVENTS
    g1: getInstance(trans);
    Init: init(encmode, _);
    doFinal: doFinal(_);
  ORDER
    g1, Init, (doFinal)+
  CONSTRAINTS
    trans in {"AES/GCM/NoPadding", "AES/CBC/PKCS5Padding", ...};
    encmode in {1, 2};
  ```
- **Analysis frameworks:** Soot, SootUp, and Opal (Scala)
- **Available as:** CLI tool AND GitHub Action
- **Version:** v5.0.1 | 78 stars | 31 contributors | Active
- **License:** EPL-2.0

**Relevance to our problems:**
- ✅ CrySL rules **encode typestate** — traces `Cipher.getInstance()` → `init()` → `doFinal()` call sequences with constraint checking on arguments
- ✅ Could resolve all Java `MessageDigest.getInstance(variable)` cases through data flow
- ✅ Distinguishes BouncyCastle **usage** from **registration** (typestate tracks which APIs are actually called)
- ⚠️ Java-only
- ⚠️ Academic tool; integration would require spawning JVM subprocess
- ❌ Does not resolve X.509 from dependencies

---

### 3. CryptoGuard

> **Source:** [github.com/CryptoGuardOSS/cryptoguard](https://github.com/CryptoGuardOSS/cryptoguard)

- **What it is:** Java/Android cryptographic misuse detection via **backward program slicing**
- **Key technique:** For each crypto API call, performs inter-procedural backward slicing to determine what values flow into the arguments
- **Input formats:** Source (Maven/Gradle), JAR, APK, Java files, class files
- **Requires:** Java 8
- **Version:** v04.05.03 (2020) | 121 stars | GPL-3.0
- **Status:** ⚠️ Last release 2020 — appears unmaintained

**Relevance to our problems:**
- ✅ Backward program slicing is the **exact technique** needed to resolve `MessageDigest.getInstance(variable)` — traces where `variable` gets its value
- ✅ Works on JARs/APKs — could analyze dependency code
- ⚠️ Java 8 only, unmaintained since 2020
- ⚠️ Research prototype quality
- ❌ Does not resolve X.509

**Technique insight:** Even if we don't use CryptoGuard directly, the **backward slicing approach** could be implemented for specific patterns:
```
// Instead of just regex-matching MessageDigest.getInstance(...)
// Search backward from the call site:
String algo = "SHA-256";          // ← found 3 lines above
MessageDigest md = MessageDigest.getInstance(algo);
```

---

### 4. CodeQL Crypto Queries

> **Source:** [github.com/github/codeql (Java CWE-327)](https://github.com/github/codeql/tree/main/java/ql/src/Security/CWE/CWE-327)

- **What it is:** CodeQL's built-in queries for detecting weak cryptographic algorithms, using GitHub's **data flow analysis library**
- **Key queries:**
  - `BrokenCryptoAlgorithm.ql` — path-problem analysis with taint tracking
  - `MaybeBrokenCryptoAlgorithm.ql` — less certain detections
  - Additional: insufficient key size, RSA without OAEP, static IV, predictable seed
- **Languages:** Java, JavaScript, Python, C/C++, C#, Go, Ruby, Swift
- **Technique:** DataFlow library traces string values through method boundaries to resolve `Cipher.getInstance(variable)` 
- **License:** MIT

**Relevance to our problems:**
- ✅ Multi-language data flow analysis — resolves dynamic arguments across Java, Python, JS, Go
- ✅ Can write **custom CodeQL queries** for our specific patterns (X.509 signature algorithm extraction, BouncyCastle usage vs registration)
- ✅ GitHub-native — available in GitHub Actions via `github/codeql-action`
- ⚠️ Requires CodeQL database creation per repository (build step)
- ⚠️ Query authoring has learning curve (Datalog-like language)
- ❌ Does not resolve X.509 from compiled dependencies

**Example approach for our use case:**
```ql
// Custom query: Trace algorithm argument to MessageDigest.getInstance()
from MethodAccess ma, Expr arg, StringLiteral lit
where
  ma.getMethod().hasName("getInstance") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
  arg = ma.getArgument(0) and
  DataFlow::localFlow(DataFlow::exprNode(lit), DataFlow::exprNode(arg))
select ma, lit.getValue() + " flows to MessageDigest.getInstance()"
```

---

### 5. Joern CPG Platform

> **Source:** [github.com/joernio/joern](https://github.com/joernio/joern)

- **What it is:** Code Property Graph (CPG) platform that creates a unified graph combining **AST + CFG + PDG** for multi-language analysis
- **Languages:** C/C++, Java, JavaScript, Python, Kotlin, PHP, Ruby, Go + binary (Ghidra)
- **Query language:** Scala-based (cpgql) with interactive shell
- **Key capabilities:** Data flow analysis, taint tracking, reachability queries, custom pattern matching
- **Version:** v4.0.492 | 3,000+ stars | 79 contributors | Very active
- **License:** Apache 2.0

**Relevance to our problems:**
- ✅ Can write custom queries to trace crypto arguments through call graphs
- ✅ Multi-language — single analysis framework for all 8 of our supported languages
- ✅ Reachability analysis can determine if BouncyCastle provider paths actually reach specific algorithm instantiation
- ⚠️ Heavy infrastructure (JVM + Scala)
- ⚠️ Requires importing each repository into a CPG database
- ⚠️ Steep learning curve for query authoring

**Example Joern query:**
```scala
// Find all arguments flowing into MessageDigest.getInstance()
def source = cpg.literal.typeFullName("java.lang.String")
def sink = cpg.call.name("getInstance").where(_.receiver.typeFullName("java.security.MessageDigest")).argument(1)
sink.reachableBy(source).l
```

---

### 6. Frida Dynamic Instrumentation

> **Source:** [frida.re](https://frida.re/docs/javascript-api/)

- **What it is:** Dynamic instrumentation toolkit with `Interceptor` API for hooking function calls at runtime
- **Key capability:** `Interceptor.attach(target, { onEnter(args) {...} })` — intercept ANY function call, inspect arguments, modify behavior
- **Java bridge:** `Java.use('javax.crypto.Cipher')` — hook JCA/JCE calls directly with argument inspection
- **ObjC bridge:** Hook CommonCrypto, Security.framework on macOS/iOS
- **Platforms:** Windows, macOS, Linux, iOS, Android
- **Version:** 17.x | 15,000+ stars | Very active

**Relevance to our problems:**
- ✅ **Definitively resolves ALL dynamic argument cases** — instruments the actual API calls at runtime and captures concrete values
- ✅ Java bridge enables hooking `MessageDigest.getInstance()`, `Cipher.getInstance()`, `KeyGenerator.getInstance()` etc.
- ✅ Can trace actual X.509 certificate chains being loaded at runtime
- ⚠️ Requires running the application (dynamic analysis)
- ⚠️ Only captures code paths exercised during the instrumented run
- ⚠️ Significant operational complexity
- ❌ Not suitable for CI/CD scanning of source code

**Example Frida script for crypto API hooking:**
```javascript
Java.perform(() => {
  const MessageDigest = Java.use('java.security.MessageDigest');
  MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
    console.log('[MessageDigest] Algorithm: ' + algo);
    console.log('[MessageDigest] Called from:\n' + Java.backtrace().frames.map(f => f.className + '.' + f.methodName).join('\n'));
    return this.getInstance(algo);
  };
  
  const Cipher = Java.use('javax.crypto.Cipher');
  Cipher.getInstance.overload('java.lang.String').implementation = function(transform) {
    console.log('[Cipher] Transform: ' + transform);
    return this.getInstance(transform);
  };
});
```

---

### 7. YARA Binary Detection

> **Source:** [github.com/goffinet/crypto-detection](https://github.com/goffinet/crypto-detection)

- **What it is:** YARA rules for binary-level cryptographic constant detection
- **Covers:** ChaCha20, RC4, AES (Sbox/key schedule), DES, MD5, SHA1, SHA2, SHA3, BASE64
- **Techniques:**
  - Magic constant matching (AES S-box: `0x63 0x7c 0x77 ...`)
  - x86-64 instruction pattern matching (including SSE3/AVX OpenSSL-specific sequences)
  - Radare2-based function-scope analysis
- **Related tools:** FindCrypt (IDA Pro), Manalyze, CryptoHunt, CAPA (Mandiant), grap

**Relevance to our problems:**
- ⚠️ Low value — we analyze **source code**, not binaries
- ✅ Could complement dependency scanning by detecting crypto in compiled JARs/DLLs
- ✅ Constant-based detection reveals which algorithms are actually compiled into a binary (resolves some X.509/BC provider cases if the dependency binaries can be scanned)
- ⚠️ False positive rate can be high
- ❌ Cannot resolve dynamic arguments or X.509 certificates

---

### 8. Certificate File Parsing (Custom)

This isn't a specific tool but a **technique** inspired by cbomkit-theia's certificate plugin.

- **Concept:** Scan the repository filesystem for certificate files (`.pem`, `.crt`, `.der`, `.p7b`, `.pfx`, `.jks`, `.p12`) and parse them to extract:
  - Signature algorithm (e.g., `sha256WithRSAEncryption`, `ECDSA-with-SHA256`, `ML-DSA-65`)
  - Public key algorithm & key size (e.g., `RSA-2048`, `EC-P256`, `ML-KEM-768`)
  - Certificate chain information
  - Validity dates
- **Implementation in our stack:** Use Node.js `crypto` module (`crypto.createPublicKey()`, `X509Certificate` class — available since Node.js 15)
- **Effort:** Low — standard library, no external dependencies

**Relevance to our problems:**
- ✅ **Directly resolves certificate-file X.509 conditionals** — transforms "X.509 (conditional)" into "RSA-2048 (not-quantum-safe)" or "ML-DSA-65 (quantum-safe)"
- ⚠️ Only resolves certificates present as **files** in the repository, not certificates from dependency metadata
- ⚠️ JKS/PKCS12 keystores require password (may not be available)
- ❌ Cannot resolve X.509 references in dependency source code  

---

## Feasibility Matrix

| Tool/Technique | Resolves X.509 | Resolves BC-Provider | Resolves Dynamic Args | Multi-Language | Integration Effort | Maintenance Burden | Infrastructure |
|---------------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **Certificate Parsing** | ✅ (files only) | ❌ | ❌ | N/A | 🟢 Low | 🟢 Low | None |
| **sonar-cryptography** | ❌ | ✅ | ✅ | Java/Python/Go | 🔴 High | 🟡 Medium | SonarQube |
| **CryptoAnalysis (CrySL)** | ❌ | ✅ | ✅ (Java) | Java only | 🔴 High | 🟡 Medium | JVM |
| **CodeQL Queries** | ⚠️ (partial) | ✅ | ✅ | Multi | 🟡 Medium | 🟡 Medium | CodeQL DB build |
| **Joern CPG** | ⚠️ (partial) | ✅ | ✅ | Multi | 🔴 High | 🔴 High | JVM + Scala |
| **Enhanced Source Context** | ❌ | ⚠️ | ✅ (partial) | Multi | 🟢 Low | 🟢 Low | None |
| **Frida Instrumentation** | ✅ | ✅ | ✅ | Multi | 🔴 High | 🔴 High | Running app |
| **YARA Binary** | ⚠️ (deps) | ⚠️ | ❌ | Binary | 🟡 Medium | 🟢 Low | YARA engine |
| **CryptoGuard** | ❌ | ❌ | ✅ (Java) | Java only | 🟡 Medium | 🔴 Unmaintained | Java 8 |

### Scoring Key
- **Integration Effort:** 🟢 Days | 🟡 Weeks | 🔴 Months
- **Maintenance Burden:** 🟢 Self-contained | 🟡 Periodic updates | 🔴 Active maintenance needed
- **Infrastructure:** External dependencies required beyond our Node.js backend

---

## Prioritized Implementation Plan

### Phase 1 — Quick Wins (1-2 weeks) ✅ IMPLEMENTED

#### 1A. Certificate File Parsing ✅
**Status:** Implemented in `backend/src/services/scanner/certificateFileScanner.ts`
**Impact:** Resolves certificate-file X.509 conditionals
**Effort:** Low (Node.js `crypto.X509Certificate` API)
**Estimated resolution:** ~50-200 of the 1,350 X.509 conditionals (those with actual cert files in repos)

Implementation includes:
- `scanCertificateFiles()` — discovers and parses `.pem`, `.crt`, `.cer`, `.der` files
- `scanKeystoreFiles()` — detects `.jks`, `.p12`, `.pfx`, `.keystore` files
- `discoverCertificateFiles()` — recursive file discovery with exclusion patterns
- Multi-certificate PEM bundle support
- DER binary format support
- Private/public key file detection
- Full PQC enrichment via `enrichAssetWithPQCData()`
- `detectionSource: 'certificate'` on all findings

```typescript
// Implementation sketch for backend/src/services/scanner/certificateFileScanner.ts
import { X509Certificate, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { glob } from 'glob';

interface CertificateInfo {
  signatureAlgorithm: string;  // e.g., "sha256WithRSAEncryption"
  publicKeyAlgorithm: string;  // e.g., "RSA"
  publicKeySize: number;       // e.g., 2048
  subject: string;
  issuer: string;
  validTo: Date;
  filePath: string;
}

async function scanCertificateFiles(repoPath: string): Promise<CertificateInfo[]> {
  const certPatterns = ['**/*.pem', '**/*.crt', '**/*.cer', '**/*.der'];
  const files = await glob(certPatterns, { cwd: repoPath });
  
  return Promise.all(files.map(async (file) => {
    const content = await readFile(`${repoPath}/${file}`);
    const cert = new X509Certificate(content);
    const pubKey = createPublicKey(cert.publicKey);
    
    return {
      signatureAlgorithm: cert.sigAlgName,     // "SHA256withRSA", "ECDSA", etc.
      publicKeyAlgorithm: pubKey.asymmetricKeyType,  // "rsa", "ec", "ed25519"
      publicKeySize: pubKey.asymmetricKeySize,
      subject: cert.subject,
      issuer: cert.issuer,
      validTo: new Date(cert.validTo),
      filePath: file,
    };
  }));
}
```

Then feed `signatureAlgorithm` and `publicKeyAlgorithm` into `classifyAlgorithm()` from `pqcRiskEngine.ts` — immediately promoting X.509 conditionals to definitive classifications.

#### 1B. Enhanced Backward Variable Resolution ✅
**Status:** Implemented in `backend/src/services/scanner/scannerUtils.ts`
**Impact:** Resolves dynamic argument cases where the variable is assigned within the same method
**Effort:** Low (extend existing `pqcParameterAnalyzer.ts`)
**Estimated resolution:** ~15-30 of the ~52 dynamic argument cases

`resolveVariableToAlgorithm()` now implements **7 resolution strategies** (in priority order):
1. **Backward search (100 lines)** — scans up from call site for `varName = "ALGORITHM"` assignments
2. **Class-level constants** — matches `static final`, `const`, `readonly` field declarations
3. **Ternary/conditional** — extracts algorithm from ternary expressions
4. **Enum/switch-case** — detects enum constants or switch/case values near the variable
5. **Method parameter → call site** — traces method parameters to their call sites with positional argument matching
6. **String concatenation root** — extracts the root algorithm from concatenated strings
7. **Cross-file import** — detects imported constants from other modules

Additionally, `resolveVariableBackward()` was added for the PQC parameter analyzer to use when processing source context blocks.

The current parameter analyzer searches ±15 lines around the API call. Enhance it with **simple backward variable resolution**:

```typescript
// Enhancement for pqcParameterAnalyzer.ts
function resolveVariableBackward(sourceContext: string, variableName: string): string | null {
  // Pattern: const/let/var varName = "LITERAL_VALUE"
  // Pattern: String varName = "LITERAL_VALUE"
  // Pattern: varName = "LITERAL_VALUE"
  const patterns = [
    new RegExp(`(?:const|let|var|String|string)\\s+${escapeRegex(variableName)}\\s*=\\s*['"](\\w[\\w\\-/]+)['"]`),
    new RegExp(`${escapeRegex(variableName)}\\s*=\\s*['"](\\w[\\w\\-/]+)['"]`),
  ];
  
  for (const pattern of patterns) {
    const match = sourceContext.match(pattern);
    if (match) return match[1];
  }
  return null;
}
```

This is a **simplified backward slice** — not as powerful as CryptoGuard's inter-procedural analysis but handles the common case where:
```java
String algo = "SHA-256";  // or: const algo = 'AES-GCM';
MessageDigest.getInstance(algo);
```

#### 1C. BouncyCastle-Provider Reclassification ✅
**Status:** Implemented in `backend/src/services/pqcRiskEngine.ts`
**Impact:** Eliminates ~137 "false" conditionals
**Effort:** Minimal (data model change)
**Estimated resolution:** All 137 BouncyCastle-Provider entries

Implementation:
- Added `isInformational?: boolean` flag to the `AlgorithmProfile` interface
- Marked `BouncyCastle-Provider`, `JCE-Signature-Registration`, `JCE-KeyPairGen-Registration`, `JCE-Digest-Registration` as `isInformational: true`
- `enrichAssetWithPQCData()` now handles informational entries: confidence 10, COMPLIANT status, `[INFORMATIONAL]` prefix
- New exported helpers: `isInformationalAsset()` and `filterInformationalAssets()`
- Informational assets are excluded from risk scoring and conditional/unknown counts

---

### Phase 2 — Medium Effort (1-2 months)

#### 2A. CodeQL Integration for Dynamic Argument Resolution ✅
**Status:** Implemented in `backend/src/services/scanner/externalToolIntegration.ts`
**Impact:** Resolves remaining dynamic argument cases via proper data flow analysis
**Effort:** Medium (custom CodeQL queries + CI pipeline integration)
**Estimated resolution:** ~40-50 of the ~52 dynamic argument cases

Implementation includes:
- `runExternalToolScans()` — orchestrates all three external tools (CodeQL, cbomkit-theia, CryptoAnalysis)
- `checkToolAvailability()` — tests whether each tool's CLI is accessible
- `runCodeQLAnalysis()` — creates CodeQL database, runs custom `.ql` queries, parses SARIF output
- `runCbomkitTheia()` — runs cbomkit-theia filesystem scanning, parses JSON output
- `runCryptoAnalysis()` — runs CrySL-based typestate analysis, parses JSON report
- `deduplicateExternalAssets()` — merges external findings with regex results (enriches existing, adds novel)
- All tools optional — fail gracefully if not installed
- Custom CodeQL queries for `MessageDigest`, `Cipher`, `KeyGenerator`, `Signature` argument resolution

> **Note:** The external tool integration framework is fully implemented. The tools themselves need to be installed separately on the system for the integration to produce results.

Write custom CodeQL queries for each dynamic argument pattern:

```ql
// queries/crypto/MessageDigestAlgorithm.ql
/**
 * @name MessageDigest algorithm resolution
 * @description Traces string values flowing into MessageDigest.getInstance()
 * @kind problem
 * @tags security cryptography cbom
 */
import java
import semmle.code.java.dataflow.DataFlow

class MessageDigestSource extends DataFlow::Node {
  MessageDigestSource() {
    this.asExpr() instanceof StringLiteral
  }
}

class MessageDigestSink extends DataFlow::Node {
  MessageDigestSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getInstance") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

from MessageDigestSource source, MessageDigestSink sink
where DataFlow::localFlow(source, sink)
select sink, "MessageDigest uses algorithm: " + source.asExpr().(StringLiteral).getValue()
```

**Integration approach:**
1. Add CodeQL database build step to our GitHub Action
2. Run custom queries alongside our regex scanner
3. Parse CodeQL SARIF output to enrich our CBOM with resolved algorithm names
4. Feed resolved algorithms into `classifyAlgorithm()`

#### 2B. Trust Store / Keystore Scanning
**Impact:** Resolves X.509 conditionals from Java keystores
**Effort:** Medium (requires optional `keytool` or `openssl` subprocess)
**Estimated resolution:** ~100-300 additional X.509 resolutions

Scan for `.jks`, `.p12`, `.pfx`, `.keystore` files and extract certificate information:
```bash
# List certificates in a keystore (when password is known or default)
keytool -list -v -keystore app.jks -storepass changeit 2>/dev/null | grep "Signature algorithm"
```

For passwordless inspection, use `openssl` for PKCS12:
```bash
openssl pkcs12 -in store.p12 -nokeys -passin pass: | openssl x509 -noout -text | grep "Signature Algorithm"
```

---

### Phase 3 — Strategic Investment (3-6 months)

#### 3A. sonar-cryptography Integration
**Impact:** AST-level crypto detection for Java, Python, Go
**Effort:** High (SonarQube infrastructure or custom rule extraction)
**Estimated resolution:** Near-complete resolution of all dynamic argument cases in supported languages

**Two approaches:**

1. **Full SonarQube integration:** Deploy SonarQube with sonar-cryptography plugin, run analysis, import results
   - Pro: Production-grade analysis, actively maintained
   - Con: Heavy infrastructure requirement

2. **Detection rule extraction:** Study sonar-cryptography's [detection rules architecture](https://github.com/IBM/sonar-cryptography) and port key patterns to our scanner
   - Pro: No external infrastructure, enriches our codebase
   - Con: Significant reverse-engineering effort, must maintain parity

#### 3B. Joern-Based Custom Crypto Analysis
**Impact:** Universal data flow analysis across all languages
**Effort:** High (Joern infrastructure + query development)
**Estimated resolution:** Near-complete for all dynamic argument cases

```scala
// Example Joern analysis pipeline
@main def analyzeRepo(repoPath: String): Unit = {
  importCode(repoPath)
  
  // Find all crypto API calls with non-literal arguments
  val dynamicCryptoCalls = cpg.call
    .name("getInstance")
    .where(_.typeFullName(".*MessageDigest.*|.*Cipher.*|.*KeyGenerator.*"))
    .argument(1)
    .whereNot(_.isLiteral)
    .l
  
  // Trace each argument to its source
  dynamicCryptoCalls.foreach { arg =>
    val sources = arg.reachableBy(cpg.literal).dedup.l
    println(s"${arg.location}: resolved to ${sources.map(_.code)}")
  }
}
```

---

### Phase 4 — Future / Research (6+ months)

#### 4A. Frida-Based Runtime Crypto Telemetry
**Impact:** 100% resolution of all runtime crypto usage
**Effort:** Very High (requires running applications, test suites)
**Estimated resolution:** Complete — captures actual crypto APIs called during execution

Useful as a **validation tool** rather than a primary scanner, comparing static analysis results with runtime observations. Could be offered as an optional "deep scan" mode.

#### 4B. YARA-Based Dependency Binary Scanning
**Impact:** Identifies crypto algorithms compiled into dependency binaries
**Effort:** Medium
**Estimated resolution:** Marginal — addresses a niche case (crypto constants in compiled dependencies)

---

## Impact Estimates

| Phase | Technique | Status | X.509 Resolved | BC-Provider Resolved | Dynamic Args Resolved | Total Reduction |
|-------|-----------|--------|:-:|:-:|:-:|:-:|
| 1A | Cert File Parsing | ✅ Implemented | ~100-200 | — | — | ~100-200 |
| 1B | Backward Variable Resolution | ✅ Implemented | — | — | ~15-30 | ~15-30 |
| 1C | BC-Provider Reclassification | ✅ Implemented | — | **~137** | — | ~137 |
| 2A | External Tool Integration | ✅ Implemented | — | — | ~40-50 | ~40-50 |
| 2B | Keystore Scanning | Planned | ~100-300 | — | — | ~100-300 |
| 3A | sonar-cryptography | Planned | — | ✅ remaining | ✅ remaining | ~50-100 |
| | **CUMULATIVE** | | **~200-500** | **~137** | **~52** | **~390-690** |

**Realistic expectation:** Phases 1+2 could reduce the ~1,569 irreducible assets by **~400-700** (~25-45%), with the remainder being X.509 references in dependency metadata that no tool can resolve without runtime analysis.

**Ceiling:** ~1,000+ X.509 from dependency metadata will remain conditional regardless of tooling. These represent "BouncyCastle JAR references cert format" — the actual certificate is generated/configured at deployment time. The **Network Scanner** (already implemented) is the correct tool for those.

---

## Architecture for Integration

```
                              ┌─────────────────────┐
                              │   Scanner Pipeline   │
                              └─────────┬───────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
          ┌─────────────┐    ┌─────────────────┐  ┌──────────────────┐
          │  Regex       │    │  Certificate    │  │  External Tools   │
          │  Scanner     │    │  File Scanner   │  │  CodeQL           │
          │  (existing)  │    │  (Phase 1A) ✅   │  │  cbomkit-theia    │
          └──────┬──────┘    └────────┬────────┘  │  CryptoAnalysis   │
                 │                    │           │  (Phase 2A) ✅    │
                 └────────────────────┼───────────┘───────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │  Scanner Aggregator    │
                          │  (scannerAggregator.ts) │
                          │  10-step pipeline       │
                          │  Merges & deduplicates  │
                          └───────────┬───────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │  PQC Risk Engine       │
                          │  + Parameter Analyzer   │
                          │  + 7-Strategy Variable  │
                          │    Resolution (1B) ✅    │
                          │  + Informational Filter │
                          │    (1C) ✅               │
                          └───────────┬───────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │  CBOM Output           │
                          │  (CycloneDX v1.6)      │
                          └───────────────────────┘
```

### Key Design Decisions

1. **Certificate file scanner** plugs into `scannerAggregator.ts` as step 4 of the 10-step pipeline ✅
2. **7-strategy variable resolution** enhances `scannerUtils.ts` — backward search, constants, ternary, enum, call-site tracing, concatenation, imports ✅
3. **BC-Provider reclassification** adds `isInformational` flag to `AlgorithmProfile` in `pqcRiskEngine.ts` ✅
4. **External tools** (CodeQL, cbomkit-theia, CryptoAnalysis) are invoked via subprocess with SARIF/JSON output parsing in `externalToolIntegration.ts` ✅
5. **Deduplication** enriches existing assets from external findings rather than creating duplicates ✅

---

## References

| Tool | Repository | Stars | License | Status |
|------|-----------|-------|---------|--------|
| sonar-cryptography | [IBM/sonar-cryptography](https://github.com/IBM/sonar-cryptography) | 55 | Apache-2.0 | Active |
| CBOMKit | [IBM/cbomkit](https://github.com/IBM/cbomkit) | 80 | Apache-2.0 | Active |
| cbomkit-theia | [IBM/cbomkit-theia](https://github.com/IBM/cbomkit-theia) | — | Apache-2.0 | Active |
| CryptoAnalysis | [CROSSINGTUD/CryptoAnalysis](https://github.com/CROSSINGTUD/CryptoAnalysis) | 78 | EPL-2.0 | Active |
| CryptoGuard | [CryptoGuardOSS/cryptoguard](https://github.com/CryptoGuardOSS/cryptoguard) | 121 | GPL-3.0 | ⚠️ Unmaintained |
| CodeQL | [github/codeql](https://github.com/github/codeql) | 7,800+ | MIT | Active |
| Joern | [joernio/joern](https://github.com/joernio/joern) | 3,000+ | Apache-2.0 | Very Active |
| Frida | [frida/frida](https://github.com/frida/frida) | 15,000+ | wxWindows | Very Active |
| crypto-detection YARA | [goffinet/crypto-detection](https://github.com/goffinet/crypto-detection) | 10 | — | Low Activity |
