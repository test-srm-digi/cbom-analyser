/**
 * Scanner Aggregator Service
 *
 * Orchestrates code scanning (sonar-cryptography) and network scanning,
 * then merges results into a unified CycloneDX 1.6 CBOM.
 */
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  CBOMDocument,
  CryptoAsset,
  AssetType,
  CryptoPrimitive,
  CryptoFunction,
  QuantumSafetyStatus,
  CryptoDependency,
} from '../types';
import { enrichAssetWithPQCData, calculateReadinessScore, checkNISTPQCCompliance, syncQuantumSafetyWithVerdict } from './pqcRiskEngine';
import { scanNetworkCrypto, networkResultToCBOMAsset } from './networkScanner';
import { scanDependencies, cryptoLibToCBOMAssets } from './dependencyScanner';
import { analyzeAllConditionalAssets } from './pqcParameterAnalyzer';

const execAsync = promisify(exec);

// ─── Glob Pattern Matching ───────────────────────────────────────────────────

/**
 * Convert a glob pattern to a regex.
 * Supports: ** (any path), * (any chars in segment), ? (single char)
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/\\/g, '/') // normalize slashes
    .replace(/[.+^${}()|[\]]/g, '\\$&') // escape regex special chars
    .replace(/\*\*/g, '{{GLOBSTAR}}') // placeholder for **
    .replace(/\*/g, '[^/]*') // * matches anything except /
    .replace(/\?/g, '.') // ? matches single char
    .replace(/\{\{GLOBSTAR\}\}/g, '.*'); // ** matches anything including /
  return new RegExp(`^${escaped}$|/${escaped}$|^${escaped}/|/${escaped}/`);
}

/**
 * Check if a file path matches any of the exclude patterns.
 */
function shouldExcludeFile(filePath: string, excludePatterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  return excludePatterns.some(pattern => {
    const regex = globToRegex(pattern);
    return regex.test(normalizedPath);
  });
}

// ─── CBOM Builder ────────────────────────────────────────────────────────────

/**
 * Create an empty CBOM document shell.
 */
export function createEmptyCBOM(componentName: string, componentVersion?: string): CBOMDocument {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${uuidv4()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'QuantumGuard',
          name: 'CBOM Hub',
          version: '1.0.0',
        },
      ],
      component: {
        name: componentName,
        version: componentVersion,
        type: 'application',
      },
    },
    components: [],
    cryptoAssets: [],
    dependencies: [],
  };
}

/**
 * Parse and validate an uploaded CBOM JSON file.
 * Supports both standard CycloneDX 1.6 CBOM and custom formats.
 */
export function parseCBOMFile(jsonContent: string): CBOMDocument {
  let data = JSON.parse(jsonContent);

  // Unwrap API response wrapper: { success, cbom, readinessScore, ... }
  if (data.success !== undefined && data.cbom) {
    data = data.cbom;
  }

  // If it's already in our internal format
  if (data.bomFormat === 'CycloneDX' && data.cryptoAssets) {
    // Enrich each asset with PQC data
    data.cryptoAssets = data.cryptoAssets.map((asset: CryptoAsset) =>
      enrichAssetWithPQCData(asset)
    );
    return data as CBOMDocument;
  }

  // If it's a standard CycloneDX with components that have cryptoProperties
  if (data.bomFormat === 'CycloneDX' && data.components) {
    const cbom = createEmptyCBOM(
      data.metadata?.component?.name || 'Unknown',
      data.metadata?.component?.version
    );
    cbom.metadata = data.metadata || cbom.metadata;

    // Map components with crypto properties to our CryptoAsset format
    for (const component of data.components) {
      if (component.cryptoProperties || component['crypto-properties']) {
        const cryptoProps = component.cryptoProperties || component['crypto-properties'];

        // Extract location from evidence, converting absolute paths to relative
        let location: { fileName: string; lineNumber?: number } | undefined;
        const firstOccurrence = component.evidence?.occurrences?.[0];
        if (firstOccurrence) {
          let fileName = firstOccurrence.location || '';
          // Strip absolute path prefix to make it relative
          if (fileName.startsWith('/')) {
            // Try to find src/ or main/ in the path and use from there
            const srcIdx = fileName.indexOf('/src/');
            if (srcIdx >= 0) {
              fileName = fileName.substring(srcIdx + 1);
            } else {
              // Fallback: use just the filename
              fileName = fileName.split('/').slice(-3).join('/');
            }
          }
          location = {
            fileName,
            lineNumber: firstOccurrence.line,
          };
        }

        const asset: CryptoAsset = {
          id: component['bom-ref'] || uuidv4(),
          name: component.name,
          type: component.type || 'crypto-asset',
          version: component.version,
          description: component.description,
          cryptoProperties: {
            assetType: cryptoProps.assetType || cryptoProps['asset-type'] || AssetType.ALGORITHM,
            algorithmProperties: cryptoProps.algorithmProperties,
            protocolProperties: cryptoProps.protocolProperties,
          },
          location,
          quantumSafety: QuantumSafetyStatus.UNKNOWN,
        };
        cbom.cryptoAssets.push(enrichAssetWithPQCData(asset));
      }
    }

    cbom.components = data.components;
    cbom.dependencies = data.dependencies;
    return cbom;
  }

  throw new Error('Invalid CBOM format. Expected CycloneDX 1.6 CBOM JSON.');
}

// ─── Sonar-Cryptography Integration ─────────────────────────────────────────

/**
 * Execute the sonar-cryptography scanner via CLI against a target repo.
 * Requires:
 *   - sonar-scanner CLI installed (brew install sonar-scanner)
 *   - SonarQube running with sonar-cryptography plugin
 *   - SONAR_HOST_URL and SONAR_TOKEN environment variables
 *
 * The plugin outputs a CycloneDX 1.6 CBOM as `cbom.json` in the project root.
 * Falls back to regex-based scanning if sonar-scanner is unavailable.
 */
export async function runSonarCryptoScan(repoPath: string, excludePatterns?: string[]): Promise<CBOMDocument> {
  const cbom = createEmptyCBOM(path.basename(repoPath));

  const sonarHostUrl = process.env.SONAR_HOST_URL || 'http://localhost:9090';
  const sonarToken = process.env.SONAR_TOKEN;

  try {
    // Check if sonar-scanner is available
    await execAsync('which sonar-scanner');

    if (!sonarToken) {
      console.warn('SONAR_TOKEN not set — falling back to regex scanner.');
      return runRegexCryptoScan(repoPath, excludePatterns);
    }

    const projectKey = `quantumguard-${path.basename(repoPath).replace(/[^a-zA-Z0-9_-]/g, '-')}`;

    // Detect Java compiled class directories (sonar.java.binaries is required when .java files exist)
    const javaBinCandidates = ['target/classes', 'build/classes', 'out/production', 'bin'];
    const javaBinDirs = javaBinCandidates
      .map(d => path.join(repoPath, d))
      .filter(d => fs.existsSync(d));
    // If no compiled classes exist, create a temp empty dir so SonarQube doesn't error out
    const tempBinDir = path.join(repoPath, '.sonar-tmp-bin');
    if (javaBinDirs.length === 0) {
      fs.mkdirSync(tempBinDir, { recursive: true });
      javaBinDirs.push(tempBinDir);
    }

    // Build sonar-scanner arguments
    const args = [
      `-Dsonar.projectKey=${projectKey}`,
      `-Dsonar.projectName="QuantumGuard Scan: ${path.basename(repoPath)}"`,
      `-Dsonar.sources=.`,
      `-Dsonar.java.binaries=${javaBinDirs.map(d => path.relative(repoPath, d) || '.').join(',')}`,
      `-Dsonar.host.url=${sonarHostUrl}`,
      `-Dsonar.token=${sonarToken}`,
      `-Dsonar.scm.disabled=true`,
      // Exclude files that SonarQube can't parse (Helm templates, build output, etc.)
      `-Dsonar.exclusions=**/charts/**/templates/**,**/node_modules/**,**/target/**,**/build/**,**/dist/**,**/.git/**`,
      // Allow the token to create new projects automatically
      `-Dsonar.qualitygate.wait=false`,
    ].join(' ');

    console.log(`Running sonar-scanner against ${repoPath} → ${sonarHostUrl}`);
    const { stdout, stderr } = await execAsync(
      `sonar-scanner ${args}`,
      { cwd: repoPath, timeout: 600000 }
    );

    console.log('Sonar scan output:', stdout);
    if (stderr) {
      console.warn('Sonar scan warnings:', stderr);
    }

    // The sonar-cryptography plugin writes cbom.json in the project root
    const cbomPaths = [
      path.join(repoPath, 'cbom.json'),
      path.join(repoPath, '.scannerwork', 'cbom.json'),
      path.join(repoPath, '.scannerwork', 'cbom-report.json'),
    ];

    for (const reportPath of cbomPaths) {
      if (fs.existsSync(reportPath)) {
        console.log(`Found CBOM report at: ${reportPath}`);
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        // Clean up temp dir if we created one
        if (fs.existsSync(tempBinDir)) {
          fs.rmSync(tempBinDir, { recursive: true, force: true });
        }
        return parseCBOMFile(JSON.stringify(report));
      }
    }

    // Clean up temp dir
    if (fs.existsSync(tempBinDir)) {
      fs.rmSync(tempBinDir, { recursive: true, force: true });
    }

    console.warn('No CBOM output file found after sonar scan. Falling back to regex.');
    return runRegexCryptoScan(repoPath, excludePatterns);
  } catch (error) {
    // Clean up temp dir on failure
    const tempBinDir = path.join(repoPath, '.sonar-tmp-bin');
    if (fs.existsSync(tempBinDir)) {
      fs.rmSync(tempBinDir, { recursive: true, force: true });
    }
    console.warn(
      'Sonar-cryptography scanner not available or failed. ' +
      'Falling back to regex-based scanning.',
      (error as Error).message
    );
    // Fall back to regex-based scanning
    return runRegexCryptoScan(repoPath, excludePatterns);
  }

  return cbom;
}

/**
 * Fallback: Regex-based crypto detection for when sonar-scanner is unavailable.
 * Scans Java and Python files for common cryptographic patterns.
 */
export async function runRegexCryptoScan(repoPath: string, excludePatterns?: string[]): Promise<CBOMDocument> {
  const cbom = createEmptyCBOM(path.basename(repoPath));

  // Pattern type with optional asset-type override and algorithm extraction from capture group 1
  type CryptoPattern = {
    pattern: RegExp;
    algorithm: string;          // static name OR fallback when capture group is empty
    primitive: CryptoPrimitive;
    cryptoFunction: CryptoFunction;
    assetType?: AssetType;      // defaults to ALGORITHM if omitted
    extractAlgorithm?: boolean; // when true, prefer capture group 1 over static `algorithm`
    resolveVariable?: boolean;  // when true, capture group 1 is a variable name to resolve
    scanContext?: boolean;       // when true, scan nearby lines for algorithm context clues
  };

  /**
   * Resolve a variable name to its string-literal value by scanning surrounding
   * lines for common Java/TS/Python assignment patterns:
   *   String algo = "RSA";
   *   final String ALGO = "RSA";
   *   private static final String KEY_ALGO = "RSA";
   *   algo = "RSA"
   *   ALGO: str = "RSA"
   *   const algo = "RSA"
   *   const algo = 'RSA'
   *
   * Returns the resolved algorithm name or null if not found.
   */
  function resolveVariableToAlgorithm(varName: string, lines: string[], matchLine: number): string | null {
    // Build regex: look for `varName = "something"` or `varName = 'something'`
    const assignmentRe = new RegExp(
      `(?:^|\\s)${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[:=]\\s*["']([^"']+)["']`,
    );
    // Scan ±50 lines from the match for the assignment (covers field declarations, local vars)
    const start = Math.max(0, matchLine - 50);
    const end = Math.min(lines.length, matchLine + 50);
    for (let i = start; i < end; i++) {
      const m = lines[i].match(assignmentRe);
      if (m) return m[1];
    }
    // Also look for common constant-naming patterns: VARIABLE_NAME → search for ".*ALGORITHM.*= "
    // If the variable is a method parameter, look at callers within the same file
    // (heuristic: search the whole file for any string that looks like an algorithm name near this var)
    const paramCallRe = new RegExp(
      `\\.getInstance\\s*\\([^)]*${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^)]*\\)`,
    );
    // If the variable is used in a method parameter, try to find what the method is called with
    // e.g., createKeyPair(algo) → look for createKeyPair("RSA")
    const methodCallRe = /function|def |private |public |protected |static /;
    for (let i = Math.max(0, matchLine - 5); i <= Math.min(lines.length - 1, matchLine + 5); i++) {
      const line = lines[i];
      // Check if this line defines a method/function that takes the variable as param
      if (methodCallRe.test(line) && line.includes(varName)) {
        // Find the method/function name
        const funcNameMatch = line.match(/(?:def\s+|function\s+|(?:public|private|protected|static)\s+\S+\s+)(\w+)\s*\(/);
        if (funcNameMatch) {
          const funcName = funcNameMatch[1];
          // Search the file for calls to this function with a string literal
          for (const fileLine of lines) {
            const callMatch = fileLine.match(new RegExp(`${funcName}\\s*\\([^)]*["']([A-Za-z0-9_/.-]+)["']`));
            if (callMatch) return callMatch[1];
          }
        }
      }
    }
    return null;
  }

  /**
   * Extract algorithms from WebCrypto (crypto.subtle) API calls.
   * Looks for algorithm name objects like { name: 'RSA-OAEP' }, 'AES-GCM', etc.
   */
  function scanWebCryptoContext(fileText: string): string | null {
    const algoRefs: string[] = [];

    // Pattern 1: crypto.subtle.<method>({ name: 'ALGO', ... })
    // e.g., crypto.subtle.encrypt({ name: 'AES-GCM', ... }, key, data)
    // e.g., crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, ... })
    const subtleCallRe = /crypto\.subtle\.(\w+)\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = subtleCallRe.exec(fileText)) !== null) {
      const method = m[1]; // encrypt, sign, generateKey, etc.
      const algo = m[2];   // RSA-OAEP, AES-GCM, ECDSA, etc.
      const label = `${algo} (${method})`;
      if (!algoRefs.includes(label)) algoRefs.push(label);
    }

    // Pattern 2: algorithm object defined separately:
    // const algorithm = { name: 'RSA-OAEP', ... }
    // { name: "ECDSA", namedCurve: "P-256" }
    const algoObjRe = /\{\s*name\s*:\s*['"]([^'"]+)['"][^}]*(?:modulusLength|namedCurve|length|hash|saltLength|counter|iv|label)\s*:/g;
    while ((m = algoObjRe.exec(fileText)) !== null) {
      if (!algoRefs.some(r => r.startsWith(m![1]))) algoRefs.push(m![1]);
    }

    // Pattern 3: standalone string algorithm names in subtle calls
    // crypto.subtle.digest('SHA-256', data)
    const digestRe = /crypto\.subtle\.digest\s*\(\s*['"]([^'"]+)['"]/g;
    while ((m = digestRe.exec(fileText)) !== null) {
      const label = `${m[1]} (digest)`;
      if (!algoRefs.includes(label)) algoRefs.push(label);
    }

    // Pattern 4: importKey with algorithm: crypto.subtle.importKey('raw', ..., { name: 'AES-GCM' })
    const importKeyRe = /crypto\.subtle\.importKey\s*\([^)]*\{\s*name\s*:\s*['"]([^'"]+)['"]/g;
    while ((m = importKeyRe.exec(fileText)) !== null) {
      const label = `${m[1]} (importKey)`;
      if (!algoRefs.includes(label)) algoRefs.push(label);
    }

    // Pattern 5: namedCurve references revealing EC usage
    const curvesRe = /namedCurve\s*:\s*['"]([^'"]+)['"]/g;
    while ((m = curvesRe.exec(fileText)) !== null) {
      const label = `EC:${m[1]}`;
      if (!algoRefs.includes(label)) algoRefs.push(label);
    }

    // Pattern 6: modulusLength revealing RSA key size
    const modulusRe = /modulusLength\s*:\s*(\d+)/g;
    const keySizes: string[] = [];
    while ((m = modulusRe.exec(fileText)) !== null) {
      if (!keySizes.includes(m[1])) keySizes.push(m[1]);
    }

    if (algoRefs.length > 0) {
      let desc = `WebCrypto (crypto.subtle) algorithms found in file: ${algoRefs.join(', ')}.`;
      if (keySizes.length > 0) desc += ` Key sizes: ${keySizes.join(', ')}-bit.`;
      desc += ' Review each algorithm for PQC readiness.';
      return desc;
    }
    return 'WebCrypto (crypto.subtle) detected but could not determine specific algorithms from the file. Check crypto.subtle.encrypt/sign/generateKey calls for the algorithm parameter.';
  }

  /**
   * Extract algorithms from X.509 certificate usage patterns.
   * Scans for signature algorithms, certificate builder APIs, and key usage.
   */
  function scanX509Context(fileText: string, existingAlgoRefs: string[]): string | null {
    const algoRefs = [...existingAlgoRefs];
    let m;

    // getSigAlgName(), getSigAlgOID()
    const sigAlgRe = /getSigAlg(?:Name|OID)\s*\(\s*\)/g;
    if (sigAlgRe.test(fileText)) {
      if (!algoRefs.includes('getSigAlgName()')) algoRefs.push('getSigAlgName()');
    }

    // Certificate signature algorithm in string literals: "SHA256withRSA", "SHA384withECDSA", "Ed25519"
    const sigLiteralRe = /["']((?:SHA\d+with\w+|MD5with\w+|Ed25519|Ed448|ML-DSA-\d+|SLH-DSA-\w+))['"]/g;
    while ((m = sigLiteralRe.exec(fileText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // JcaContentSignerBuilder("SHA256withRSA"), ContentSigner
    const contentSignerRe = /JcaContentSignerBuilder\s*\(\s*["']([^"']+)["']/g;
    while ((m = contentSignerRe.exec(fileText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // X509v3CertificateBuilder, JcaX509v3CertificateBuilder
    const certBuilderRe = /(?:Jca)?X509v3CertificateBuilder/g;
    if (certBuilderRe.test(fileText) && !algoRefs.includes('X509v3CertificateBuilder')) {
      algoRefs.push('X509v3CertificateBuilder');
    }

    // AlgorithmIdentifier with OID or algorithm name
    const algIdRe = /AlgorithmIdentifier\s*\(\s*(?:new\s+ASN1ObjectIdentifier\s*\(\s*)?["']([^"']+)["']/g;
    while ((m = algIdRe.exec(fileText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // PKCS10CertificationRequest (CSR)
    const csrRe = /PKCS10CertificationRequest|JcaPKCS10CertificationRequestBuilder/g;
    if (csrRe.test(fileText)) {
      if (!algoRefs.includes('PKCS10/CSR')) algoRefs.push('PKCS10/CSR');
    }

    // Explicit key type references: RSAPublicKey, ECPublicKey, etc.
    const keyTypeRe = /\b(RSA(?:Public|Private)Key|EC(?:Public|Private)Key|EdDSAPublicKey|EdDSAPrivateKey)\b/g;
    while ((m = keyTypeRe.exec(fileText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // XDH / X25519 / X448 key agreement in cert context
    const xdhRe = /\b(X25519|X448|XDH)\b/g;
    while ((m = xdhRe.exec(fileText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    if (algoRefs.length > 0) {
      return `X.509 certificate operations in this file use: ${algoRefs.join(', ')}. Review each for PQC readiness.`;
    }
    return 'X.509 certificate detected but could not determine the signature algorithm from this file. Check the certificate signing algorithm and key type used.';
  }

  /**
   * Scan nearby lines for crypto-relevant context clues.
   * For provider/certificate/WebCrypto detections, scans the **entire file**
   * since the algorithm usage may be distant from the detection point.
   * For other patterns, scans ±30 lines.
   * Returns a description string with found algorithms.
   */
  function scanNearbyContext(lines: string[], matchLine: number, assetName: string): string | null {
    // Whole-file scan for providers, certificates, and WebCrypto; ±30 lines for others
    const isProvider = assetName.toLowerCase().includes('provider');
    const isCertificate = assetName === 'X.509';
    const isWebCrypto = assetName === 'WebCrypto';
    const wholeFile = isProvider || isCertificate || isWebCrypto;
    const start = wholeFile ? 0 : Math.max(0, matchLine - 30);
    const end = wholeFile ? lines.length : Math.min(lines.length, matchLine + 30);
    const nearbyText = lines.slice(start, end).join('\n');

    // ── WebCrypto-specific: extract algorithms from crypto.subtle API calls ──
    if (isWebCrypto) {
      return scanWebCryptoContext(nearbyText);
    }

    // Look for getInstance("...") calls nearby to determine which algorithms are in scope
    const algoRefs: string[] = [];
    const getInstanceRe = /(?:Cipher|Signature|KeyPairGenerator|KeyFactory|KeyAgreement|MessageDigest|Mac|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*"([^"]+)"/g;
    let m;
    while ((m = getInstanceRe.exec(nearbyText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // Look for signature algorithm references: getSigAlgName(), getSignature(), "SHA256withRSA" etc.
    const sigAlgoRe = /(SHA\d+with\w+|MD5with\w+|Ed25519|Ed448|ECDSA|RSA|DSA)/g;
    while ((m = sigAlgoRe.exec(nearbyText)) !== null) {
      if (!algoRefs.includes(m[1])) algoRefs.push(m[1]);
    }

    // Look for KeyStore type references
    const keyStoreRe = /KeyStore\.getInstance\s*\(\s*"([^"]+)"/;
    const ksMatch = nearbyText.match(keyStoreRe);
    if (ksMatch && !algoRefs.includes(ksMatch[1])) algoRefs.push(`KeyStore:${ksMatch[1]}`);

    // ── X.509-specific: look for certificate-related algorithm references ──
    if (isCertificate) {
      return scanX509Context(nearbyText, algoRefs);
    }

    if (isProvider) {
      // ── Provider-specific: also look for explicit BC provider references ──
      // getInstance("AES", "BC") or getInstance("RSA/ECB/PKCS1Padding", bcProvider)
      const bcProviderRe = /getInstance\s*\(\s*"([^"]+)"\s*,\s*(?:"BC"|"BouncyCastle"|[Bb]c\w*|new\s+BouncyCastleProvider\s*\(\s*\)|BouncyCastleProvider\.PROVIDER_NAME)\s*\)/g;
      while ((m = bcProviderRe.exec(nearbyText)) !== null) {
        const algo = m[1];
        if (!algoRefs.includes(algo)) algoRefs.unshift(algo); // prepend — these are confirmed BC-routed
      }

      // BouncyCastle-specific class instantiations (not via JCE)
      const bcClassRe = /new\s+((?:JcaContentSignerBuilder|JcaDigestCalculatorProviderBuilder|JcaX509CertificateConverter|JcaX509v3CertificateBuilder|JcePBESecretKeyDecryptorBuilder|JcePKCSPBEInputDecryptorProviderBuilder|BcRSAContentVerifierProviderBuilder|BcECContentVerifierProviderBuilder)\s*\(\s*"?([^")\s]*)"?)/g;
      while ((m = bcClassRe.exec(nearbyText)) !== null) {
        const className = m[1].split('(')[0].trim();
        const arg = m[2]?.trim();
        const label = arg ? `${className}(${arg})` : className;
        if (!algoRefs.includes(label)) algoRefs.push(label);
      }

      // BouncyCastle PEM / ASN1 patterns that reveal algorithm usage
      const bcPemRe = /(?:PEMParser|PEMKeyPair|JcePEMDecryptorProviderBuilder|JcaPEMKeyConverter)/g;
      while ((m = bcPemRe.exec(nearbyText)) !== null) {
        if (!algoRefs.includes(m[0])) algoRefs.push(m[0]);
      }

      // Security.addProvider / Security.insertProviderAt
      const addProviderRe = /Security\.(?:addProvider|insertProviderAt)\s*\(/g;
      const hasProvider = addProviderRe.test(nearbyText);

      if (algoRefs.length > 0) {
        const prefix = hasProvider
          ? 'BouncyCastle provider registered. Algorithms used through it'
          : 'BouncyCastle provider referenced. Algorithms found in same file';
        return `${prefix}: ${algoRefs.join(', ')}. Review each for PQC readiness.`;
      }
      return 'BouncyCastle provider registered/referenced but no specific algorithm usage found in this file. Check other files that import from this class.';
    }

    if (algoRefs.length > 0) {
      return `${assetName} used alongside: ${algoRefs.join(', ')}. Review these algorithms for PQC readiness.`;
    }
    return null;
  }

  const cryptoPatterns: CryptoPattern[] = [
    // ════════════════════════════════════════════════════════════════════════
    // ── Java: JCE getInstance() with algorithm extraction from string arg ──
    // ════════════════════════════════════════════════════════════════════════
    // MessageDigest.getInstance("SHA-256")  → extracts "SHA-256"
    { pattern: /MessageDigest\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
    // Cipher.getInstance("AES/CBC/PKCS5Padding") → extracts "AES/CBC/PKCS5Padding", normalised later
    { pattern: /Cipher\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
    // Signature.getInstance("SHA256withRSA") → extracts "SHA256withRSA"
    { pattern: /Signature\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
    // KeyFactory.getInstance("RSA") → extracts "RSA"
    { pattern: /KeyFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    // KeyPairGenerator.getInstance("RSA") → extracts "RSA"
    { pattern: /KeyPairGenerator\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    // KeyGenerator.getInstance("AES") → extracts "AES"
    { pattern: /KeyGenerator\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyGenerator', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    // SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256") → extracts "PBKDF2WithHmacSHA256"
    { pattern: /SecretKeyFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    // KeyAgreement.getInstance("ECDH") → extracts "ECDH"
    { pattern: /KeyAgreement\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'KeyAgreement', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
    // Mac.getInstance("HmacSHA256") → extracts "HmacSHA256"
    { pattern: /Mac\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
    // AlgorithmParameters.getInstance("EC") → extracts "EC"
    { pattern: /AlgorithmParameters\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'AlgorithmParameters', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, extractAlgorithm: true },
    // SecretKeySpec with algorithm arg: new SecretKeySpec(key, "AES") → extracts "AES"
    { pattern: /new\s+SecretKeySpec\s*\([^,]+,\s*"([^"]+)"[^)]*\)/g, algorithm: 'SecretKeySpec', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN, assetType: AssetType.SECRET_KEY, extractAlgorithm: true },

    // ── Java: JCE calls with variable arguments — capture variable name for resolution ──
    { pattern: /MessageDigest\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'MessageDigest', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, resolveVariable: true },
    { pattern: /Cipher\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, resolveVariable: true },
    { pattern: /Signature\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, resolveVariable: true },
    { pattern: /KeyFactory\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
    { pattern: /KeyPairGenerator\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
    { pattern: /SecretKeyFactory\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN, resolveVariable: true },
    { pattern: /Mac\.getInstance\s*\(\s*([A-Za-z_]\w*)\s*\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, resolveVariable: true },

    // ── Java: TLS / SSL (protocol asset type) ──
    { pattern: /SSLContext\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
    { pattern: /SSLContext\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

    // ── Java: Certificates — extract signature algorithm from nearby context ──
    { pattern: /CertificateFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
    { pattern: /X509Certificate/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },
    { pattern: /X509TrustManager/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, scanContext: true },

    // ── Java: Misc JCE & BouncyCastle — scan context for algorithms ──
    { pattern: /new\s+SecureRandom\s*\(/g, algorithm: 'SecureRandom', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /new\s+BouncyCastleProvider\s*\(/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
    { pattern: /BouncyCastleProvider\.PROVIDER_NAME/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },
    { pattern: /Security\.(?:addProvider|insertProviderAt)\s*\(\s*new\s+BouncyCastleProvider/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, scanContext: true },

    // ── Java: JCE Provider registration patterns ──
    // put("Signature.SHA256withRSA", ...) → extracts "SHA256withRSA"
    { pattern: /put\s*\(\s*"Signature\.([^"]+)"\s*,/g, algorithm: 'JCE-Signature-Registration', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
    { pattern: /put\s*\(\s*"KeyPairGenerator\.([^"]+)"\s*,/g, algorithm: 'JCE-KeyPairGen-Registration', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    { pattern: /put\s*\(\s*"MessageDigest\.([^"]+)"\s*,/g, algorithm: 'JCE-Digest-Registration', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
    { pattern: /put\s*\(\s*"Cipher\.([^"]+)"\s*,/g, algorithm: 'JCE-Cipher-Registration', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
    { pattern: /put\s*\(\s*"KeyAgreement\.([^"]+)"\s*,/g, algorithm: 'JCE-KeyAgreement-Registration', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE, extractAlgorithm: true },
    { pattern: /put\s*\(\s*"Mac\.([^"]+)"\s*,/g, algorithm: 'JCE-Mac-Registration', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },

    // ── Python patterns ──
    { pattern: /hashlib\.sha256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.sha1/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.md5/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.sha384/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.sha512/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.new\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
    { pattern: /from\s+Crypto\.Cipher\s+import\s+AES/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /RSA\.generate/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /from\s+cryptography\.hazmat.*\s+import.*rsa/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /from\s+cryptography\.hazmat.*\s+import.*ec\b/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /ssl\.create_default_context\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
    { pattern: /ssl\.SSLContext\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

    // ── Node.js / TypeScript patterns ──
    { pattern: /crypto\.createHash\s*\(\s*['"]([^'"]+)['"]\s*\)/g, algorithm: 'Unknown-Hash', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION, extractAlgorithm: true },
    { pattern: /crypto\.createCipheriv\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT, extractAlgorithm: true },
    { pattern: /crypto\.createDecipheriv\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT, extractAlgorithm: true },
    { pattern: /crypto\.generateKeyPairSync\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'Unknown-KeyPair', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN, extractAlgorithm: true },
    { pattern: /crypto\.createSign\s*\(\s*['"]([^'"]+)['"]\s*\)/g, algorithm: 'Unknown-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN, extractAlgorithm: true },
    { pattern: /crypto\.createHmac\s*\(\s*['"]([^'"]+)['"]/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG, extractAlgorithm: true },
    { pattern: /crypto\.randomBytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.pbkdf2Sync\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.scryptSync\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.createDiffieHellman\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
    { pattern: /crypto\.createECDH\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
    { pattern: /new\s+SubtleCrypto|crypto\.subtle\./g, algorithm: 'WebCrypto', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT, scanContext: true },
    { pattern: /tls\.createSecureContext\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
    { pattern: /tls\.connect\s*\(/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },
  ];

  /**
   * Normalise an extracted algorithm name:
   *  - "AES/CBC/PKCS5Padding" → "AES"  (take the base algo before mode/padding)
   *  - "HmacSHA256" → "HMAC-SHA256"    (normalise HmacX → HMAC-X)
   *  - "SHA256withRSA" → "SHA256withRSA" (leave composite signatures as-is for DB lookup)
   *  - "PBKDF2WithHmacSHA256" → "PBKDF2" (normalise PBKDF2 variants)
   */
  function normaliseAlgorithmName(raw: string): string {
    let name = raw.trim();
    // Cipher transforms: "AES/CBC/PKCS5Padding" → "AES"
    if (name.includes('/')) {
      name = name.split('/')[0];
    }
    // HmacSHA256 → HMAC-SHA256
    const hmacMatch = name.match(/^Hmac(.+)$/i);
    if (hmacMatch) {
      const inner = hmacMatch[1].replace(/^sha/i, 'SHA-').replace(/^md/i, 'MD');
      return `HMAC-${inner}`;
    }
    // PBKDF2WithHmacSHA256 → PBKDF2
    if (/^PBKDF2/i.test(name)) {
      return 'PBKDF2';
    }
    // NONEwithRSA → NONEwithRSA (keep as-is for dedicated DB entry)
    // SHA256withRSA, SHA384withECDSA etc. → keep as-is for DB lookup
    // SHA256 → SHA-256, SHA384 → SHA-384, SHA512 → SHA-512 (insert dash if missing)
    const shaMatch = name.match(/^SHA(\d{3,4})$/i);
    if (shaMatch) {
      return `SHA-${shaMatch[1]}`;
    }
    return name;
  }

  try {
    // Find Java, Python, JS, and TS files
    // Excludes: build artifacts, dependency dirs, compiled output, VCS dirs
    const { stdout: files } = await execAsync(
      `find "${repoPath}" -type d \\( ` +
        `-name node_modules -o -name dist -o -name build -o -name .git ` +
        `-o -name .gradle -o -name .mvn -o -name target -o -name out ` +
        `-o -name bin -o -name .next -o -name __pycache__ -o -name .tox ` +
        `-o -name coverage -o -name .nyc_output -o -name vendor ` +
      `\\) -prune -o -type f \\( ` +
        `-name "*.java" -o -name "*.py" -o -name "*.js" -o -name "*.ts" ` +
        `-o -name "*.jsx" -o -name "*.tsx" ` +
      `\\) -print | head -5000`,
      { timeout: 60000 }
    );

    // Skip minified / bundled / build artifact files
    const SKIP_FILE_PATTERNS = [
      /\.min\.js$/,                    // minified JS
      /\.chunk\.js$/,                  // webpack chunk bundles
      /\.bundle\.js$/,                 // bundled JS
      /\.[a-f0-9]{8,}\.js$/,          // hashed filenames (e.g. 3144.8c449a08.js)
      /[\\/]static[\\/]js[\\/]/,       // CRA / Spring static build output
      /[\\/]resources[\\/]main[\\/]static[\\/]/, // Spring Boot packaged static assets
      /[\\/]public[\\/]static[\\/]/,   // CRA public build output
      /[\\/]vendor[\\/]/,              // vendored dependencies
      /[\\/]\.cache[\\/]/,             // cache directories
    ];

    const fileList = files.trim().split('\n').filter(Boolean);

    // Track seen detections to avoid duplicates (same file + line + match position)
    const seen = new Set<string>();

    for (const filePath of fileList) {
      // Skip build artifacts and minified files
      if (SKIP_FILE_PATTERNS.some(p => p.test(filePath))) continue;

      // Skip files matching exclude patterns (e.g., test files)
      const relativePath = path.relative(repoPath, filePath);
      if (excludePatterns && excludePatterns.length > 0 && shouldExcludeFile(relativePath, excludePatterns)) {
        continue;
      }

      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        for (const patternDef of cryptoPatterns) {
          const { pattern, algorithm, primitive, cryptoFunction, assetType, extractAlgorithm, resolveVariable } = patternDef;
          // Reset regex lastIndex
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(content)) !== null) {
            // Find line number
            const lineNumber = content.substring(0, match.index).split('\n').length;
            const relativePath = path.relative(repoPath, filePath);

            // Deduplicate: skip if same file + line + char position already reported
            const dedupeKey = `${relativePath}:${lineNumber}:${match.index}`;
            if (seen.has(dedupeKey)) continue;
            seen.add(dedupeKey);

            // Determine the asset name: use extracted capture group when available,
            // normalise it, then fall back to the static algorithm name.
            let assetName = algorithm;
            let resolved = false;
            if (extractAlgorithm && match[1]) {
              assetName = normaliseAlgorithmName(match[1]);
              resolved = true;
            } else if (resolveVariable && match[1]) {
              // Try to resolve the variable name to an algorithm string
              const resolvedAlgo = resolveVariableToAlgorithm(match[1], lines, lineNumber - 1);
              if (resolvedAlgo) {
                assetName = normaliseAlgorithmName(resolvedAlgo);
                resolved = true;
              }
              // else keep the generic fallback name (e.g. "KeyPairGenerator")
            }

            // Build description based on detection type
            let description: string | undefined;
            if (resolveVariable && !resolved) {
              description = `${algorithm}.getInstance() called with variable "${match[1]}" — could not resolve to a specific algorithm. Manual review recommended.`;
            } else if (resolveVariable && resolved) {
              description = `Resolved from ${algorithm}.getInstance(${match[1]}) → "${assetName}"`;
            } else if (patternDef.scanContext) {
              description = scanNearbyContext(lines, lineNumber - 1, assetName) ?? undefined;
            }

            const asset: CryptoAsset = {
              id: uuidv4(),
              name: assetName,
              type: 'crypto-asset',
              description,
              cryptoProperties: {
                assetType: assetType ?? AssetType.ALGORITHM,
                algorithmProperties: {
                  primitive,
                  cryptoFunctions: [cryptoFunction],
                },
              },
              location: {
                fileName: relativePath,
                lineNumber,
              },
              quantumSafety: QuantumSafetyStatus.UNKNOWN,
            };

            cbom.cryptoAssets.push(enrichAssetWithPQCData(asset));
          }
        }
      } catch {
        // Skip files that can't be read
      }
    }

    // ── Cross-file enrichment for BouncyCastle-Provider assets ──────────────
    // When no algorithms were found in the same file as the BC provider
    // registration, scan ALL other Java files for BC-routed algorithm usage
    // and also correlate with other crypto assets already discovered.
    const bcFallbackMsg = 'BouncyCastle provider registered/referenced but no specific algorithm usage found in this file.';
    const bcProviderAssets = cbom.cryptoAssets.filter(
      a => a.name === 'BouncyCastle-Provider' && a.description?.startsWith(bcFallbackMsg),
    );

    if (bcProviderAssets.length > 0) {
      // 1. Collect algorithms already detected in other files of this project
      const projectAlgos = new Set<string>();
      for (const a of cbom.cryptoAssets) {
        if (a.name !== 'BouncyCastle-Provider' && a.name !== 'WebCrypto' && a.name !== 'X.509' && a.name !== 'SecureRandom') {
          projectAlgos.add(a.name);
        }
      }

      // 2. Targeted cross-file scan for BC-explicit patterns
      const crossFileAlgos: { algo: string; file: string }[] = [];
      for (const fp of fileList) {
        if (SKIP_FILE_PATTERNS.some(p => p.test(fp))) continue;
        if (!fp.endsWith('.java')) continue;
        const relFp = path.relative(repoPath, fp);
        // Skip the files where the provider was already detected
        if (bcProviderAssets.some(a => a.location?.fileName === relFp)) continue;
        if (excludePatterns && excludePatterns.length > 0 && shouldExcludeFile(relFp, excludePatterns)) continue;

        try {
          const fileContent = fs.readFileSync(fp, 'utf-8');

          // getInstance("algo", "BC") — explicit BC provider usage
          const bcExplicitRe = /getInstance\s*\(\s*"([^"]+)"\s*,\s*(?:"BC"|"BouncyCastle"|[Bb]c\w*|new\s+BouncyCastleProvider\s*\(\s*\)|BouncyCastleProvider\.PROVIDER_NAME)\s*\)/g;
          let cm: RegExpExecArray | null;
          while ((cm = bcExplicitRe.exec(fileContent)) !== null) {
            crossFileAlgos.push({ algo: cm[1], file: relFp });
          }

          // BouncyCastle-specific class instantiations
          const bcClassRe = /new\s+(JcaContentSignerBuilder|JcaDigestCalculatorProviderBuilder|JcaX509CertificateConverter|JcaX509v3CertificateBuilder|JcePBESecretKeyDecryptorBuilder|BcRSAContentVerifierProviderBuilder|BcECContentVerifierProviderBuilder)\s*\(/g;
          while ((cm = bcClassRe.exec(fileContent)) !== null) {
            crossFileAlgos.push({ algo: cm[1], file: relFp });
          }

          // BouncyCastle PEM utilities
          const bcPemRe = /(?:PEMParser|PEMKeyPair|JcePEMDecryptorProviderBuilder|JcaPEMKeyConverter)/g;
          while ((cm = bcPemRe.exec(fileContent)) !== null) {
            crossFileAlgos.push({ algo: cm[0], file: relFp });
          }

          // BouncyCastle imports: import org.bouncycastle.* — extract the sub-package hint
          const bcImportRe = /import\s+org\.bouncycastle\.(\w+)/g;
          while ((cm = bcImportRe.exec(fileContent)) !== null) {
            const pkg = cm[1];
            // Only track meaningful sub-packages (not util, asn1 base, etc.)
            if (!['util', 'asn1', 'math', 'crypto', 'jce', 'jcajce', 'openssl'].includes(pkg)) {
              crossFileAlgos.push({ algo: `bc.${pkg}`, file: relFp });
            }
          }
        } catch {
          // skip unreadable files
        }
      }

      // 3. Build enriched description for each BC-Provider asset
      const uniqueCrossAlgos = [...new Set(crossFileAlgos.map(c => c.algo))];
      const crossFileFiles = [...new Set(crossFileAlgos.map(c => c.file))];

      for (const bcAsset of bcProviderAssets) {
        const parts: string[] = [];

        if (uniqueCrossAlgos.length > 0) {
          parts.push(`Cross-file scan found BC usage in ${crossFileFiles.length} other file(s): ${uniqueCrossAlgos.join(', ')}.`);
        }

        if (projectAlgos.size > 0) {
          const algoList = [...projectAlgos].slice(0, 15).join(', ');
          const suffix = projectAlgos.size > 15 ? ` (+${projectAlgos.size - 15} more)` : '';
          parts.push(`Project-wide algorithms detected: ${algoList}${suffix}.`);
        }

        if (parts.length > 0) {
          parts.push('Review each for PQC readiness.');
          bcAsset.description = parts.join(' ');
          // Re-enrich so the pqcVerdict picks up the new description
          const enriched = enrichAssetWithPQCData(bcAsset);
          Object.assign(bcAsset, enriched);
        }
      }
    }

    // ── Cross-file enrichment for X.509 assets ──────────────────────────────
    const x509FallbackMsg = 'X.509 certificate detected but could not determine the signature algorithm';
    const x509Assets = cbom.cryptoAssets.filter(
      a => a.name === 'X.509' && a.description?.startsWith(x509FallbackMsg),
    );

    if (x509Assets.length > 0) {
      const crossCertAlgos: string[] = [];
      for (const fp of fileList) {
        if (SKIP_FILE_PATTERNS.some(p => p.test(fp))) continue;
        if (!fp.endsWith('.java')) continue;
        const relFp = path.relative(repoPath, fp);
        if (x509Assets.some(a => a.location?.fileName === relFp)) continue;
        if (excludePatterns && excludePatterns.length > 0 && shouldExcludeFile(relFp, excludePatterns)) continue;

        try {
          const fc = fs.readFileSync(fp, 'utf-8');
          // Signature algorithm literals
          const sigLitRe = /["']((?:SHA\d+with\w+|MD5with\w+|Ed25519|Ed448|ML-DSA-\d+|SLH-DSA-\w+))['"]/g;
          let cm: RegExpExecArray | null;
          while ((cm = sigLitRe.exec(fc)) !== null) {
            if (!crossCertAlgos.includes(cm[1])) crossCertAlgos.push(cm[1]);
          }
          // JcaContentSignerBuilder("algo")
          const csbRe = /JcaContentSignerBuilder\s*\(\s*["']([^"']+)["']/g;
          while ((cm = csbRe.exec(fc)) !== null) {
            if (!crossCertAlgos.includes(cm[1])) crossCertAlgos.push(cm[1]);
          }
        } catch { /* skip */ }
      }

      if (crossCertAlgos.length > 0) {
        for (const x509Asset of x509Assets) {
          x509Asset.description = `Cross-file scan found certificate signature algorithms in project: ${crossCertAlgos.join(', ')}. Review each for PQC readiness.`;
          const enriched = enrichAssetWithPQCData(x509Asset);
          Object.assign(x509Asset, enriched);
        }
      }
    }

    // ── Cross-file enrichment for WebCrypto assets ──────────────────────────
    const webCryptoFallbackMsg = 'WebCrypto (crypto.subtle) detected but could not determine specific algorithms';
    const webCryptoAssets = cbom.cryptoAssets.filter(
      a => a.name === 'WebCrypto' && a.description?.startsWith(webCryptoFallbackMsg),
    );

    if (webCryptoAssets.length > 0) {
      const crossWebAlgos: string[] = [];
      for (const fp of fileList) {
        if (SKIP_FILE_PATTERNS.some(p => p.test(fp))) continue;
        if (!/\.(js|ts|jsx|tsx)$/.test(fp)) continue;
        const relFp = path.relative(repoPath, fp);
        if (webCryptoAssets.some(a => a.location?.fileName === relFp)) continue;
        if (excludePatterns && excludePatterns.length > 0 && shouldExcludeFile(relFp, excludePatterns)) continue;

        try {
          const fc = fs.readFileSync(fp, 'utf-8');
          // crypto.subtle.<method>({ name: 'ALGO' })
          const subtleRe = /crypto\.subtle\.\w+\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]/g;
          let cm: RegExpExecArray | null;
          while ((cm = subtleRe.exec(fc)) !== null) {
            if (!crossWebAlgos.includes(cm[1])) crossWebAlgos.push(cm[1]);
          }
          // Algorithm object: { name: "RSA-OAEP", ... }
          const algoObjRe = /\{\s*name\s*:\s*['"]([^'"]+)['"][^}]*(?:modulusLength|namedCurve|length|hash)\s*:/g;
          while ((cm = algoObjRe.exec(fc)) !== null) {
            if (!crossWebAlgos.includes(cm[1])) crossWebAlgos.push(cm[1]);
          }
        } catch { /* skip */ }
      }

      if (crossWebAlgos.length > 0) {
        for (const wcAsset of webCryptoAssets) {
          wcAsset.description = `Cross-file scan found WebCrypto algorithms in project: ${crossWebAlgos.join(', ')}. Review each for PQC readiness.`;
          const enriched = enrichAssetWithPQCData(wcAsset);
          Object.assign(wcAsset, enriched);
        }
      }
    }
  } catch (error) {
    console.error('Regex scan error:', (error as Error).message);
  }

  return cbom;
}

// ─── Merge Logic ─────────────────────────────────────────────────────────────

/**
 * Merge network scan assets into an existing CBOM.
 */
export function mergeCBOMs(baseCBOM: CBOMDocument, ...additionalAssets: CryptoAsset[]): CBOMDocument {
  return {
    ...baseCBOM,
    cryptoAssets: [...baseCBOM.cryptoAssets, ...additionalAssets],
    metadata: {
      ...baseCBOM.metadata,
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Full pipeline: scan code + scan dependencies + scan network + analyze conditionals + merge into unified CBOM.
 */
export async function runFullScan(
  repoPath: string,
  networkHosts?: string[]
): Promise<CBOMDocument> {
  // 1. Code scan (sonar or regex fallback)
  const codeCBOM = await runSonarCryptoScan(repoPath);

  // 2. Dependency scan — find crypto libs in pom.xml, package.json, etc.
  let depAssets: CryptoAsset[] = [];
  try {
    const thirdPartyLibs = await scanDependencies(repoPath);
    codeCBOM.thirdPartyLibraries = thirdPartyLibs;

    // Convert each library's known algorithms to CryptoAsset entries
    for (const lib of thirdPartyLibs) {
      depAssets.push(...cryptoLibToCBOMAssets(lib));
    }

    // Build dependency graph entries for third-party libs
    if (!codeCBOM.dependencies) codeCBOM.dependencies = [];
    for (const lib of thirdPartyLibs) {
      const depEntry: CryptoDependency = {
        ref: `${lib.packageManager}:${lib.groupId ? lib.groupId + ':' : ''}${lib.artifactId || lib.name}`,
        dependsOn: [],
        provides: lib.cryptoAlgorithms.map(a => `algorithm:${a}`),
      };
      codeCBOM.dependencies.push(depEntry);
    }

    console.log(`Dependency scan found ${thirdPartyLibs.length} crypto libraries with ${depAssets.length} algorithm references`);
  } catch (err) {
    console.warn('Dependency scan failed (non-blocking):', (err as Error).message);
  }

  // 3. Network scans (if hosts provided)
  const networkAssets: CryptoAsset[] = [];
  if (networkHosts && networkHosts.length > 0) {
    for (const host of networkHosts) {
      try {
        const result = await scanNetworkCrypto(host);
        networkAssets.push(networkResultToCBOMAsset(result));
      } catch (err) {
        console.warn(`Network scan failed for ${host}:`, (err as Error).message);
      }
    }
  }

  // 4. Merge all assets
  const merged = mergeCBOMs(codeCBOM, ...depAssets, ...networkAssets);

  // 5. Smart PQC parameter analysis — promote/demote CONDITIONAL assets
  merged.cryptoAssets = analyzeAllConditionalAssets(merged.cryptoAssets, repoPath);

  // 6. Safety-net: sync quantumSafety column with pqcVerdict
  //    (catches any ordering/overwrite issues from enrichment → analysis pipeline)
  merged.cryptoAssets = syncQuantumSafetyWithVerdict(merged.cryptoAssets);

  return merged;
}
