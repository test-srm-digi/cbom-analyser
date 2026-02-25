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
import { enrichAssetWithPQCData, calculateReadinessScore, checkNISTPQCCompliance } from './pqcRiskEngine';
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

    // Build sonar-scanner arguments
    const args = [
      `-Dsonar.projectKey=${projectKey}`,
      `-Dsonar.projectName="QuantumGuard Scan: ${path.basename(repoPath)}"`,
      `-Dsonar.sources=.`,
      `-Dsonar.host.url=${sonarHostUrl}`,
      `-Dsonar.token=${sonarToken}`,
      `-Dsonar.scm.disabled=true`,
      `-Dsonar.qualitygate.wait=true`,
      `-Dsonar.qualitygate.timeout=300`,
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
        return parseCBOMFile(JSON.stringify(report));
      }
    }

    console.warn('No CBOM output file found after sonar scan. Falling back to regex.');
    return runRegexCryptoScan(repoPath, excludePatterns);
  } catch (error) {
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
  };

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

    // ── Java: JCE calls with variable arguments (no string literal → generic fallback) ──
    { pattern: /MessageDigest\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'MessageDigest', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /Cipher\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'Cipher', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /Signature\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /KeyFactory\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /KeyPairGenerator\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /SecretKeyFactory\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /Mac\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },

    // ── Java: TLS / SSL (protocol asset type) ──
    { pattern: /SSLContext\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL, extractAlgorithm: true },
    { pattern: /SSLContext\.getInstance\s*\(\s*[^")][^)]*\)/g, algorithm: 'TLS', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.PROTOCOL },

    // ── Java: Certificates ──
    { pattern: /CertificateFactory\.getInstance\s*\(\s*"([^"]+)"[^)]*\)/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE, extractAlgorithm: true },
    { pattern: /X509Certificate/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },
    { pattern: /X509TrustManager/g, algorithm: 'X.509', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER, assetType: AssetType.CERTIFICATE },

    // ── Java: Misc JCE & BouncyCastle ──
    { pattern: /new\s+SecureRandom\s*\(/g, algorithm: 'SecureRandom', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /new\s+BouncyCastleProvider\s*\(/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
    { pattern: /BouncyCastleProvider\.PROVIDER_NAME/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },

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
    { pattern: /new\s+SubtleCrypto|crypto\.subtle\./g, algorithm: 'WebCrypto', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },
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
          const { pattern, algorithm, primitive, cryptoFunction, assetType, extractAlgorithm } = patternDef;
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
            if (extractAlgorithm && match[1]) {
              assetName = normaliseAlgorithmName(match[1]);
            }

            const asset: CryptoAsset = {
              id: uuidv4(),
              name: assetName,
              type: 'crypto-asset',
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

  return merged;
}
