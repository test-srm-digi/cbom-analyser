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
} from '../types';
import { enrichAssetWithPQCData, calculateReadinessScore, checkNISTPQCCompliance } from './pqcRiskEngine';
import { scanNetworkCrypto, networkResultToCBOMAsset } from './networkScanner';

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

  const cryptoPatterns: { pattern: RegExp; algorithm: string; primitive: CryptoPrimitive; cryptoFunction: CryptoFunction }[] = [
    // ── Java: Exact string-literal JCE calls ──
    { pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-?256"\s*\)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-?384"\s*\)/g, algorithm: 'SHA-384', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /MessageDigest\.getInstance\s*\(\s*"SHA-?512"\s*\)/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /MessageDigest\.getInstance\s*\(\s*"SHA3-[^"]+"\s*\)/g, algorithm: 'SHA-3', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /Cipher\.getInstance\s*\(\s*"AES[^"]*"\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /Cipher\.getInstance\s*\(\s*"RSA[^"]*"\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /KeyGenerator\.getInstance\s*\(\s*"AES"\s*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /Signature\.getInstance\s*\(\s*"SHA256withRSA"\s*\)/g, algorithm: 'RSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /Signature\.getInstance\s*\(\s*"SHA256withECDSA"\s*\)/g, algorithm: 'ECDSA', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    // ── Java: Broad dynamic JCE & BouncyCastle patterns ──
    { pattern: /KeyFactory\.getInstance\s*\([^)]+\)/g, algorithm: 'KeyFactory', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /KeyPairGenerator\.getInstance\s*\([^)]+\)/g, algorithm: 'KeyPairGenerator', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /Signature\.getInstance\s*\([^)]+\)/g, algorithm: 'Digital-Signature', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /SecretKeyFactory\.getInstance\s*\(\s*"PBKDF2[^"]*"[^)]*\)/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /SecretKeyFactory\.getInstance\s*\([^)]+\)/g, algorithm: 'SecretKeyFactory', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /new\s+SecureRandom\s*\(/g, algorithm: 'SecureRandom', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /new\s+BouncyCastleProvider\s*\(/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
    { pattern: /BouncyCastleProvider\.PROVIDER_NAME/g, algorithm: 'BouncyCastle-Provider', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.OTHER },
    { pattern: /new\s+SecretKeySpec\s*\([^)]*"AES"[^)]*\)/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /Mac\.getInstance\s*\([^)]+\)/g, algorithm: 'HMAC', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
    // ── Java: JCE Provider registration patterns (put("Signature.X", ...)) ──
    { pattern: /put\s*\(\s*"Signature\.[^"]+"\s*,/g, algorithm: 'JCE-Signature-Registration', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /put\s*\(\s*"KeyPairGenerator\.[^"]+"\s*,/g, algorithm: 'JCE-KeyPairGen-Registration', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /put\s*\(\s*"MessageDigest\.[^"]+"\s*,/g, algorithm: 'JCE-Digest-Registration', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    // Python patterns
    { pattern: /hashlib\.sha256/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.sha1/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /hashlib\.md5/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /from\s+Crypto\.Cipher\s+import\s+AES/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /RSA\.generate/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /from\s+cryptography\.hazmat.*\s+import.*rsa/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /from\s+cryptography\.hazmat.*\s+import.*ec\b/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    // Node.js / TypeScript patterns
    { pattern: /crypto\.createHash\s*\(\s*['"]sha256['"]\s*\)/g, algorithm: 'SHA-256', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/g, algorithm: 'SHA-1', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/g, algorithm: 'MD5', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /crypto\.createHash\s*\(\s*['"]sha512['"]\s*\)/g, algorithm: 'SHA-512', primitive: CryptoPrimitive.HASH, cryptoFunction: CryptoFunction.HASH_FUNCTION },
    { pattern: /crypto\.createCipheriv\s*\(\s*['"]aes-256[^'"]*['"]/g, algorithm: 'AES-256', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /crypto\.createCipheriv\s*\(\s*['"]aes-128[^'"]*['"]/g, algorithm: 'AES-128', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.ENCRYPT },
    { pattern: /crypto\.createDecipheriv\s*\(\s*['"]aes[^'"]*['"]/g, algorithm: 'AES', primitive: CryptoPrimitive.BLOCK_CIPHER, cryptoFunction: CryptoFunction.DECRYPT },
    { pattern: /crypto\.generateKeyPairSync\s*\(\s*['"]rsa['"]/g, algorithm: 'RSA', primitive: CryptoPrimitive.PKE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.generateKeyPairSync\s*\(\s*['"]ec['"]/g, algorithm: 'ECC', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.createSign\s*\(\s*['"]SHA256['"]\s*\)/g, algorithm: 'RSA-SHA256', primitive: CryptoPrimitive.SIGNATURE, cryptoFunction: CryptoFunction.SIGN },
    { pattern: /crypto\.createHmac\s*\(\s*['"]sha256['"]/g, algorithm: 'HMAC-SHA256', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
    { pattern: /crypto\.createHmac\s*\(\s*['"]sha512['"]/g, algorithm: 'HMAC-SHA512', primitive: CryptoPrimitive.MAC, cryptoFunction: CryptoFunction.TAG },
    { pattern: /crypto\.randomBytes\s*\(/g, algorithm: 'CSPRNG', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.pbkdf2Sync\s*\(/g, algorithm: 'PBKDF2', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.scryptSync\s*\(/g, algorithm: 'scrypt', primitive: CryptoPrimitive.KEY_DERIVATION, cryptoFunction: CryptoFunction.KEYGEN },
    { pattern: /crypto\.createDiffieHellman\s*\(/g, algorithm: 'Diffie-Hellman', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
    { pattern: /crypto\.createECDH\s*\(/g, algorithm: 'ECDH', primitive: CryptoPrimitive.KEY_AGREEMENT, cryptoFunction: CryptoFunction.KEY_EXCHANGE },
    { pattern: /new\s+SubtleCrypto|crypto\.subtle\./g, algorithm: 'WebCrypto', primitive: CryptoPrimitive.OTHER, cryptoFunction: CryptoFunction.ENCRYPT },
  ];

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

        for (const { pattern, algorithm, primitive, cryptoFunction } of cryptoPatterns) {
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

            const asset: CryptoAsset = {
              id: uuidv4(),
              name: algorithm,
              type: 'crypto-asset',
              cryptoProperties: {
                assetType: AssetType.ALGORITHM,
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
 * Full pipeline: scan code + scan network + merge into unified CBOM.
 */
export async function runFullScan(
  repoPath: string,
  networkHosts?: string[]
): Promise<CBOMDocument> {
  // 1. Code scan
  const codeCBOM = await runSonarCryptoScan(repoPath);

  // 2. Network scans (if hosts provided)
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

  // 3. Merge
  return mergeCBOMs(codeCBOM, ...networkAssets);
}
