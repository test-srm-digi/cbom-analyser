/**
 * External Tool Integrations
 *
 * Subprocess-based integrations with existing cryptographic analysis tools.
 * These tools are invoked when available and their results merged into the CBOM.
 *
 * All integrations are **optional** — they fail gracefully if the tool is not
 * installed, returning empty results instead of errors.
 *
 * Supported tools:
 *   1. CodeQL  — GitHub's data flow analysis for resolving dynamic crypto arguments
 *   2. cbomkit-theia — IBM's container/filesystem crypto scanner
 *   3. CryptoAnalysis — Typestate analysis for Java JCA/JCE APIs (CrySL rules)
 *
 * @see docs/advanced-resolution-techniques.md — Phases 2A, 3A
 */
import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import type { CryptoAsset, CBOMDocument } from '../../types';
import {
  AssetType,
  QuantumSafetyStatus,
} from '../../types';
import { enrichAssetWithPQCData } from '../pqcRiskEngine';
import { normaliseAlgorithmName } from './scannerUtils';

const execAsync = promisify(exec);

// ─── Availability Detection ─────────────────────────────────────────────────

interface ToolAvailability {
  codeql: boolean;
  cbomkitTheia: boolean;
  cryptoAnalysis: boolean;
  keytool: boolean;
  openssl: boolean;
}

/**
 * Check which external tools are available on the system.
 * Caches the result for the process lifetime.
 */
let cachedAvailability: ToolAvailability | null = null;

/** Reset the cached availability so that newly-installed tools are detected. */
export function resetToolAvailabilityCache(): void {
  cachedAvailability = null;
}

export async function checkToolAvailability(): Promise<ToolAvailability> {
  if (cachedAvailability) return cachedAvailability;

  const check = (cmd: string): boolean => {
    try {
      execSync(`which ${cmd} 2>/dev/null`, { encoding: 'utf-8' });
      return true;
    } catch {
      return false;
    }
  };

  cachedAvailability = {
    codeql: check('codeql'),
    cbomkitTheia: check('cbomkit-theia') || check('cbomkit'),
    cryptoAnalysis: check('CryptoAnalysis') || check('crypto-analysis'),
    keytool: check('keytool'),
    openssl: check('openssl'),
  };

  console.log('External tool availability:', JSON.stringify(cachedAvailability));
  return cachedAvailability;
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. CodeQL Integration
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Custom CodeQL queries for crypto argument resolution.
 * These are written to disk temporarily and executed via `codeql database analyze`.
 */
const CODEQL_QUERIES: Record<string, string> = {
  // Comprehensive query: find all crypto API getInstance() calls with string literal arguments.
  // This works reliably with --build-mode=none (no compilation needed).
  'CryptoAlgorithmDetection.ql': `
/**
 * @name Cryptographic algorithm detection
 * @description Finds crypto API getInstance() calls with string literal algorithm arguments
 * @kind problem
 * @tags security cryptography cbom
 * @id cbom/java/crypto-algorithm
 */
import java

from MethodAccess ma, StringLiteral sl
where
  ma.getMethod().hasName("getInstance") and
  sl = ma.getArgument(0) and
  (
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyAgreement") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Mac") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "AlgorithmParameters") or
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "SecretKeyFactory") or
    ma.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyFactory")
  )
select ma, ma.getMethod().getDeclaringType().getName() + ".getInstance() uses algorithm: " + sl.getValue()
  `.trim(),
};

/**
 * SARIF result structure (simplified).
 */
interface SARIFResult {
  ruleId: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn?: number };
    };
  }>;
}

interface SARIFRun {
  results: SARIFResult[];
}

interface SARIFReport {
  runs: SARIFRun[];
}

/**
 * Run CodeQL analysis on a repository to resolve dynamic crypto arguments.
 *
 * Pipeline:
 *   1. Try to compile Java project (mvnw/gradlew) for better analysis
 *   2. Create CodeQL database (with compilation or --build-mode=none fallback)
 *   3. Write custom .ql queries to a temp directory
 *   4. Install query pack dependencies (codeql pack install)
 *   5. Execute queries against the database
 *   6. Parse SARIF output and extract resolved algorithm names
 *
 * Returns empty array if CodeQL is not installed.
 */
export async function runCodeQLAnalysis(
  repoPath: string,
  language: string = 'java',
): Promise<CryptoAsset[]> {
  const availability = await checkToolAvailability();
  if (!availability.codeql) {
    console.log('CodeQL not available — skipping data flow analysis');
    return [];
  }

  // Normalise source root — remove trailing /. or .
  const sourceRoot = repoPath.replace(/\/?\.$/, '') || repoPath;

  const assets: CryptoAsset[] = [];
  const tmpDir = path.join(repoPath, '.cbom-codeql-tmp');

  try {
    // Create temp directory for queries and database
    fs.mkdirSync(tmpDir, { recursive: true });
    const dbDir = path.join(tmpDir, 'db');
    const queryDir = path.join(tmpDir, 'queries');
    fs.mkdirSync(queryDir, { recursive: true });

    // Write custom queries
    for (const [filename, content] of Object.entries(CODEQL_QUERIES)) {
      fs.writeFileSync(path.join(queryDir, filename), content);
    }

    // Write qlpack.yml with modern dependencies format
    fs.writeFileSync(path.join(queryDir, 'qlpack.yml'), [
      'name: cbom-crypto-queries',
      'version: 0.0.1',
      'dependencies:',
      '  codeql/java-all: "*"',
    ].join('\n'));

    // Install CodeQL pack dependencies (downloads codeql/java-all from registry)
    console.log('CodeQL: installing query pack dependencies...');
    try {
      await execAsync(`codeql pack install "${queryDir}" 2>&1`, { timeout: 120000 });
      console.log('CodeQL: pack dependencies installed successfully');
    } catch (err: any) {
      const detail = err?.stdout || err?.stderr || err?.message || 'Unknown error';
      console.warn(`CodeQL pack install warning: ${detail}`);
      // Continue anyway — might work with bundled packs
    }

    // Step 1: Create CodeQL database
    // For compiled languages, try build command first, then fall back to --build-mode=none
    const compiledLanguages = ['java', 'java-kotlin', 'c-cpp', 'csharp', 'rust'];
    const isCompiled = compiledLanguages.includes(language);
    let dbCreated = false;

    if (isCompiled) {
      // Try compilation with project build tools first (better analysis quality)
      const hasMvnw = fs.existsSync(path.join(sourceRoot, 'mvnw'));
      const hasGradlew = fs.existsSync(path.join(sourceRoot, 'gradlew'));
      const hasPom = fs.existsSync(path.join(sourceRoot, 'pom.xml'));
      const hasGradle = fs.existsSync(path.join(sourceRoot, 'build.gradle')) ||
                        fs.existsSync(path.join(sourceRoot, 'build.gradle.kts'));

      if (hasMvnw && hasPom) {
        console.log(`CodeQL: creating ${language} database with Maven wrapper...`);
        try {
          await execAsync(
            `codeql database create "${dbDir}" --language="${language}" --source-root="${sourceRoot}" --command="./mvnw compile -DskipTests -B -q" --overwrite 2>&1`,
            { timeout: 600000, cwd: sourceRoot },
          );
          dbCreated = true;
          console.log('CodeQL: database created with Maven compilation');
        } catch (mvnErr: any) {
          console.log(`CodeQL: Maven build failed — ${(mvnErr?.stdout || mvnErr?.message || '').slice(0, 200)}`);
        }
      }

      if (!dbCreated && hasGradlew && hasGradle) {
        console.log(`CodeQL: creating ${language} database with Gradle wrapper...`);
        try {
          await execAsync(
            `codeql database create "${dbDir}" --language="${language}" --source-root="${sourceRoot}" --command="./gradlew compileJava --no-daemon -q" --overwrite 2>&1`,
            { timeout: 600000, cwd: sourceRoot },
          );
          dbCreated = true;
          console.log('CodeQL: database created with Gradle compilation');
        } catch (gradleErr: any) {
          console.log(`CodeQL: Gradle build failed — ${(gradleErr?.stdout || gradleErr?.message || '').slice(0, 200)}`);
        }
      }

      if (!dbCreated) {
        // Fallback: source-only extraction (no compilation needed)
        console.log(`CodeQL: creating ${language} database in source-only mode (--build-mode=none)...`);
        try {
          await execAsync(
            `codeql database create "${dbDir}" --language="${language}" --source-root="${sourceRoot}" --build-mode=none --overwrite 2>&1`,
            { timeout: 300000, cwd: sourceRoot },
          );
          dbCreated = true;
          console.log('CodeQL: database created in source-only mode');
        } catch (err: any) {
          const detail = err?.stdout || err?.stderr || err?.message || 'Unknown error';
          console.warn(`CodeQL database creation failed:\n${detail}`);
          return [];
        }
      }
    } else {
      // Non-compiled languages (JS/TS, Python, Ruby) — no build needed
      console.log(`CodeQL: creating ${language} database for ${sourceRoot}...`);
      try {
        await execAsync(
          `codeql database create "${dbDir}" --language="${language}" --source-root="${sourceRoot}" --overwrite 2>&1`,
          { timeout: 300000, cwd: sourceRoot },
        );
        dbCreated = true;
      } catch (err) {
        console.warn(`CodeQL database creation failed: ${(err as Error).message}`);
        return [];
      }
    }

    if (!dbCreated) return [];

    // Step 2: Run queries
    const sarifOutput = path.join(tmpDir, 'results.sarif');
    console.log('CodeQL: running crypto analysis queries...');
    try {
      await execAsync(
        `codeql database analyze "${dbDir}" "${queryDir}" --format=sarifv2.1.0 --output="${sarifOutput}" 2>&1`,
        { timeout: 600000 },  // 10 min timeout
      );
    } catch (err: any) {
      const detail = err?.stdout || err?.stderr || err?.message || 'Unknown error';
      console.warn(`CodeQL analysis failed:\n${detail}`);
      return [];
    }

    // Step 3: Parse SARIF results
    if (fs.existsSync(sarifOutput)) {
      const sarif: SARIFReport = JSON.parse(fs.readFileSync(sarifOutput, 'utf-8'));
      for (const run of sarif.runs ?? []) {
        for (const result of run.results ?? []) {
          const asset = parseSARIFResult(result, repoPath);
          if (asset) assets.push(asset);
        }
      }
    }

    console.log(`CodeQL: resolved ${assets.length} crypto algorithm references`);
  } catch (err) {
    console.warn(`CodeQL integration error: ${(err as Error).message}`);
  } finally {
    // Clean up temp directory
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch { /* ignore */ }
  }

  return assets;
}

/**
 * Parse a single SARIF result into a CryptoAsset.
 */
function parseSARIFResult(result: SARIFResult, repoPath: string): CryptoAsset | null {
  const msg = result.message.text;
  const loc = result.locations?.[0]?.physicalLocation;

  // Extract algorithm name from message like "MessageDigest.getInstance() uses algorithm: SHA-256"
  const algoMatch = msg.match(/(?:algorithm|transform):\s*(.+)$/i);
  if (!algoMatch) return null;

  const rawAlgo = algoMatch[1].trim();
  const algo = normaliseAlgorithmName(rawAlgo);
  const fileName = loc?.artifactLocation?.uri ?? 'unknown';
  const lineNumber = loc?.region?.startLine ?? 0;

  // Determine API from message text (e.g., "Cipher.getInstance() uses algorithm: ...")
  const apiMatch = msg.match(/^(\w+)\.getInstance\(\)/);
  const api = apiMatch?.[1] || 'Unknown';

  const asset: CryptoAsset = {
    id: uuidv4(),
    name: algo,
    type: AssetType.ALGORITHM,
    description: `${api}.getInstance("${rawAlgo}") — resolved via CodeQL source analysis.`,
    cryptoProperties: {
      assetType: AssetType.ALGORITHM,
    },
    location: {
      fileName: fileName.replace(/^\//, ''),
      lineNumber,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'codeql',
  };

  return enrichAssetWithPQCData(asset);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. cbomkit-theia Integration
// ═══════════════════════════════════════════════════════════════════════════

/**
 * cbomkit-theia output structure (partial — only fields we use).
 */
interface CbomkitComponent {
  type: string;
  name: string;
  'crypto-properties'?: {
    assetType: string;
    algorithmProperties?: {
      algorithm?: string;
      primitive?: string;
      parameterSetIdentifier?: string;
    };
    certificateProperties?: {
      signatureAlgorithm?: string;
      subjectPublicKeyAlgorithm?: string;
      certificateFormat?: string;
      subjectName?: string;
      issuerName?: string;
    };
    oid?: string;
  };
  evidence?: {
    occurrences: Array<{
      location: string;
      line?: number;
    }>;
  };
}

interface CbomkitOutput {
  components?: CbomkitComponent[];
}

/**
 * Run cbomkit-theia on a repository/directory to detect crypto assets.
 *
 * cbomkit-theia uses plugins:
 *   - certificates: Scans for X.509 certs and extracts signature algorithms
 *   - javasecurity: Reads java.security config
 *   - opensslconf: Reads OpenSSL configuration
 *   - keys: Detects private/public key files
 *   - secrets: gitleaks-based secret detection
 *
 * Returns empty array if cbomkit-theia is not installed.
 */
export async function runCbomkitTheia(repoPath: string): Promise<CryptoAsset[]> {
  const availability = await checkToolAvailability();

  // Check for cbomkit-theia binary
  const binaryName = availability.cbomkitTheia
    ? (execSync('which cbomkit-theia 2>/dev/null || which cbomkit 2>/dev/null', { encoding: 'utf-8' }).trim())
    : null;

  if (!binaryName) {
    console.log('cbomkit-theia not available — skipping filesystem crypto scan');
    return [];
  }

  const assets: CryptoAsset[] = [];
  const outputFile = path.join(repoPath, '.cbom-theia-output.json');

  try {
    // Run cbomkit-theia on the directory
    console.log(`cbomkit-theia: scanning ${repoPath}...`);
    await execAsync(
      `"${binaryName}" dir "${repoPath}" --output "${outputFile}" 2>&1`,
      { timeout: 120000, cwd: repoPath },  // 2 min timeout
    );

    if (fs.existsSync(outputFile)) {
      const output: CbomkitOutput = JSON.parse(fs.readFileSync(outputFile, 'utf-8'));

      for (const component of output.components ?? []) {
        const asset = parseCbomkitComponent(component, repoPath);
        if (asset) assets.push(asset);
      }
    }

    console.log(`cbomkit-theia: found ${assets.length} crypto assets`);
  } catch (err) {
    console.warn(`cbomkit-theia integration error: ${(err as Error).message}`);
  } finally {
    try {
      fs.unlinkSync(outputFile);
    } catch { /* ignore */ }
  }

  return assets;
}

/**
 * Parse a cbomkit-theia component into a CryptoAsset.
 */
function parseCbomkitComponent(component: CbomkitComponent, repoPath: string): CryptoAsset | null {
  const props = component['crypto-properties'];
  if (!props) return null;

  const location = component.evidence?.occurrences?.[0];
  let name = component.name;
  let type = AssetType.ALGORITHM;

  // Certificate assets
  if (props.assetType === 'certificate' || props.certificateProperties) {
    type = AssetType.CERTIFICATE;
    const sigAlg = props.certificateProperties?.signatureAlgorithm;
    if (sigAlg) name = sigAlg;
  }

  // Algorithm assets
  if (props.algorithmProperties?.algorithm) {
    name = normaliseAlgorithmName(props.algorithmProperties.algorithm);
  }

  const asset: CryptoAsset = {
    id: uuidv4(),
    name,
    type,
    description: `Detected by cbomkit-theia: ${component.name}${props.oid ? ` (OID: ${props.oid})` : ''}.`,
    cryptoProperties: {
      assetType: type,
      ...(props.certificateProperties ? {
        certificateProperties: {
          signatureAlgorithm: props.certificateProperties.signatureAlgorithm,
          subjectPublicKeyAlgorithm: props.certificateProperties.subjectPublicKeyAlgorithm,
          certificateFormat: props.certificateProperties.certificateFormat,
          subjectName: props.certificateProperties.subjectName,
          issuerName: props.certificateProperties.issuerName,
        },
      } : {}),
      ...(props.oid ? { oid: props.oid } : {}),
    },
    location: {
      fileName: location?.location
        ? path.relative(repoPath, location.location)
        : 'unknown',
      lineNumber: location?.line ?? 0,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'cbomkit-theia',
  };

  return enrichAssetWithPQCData(asset);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. CryptoAnalysis (CogniCryptSAST) Integration
// ═══════════════════════════════════════════════════════════════════════════

/**
 * CryptoAnalysis CLI output format (partial).
 */
interface CryptoAnalysisResult {
  className: string;
  methodName: string;
  lineNumber: number;
  errorType: string;        // ConstraintError, TypestateError, etc.
  violatedRule: string;      // CrySL rule name
  details: string;           // Human-readable description
  algorithm?: string;        // Resolved algorithm (for ConstraintError)
}

/**
 * Run CryptoAnalysis (CogniCryptSAST / HeadlessJavaScanner) on a Java project.
 *
 * CryptoAnalysis uses CrySL rules to perform typestate analysis on JCA/JCE APIs:
 *   - Traces Cipher, MessageDigest, KeyGenerator, etc. through their full lifecycle
 *   - Resolves variable arguments via pointer/data-flow analysis
 *   - Checks API call ordering (typestate)
 *   - Validates constraint compliance (key sizes, algorithms, etc.)
 *
 * Requires: Java 17+, HeadlessJavaScanner JAR, compiled .class or .jar files
 * Returns empty array if CryptoAnalysis is not installed.
 */
export async function runCryptoAnalysis(repoPath: string): Promise<CryptoAsset[]> {
  const availability = await checkToolAvailability();
  if (!availability.cryptoAnalysis) {
    console.log('CryptoAnalysis not available — skipping Java typestate analysis');
    return [];
  }

  const assets: CryptoAsset[] = [];

  try {
    // Find Java source directories
    const javaFiles = findFilesRecursive(repoPath, '.java');
    if (javaFiles.length === 0) {
      console.log('CryptoAnalysis: no Java files found — skipping');
      return [];
    }

    // Look for build artifacts (needed for CryptoAnalysis)
    let targetDir = findBuildTarget(repoPath);

    // If no build artifacts, try to compile with Maven/Gradle wrapper
    if (!targetDir) {
      console.log('CryptoAnalysis: no compiled classes found — attempting compilation...');
      const hasMvnw = fs.existsSync(path.join(repoPath, 'mvnw'));
      const hasGradlew = fs.existsSync(path.join(repoPath, 'gradlew'));

      try {
        if (hasMvnw) {
          await execAsync(`chmod +x ./mvnw && ./mvnw compile -DskipTests -B -q 2>&1`, {
            timeout: 300000, cwd: repoPath,
          });
        } else if (hasGradlew) {
          await execAsync(`chmod +x ./gradlew && ./gradlew compileJava --no-daemon -q 2>&1`, {
            timeout: 300000, cwd: repoPath,
          });
        }
      } catch {
        console.log('CryptoAnalysis: compilation failed — cannot analyze without compiled classes');
      }

      targetDir = findBuildTarget(repoPath);
      if (!targetDir) {
        console.log('CryptoAnalysis: no compiled Java classes found (target/classes or build/classes) — skipping');
        return [];
      }
    }

    const outputDir = path.join(repoPath, '.cbom-cryptoanalysis-tmp');
    fs.mkdirSync(outputDir, { recursive: true });

    console.log(`CryptoAnalysis: analyzing ${targetDir}...`);

    // Run CryptoAnalysis (HeadlessJavaScanner v5.x CLI)
    const binName = execSync('which CryptoAnalysis 2>/dev/null || which crypto-analysis 2>/dev/null', { encoding: 'utf-8' }).trim();

    // Check for CrySL rules (downloaded by entrypoint.sh)
    const rulesDir = '/opt/cbom-tools/crysl-rules';
    const hasRules = fs.existsSync(rulesDir);
    const rulesFlag = hasRules ? `--rulesDir "${rulesDir}"` : '';

    try {
      await execAsync(
        `"${binName}" --appPath "${targetDir}" ${rulesFlag} --reportFormat SARIF --reportPath "${outputDir}" 2>&1`,
        { timeout: 300000 },  // 5 min timeout
      );
    } catch (err) {
      console.warn(`CryptoAnalysis execution failed: ${(err as Error).message}`);
      return [];
    }

    // Parse SARIF results
    const reportFiles = fs.readdirSync(outputDir).filter(f => f.endsWith('.sarif') || f.endsWith('.json'));
    for (const reportFile of reportFiles) {
      try {
        const report = JSON.parse(fs.readFileSync(path.join(outputDir, reportFile), 'utf-8'));

        // Try SARIF format first (v5.x default)
        if (report.runs) {
          for (const run of (report as SARIFReport).runs ?? []) {
            for (const result of run.results ?? []) {
              const asset = parseCryptoAnalysisSARIFResult(result, repoPath);
              if (asset) assets.push(asset);
            }
          }
        } else {
          // Fallback: legacy JSON format
          const results: CryptoAnalysisResult[] = Array.isArray(report) ? report : report.results ?? [];
          for (const result of results) {
            const asset = parseCryptoAnalysisResult(result, repoPath);
            if (asset) assets.push(asset);
          }
        }
      } catch { /* skip malformed */ }
    }

    // Clean up
    try {
      fs.rmSync(outputDir, { recursive: true, force: true });
    } catch { /* ignore */ }

    console.log(`CryptoAnalysis: found ${assets.length} crypto findings`);
  } catch (err) {
    console.warn(`CryptoAnalysis integration error: ${(err as Error).message}`);
  }

  return assets;
}

/**
 * Parse a CryptoAnalysis result into a CryptoAsset.
 */
function parseCryptoAnalysisResult(
  result: CryptoAnalysisResult,
  repoPath: string,
): CryptoAsset | null {
  // Extract algorithm from details or algorithm field
  let algo = result.algorithm;
  if (!algo) {
    // Try to extract from details string
    const algoMatch = result.details.match(/["']([A-Za-z0-9/_-]+(?:\/[A-Za-z0-9_-]+)?(?:\/[A-Za-z0-9_-]+)?)["']/);
    if (algoMatch) algo = algoMatch[1];
  }

  if (!algo) return null;

  const normAlgo = normaliseAlgorithmName(algo);

  // Convert class name to file path
  const filePath = result.className.replace(/\./g, '/') + '.java';

  const asset: CryptoAsset = {
    id: uuidv4(),
    name: normAlgo,
    type: AssetType.ALGORITHM,
    description: `Detected by CryptoAnalysis (CrySL typestate analysis): ${result.details}. ` +
      `Error type: ${result.errorType}. Rule: ${result.violatedRule}.`,
    cryptoProperties: {
      assetType: AssetType.ALGORITHM,
    },
    location: {
      fileName: filePath,
      lineNumber: result.lineNumber,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'cryptoanalysis',
  };

  return enrichAssetWithPQCData(asset);
}

/**
 * Parse a CryptoAnalysis SARIF result into a CryptoAsset (v5.x output format).
 */
function parseCryptoAnalysisSARIFResult(
  result: SARIFResult,
  repoPath: string,
): CryptoAsset | null {
  const msg = result.message?.text ?? '';
  const loc = result.locations?.[0]?.physicalLocation;

  // Try to extract algorithm name from SARIF message
  // CryptoAnalysis messages often reference algorithms in quotes or after "algorithm:"
  const algoMatch = msg.match(
    /(?:algorithm|transform|cipher|digest)[:=\s]+["']?([A-Za-z0-9/_-]+(?:\/[A-Za-z0-9_-]+)*)["']?/i,
  ) ?? msg.match(
    /["']([A-Za-z0-9/_-]+(?:\/[A-Za-z0-9_-]+)*)["']/,
  );

  if (!algoMatch) return null;

  const rawAlgo = algoMatch[1].trim();
  const algo = normaliseAlgorithmName(rawAlgo);
  const fileName = loc?.artifactLocation?.uri ?? 'unknown';
  const lineNumber = loc?.region?.startLine ?? 0;

  const asset: CryptoAsset = {
    id: uuidv4(),
    name: algo,
    type: AssetType.ALGORITHM,
    description: `Detected by CryptoAnalysis (CrySL typestate analysis): ${msg}. Rule: ${result.ruleId}.`,
    cryptoProperties: {
      assetType: AssetType.ALGORITHM,
    },
    location: {
      fileName: fileName.replace(/^\//, ''),
      lineNumber,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'cryptoanalysis',
  };

  return enrichAssetWithPQCData(asset);
}

// ─── Utility Functions ──────────────────────────────────────────────────────

/**
 * Recursively find files with a given extension.
 */
function findFilesRecursive(dir: string, ext: string): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (/^(node_modules|\.git|target|build|dist|vendor)$/.test(entry.name)) continue;
        results.push(...findFilesRecursive(fullPath, ext));
      } else if (entry.name.endsWith(ext)) {
        results.push(fullPath);
      }
    }
  } catch { /* ignore permission errors */ }
  return results;
}

/**
 * Find compiled Java class directory for CryptoAnalysis.
 */
function findBuildTarget(repoPath: string): string | null {
  const candidates = [
    'target/classes',
    'build/classes',
    'build/classes/java/main',
    'out/production',
  ];

  for (const candidate of candidates) {
    const fullPath = path.join(repoPath, candidate);
    if (fs.existsSync(fullPath)) return fullPath;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Unified External Scanner Runner
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run all available external tools and merge their findings.
 *
 * This is the main entry point called from scannerAggregator.ts.
 * Each tool runs independently and fails gracefully.
 */
export async function runExternalToolScans(
  repoPath: string,
  options?: {
    enableCodeQL?: boolean;
    enableCbomkitTheia?: boolean;
    enableCryptoAnalysis?: boolean;
    codeqlLanguage?: string;
  },
): Promise<CryptoAsset[]> {
  const allAssets: CryptoAsset[] = [];
  const availability = await checkToolAvailability();

  // Run tools in parallel where possible
  const promises: Promise<CryptoAsset[]>[] = [];

  if ((options?.enableCodeQL !== false) && availability.codeql) {
    promises.push(
      runCodeQLAnalysis(repoPath, options?.codeqlLanguage)
        .catch(err => {
          console.warn('CodeQL scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if ((options?.enableCbomkitTheia !== false) && availability.cbomkitTheia) {
    promises.push(
      runCbomkitTheia(repoPath)
        .catch(err => {
          console.warn('cbomkit-theia scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if ((options?.enableCryptoAnalysis !== false) && availability.cryptoAnalysis) {
    promises.push(
      runCryptoAnalysis(repoPath)
        .catch(err => {
          console.warn('CryptoAnalysis scan failed:', (err as Error).message);
          return [] as CryptoAsset[];
        })
    );
  }

  if (promises.length > 0) {
    const results = await Promise.allSettled(promises);
    for (const result of results) {
      if (result.status === 'fulfilled') {
        allAssets.push(...result.value);
      }
    }
  }

  if (allAssets.length > 0) {
    console.log(`External tools: found ${allAssets.length} total crypto assets`);
  }

  return allAssets;
}

/**
 * Deduplicate assets from external tools against existing CBOM assets.
 *
 * An external finding is considered a duplicate if there's already an asset with:
 *   - Same normalised algorithm name
 *   - Same file (or within ±5 lines)
 *
 * When a duplicate is found, the external tool's finding enriches the existing
 * asset (higher confidence, additional context) rather than creating a new one.
 */
export function deduplicateExternalAssets(
  existingAssets: CryptoAsset[],
  externalAssets: CryptoAsset[],
): CryptoAsset[] {
  const newAssets: CryptoAsset[] = [];

  for (const extAsset of externalAssets) {
    const extName = normaliseAlgorithmName(extAsset.name).toLowerCase();
    const extFile = extAsset.location?.fileName ?? '';
    const extLine = extAsset.location?.lineNumber ?? 0;

    // Check for duplicate
    const duplicate = existingAssets.find(existing => {
      const existName = normaliseAlgorithmName(existing.name).toLowerCase();
      const existFile = existing.location?.fileName ?? '';
      const existLine = existing.location?.lineNumber ?? 0;

      return (
        existName === extName &&
        existFile === extFile &&
        Math.abs(existLine - extLine) <= 5
      );
    });

    if (duplicate) {
      // Enrich existing asset with external tool data
      if (extAsset.description) {
        duplicate.description = (duplicate.description ?? '') +
          ` | External tool confirmation: ${extAsset.description}`;
      }
      // Boost confidence if we have a pqcVerdict
      if (duplicate.pqcVerdict && extAsset.pqcVerdict) {
        duplicate.pqcVerdict.confidence = Math.min(100,
          duplicate.pqcVerdict.confidence + 15);
        duplicate.pqcVerdict.reasons.push(
          `✓ Confirmed by ${extAsset.detectionSource} external tool analysis.`,
        );
      }
    } else {
      newAssets.push(extAsset);
    }
  }

  return newAssets;
}
