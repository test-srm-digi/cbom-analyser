/**
 * CodeQL Integration
 *
 * GitHub's data-flow analysis for resolving dynamic crypto arguments.
 * Creates a CodeQL database, runs custom .ql queries, and parses SARIF output.
 *
 * @see docs/advanced-resolution-techniques.md — Phase 2A
 */
import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import type { CryptoAsset } from '../../../types';
import { AssetType, QuantumSafetyStatus } from '../../../types';
import { enrichAssetWithPQCData } from '../../pqc';
import { normaliseAlgorithmName } from '../scannerUtils';
import { checkToolAvailability } from './availability';
import type { SARIFResult, SARIFReport } from './types';

const execAsync = promisify(exec);

/**
 * Custom CodeQL queries for crypto argument resolution.
 * These are written to disk temporarily and executed via `codeql database analyze`.
 */
export const CODEQL_QUERIES: Record<string, string> = {
  // Comprehensive query: find all crypto API getInstance() calls with string literal arguments.
  // Uses hasName() (simple class name) instead of hasQualifiedName() so it works
  // with --build-mode=none where full type resolution may be partial.
  'CryptoAlgorithmDetection.ql': `
/**
 * @name Cryptographic algorithm detection
 * @description Finds crypto API getInstance() calls with string literal algorithm arguments
 * @kind problem
 * @tags security cryptography cbom
 * @id cbom/java/crypto-algorithm
 */
import java

from MethodAccess ma, StringLiteral sl, string className, string algoValue
where
  ma.getMethod().hasName("getInstance") and
  sl = ma.getArgument(0) and
  className = ma.getMethod().getDeclaringType().getName() and
  algoValue = sl.getValue() and
  (
    className = "MessageDigest" or
    className = "Cipher" or
    className = "KeyGenerator" or
    className = "Signature" or
    className = "KeyPairGenerator" or
    className = "KeyAgreement" or
    className = "Mac" or
    className = "SSLContext" or
    className = "AlgorithmParameters" or
    className = "SecretKeyFactory" or
    className = "KeyFactory"
  )
select ma, className + ".getInstance() uses algorithm: " + algoValue
  `.trim(),
};

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

    // Write custom queries — standalone .ql files (no qlpack.yml).
    // Without a qlpack.yml, CodeQL treats these as standalone queries and
    // resolves `import java` through the bundle's built-in search path
    // (the binary automatically discovers packs bundled alongside it).
    // A qlpack.yml with `dependencies` would trigger the package-cache
    // resolution system, which doesn't reliably find bundled packs.
    for (const [filename, content] of Object.entries(CODEQL_QUERIES)) {
      fs.writeFileSync(path.join(queryDir, filename), content);
    }

    // Resolve CodeQL home directory.
    // The bundle extracts to e.g. /opt/cbom-tools/codeql/ with packs in qlpacks/.
    let codeqlHome = '';
    try {
      const bin = execSync('which codeql', { encoding: 'utf-8' }).trim();
      codeqlHome = path.dirname(fs.realpathSync(bin));
      console.log(`CodeQL: home directory: ${codeqlHome}`);
    } catch {
      console.log('CodeQL: could not resolve home directory — will try default search path');
    }
    // --search-path must point to the qlpacks/ directory (the immediate parent
    // of the namespace dirs like codeql/java-all/).  Pointing at the bundle
    // root doesn't work because CodeQL only treats directories with a
    // .codeqlmanifest.json or "immediate parents of pack dirs" as valid roots.
    const qlpacksRoot = codeqlHome ? path.join(codeqlHome, 'qlpacks') : '';
    const searchPathFlag = qlpacksRoot && fs.existsSync(qlpacksRoot)
      ? `--search-path="${qlpacksRoot}"`
      : (codeqlHome ? `--search-path="${codeqlHome}"` : '');

    // Verify the bundled java-all pack is discoverable.
    // This catches misconfiguration early (e.g. CLI-only download without packs).
    if (codeqlHome) {
      const qlpacksDir = path.join(codeqlHome, 'qlpacks', 'codeql', 'java-all');
      if (fs.existsSync(qlpacksDir)) {
        const versions = fs.readdirSync(qlpacksDir).filter(d => !d.startsWith('.'));
        console.log(`CodeQL: bundled codeql/java-all found (${versions[0] || 'unknown version'})`);
      } else {
        console.warn(
          'CodeQL: codeql/java-all NOT found in bundle. ' +
          'Ensure the CodeQL *bundle* (not CLI-only) is installed. ' +
          'See: https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli',
        );
      }
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
    // Pass each .ql file individually to avoid qlpack.yml detection.
    // --search-path tells CodeQL where to look for library packs (belt-and-suspenders;
    // the bundled binary already knows about its own packs).
    const sarifOutput = path.join(tmpDir, 'results.sarif');
    const queryFiles = Object.keys(CODEQL_QUERIES)
      .map(f => `"${path.join(queryDir, f)}"`)
      .join(' ');
    console.log('CodeQL: running crypto analysis queries...');
    try {
      const analyzeCmd = `codeql database analyze "${dbDir}" ${queryFiles} --format=sarifv2.1.0 --output="${sarifOutput}" ${searchPathFlag} 2>&1`;
      console.log(`CodeQL: ${analyzeCmd}`);
      const { stdout: analyzeOut } = await execAsync(analyzeCmd, { timeout: 600000 });
      console.log(`CodeQL: analyze completed — ${analyzeOut.slice(-200)}`);
    } catch (err: any) {
      const detail = err?.stdout || err?.stderr || err?.message || 'Unknown error';
      console.warn(`CodeQL analysis failed:\n${detail.slice(0, 500)}`);
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
