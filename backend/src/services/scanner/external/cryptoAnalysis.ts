/**
 * CryptoAnalysis (CogniCryptSAST) Integration
 *
 * Typestate analysis for Java JCA/JCE APIs using CrySL rules.
 * Traces Cipher, MessageDigest, KeyGenerator, etc. through their full lifecycle.
 *
 * Requires: Java 17+, HeadlessJavaScanner JAR, compiled .class or .jar files
 *
 * @see docs/advanced-resolution-techniques.md — Phase 3A
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
import { findFilesRecursive, findBuildTarget } from './utils';
import type { SARIFResult, SARIFReport, CryptoAnalysisResult } from './types';

const execAsync = promisify(exec);

/** 50 MB — large Java projects can produce huge build output */
const MAX_BUFFER = 50 * 1024 * 1024;

/**
 * Run CryptoAnalysis (CogniCryptSAST / HeadlessJavaScanner) on a Java project.
 *
 * CryptoAnalysis uses CrySL rules to perform typestate analysis on JCA/JCE APIs:
 *   - Traces Cipher, MessageDigest, KeyGenerator, etc. through their full lifecycle
 *   - Resolves variable arguments via pointer/data-flow analysis
 *   - Checks API call ordering (typestate)
 *   - Validates constraint compliance (key sizes, algorithms, etc.)
 *
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
            timeout: 300000, cwd: repoPath, maxBuffer: MAX_BUFFER,
          });
        } else if (hasGradlew) {
          await execAsync(`chmod +x ./gradlew && ./gradlew compileJava --no-daemon -q 2>&1`, {
            timeout: 300000, cwd: repoPath, maxBuffer: MAX_BUFFER,
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
        { timeout: 300000, maxBuffer: MAX_BUFFER },  // 5 min timeout
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
