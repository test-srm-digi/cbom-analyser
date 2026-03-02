/**
 * Regex-based crypto scanner — pattern-matching fallback when sonar-scanner
 * is unavailable.  Scans source and configuration files for cryptographic
 * usage, then enriches results with cross-file context.
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
  QuantumSafetyStatus,
  CBOMRepository,
} from '../../types';
import { enrichAssetWithPQCData } from '../pqcRiskEngine';
import { SKIP_FILE_PATTERNS } from '../scanner/scannerTypes';
import {
  shouldExcludeFile,
  normaliseAlgorithmName,
  resolveVariableToAlgorithm,
  filterFalsePositives,
} from '../scanner/scannerUtils';
import { scanNearbyContext } from '../scanner/contextScanners';
import { allCryptoPatterns, allConfigPatterns, CONFIG_FILENAMES } from '../scanner/patterns';
import { createEmptyCBOM } from './cbomBuilder';

const execAsync = promisify(exec);

/**
 * Fallback: Regex-based crypto detection for when sonar-scanner is unavailable.
 * Scans Java and Python files for common cryptographic patterns.
 */
export async function runRegexCryptoScan(repoPath: string, excludePatterns?: string[], repository?: CBOMRepository): Promise<CBOMDocument> {
  const cbom = createEmptyCBOM(path.basename(repoPath), undefined, repository);

  // All patterns are imported from scanner/patterns module
  const cryptoPatterns = allCryptoPatterns;

  try {
    // Find source files for all supported languages
    // Excludes: build artifacts, dependency dirs, compiled output, VCS dirs
    const { stdout: files } = await execAsync(
      `find "${repoPath}" -type d \\( ` +
        `-name node_modules -o -name dist -o -name build -o -name .git ` +
        `-o -name .gradle -o -name .mvn -o -name target -o -name out ` +
        `-o -name bin -o -name .next -o -name __pycache__ -o -name .tox ` +
        `-o -name coverage -o -name .nyc_output -o -name vendor ` +
        `-o -name obj -o -name packages -o -name .nuget ` +
      `\\) -prune -o -type f \\( ` +
        `-name "*.java" -o -name "*.py" -o -name "*.js" -o -name "*.ts" ` +
        `-o -name "*.jsx" -o -name "*.tsx" ` +
        `-o -name "*.cpp" -o -name "*.cxx" -o -name "*.cc" -o -name "*.c" ` +
        `-o -name "*.h" -o -name "*.hpp" -o -name "*.hxx" ` +
        `-o -name "*.cs" ` +
        `-o -name "*.go" ` +
        `-o -name "*.php" ` +
        `-o -name "*.rs" ` +
      `\\) -print | head -5000`,
      { timeout: 60000 }
    );

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

    // ── Configuration / artifact file scanning (cbomkit-theia inspired) ─────
    scanConfigFiles(repoPath, excludePatterns, seen, cbom);

    // ── Cross-file enrichment ───────────────────────────────────────────────
    enrichBouncyCastleProviders(cbom, fileList, repoPath, excludePatterns);
    enrichX509Assets(cbom, fileList, repoPath, excludePatterns);
    enrichWebCryptoAssets(cbom, fileList, repoPath, excludePatterns);
  } catch (error) {
    console.error('Regex scan error:', (error as Error).message);
  }

  // Remove false positives (e.g. HashMap, HashSet misclassified as crypto)
  cbom.cryptoAssets = filterFalsePositives(cbom.cryptoAssets);

  return cbom;
}

// ─── Configuration / artifact file scanning ─────────────────────────────────

function scanConfigFiles(
  repoPath: string,
  excludePatterns: string[] | undefined,
  seen: Set<string>,
  cbom: CBOMDocument,
): void {
  try {
    const configNameArgs = CONFIG_FILENAMES.map(n => `-name "${n}"`).join(' -o ');
    // execSync returns the stdout string directly (not { stdout })
    const configFiles = require('child_process').execSync(
      `find "${repoPath}" -type d \\( ` +
        `-name node_modules -o -name dist -o -name build -o -name .git ` +
        `-o -name target -o -name out -o -name vendor ` +
      `\\) -prune -o -type f \\( ` +
        `-name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.key" ` +
        `-o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.pub" ` +
        `-o -name "*.security" -o -name "*.cnf" -o -name "*.conf" ` +
        `-o -name "*.keystore" -o -name "*.truststore" ` +
        `-o ${configNameArgs} ` +
      `\\) -print | head -500`,
      { timeout: 30000, encoding: 'utf-8' }
    ) as string;

    const configFileList = configFiles.trim().split('\n').filter(Boolean);

    for (const cfgPath of configFileList) {
      const relativePath = path.relative(repoPath, cfgPath);
      if (excludePatterns && excludePatterns.length > 0 && shouldExcludeFile(relativePath, excludePatterns)) continue;

      try {
        const content = fs.readFileSync(cfgPath, 'utf-8');
        // Skip binary files (certificates in DER format won't parse as UTF-8 meaningfully)
        if (content.includes('\0')) continue;

        for (const patternDef of allConfigPatterns) {
          const { pattern, algorithm, primitive, cryptoFunction: cf, assetType, extractAlgorithm } = patternDef;
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(content)) !== null) {
            const lineNumber = content.substring(0, match.index).split('\n').length;
            const dedupeKey = `${relativePath}:${lineNumber}:${match.index}`;
            if (seen.has(dedupeKey)) continue;
            seen.add(dedupeKey);

            let assetName = algorithm;
            if (extractAlgorithm && match[1]) {
              assetName = normaliseAlgorithmName(match[1]);
            }

            const asset: CryptoAsset = {
              id: uuidv4(),
              name: assetName,
              type: 'crypto-asset',
              description: `Detected in configuration/artifact file: ${path.basename(cfgPath)}`,
              cryptoProperties: {
                assetType: assetType ?? AssetType.ALGORITHM,
                algorithmProperties: {
                  primitive,
                  cryptoFunctions: [cf],
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
  } catch (err) {
    console.warn('Config file scan failed (non-blocking):', (err as Error).message);
  }
}

// ─── Cross-file enrichment: BouncyCastle ────────────────────────────────────

function enrichBouncyCastleProviders(
  cbom: CBOMDocument,
  fileList: string[],
  repoPath: string,
  excludePatterns: string[] | undefined,
): void {
  const bcFallbackMsg = 'BouncyCastle provider registered/referenced but no specific algorithm usage found in this file.';
  const bcProviderAssets = cbom.cryptoAssets.filter(
    a => a.name === 'BouncyCastle-Provider' && a.description?.startsWith(bcFallbackMsg),
  );

  if (bcProviderAssets.length === 0) return;

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

// ─── Cross-file enrichment: X.509 ──────────────────────────────────────────

function enrichX509Assets(
  cbom: CBOMDocument,
  fileList: string[],
  repoPath: string,
  excludePatterns: string[] | undefined,
): void {
  const x509FallbackMsg = 'X.509 certificate detected but could not determine the signature algorithm';
  const x509Assets = cbom.cryptoAssets.filter(
    a => a.name === 'X.509' && a.description?.startsWith(x509FallbackMsg),
  );

  if (x509Assets.length === 0) return;

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

// ─── Cross-file enrichment: WebCrypto ───────────────────────────────────────

function enrichWebCryptoAssets(
  cbom: CBOMDocument,
  fileList: string[],
  repoPath: string,
  excludePatterns: string[] | undefined,
): void {
  const webCryptoFallbackMsg = 'WebCrypto (crypto.subtle) detected but could not determine specific algorithms';
  const webCryptoAssets = cbom.cryptoAssets.filter(
    a => a.name === 'WebCrypto' && a.description?.startsWith(webCryptoFallbackMsg),
  );

  if (webCryptoAssets.length === 0) return;

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
