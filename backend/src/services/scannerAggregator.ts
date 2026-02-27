/**
 * Scanner Aggregator Service
 *
 * Orchestrates code scanning (sonar-cryptography) and network scanning,
 * then merges results into a unified CycloneDX 1.7 CBOM.
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
  CBOMRepository,
} from '../types';
import { enrichAssetWithPQCData, calculateReadinessScore, checkNISTPQCCompliance, syncQuantumSafetyWithVerdict } from './pqcRiskEngine';
import { scanNetworkCrypto, networkResultToCBOMAsset } from './networkScanner';
import { scanDependencies, cryptoLibToCBOMAssets } from './dependencyScanner';
import { analyzeAllConditionalAssets } from './pqcParameterAnalyzer';

// ── Scanner module (refactored) ──
import { CryptoPattern, SKIP_FILE_PATTERNS } from './scanner/scannerTypes';
import { globToRegex, shouldExcludeFile, normaliseAlgorithmName, resolveVariableToAlgorithm } from './scanner/scannerUtils';
import { scanNearbyContext } from './scanner/contextScanners';
import { allCryptoPatterns } from './scanner/patterns';

const execAsync = promisify(exec);

// ─── CBOM Builder ────────────────────────────────────────────────────────────

/**
 * Create an empty CBOM document shell.
 */
export function createEmptyCBOM(
  componentName: string,
  componentVersion?: string,
  repository?: CBOMRepository,
): CBOMDocument {
  // When the scan path is "." or empty, derive a meaningful name from the
  // repository URL (e.g. "https://github.com/org/repo" → "repo") or fall back
  // to a generic label.
  let resolvedName = componentName;
  if (!resolvedName || resolvedName === '.') {
    if (repository?.url) {
      const urlSegments = repository.url.replace(/\/+$/, '').split('/');
      resolvedName = urlSegments[urlSegments.length - 1] || 'Unknown Project';
    } else {
      resolvedName = 'Unknown Project';
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
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
        name: resolvedName,
        version: componentVersion,
        type: 'application',
      },
      ...(repository ? { repository } : {}),
    },
    components: [],
    cryptoAssets: [],
    dependencies: [],
  };
}

/**
 * Parse and validate an uploaded CBOM JSON file.
 * Supports both standard CycloneDX 1.6/1.7 CBOM and custom formats.
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

  throw new Error('Invalid CBOM format. Expected CycloneDX CBOM JSON (1.6 or 1.7).');
}

// ─── Sonar-Cryptography Integration ─────────────────────────────────────────

/**
 * Execute the sonar-cryptography scanner via CLI against a target repo.
 * Requires:
 *   - sonar-scanner CLI installed (brew install sonar-scanner)
 *   - SonarQube running with sonar-cryptography plugin
 *   - SONAR_HOST_URL and SONAR_TOKEN environment variables
 *
 * The plugin outputs a CycloneDX 1.7 CBOM as `cbom.json` in the project root.
 * Falls back to regex-based scanning if sonar-scanner is unavailable.
 */
export async function runSonarCryptoScan(repoPath: string, excludePatterns?: string[], repository?: CBOMRepository): Promise<CBOMDocument> {
  const cbom = createEmptyCBOM(path.basename(repoPath), undefined, repository);

  const sonarHostUrl = process.env.SONAR_HOST_URL || 'http://localhost:9090';
  const sonarToken = process.env.SONAR_TOKEN;

  try {
    // Check if sonar-scanner is available
    await execAsync('which sonar-scanner');

    if (!sonarToken) {
      console.warn('SONAR_TOKEN not set — falling back to regex scanner.');
      return runRegexCryptoScan(repoPath, excludePatterns, repository);
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
    return runRegexCryptoScan(repoPath, excludePatterns, repository);
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
    return runRegexCryptoScan(repoPath, excludePatterns, repository);
  }

  return cbom;
}

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
      `\\) -print | head -5000`,
      { timeout: 60000 }
    );

    // SKIP_FILE_PATTERNS is imported from scanner/scannerTypes

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
  networkHosts?: string[],
  repository?: CBOMRepository,
): Promise<CBOMDocument> {
  // 1. Code scan (sonar or regex fallback)
  const codeCBOM = await runSonarCryptoScan(repoPath, undefined, repository);

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
