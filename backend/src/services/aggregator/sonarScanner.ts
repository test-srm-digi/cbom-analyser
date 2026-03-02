/**
 * Sonar-Cryptography Integration — runs the SonarQube crypto plugin via CLI.
 * Falls back to regex-based scanning when sonar-scanner is unavailable.
 */
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { CBOMDocument, CBOMRepository } from '../../types';
import { createEmptyCBOM, parseCBOMFile } from './cbomBuilder';
import { runRegexCryptoScan } from './regexScanner';

const execAsync = promisify(exec);

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
