import type { XBOMDocument, XBOMAnalytics } from '../../types';

/** Format an ISO timestamp for display */
export function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** Client-side analytics computation for uploaded xBOMs */
export function computeLocalAnalytics(xbom: XBOMDocument): XBOMAnalytics {
  const cryptoAssets = xbom.cryptoAssets ?? [];
  const vulns = xbom.vulnerabilities ?? [];
  const totalCrypto = cryptoAssets.length;
  const qSafe = cryptoAssets.filter(
    (a) => a.quantumSafety === 'quantum-safe',
  ).length;
  const notSafe = cryptoAssets.filter(
    (a) => a.quantumSafety === 'not-quantum-safe',
  ).length;
  const conditional = cryptoAssets.filter(
    (a) => a.quantumSafety === 'conditional',
  ).length;
  const unknown = totalCrypto - qSafe - notSafe - conditional;
  const score =
    totalCrypto > 0 ? Math.round((qSafe / totalCrypto) * 100) : 100;

  const vulnCritical = vulns.filter((v) =>
    v.ratings?.some((r: any) => r.severity === 'critical'),
  ).length;
  const vulnHigh = vulns.filter(
    (v) =>
      v.ratings?.some((r: any) => r.severity === 'high') &&
      !v.ratings?.some((r: any) => r.severity === 'critical'),
  ).length;
  const vulnMedium = vulns.filter((v) =>
    v.ratings?.some((r: any) => r.severity === 'medium'),
  ).length;
  const vulnLow = vulns.filter((v) =>
    v.ratings?.some((r: any) => r.severity === 'low'),
  ).length;

  return {
    quantumReadiness: {
      score,
      totalAssets: totalCrypto,
      quantumSafe: qSafe,
      notQuantumSafe: notSafe,
      conditional,
      unknown,
    },
    compliance: {
      isCompliant: notSafe === 0,
      policy: 'PQC Readiness',
      source: 'local-analysis',
      totalAssets: totalCrypto,
      compliantAssets: qSafe + conditional,
      nonCompliantAssets: notSafe,
      unknownAssets: unknown,
    },
    vulnerabilitySummary: {
      total: vulns.length,
      critical: vulnCritical,
      high: vulnHigh,
      medium: vulnMedium,
      low: vulnLow,
      info: 0,
    },
    totalSoftwareComponents: xbom.components?.length ?? 0,
    totalCryptoAssets: totalCrypto,
    totalCrossReferences: xbom.crossReferences?.length ?? 0,
  };
}

/** Generate GitHub Actions workflow YAML for xBOM scanning */
export function generateXBOMWorkflowYaml(opts: {
  branches: string;
  scanPath: string;
  specVersion: string;
  excludePatterns: string;
  failOnVulnerable: boolean;
  trivySeverity: string;
}): string {
  const branchList = opts.branches
    .split(',')
    .map((b) => b.trim())
    .filter(Boolean)
    .join(', ');
  return `# xBOM Generator — Unified SBOM + CBOM
# Copy this file to .github/workflows/xbom.yml in your repository

name: xBOM — Unified SBOM + CBOM

on:
  push:
    branches: [${branchList}]
  pull_request:
    branches: [${branchList}]
  workflow_dispatch:
    inputs:
      scan-path:
        description: 'Path to scan'
        default: '${opts.scanPath}'

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  xbom:
    name: Generate xBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Step 1: Install & Run Trivy (SBOM)
      - name: Install & Run Trivy (SBOM + Vulnerabilities)
        run: |
          sudo apt-get update -qq && sudo apt-get install -yqq wget apt-transport-https gnupg lsb-release
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
          echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
          sudo apt-get update -qq && sudo apt-get install -yqq trivy
          trivy fs \\
            --format cyclonedx \\
            --output sbom.json \\
            --severity "${opts.trivySeverity}" \\
            --scanners vuln,license \\
            "\${{ github.event.inputs.scan-path || '${opts.scanPath}' }}"

      # Step 2: CBOM Analyser
      - name: Run CBOM Analyser
        uses: annanay-sharma/cbom-analyser@main
        with:
          output-format: json
          output-file: cbom-report.json
          scan-path: \${{ github.event.inputs.scan-path || '${opts.scanPath}' }}
          exclude-patterns: '${opts.excludePatterns}'
          fail-on-vulnerable: 'false'
          enable-codeql: 'true'
          enable-cbomkit-theia: 'true'
          enable-crypto-analysis: 'true'
          codeql-language: 'java'

      # Step 3: Merge → xBOM
      - name: Merge SBOM + CBOM → xBOM
        uses: actions/github-script@v7
        id: merge
        with:
          script: |
            const fs = require('fs');
            const crypto = require('crypto');
            const sbom = JSON.parse(fs.readFileSync('sbom.json', 'utf-8'));
            const cbomRaw = JSON.parse(fs.readFileSync('cbom-report.json', 'utf-8'));
            const cbom = cbomRaw.cbom || cbomRaw;

            const xbom = {
              bomFormat: 'CycloneDX',
              specVersion: '${opts.specVersion}',
              serialNumber: \`urn:uuid:\$\{crypto.randomUUID()\}\`,
              version: 1,
              metadata: {
                timestamp: new Date().toISOString(),
                tools: [{ vendor: 'QuantumGuard', name: 'xBOM Merge', version: '1.0.0' }],
                repository: {
                  url: \`\$\{process.env.GITHUB_SERVER_URL\}/\$\{process.env.GITHUB_REPOSITORY\}\`,
                  branch: process.env.GITHUB_REF_NAME
                }
              },
              components: sbom.components || [],
              cryptoAssets: cbom.cryptoAssets || [],
              dependencies: [...(sbom.dependencies || []), ...(cbom.dependencies || [])],
              vulnerabilities: sbom.vulnerabilities || [],
              crossReferences: []
            };

            fs.writeFileSync('xbom.json', JSON.stringify(xbom, null, 2));
            core.setOutput('total-components', xbom.components.length);
            core.setOutput('total-crypto-assets', xbom.cryptoAssets.length);

      - uses: actions/upload-artifact@v4
        with:
          name: xbom-report
          path: |
            xbom.json
            sbom.json
            cbom-report.json
          retention-days: 90${
    opts.failOnVulnerable
      ? `

      - name: Check quantum safety
        run: |
          NOT_SAFE=$(cat xbom.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for a in d.get('cryptoAssets',[]) if a.get('quantumSafety')!='quantum-safe'))")
          if [ "$NOT_SAFE" -gt 0 ]; then
            echo "❌ $NOT_SAFE non-quantum-safe cryptographic assets detected"
            exit 1
          fi`
      : ''
  }
`;
}
