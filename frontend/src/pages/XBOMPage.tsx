/**
 * XBOMPage — Unified SBOM + CBOM viewer
 *
 * Screens:
 *  • List view   — shows stored xBOMs, generate/merge forms
 *  • Detail view — tabs: Overview  |  Software Components  |  Crypto Assets
 *                        Vulnerabilities  |  Cross-References
 */
import { useState, useRef, useCallback } from 'react';
import {
  useGetXBOMStatusQuery,
  useGetXBOMListQuery,
  useGetXBOMQuery,
  useGenerateXBOMMutation,
  useMergeXBOMMutation,
  useDeleteXBOMMutation,
} from '../store/api';
import type { XBOMDocument, XBOMAnalytics, XBOMListItem, SBOMComponent, SBOMVulnerability, XBOMCrossReference, CryptoAsset } from '../types';
import s from './XBOMPage.module.scss';

/* ── helper ─────────────── */
function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

type DetailTab = 'overview' | 'software' | 'crypto' | 'vulnerabilities' | 'cross-references';

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export default function XBOMPage() {
  const { data: status } = useGetXBOMStatusQuery();
  const { data: xbomList = [], isLoading: listLoading } = useGetXBOMListQuery();
  const [deleteXBOM] = useDeleteXBOMMutation();

  const [selectedId, setSelectedId] = useState<string | null>(null);

  /* ── List / Detail toggle ─── */
  if (selectedId) {
    return <XBOMDetailView id={selectedId} onBack={() => setSelectedId(null)} />;
  }

  return (
    <div className={s.xbomPage}>
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">xBOM</h1>
        <p className="dc1-page-subtitle">
          Unified Software + Cryptographic Bill of Materials
        </p>
      </div>

      {/* Status cards */}
      <div className={s.statusCards}>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Trivy Scanner</span>
          <span className={`${s.statusBadge} ${status?.trivyInstalled ? s.badgeGreen : s.badgeRed}`}>
            {status?.trivyInstalled ? '● Installed' : '● Not found'}
          </span>
          {status?.trivyVersion && (
            <span style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>v{status.trivyVersion}</span>
          )}
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Stored xBOMs</span>
          <span className={s.statusValue}>{status?.storedXBOMs ?? 0}</span>
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>SBOM Generation</span>
          <span className={`${s.statusBadge} ${status?.capabilities?.sbomGeneration ? s.badgeGreen : s.badgeAmber}`}>
            {status?.capabilities?.sbomGeneration ? 'Ready' : 'Unavailable'}
          </span>
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>CBOM Generation</span>
          <span className={`${s.statusBadge} ${s.badgeGreen}`}>Ready</span>
        </div>
      </div>

      {/* Generate / Merge — tabbed, only one active */}
      <GenerateOrMerge />

      {/* xBOM list */}
      <div className="dc1-card">
        <h3 className="dc1-card-section-title">Stored xBOMs</h3>

        {listLoading ? (
          <div className={s.spinner}><div className={s.spinnerDot} /><div className={s.spinnerDot} /><div className={s.spinnerDot} /></div>
        ) : xbomList.length === 0 ? (
          <div className={s.emptyState}>
            <h3>No xBOMs generated yet</h3>
            <p>Generate one from a repository scan or merge existing SBOM + CBOM files.</p>
          </div>
        ) : (
          <div className={s.xbomList}>
            <div className={`${s.listRow} ${s.listHeader}`}>
              <span>Component</span>
              <span>Timestamp</span>
              <span>Software</span>
              <span>Crypto</span>
              <span>Vulns</span>
              <span>Cross-refs</span>
              <span />
            </div>
            {xbomList.map((item: XBOMListItem) => (
              <div key={item.id} className={s.listRow}>
                <span
                  className="dc1-cell-name"
                  style={{ cursor: 'pointer', color: 'var(--dc1-primary)' }}
                  onClick={() => setSelectedId(item.id)}
                >
                  {item.component}
                </span>
                <span>{fmtDate(item.timestamp)}</span>
                <span>{item.softwareComponents}</span>
                <span>{item.cryptoAssets}</span>
                <span>{item.vulnerabilities}</span>
                <span>{item.crossReferences}</span>
                <span className={s.actionBtns}>
                  <button className={s.iconBtn} title="View" onClick={() => setSelectedId(item.id)}>
                    View
                  </button>
                  <button className={`${s.iconBtn} ${s.iconBtnDanger}`} title="Delete"
                    onClick={() => { if (confirm('Delete this xBOM?')) deleteXBOM(item.id); }}>
                    ✕
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Generate or Merge — tabbed, only one active at a time              */
/* ================================================================== */

type InputMode = 'generate' | 'merge';

function GenerateOrMerge() {
  const [inputMode, setInputMode] = useState<InputMode>('generate');

  return (
    <div className="dc1-card" style={{ marginBottom: 24 }}>
      {/* mode tabs */}
      <div className={s.tabs} style={{ marginBottom: 16 }}>
        <button className={`${s.tab} ${inputMode === 'generate' ? s.tabActive : ''}`} onClick={() => setInputMode('generate')}>
          Generate from Scan
        </button>
        <button className={`${s.tab} ${inputMode === 'merge' ? s.tabActive : ''}`} onClick={() => setInputMode('merge')}>
          Merge Existing Files
        </button>
      </div>

      {inputMode === 'generate' ? <GenerateForm /> : <MergeForm />}
    </div>
  );
}

/* ── xBOM workflow YAML generator ────────── */
function generateXBOMWorkflowYaml(opts: {
  branches: string;
  scanPath: string;
  specVersion: string;
  excludePatterns: string;
  failOnVulnerable: boolean;
  trivySeverity: string;
}): string {
  const branchList = opts.branches.split(',').map(b => b.trim()).filter(Boolean).join(', ');
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

      # Step 1: Trivy SBOM
      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Run Trivy (SBOM + Vulnerabilities)
        run: |
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
          retention-days: 90${opts.failOnVulnerable ? `

      - name: Check quantum safety
        run: |
          NOT_SAFE=$(cat xbom.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for a in d.get('cryptoAssets',[]) if a.get('quantumSafety')!='quantum-safe'))")
          if [ "$NOT_SAFE" -gt 0 ]; then
            echo "❌ $NOT_SAFE non-quantum-safe cryptographic assets detected"
            exit 1
          fi` : ''}
`;
}

function GenerateForm() {
  const [generateXBOM, { isLoading }] = useGenerateXBOMMutation();
  const [repoPath, setRepoPath] = useState('');
  const [branch, setBranch] = useState('');
  const [mode, setMode] = useState<'full' | 'sbom-only' | 'cbom-only'>('full');
  const [specVersion, setSpecVersion] = useState<'1.6' | '1.7'>('1.6');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  /* ── GitHub Actions workflow snippet ── */
  const [showWorkflow, setShowWorkflow] = useState(false);
  const [wfBranches, setWfBranches] = useState('main');
  const [wfScanPath, setWfScanPath] = useState('.');
  const [wfExclude, setWfExclude] = useState('default');
  const [wfFailOnVuln, setWfFailOnVuln] = useState(false);
  const [wfSeverity, setWfSeverity] = useState('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL');
  const [copied, setCopied] = useState(false);

  const workflowYaml = generateXBOMWorkflowYaml({
    branches: wfBranches,
    scanPath: wfScanPath,
    specVersion,
    excludePatterns: wfExclude,
    failOnVulnerable: wfFailOnVuln,
    trivySeverity: wfSeverity,
  });

  const handleCopy = () => {
    navigator.clipboard.writeText(workflowYaml).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleSubmit = async () => {
    if (!repoPath.trim()) { setError('Repository / directory path is required'); return; }
    setError('');
    setSuccess('');
    try {
      const res = await generateXBOM({
        repoPath: repoPath.trim(),
        mode,
        specVersion,
        branch: branch.trim() || undefined,
      }).unwrap();
      if (res.success) {
        setSuccess(`xBOM generated — ${res.analytics?.totalSoftwareComponents ?? 0} software components, ${res.analytics?.totalCryptoAssets ?? 0} crypto assets, ${res.analytics?.totalCrossReferences ?? 0} cross-references`);
        setRepoPath('');
        setBranch('');
      } else {
        setError(res.error || res.message || 'Generation failed');
      }
    } catch (e: any) {
      setError(e?.data?.error || e?.data?.message || e?.message || 'Generation failed');
    }
  };

  return (
    <div style={{ padding: '0 4px' }}>
      {/* ── GitHub Actions Integration ── */}
      <div className={s.workflowSection} style={{ borderTop: 'none', paddingTop: 0 }}>
        <div className={s.workflowHeader} onClick={() => setShowWorkflow(!showWorkflow)}>
          <span style={{ fontSize: 14, transition: 'transform 0.15s', transform: showWorkflow ? 'rotate(90deg)' : 'rotate(0)' }}>▶</span>
          <span className={s.workflowTitle}>GitHub Actions Integration</span>
          <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 10, background: 'var(--dc1-bg-muted, #f1f5f9)', color: 'var(--dc1-text-muted)' }}>Recommended</span>
        </div>
        <p className={s.workflowSubtext}>
          Add the xBOM workflow to your GitHub repository to automatically generate unified SBOM + CBOM reports on every push. Copy the YAML below into <code>.github/workflows/xbom.yml</code>.
        </p>

        {showWorkflow && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
              <div className={s.formRow}>
                <label>Branches</label>
                <input value={wfBranches} onChange={(e) => setWfBranches(e.target.value)} placeholder="main, develop" />
              </div>
              <div className={s.formRow}>
                <label>Scan Path</label>
                <input value={wfScanPath} onChange={(e) => setWfScanPath(e.target.value)} placeholder="." />
              </div>
              <div className={s.formRow}>
                <label>Exclude Patterns</label>
                <input value={wfExclude} onChange={(e) => setWfExclude(e.target.value)} placeholder="default" />
              </div>
              <div className={s.formRow}>
                <label>Trivy Severity Filter</label>
                <input value={wfSeverity} onChange={(e) => setWfSeverity(e.target.value)} placeholder="CRITICAL,HIGH" />
              </div>
              <div className={s.formRow}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input type="checkbox" checked={wfFailOnVuln} onChange={(e) => setWfFailOnVuln(e.target.checked)} style={{ width: 'auto' }} />
                  Fail if non-quantum-safe crypto detected
                </label>
              </div>
            </div>

            <div className={s.yamlCodeWrap}>
              <div className={s.yamlCodeHeader}>
                <span className={s.yamlCodeFilename}>.github/workflows/xbom.yml</span>
                <button type="button" className={s.yamlCopyBtn} onClick={handleCopy}>
                  {copied ? '✓ Copied!' : '⧉ Copy workflow'}
                </button>
              </div>
              <pre className={s.yamlCodeBlock}><code>{workflowYaml}</code></pre>
            </div>

            <a
              className={s.workflowLink}
              href="https://github.com/annanay-sharma/cbom-analyser/blob/main/.github/workflows/xbom.yml"
              target="_blank" rel="noreferrer"
            >
              View full reference workflow →
            </a>
          </>
        )}
      </div>

      {/* ── OR divider ── */}
      <div className={s.orDivider}>
        <span>or scan locally</span>
      </div>

      {/* ── Local scan form ── */}
      <p style={{ fontSize: 13, color: 'var(--dc1-text-muted)', marginBottom: 16 }}>
        Scan a local directory on this server. Trivy generates the SBOM (if installed)
        and the CBOM Analyser scans for cryptographic usage.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className={s.formRow}>
          <label>Repository / Directory Path *</label>
          <input placeholder="/path/to/local/repo" value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
        </div>

        <div className={s.formRow}>
          <label>Branch</label>
          <input placeholder="main" value={branch} onChange={(e) => setBranch(e.target.value)} />
        </div>

        <div className={s.formRow}>
          <label>Scan Mode</label>
          <select value={mode} onChange={(e) => setMode(e.target.value as any)}>
            <option value="full">Full (SBOM + CBOM)</option>
            <option value="sbom-only">SBOM Only (Trivy)</option>
            <option value="cbom-only">CBOM Only</option>
          </select>
        </div>

        <div className={s.formRow}>
          <label>CycloneDX Spec Version</label>
          <select value={specVersion} onChange={(e) => setSpecVersion(e.target.value as '1.6' | '1.7')}>
            <option value="1.6">CycloneDX 1.6</option>
            <option value="1.7">CycloneDX 1.7</option>
          </select>
        </div>
      </div>

      {error && <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>{error}</div>}
      {success && <div style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8 }}>{success}</div>}

      <div className={s.formActions}>
        <button className="dc1-btn-primary" onClick={handleSubmit} disabled={isLoading}>
          {isLoading ? 'Generating…' : 'Generate xBOM'}
        </button>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Merge Form                                                         */
/* ================================================================== */

function MergeForm() {
  const [mergeXBOM, { isLoading }] = useMergeXBOMMutation();
  const [sbomText, setSbomText] = useState('');
  const [cbomText, setCbomText] = useState('');
  const [specVersion, setSpecVersion] = useState<'1.6' | '1.7'>('1.6');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const sbomFileRef = useRef<HTMLInputElement>(null);
  const cbomFileRef = useRef<HTMLInputElement>(null);

  const loadFile = useCallback((setter: (v: string) => void) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setter(reader.result as string);
    reader.readAsText(f);
  }, []);

  const handleMerge = async () => {
    let sbom: object | undefined;
    let cbom: object | undefined;
    try { if (sbomText.trim()) sbom = JSON.parse(sbomText); } catch { setError('Invalid SBOM JSON'); return; }
    try { if (cbomText.trim()) cbom = JSON.parse(cbomText); } catch { setError('Invalid CBOM JSON'); return; }
    if (!sbom && !cbom) { setError('At least one of SBOM or CBOM is required'); return; }
    setError('');
    setSuccess('');
    try {
      const res = await mergeXBOM({ sbom, cbom, specVersion }).unwrap();
      if (res.success) {
        setSuccess(`xBOM merged — ${res.analytics?.totalSoftwareComponents ?? 0} software, ${res.analytics?.totalCryptoAssets ?? 0} crypto, ${res.analytics?.totalCrossReferences ?? 0} cross-refs`);
        setSbomText('');
        setCbomText('');
      } else {
        setError(res.error || res.message || 'Merge failed');
      }
    } catch (e: any) {
      setError(e?.data?.error || e?.data?.message || e?.message || 'Merge failed');
    }
  };

  return (
    <div style={{ padding: '0 4px' }}>
      <p style={{ fontSize: 13, color: 'var(--dc1-text-muted)', marginBottom: 16 }}>
        Upload or paste pre-existing SBOM and/or CBOM CycloneDX JSON files. The merge engine will
        combine them into a unified xBOM and build cross-references between software components and crypto assets.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className={s.formRow} style={{ gridColumn: '1 / -1' }}>
          <label>
            SBOM (CycloneDX JSON)
            <button className={s.backBtn} style={{ marginLeft: 8 }} onClick={() => sbomFileRef.current?.click()}>Upload file</button>
          </label>
          <input type="file" accept=".json" ref={sbomFileRef} style={{ display: 'none' }} onChange={loadFile(setSbomText)} />
          <textarea placeholder='Paste SBOM JSON or upload a file…' value={sbomText} onChange={(e) => setSbomText(e.target.value)} />
        </div>

        <div className={s.formRow} style={{ gridColumn: '1 / -1' }}>
          <label>
            CBOM (CycloneDX JSON)
            <button className={s.backBtn} style={{ marginLeft: 8 }} onClick={() => cbomFileRef.current?.click()}>Upload file</button>
          </label>
          <input type="file" accept=".json" ref={cbomFileRef} style={{ display: 'none' }} onChange={loadFile(setCbomText)} />
          <textarea placeholder='Paste CBOM JSON or upload a file…' value={cbomText} onChange={(e) => setCbomText(e.target.value)} />
        </div>

        <div className={s.formRow}>
          <label>CycloneDX Spec Version</label>
          <select value={specVersion} onChange={(e) => setSpecVersion(e.target.value as '1.6' | '1.7')}>
            <option value="1.6">CycloneDX 1.6</option>
            <option value="1.7">CycloneDX 1.7</option>
          </select>
        </div>
      </div>

      {error && <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>{error}</div>}
      {success && <div style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8 }}>{success}</div>}

      <div className={s.formActions}>
        <button className="dc1-btn-primary" onClick={handleMerge} disabled={isLoading}>
          {isLoading ? 'Merging…' : 'Merge to xBOM'}
        </button>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  xBOM Detail View                                                   */
/* ================================================================== */

function XBOMDetailView({ id, onBack }: { id: string; onBack: () => void }) {
  const { data, isLoading, error } = useGetXBOMQuery(id);
  const [tab, setTab] = useState<DetailTab>('overview');

  if (isLoading) return <div className={s.spinner}><div className={s.spinnerDot} /><div className={s.spinnerDot} /><div className={s.spinnerDot} /></div>;
  if (error || !data?.xbom) return <div className={s.emptyState}><h3>Failed to load xBOM</h3><button className={s.backBtn} onClick={onBack}>← Back</button></div>;

  const xbom = data.xbom;
  const analytics = data.analytics;

  const tabDef: { key: DetailTab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'software', label: 'Software', count: xbom.components?.length },
    { key: 'crypto', label: 'Crypto Assets', count: xbom.cryptoAssets?.length },
    { key: 'vulnerabilities', label: 'Vulnerabilities', count: xbom.vulnerabilities?.length },
    { key: 'cross-references', label: 'Cross-References', count: xbom.crossReferences?.length },
  ];

  return (
    <div className={s.xbomPage}>
      <div className={s.detailHeader}>
        <div>
          <button className={s.backBtn} onClick={onBack}>← Back to xBOM list</button>
          <h2 style={{ margin: '8px 0 4px' }}>{xbom.metadata?.component?.name ?? 'xBOM'}</h2>
          <div className={s.detailMeta}>
            <span>Format: {xbom.bomFormat} {xbom.specVersion}</span>
            <span>Generated: {fmtDate(xbom.metadata?.timestamp)}</span>
            {xbom.metadata?.repository?.url && <span>Repo: {xbom.metadata.repository.url}</span>}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className={s.tabs}>
        {tabDef.map(t => (
          <button key={t.key} className={`${s.tab} ${tab === t.key ? s.tabActive : ''}`} onClick={() => setTab(t.key)}>
            {t.label}
            {t.count !== undefined && <span className={s.tabBadge}>{t.count}</span>}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && <OverviewTab xbom={xbom} analytics={analytics} />}
      {tab === 'software' && <SoftwareTab components={xbom.components} />}
      {tab === 'crypto' && <CryptoTab assets={xbom.cryptoAssets} />}
      {tab === 'vulnerabilities' && <VulnerabilityTab vulns={xbom.vulnerabilities} analytics={analytics} />}
      {tab === 'cross-references' && <CrossRefTab refs={xbom.crossReferences} />}
    </div>
  );
}

/* ── Overview Tab ────────── */
function OverviewTab({ xbom, analytics }: { xbom: XBOMDocument; analytics?: XBOMAnalytics }) {
  return (
    <>
      <div className={s.statusCards}>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Software Components</span>
          <span className={s.statusValue}>{analytics?.totalSoftwareComponents ?? xbom.components?.length ?? 0}</span>
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Crypto Assets</span>
          <span className={s.statusValue}>{analytics?.totalCryptoAssets ?? xbom.cryptoAssets?.length ?? 0}</span>
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Vulnerabilities</span>
          <span className={s.statusValue}>{xbom.vulnerabilities?.length ?? 0}</span>
        </div>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Cross-References</span>
          <span className={s.statusValue}>{analytics?.totalCrossReferences ?? xbom.crossReferences?.length ?? 0}</span>
        </div>
      </div>

      {analytics && (
        <div className="dc1-card" style={{ marginTop: 16 }}>
          <h3 className="dc1-card-section-title">Quantum Readiness</h3>
          <div className={s.statusCards}>
            <div className={s.statusCard}>
              <span className={s.statusLabel}>Readiness Score</span>
              <span className={s.statusValue}>{analytics.quantumReadiness?.score ?? '—'}</span>
            </div>
            <div className={s.statusCard}>
              <span className={s.statusLabel}>Quantum Safe</span>
              <span className={`${s.statusBadge} ${s.badgeGreen}`}>{analytics.quantumReadiness?.quantumSafe ?? 0}</span>
            </div>
            <div className={s.statusCard}>
              <span className={s.statusLabel}>Not Quantum Safe</span>
              <span className={`${s.statusBadge} ${s.badgeRed}`}>{analytics.quantumReadiness?.notQuantumSafe ?? 0}</span>
            </div>
            <div className={s.statusCard}>
              <span className={s.statusLabel}>Conditional</span>
              <span className={`${s.statusBadge} ${s.badgeAmber}`}>{analytics.quantumReadiness?.conditional ?? 0}</span>
            </div>
          </div>
        </div>
      )}

      {analytics?.vulnerabilitySummary && analytics.vulnerabilitySummary.total > 0 && (
        <div className="dc1-card" style={{ marginTop: 16 }}>
          <h3 className="dc1-card-section-title">Vulnerability Summary</h3>
          <VulnSummaryGrid vuln={analytics.vulnerabilitySummary} />
        </div>
      )}
    </>
  );
}

/* ── Software Components Tab ── */
function SoftwareTab({ components }: { components?: SBOMComponent[] }) {
  const items = components ?? [];
  if (!items.length) return <div className={s.emptyState}><h3>No software components</h3></div>;

  return (
    <div className="dc1-card">
      <div className="dc1-table-wrapper">
        <table className="dc1-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Type</th>
              <th>Group</th>
              <th>PURL</th>
              <th>Licenses</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c, i) => (
              <tr key={c['bom-ref'] ?? i}>
                <td className="dc1-cell-name">{c.name}</td>
                <td>{c.version ?? '—'}</td>
                <td>{c.type}</td>
                <td>{c.group ?? '—'}</td>
                <td style={{ fontSize: 11, fontFamily: 'monospace', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.purl ?? '—'}
                </td>
                <td>{c.licenses?.map(l => l.license?.id ?? l.license?.name ?? l.expression).filter(Boolean).join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Crypto Assets Tab ── */
function CryptoTab({ assets }: { assets?: CryptoAsset[] }) {
  const items = assets ?? [];
  if (!items.length) return <div className={s.emptyState}><h3>No cryptographic assets</h3></div>;

  return (
    <div className="dc1-card">
      <div className="dc1-table-wrapper">
        <table className="dc1-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Primitive</th>
              <th>Parameter Set</th>
              <th>Quantum Safety</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a, i) => (
              <tr key={a.id ?? i}>
                <td className="dc1-cell-name">{a.name}</td>
                <td>{a.cryptoProperties?.assetType ?? a.type}</td>
                <td>{a.cryptoProperties?.algorithmProperties?.primitive ?? '—'}</td>
                <td>{a.cryptoProperties?.algorithmProperties?.parameterSetIdentifier ?? '—'}</td>
                <td>
                  <span className={`${s.statusBadge} ${
                    a.quantumSafety === 'quantum-safe' ? s.badgeGreen :
                    a.quantumSafety === 'not-quantum-safe' ? s.badgeRed : s.badgeAmber
                  }`}>
                    {a.quantumSafety}
                  </span>
                </td>
                <td style={{ fontSize: 11, fontFamily: 'monospace' }}>
                  {a.location?.fileName ?? '—'}
                  {a.location?.lineNumber ? `:${a.location.lineNumber}` : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Vulnerabilities Tab ── */
function VulnerabilityTab({ vulns, analytics }: { vulns?: SBOMVulnerability[]; analytics?: XBOMAnalytics }) {
  const items = vulns ?? [];

  return (
    <>
      {analytics?.vulnerabilitySummary && <VulnSummaryGrid vuln={analytics.vulnerabilitySummary} />}

      {items.length === 0 ? (
        <div className={s.emptyState}><h3>No vulnerabilities detected</h3><p>Trivy did not find any known vulnerabilities in this scan.</p></div>
      ) : (
        <div className="dc1-card">
          <div className="dc1-table-wrapper">
            <table className="dc1-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Score</th>
                  <th>Description</th>
                  <th>Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {items.map((v, i) => {
                  const rating = v.ratings?.[0];
                  const sev = (rating?.severity ?? 'unknown').toLowerCase();
                  return (
                    <tr key={v.id + '-' + i}>
                      <td className="dc1-cell-name" style={{ fontFamily: 'monospace', fontSize: 12 }}>{v.id}</td>
                      <td>{v.source?.name ?? '—'}</td>
                      <td>
                        <span className={`${s.statusBadge} ${
                          sev === 'critical' ? s.badgeRed :
                          sev === 'high' ? s.badgeRed :
                          sev === 'medium' ? s.badgeAmber : s.badgeGreen
                        }`}>
                          {rating?.severity ?? 'Unknown'}
                        </span>
                      </td>
                      <td>{rating?.score ?? '—'}</td>
                      <td style={{ maxWidth: 300, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {v.description ?? '—'}
                      </td>
                      <td style={{ fontSize: 12 }}>{v.recommendation ?? '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

/* ── Cross-References Tab ── */
function CrossRefTab({ refs }: { refs?: XBOMCrossReference[] }) {
  const items = refs ?? [];
  if (!items.length) return <div className={s.emptyState}><h3>No cross-references</h3><p>No relational links between software components and crypto assets were found.</p></div>;

  const methodClass = (m: string) => {
    switch (m) {
      case 'dependency-manifest': return s.linkMethodManifest;
      case 'code-scan': return s.linkMethodCodeScan;
      case 'file-co-location': return s.linkMethodCoLocation;
      default: return s.linkMethodManual;
    }
  };

  return (
    <div className="dc1-card">
      <div className={`${s.crossRefRow} ${s.crossRefHeader}`}>
        <span>Software Component</span>
        <span>Crypto Assets</span>
        <span>Link Method</span>
      </div>
      {items.map((cr, i) => (
        <div key={i} className={s.crossRefRow}>
          <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{cr.softwareRef}</span>
          <span className={s.chipList}>
            {cr.cryptoRefs.map((r, j) => <span key={j} className={s.chip}>{r}</span>)}
          </span>
          <span className={`${s.linkMethodTag} ${methodClass(cr.linkMethod)}`}>{cr.linkMethod}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Vuln Summary Grid (shared) ── */
function VulnSummaryGrid({ vuln }: { vuln: { total: number; critical: number; high: number; medium: number; low: number; info: number } }) {
  return (
    <div className={s.vulnGrid}>
      <div className={`${s.vulnCard} ${s.criticalCard}`}><h4>Critical</h4><span className={s.vulnCount} style={{ color: '#991b1b' }}>{vuln.critical}</span></div>
      <div className={`${s.vulnCard} ${s.highCard}`}><h4>High</h4><span className={s.vulnCount} style={{ color: '#ef4444' }}>{vuln.high}</span></div>
      <div className={`${s.vulnCard} ${s.mediumCard}`}><h4>Medium</h4><span className={s.vulnCount} style={{ color: '#f59e0b' }}>{vuln.medium}</span></div>
      <div className={`${s.vulnCard} ${s.lowCard}`}><h4>Low</h4><span className={s.vulnCount} style={{ color: '#3b82f6' }}>{vuln.low}</span></div>
      <div className={`${s.vulnCard} ${s.infoCard}`}><h4>Info</h4><span className={s.vulnCount} style={{ color: '#94a3b8' }}>{vuln.info}</span></div>
    </div>
  );
}
