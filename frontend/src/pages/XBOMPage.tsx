/**
 * XBOMPage — Unified SBOM + CBOM viewer
 *
 * Screens:
 *  • List view   — shows stored xBOMs, generate/merge forms
 *  • Detail view — tabs: Overview  |  Software Components  |  Crypto Assets
 *                        Vulnerabilities  |  Cross-References
 */
import { useState, useRef, useCallback, useMemo } from 'react';
import {
  useGetXBOMStatusQuery,
  useGetXBOMListQuery,
  useGetXBOMQuery,
  useGenerateXBOMMutation,
  useMergeXBOMMutation,
  useUploadXBOMMutation,
  useDeleteXBOMMutation,
} from '../store/api';
import type { XBOMDocument, XBOMAnalytics, XBOMListItem, SBOMComponent, SBOMVulnerability, XBOMCrossReference, CryptoAsset } from '../types';
import {
  SoftwarePanel,
  CryptoPanel,
  CryptoAnalysisPanel,
  VulnerabilityPanel,
  CrossRefPanel,
  BomOverviewPanel,
  BomDownloadButtons,
} from '../components/bom-panels';
import Pagination from '../components/Pagination';
import { Download } from 'lucide-react';
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
  const [localXbom, setLocalXbom] = useState<{ xbom: XBOMDocument; analytics: XBOMAnalytics } | null>(null);
  const [listPage, setListPage] = useState(1);
  const [listPageSize, setListPageSize] = useState(25);

  const pagedList = useMemo(() => {
    const start = (listPage - 1) * listPageSize;
    return xbomList.slice(start, start + listPageSize);
  }, [xbomList, listPage, listPageSize]);

  const downloadXbom = useCallback(async (id: string, component: string) => {
    try {
      const res = await fetch(`/api/xbom/${encodeURIComponent(id)}`);
      const json = await res.json();
      const blob = new Blob([JSON.stringify(json.xbom ?? json, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${component.replace(/[^a-zA-Z0-9_-]/g, '_')}-xbom.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  }, []);

  /* ── Local upload viewer ─── */
  if (localXbom) {
    return <LocalXBOMDetailView xbom={localXbom.xbom} analytics={localXbom.analytics} onBack={() => setLocalXbom(null)} />;
  }

  /* ── Server-stored detail view ─── */
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

      {/* Generate / Merge / Upload — tabbed, only one active */}
      <GenerateOrMerge onViewLocal={(xbom, analytics) => setLocalXbom({ xbom, analytics })} />

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
            {pagedList.map((item: XBOMListItem) => (
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
                  <button
                    className={s.iconBtn}
                    title="Download xBOM"
                    onClick={() => downloadXbom(item.id, item.component)}
                    style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
                  >
                    <Download size={14} />
                  </button>
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
            <Pagination
              page={listPage}
              total={xbomList.length}
              pageSize={listPageSize}
              onPageChange={setListPage}
              onPageSizeChange={(sz) => { setListPageSize(sz); setListPage(1); }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Generate or Merge — tabbed, only one active at a time              */
/* ================================================================== */

type InputMode = 'generate' | 'merge' | 'upload';

function GenerateOrMerge({ onViewLocal }: { onViewLocal: (xbom: XBOMDocument, analytics: XBOMAnalytics) => void }) {
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
        <button className={`${s.tab} ${inputMode === 'upload' ? s.tabActive : ''}`} onClick={() => setInputMode('upload')}>
          Upload xBOM
        </button>
      </div>

      {inputMode === 'generate' && <GenerateForm />}
      {inputMode === 'merge' && <MergeForm />}
      {inputMode === 'upload' && <UploadForm onViewLocal={onViewLocal} />}
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
/*  Upload Form                                                        */
/* ================================================================== */

/** Client-side analytics computation for uploaded xBOMs */
function computeLocalAnalytics(xbom: XBOMDocument): XBOMAnalytics {
  const cryptoAssets = xbom.cryptoAssets ?? [];
  const vulns = xbom.vulnerabilities ?? [];
  const totalCrypto = cryptoAssets.length;
  const qSafe = cryptoAssets.filter(a => a.quantumSafety === 'quantum-safe').length;
  const notSafe = cryptoAssets.filter(a => a.quantumSafety === 'not-quantum-safe').length;
  const conditional = cryptoAssets.filter(a => a.quantumSafety === 'conditional').length;
  const unknown = totalCrypto - qSafe - notSafe - conditional;
  const score = totalCrypto > 0 ? Math.round((qSafe / totalCrypto) * 100) : 100;

  const vulnCritical = vulns.filter(v => v.ratings?.some((r: any) => r.severity === 'critical')).length;
  const vulnHigh = vulns.filter(v => v.ratings?.some((r: any) => r.severity === 'high') && !v.ratings?.some((r: any) => r.severity === 'critical')).length;
  const vulnMedium = vulns.filter(v => v.ratings?.some((r: any) => r.severity === 'medium')).length;
  const vulnLow = vulns.filter(v => v.ratings?.some((r: any) => r.severity === 'low')).length;

  return {
    quantumReadiness: { score, totalAssets: totalCrypto, quantumSafe: qSafe, notQuantumSafe: notSafe, conditional, unknown },
    compliance: { isCompliant: notSafe === 0, policy: 'PQC Readiness', source: 'local-analysis', totalAssets: totalCrypto, compliantAssets: qSafe + conditional, nonCompliantAssets: notSafe, unknownAssets: unknown },
    vulnerabilitySummary: { total: vulns.length, critical: vulnCritical, high: vulnHigh, medium: vulnMedium, low: vulnLow, info: 0 },
    totalSoftwareComponents: xbom.components?.length ?? 0,
    totalCryptoAssets: totalCrypto,
    totalCrossReferences: xbom.crossReferences?.length ?? 0,
  };
}

function UploadForm({ onViewLocal }: { onViewLocal: (xbom: XBOMDocument, analytics: XBOMAnalytics) => void }) {
  const [uploadXBOM, { isLoading: uploading }] = useUploadXBOMMutation();
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [fileName, setFileName] = useState('');
  const [jsonText, setJsonText] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const parseAndView = useCallback((raw: string, name: string) => {
    try {
      setError('');
      const parsed = JSON.parse(raw);
      if (parsed.bomFormat !== 'CycloneDX') {
        setError('Invalid file: bomFormat must be CycloneDX');
        return;
      }
      const xbom: XBOMDocument = {
        bomFormat: parsed.bomFormat,
        specVersion: parsed.specVersion ?? '1.6',
        serialNumber: parsed.serialNumber ?? `local-${Date.now()}`,
        version: parsed.version ?? 1,
        metadata: parsed.metadata ?? { timestamp: new Date().toISOString(), tools: [] },
        components: parsed.components ?? [],
        cryptoAssets: parsed.cryptoAssets ?? [],
        dependencies: parsed.dependencies ?? [],
        vulnerabilities: parsed.vulnerabilities ?? [],
        crossReferences: parsed.crossReferences ?? [],
        thirdPartyLibraries: parsed.thirdPartyLibraries,
      };
      const analytics = computeLocalAnalytics(xbom);
      setFileName(name);
      setSuccess(
        `${name} loaded — ${xbom.components.length} software, ` +
        `${xbom.cryptoAssets.length} crypto, ` +
        `${xbom.vulnerabilities.length} vulns, ` +
        `${xbom.crossReferences.length} cross-refs`
      );
      onViewLocal(xbom, analytics);
    } catch {
      setError('Invalid JSON — could not parse xBOM file');
    }
  }, [onViewLocal]);

  const handleFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = () => parseAndView(reader.result as string, file.name);
    reader.readAsText(file);
  }, [parseAndView]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const handleSaveToServer = async () => {
    if (!jsonText.trim() && !fileName) { setError('Upload or paste an xBOM file first'); return; }
    setError('');
    setSuccess('');
    try {
      let body: any;
      if (jsonText.trim()) {
        body = { xbom: JSON.parse(jsonText) };
      } else {
        setError('Please paste the xBOM JSON or upload a file');
        return;
      }
      const fd = new FormData();
      fd.append('xbom', JSON.stringify(body.xbom));
      const res = await uploadXBOM(fd).unwrap();
      if (res.success) {
        setSuccess(res.message || 'xBOM uploaded and saved');
      } else {
        setError(res.error || 'Upload failed');
      }
    } catch (e: any) {
      setError(e?.data?.error || e?.message || 'Upload failed');
    }
  };

  return (
    <div style={{ padding: '0 4px' }}>
      <p style={{ fontSize: 13, color: 'var(--dc1-text-muted)', marginBottom: 16 }}>
        Upload a pre-existing xBOM JSON file (e.g. from a CI/CD artifact) to view it instantly.
        You can also save it to the server for persistent storage.
      </p>

      {/* Drag-and-drop zone */}
      <div
        className={`${s.dropZone} ${dragActive ? s.dropZoneActive : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input
          type="file"
          accept=".json"
          ref={fileRef}
          style={{ display: 'none' }}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) {
              handleFile(file);
              // Also store JSON text for save-to-server
              const reader = new FileReader();
              reader.onload = () => setJsonText(reader.result as string);
              reader.readAsText(file);
            }
          }}
        />
        {fileName ? (
          <>
            <span style={{ fontSize: 20 }}>📄</span>
            <span style={{ fontWeight: 600, color: 'var(--dc1-text)' }}>{fileName}</span>
            <span>Drop another file to replace</span>
          </>
        ) : (
          <>
            <span style={{ fontSize: 20 }}>📤</span>
            <span style={{ fontWeight: 500 }}>Drop an xBOM JSON file here</span>
            <span>(or click to browse)</span>
          </>
        )}
      </div>

      {/* OR paste JSON */}
      <div className={s.orDivider}><span>or paste JSON</span></div>

      <div className={s.formRow}>
        <textarea
          placeholder='Paste xBOM JSON here…'
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          style={{ minHeight: 120 }}
        />
      </div>

      {error && <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>{error}</div>}
      {success && <div style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8 }}>{success}</div>}

      <div className={s.formActions}>
        <button
          className="dc1-btn-primary"
          onClick={() => {
            if (jsonText.trim()) {
              parseAndView(jsonText, 'pasted-xbom.json');
            } else {
              setError('Upload or paste an xBOM file to view');
            }
          }}
        >
          View xBOM
        </button>
        <button
          className={s.iconBtn}
          style={{ padding: '8px 16px', fontSize: 13 }}
          onClick={handleSaveToServer}
          disabled={uploading}
        >
          {uploading ? 'Saving…' : 'Save to server'}
        </button>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  xBOM Detail View (server-stored)                                   */
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

  const componentName = xbom.metadata?.component?.name ?? 'xBOM';

  return (
    <div className={s.xbomPage}>
      <div className={s.detailHeader}>
        <div>
          <button className={s.backBtn} onClick={onBack}>← Back to xBOM list</button>
          <h2 style={{ margin: '8px 0 4px' }}>{componentName}</h2>
          <div className={s.detailMeta}>
            <span>Format: {xbom.bomFormat} {xbom.specVersion}</span>
            <span>Generated: {fmtDate(xbom.metadata?.timestamp)}</span>
            {xbom.metadata?.repository?.url && <span>Repo: {xbom.metadata.repository.url}</span>}
          </div>
        </div>
        <BomDownloadButtons
          compact
          items={[
            { label: 'xBOM', filename: `${componentName}-xbom.json`, data: xbom },
            { label: 'SBOM', filename: `${componentName}-sbom.json`, data: xbom.components?.length ? { bomFormat: 'CycloneDX', specVersion: xbom.specVersion, components: xbom.components } : null },
            { label: 'CBOM', filename: `${componentName}-cbom.json`, data: xbom.cryptoAssets?.length ? { bomFormat: 'CycloneDX', specVersion: xbom.specVersion, cryptoAssets: xbom.cryptoAssets } : null },
          ]}
        />
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

      {/* Tab content — shared panels */}
      {tab === 'overview' && <BomOverviewPanel xbom={xbom} analytics={analytics} />}
      {tab === 'software' && <SoftwarePanel components={xbom.components ?? []} />}
      {tab === 'crypto' && <CryptoAnalysisPanel assets={xbom.cryptoAssets ?? []} />}
      {tab === 'vulnerabilities' && <VulnerabilityPanel vulns={xbom.vulnerabilities ?? []} summary={analytics?.vulnerabilitySummary} />}
      {tab === 'cross-references' && <CrossRefPanel refs={xbom.crossReferences ?? []} components={xbom.components} cryptoAssets={xbom.cryptoAssets} />}
    </div>
  );
}

/* ================================================================== */
/*  xBOM Detail View (local / uploaded — no server fetch)              */
/* ================================================================== */

function LocalXBOMDetailView({ xbom, analytics, onBack }: { xbom: XBOMDocument; analytics: XBOMAnalytics; onBack: () => void }) {
  const [uploadXBOM, { isLoading: saving }] = useUploadXBOMMutation();
  const [tab, setTab] = useState<DetailTab>('overview');
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    const fd = new FormData();
    fd.append('xbom', JSON.stringify(xbom));
    try {
      await uploadXBOM(fd).unwrap();
      setSaved(true);
    } catch { /* ignore */ }
  };

  const tabDef: { key: DetailTab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'software', label: 'Software', count: xbom.components?.length },
    { key: 'crypto', label: 'Crypto Assets', count: xbom.cryptoAssets?.length },
    { key: 'vulnerabilities', label: 'Vulnerabilities', count: xbom.vulnerabilities?.length },
    { key: 'cross-references', label: 'Cross-References', count: xbom.crossReferences?.length },
  ];

  const componentName = xbom.metadata?.component?.name ?? 'xBOM';

  return (
    <div className={s.xbomPage}>
      <div className={s.detailHeader}>
        <div>
          <button className={s.backBtn} onClick={onBack}>← Back to xBOM list</button>
          <h2 style={{ margin: '8px 0 4px' }}>
            {componentName}
            <span style={{ fontSize: 12, fontWeight: 400, marginLeft: 10, padding: '2px 8px', borderRadius: 10, background: '#dbeafe', color: '#1d4ed8' }}>Uploaded</span>
          </h2>
          <div className={s.detailMeta}>
            <span>Format: {xbom.bomFormat} {xbom.specVersion}</span>
            <span>Generated: {fmtDate(xbom.metadata?.timestamp)}</span>
            {xbom.metadata?.repository?.url && <span>Repo: {xbom.metadata.repository.url}</span>}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <BomDownloadButtons
            compact
            items={[
              { label: 'xBOM', filename: `${componentName}-xbom.json`, data: xbom },
              { label: 'SBOM', filename: `${componentName}-sbom.json`, data: xbom.components?.length ? { bomFormat: 'CycloneDX', specVersion: xbom.specVersion, components: xbom.components } : null },
              { label: 'CBOM', filename: `${componentName}-cbom.json`, data: xbom.cryptoAssets?.length ? { bomFormat: 'CycloneDX', specVersion: xbom.specVersion, cryptoAssets: xbom.cryptoAssets } : null },
            ]}
          />
          <button
            className={s.iconBtn}
            style={{ padding: '8px 16px', fontSize: 13, opacity: saved ? 0.6 : 1 }}
            onClick={handleSave}
            disabled={saving || saved}
          >
            {saved ? '✓ Saved' : saving ? 'Saving…' : 'Save to server'}
          </button>
        </div>
      </div>

      <div className={s.tabs}>
        {tabDef.map(t => (
          <button key={t.key} className={`${s.tab} ${tab === t.key ? s.tabActive : ''}`} onClick={() => setTab(t.key)}>
            {t.label}
            {t.count !== undefined && <span className={s.tabBadge}>{t.count}</span>}
          </button>
        ))}
      </div>

      {/* Tab content — shared panels */}
      {tab === 'overview' && <BomOverviewPanel xbom={xbom} analytics={analytics} />}
      {tab === 'software' && <SoftwarePanel components={xbom.components ?? []} />}
      {tab === 'crypto' && <CryptoAnalysisPanel assets={xbom.cryptoAssets ?? []} />}
      {tab === 'vulnerabilities' && <VulnerabilityPanel vulns={xbom.vulnerabilities ?? []} summary={analytics?.vulnerabilitySummary} />}
      {tab === 'cross-references' && <CrossRefPanel refs={xbom.crossReferences ?? []} components={xbom.components} cryptoAssets={xbom.cryptoAssets} />}
    </div>
  );
}



