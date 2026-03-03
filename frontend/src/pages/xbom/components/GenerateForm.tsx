import { useState } from 'react';
import {
  useGetXBOMStatusQuery,
  useGenerateXBOMMutation,
  useInstallTrivyMutation,
  useRecheckTrivyMutation,
} from '../../../store/api';
import type { XBOMDocument } from '../../../types';
import { Download, AlertCircle, Terminal, CheckCircle2, Copy, Loader2, RefreshCw } from 'lucide-react';
import { generateXBOMWorkflowYaml } from '../utils';
import s from '../../XBOMPage.module.scss';

export default function GenerateForm() {
  const { data: status, refetch: refetchStatus } = useGetXBOMStatusQuery();
  const [installTrivy, { isLoading: isInstalling }] = useInstallTrivyMutation();
  const [recheckTrivy, { isLoading: isRechecking }] = useRecheckTrivyMutation();
  const [installMsg, setInstallMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [generateXBOM, { isLoading }] = useGenerateXBOMMutation();
  const [repoPath, setRepoPath] = useState('');
  const [branch, setBranch] = useState('');
  const [mode, setMode] = useState<'full' | 'sbom-only' | 'cbom-only'>('full');
  const [specVersion, setSpecVersion] = useState<'1.6' | '1.7'>('1.6');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [generatedXbom, setGeneratedXbom] = useState<XBOMDocument | null>(null);

  /* ── External tool toggles ── */
  const [enableCodeQL, setEnableCodeQL] = useState(true);
  const [enableCbomkitTheia, setEnableCbomkitTheia] = useState(true);
  const [enableCryptoAnalysis, setEnableCryptoAnalysis] = useState(true);
  const [codeqlLanguage, setCodeqlLanguage] = useState('java');
  const [showAdvanced, setShowAdvanced] = useState(false);

  /* ── GitHub Actions workflow snippet ── */
  const [showWorkflow, setShowWorkflow] = useState(false);
  const [wfBranches, setWfBranches] = useState('main');
  const [wfScanPath, setWfScanPath] = useState('.');
  const [wfExclude, setWfExclude] = useState('default');
  const [wfFailOnVuln, setWfFailOnVuln] = useState(false);
  const [wfSeverity, setWfSeverity] = useState(
    'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
  );
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
    if (!repoPath.trim()) {
      setError('Repository / directory path is required');
      return;
    }
    setError('');
    setSuccess('');
    setGeneratedXbom(null);
    try {
      const res = await generateXBOM({
        repoPath: repoPath.trim(),
        mode,
        specVersion,
        branch: branch.trim() || undefined,
        externalTools: {
          enableCodeQL,
          enableCbomkitTheia,
          enableCryptoAnalysis,
          codeqlLanguage,
        },
      }).unwrap();
      if (res.success) {
        setSuccess(
          `xBOM generated — ${res.analytics?.totalSoftwareComponents ?? 0} software components, ${res.analytics?.totalCryptoAssets ?? 0} crypto assets, ${res.analytics?.totalCrossReferences ?? 0} cross-references`,
        );
        if (res.xbom) setGeneratedXbom(res.xbom as XBOMDocument);
        setRepoPath('');
        setBranch('');
      } else {
        setError(res.error || res.message || 'Generation failed');
      }
    } catch (e: any) {
      setError(
        e?.data?.error || e?.data?.message || e?.message || 'Generation failed',
      );
    }
  };

  return (
    <div className={s.formCardWrapper} style={{ padding: '0 4px' }}>
      {/* ── Loading overlay ── */}
      {isLoading && (
        <div className={s.loadingOverlay}>
          <Loader2 size={32} />
          <span className={s.loadingOverlayText}>Generating xBOM…</span>
          <span className={s.loadingOverlaySubText}>Scanning repository for software dependencies &amp; crypto assets</span>
        </div>
      )}

      {/* ── Scanner status mini-cards ── */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <div style={{
          flex: 1, padding: '10px 14px', borderRadius: 8,
          border: '1px solid var(--dc1-border)', background: 'var(--dc1-bg-card, #fff)',
        }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--dc1-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Trivy Scanner</span>
          <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              fontSize: 12, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
              background: status?.trivyInstalled ? '#dcfce7' : '#fee2e2',
              color: status?.trivyInstalled ? '#16a34a' : '#dc2626',
            }}>
              {status?.trivyInstalled ? '● Installed' : '● Not found'}
            </span>
            {status?.trivyVersion && <span style={{ fontSize: 11, color: 'var(--dc1-text-muted)' }}>v{status.trivyVersion}</span>}
          </div>
        </div>
        <div style={{
          flex: 1, padding: '10px 14px', borderRadius: 8,
          border: '1px solid var(--dc1-border)', background: 'var(--dc1-bg-card, #fff)',
        }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--dc1-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>SBOM Generation</span>
          <div style={{ marginTop: 4 }}>
            <span style={{
              fontSize: 12, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
              background: status?.capabilities?.sbomGeneration ? '#dcfce7' : '#fef3c7',
              color: status?.capabilities?.sbomGeneration ? '#16a34a' : '#d97706',
            }}>
              {status?.capabilities?.sbomGeneration ? 'Ready' : 'Unavailable'}
            </span>
          </div>
        </div>
        <div style={{
          flex: 1, padding: '10px 14px', borderRadius: 8,
          border: '1px solid var(--dc1-border)', background: 'var(--dc1-bg-card, #fff)',
        }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--dc1-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>CBOM Generation</span>
          <div style={{ marginTop: 4 }}>
            <span style={{
              fontSize: 12, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
              background: '#dcfce7', color: '#16a34a',
            }}>Ready</span>
          </div>
        </div>
      </div>

      {/* ── Trivy setup guide ── */}
      {status && !status.trivyInstalled && (
        <div style={{
          margin: '0 0 20px',
          padding: '16px 20px',
          borderRadius: 8,
          border: '1px solid #fde68a',
          background: 'linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%)',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <AlertCircle size={18} style={{ color: '#d97706', flexShrink: 0, marginTop: 2 }} />
            <div style={{ flex: 1 }}>
              <h4 style={{ margin: '0 0 4px', fontSize: 13, fontWeight: 700, color: '#92400e' }}>
                Trivy Scanner Required for SBOM Generation
              </h4>
              <p style={{ margin: '0 0 12px', fontSize: 12, lineHeight: 1.5, color: '#78350f' }}>
                <strong>Trivy</strong> is an open-source security scanner by Aqua Security. It scans repositories for software dependencies, vulnerabilities, and licenses to generate SBOMs.
                Without Trivy, only CBOM generation is available.
              </p>

              <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  disabled={isInstalling}
                  onClick={async () => {
                    setInstallMsg(null);
                    try {
                      const res = await installTrivy().unwrap();
                      setInstallMsg({ ok: res.success, text: res.message });
                      if (res.success) refetchStatus();
                    } catch (e: any) {
                      setInstallMsg({ ok: false, text: e?.data?.message || 'Installation failed' });
                    }
                  }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    padding: '8px 18px', fontSize: 13, fontWeight: 600,
                    background: '#d97706', color: '#fff',
                    border: 'none', borderRadius: 6, cursor: isInstalling ? 'wait' : 'pointer',
                    opacity: isInstalling ? 0.7 : 1, transition: 'all 0.15s',
                  }}
                >
                  {isInstalling ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Download size={14} />}
                  {isInstalling ? 'Installing Trivy…' : 'Install Trivy Automatically'}
                </button>

                <button
                  disabled={isRechecking}
                  onClick={async () => {
                    await recheckTrivy().unwrap();
                    refetchStatus();
                  }}
                  title="Already installed Trivy? Click to re-check."
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    padding: '8px 14px', fontSize: 12, fontWeight: 600,
                    background: 'rgba(255,255,255,0.7)', color: '#78350f',
                    border: '1px solid #fde68a', borderRadius: 6, cursor: 'pointer',
                    transition: 'all 0.15s',
                  }}
                >
                  <RefreshCw size={13} style={isRechecking ? { animation: 'spin 1s linear infinite' } : undefined} />
                  Re-check
                </button>
              </div>

              {installMsg && (
                <div style={{
                  marginTop: 10, padding: '8px 12px', borderRadius: 6, fontSize: 12, fontWeight: 500,
                  background: installMsg.ok ? '#dcfce7' : '#fee2e2',
                  color: installMsg.ok ? '#16a34a' : '#dc2626',
                  border: `1px solid ${installMsg.ok ? '#bbf7d0' : '#fecaca'}`,
                }}>
                  {installMsg.ok ? <CheckCircle2 size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> : <AlertCircle size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />}
                  {installMsg.text}
                </div>
              )}

              <details style={{ marginTop: 12 }}>
                <summary style={{ fontSize: 11, fontWeight: 600, color: '#92400e', cursor: 'pointer' }}>Or install manually</summary>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginTop: 8 }}>
                  {[
                    { label: 'macOS (Homebrew)', cmd: 'brew install trivy' },
                    { label: 'Linux (apt)', cmd: 'sudo apt-get install trivy' },
                    { label: 'Docker', cmd: 'docker pull aquasec/trivy' },
                  ].map(({ label, cmd }) => (
                    <div key={label} style={{ padding: '8px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.7)', border: '1px solid #fde68a' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
                        <Terminal size={12} style={{ color: '#92400e' }} />
                        <span style={{ fontSize: 10, fontWeight: 700, color: '#92400e', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</span>
                      </div>
                      <div style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '6px 10px', borderRadius: 5,
                        background: '#1e1e2e', fontFamily: 'monospace', fontSize: 11, color: '#a6e3a1',
                      }}>
                        <code>{cmd}</code>
                        <button
                          title="Copy"
                          onClick={() => navigator.clipboard.writeText(cmd)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: 2 }}
                        >
                          <Copy size={12} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            </div>
          </div>
        </div>
      )}

      {/* ── Local scan form ── */}
      <p
        style={{
          fontSize: 13,
          color: 'var(--dc1-text-muted)',
          marginBottom: 16,
        }}
      >
        Scan a local directory on this server. Trivy generates the SBOM (if
        installed) and the CBOM Analyser scans for cryptographic usage.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className={s.formRow}>
          <label>Repository / Directory Path *</label>
          <input
            placeholder="/path/to/local/repo"
            value={repoPath}
            onChange={(e) => setRepoPath(e.target.value)}
          />
        </div>

        <div className={s.formRow}>
          <label>Branch</label>
          <input
            placeholder="main"
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
          />
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
          <select
            value={specVersion}
            onChange={(e) => setSpecVersion(e.target.value as '1.6' | '1.7')}
          >
            <option value="1.6">CycloneDX 1.6</option>
            <option value="1.7">CycloneDX 1.7</option>
          </select>
        </div>
      </div>

      {/* ── Advanced: External Analysis Tools ── */}
      <div style={{ marginTop: 12 }}>
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--dc1-primary)', fontSize: 12, fontWeight: 600,
            display: 'flex', alignItems: 'center', gap: 4, padding: 0,
          }}
        >
          <span style={{ transform: showAdvanced ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s', display: 'inline-block' }}>▶</span>
          Advanced: External Analysis Tools
        </button>

        {showAdvanced && (
          <div style={{
            marginTop: 8, padding: '12px 16px', borderRadius: 8,
            border: '1px solid var(--dc1-border)', background: 'var(--dc1-bg-card, #fff)',
          }}>
            <p style={{ fontSize: 11, color: 'var(--dc1-text-muted)', margin: '0 0 10px 0' }}>
              Enable/disable external cryptographic analysis tools. Tools are auto-detected — disabled tools are skipped gracefully.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 24px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                <input type="checkbox" checked={enableCodeQL} onChange={(e) => setEnableCodeQL(e.target.checked)} />
                <span style={{ fontWeight: 600 }}>CodeQL</span>
                <span style={{ color: 'var(--dc1-text-muted)', fontSize: 11 }}>— data-flow crypto analysis</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                <input type="checkbox" checked={enableCbomkitTheia} onChange={(e) => setEnableCbomkitTheia(e.target.checked)} />
                <span style={{ fontWeight: 600 }}>cbomkit-theia</span>
                <span style={{ color: 'var(--dc1-text-muted)', fontSize: 11 }}>— IBM filesystem scanner</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                <input type="checkbox" checked={enableCryptoAnalysis} onChange={(e) => setEnableCryptoAnalysis(e.target.checked)} />
                <span style={{ fontWeight: 600 }}>CryptoAnalysis</span>
                <span style={{ color: 'var(--dc1-text-muted)', fontSize: 11 }}>— Java JCA/JCE typestate</span>
              </label>
              {enableCodeQL && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                  <label style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>CodeQL Language:</label>
                  <select
                    value={codeqlLanguage}
                    onChange={(e) => setCodeqlLanguage(e.target.value)}
                    style={{ fontSize: 12, padding: '2px 6px' }}
                  >
                    <option value="java">Java</option>
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript</option>
                    <option value="csharp">C#</option>
                    <option value="cpp">C/C++</option>
                    <option value="go">Go</option>
                  </select>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>
          {error}
        </div>
      )}
      {success && (
        <div
          style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        >
          <span>{success}</span>
          {generatedXbom && (
            <button
              className="dc1-btn-secondary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, padding: '4px 12px' }}
              onClick={() => {
                const name = generatedXbom.metadata?.component?.name || 'generated';
                const blob = new Blob([JSON.stringify(generatedXbom, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${name.replace(/[^a-zA-Z0-9_-]/g, '_')}-xbom.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              }}
            >
              <Download size={13} /> Download xBOM
            </button>
          )}
        </div>
      )}

      <div className={s.formActions}>
        <button
          className="dc1-btn-primary"
          onClick={handleSubmit}
          disabled={isLoading}
        >
          {isLoading ? 'Generating…' : 'Generate xBOM'}
        </button>
      </div>
    </div>
  );
}
