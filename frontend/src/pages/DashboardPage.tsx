import { useState, useMemo, useCallback } from 'react';
import {
  Upload,
  ShieldCheck,
  Database,
  ArrowLeft,
  AlertTriangle,
  FileCode2,
  Clock,
  Package,
  Download,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { CBOMDocument, QuantumReadinessScore, ComplianceSummary } from '../types';
import {
  CBOMHeader,
  ReadinessScoreCard,
  QuantumSafetyDonut,
  PrimitivesDonut,
  FunctionsDonut,
  CryptoBubbleChart,
  ComplianceBanner,
  CbomStatsRow,
  AssetListView,
  ThirdPartyLibrariesView,
} from '../components';
import { useGetCbomImportQuery, useGetCbomUploadsQuery } from '../store/api';
import type { CbomUploadItem } from '../store/api';
import { CbomStatusBadge, ProgressBar } from './discovery/components';
import { parseCbomJson } from '../utils/cbomParser';
import s from './discovery/ImportHeader.module.scss';

type Tab = 'overview' | 'inventory';

interface Props {
  /* Upload / sample-data flow (props-driven) */
  cbom?: CBOMDocument | null;
  readinessScore?: QuantumReadinessScore | null;
  compliance?: ComplianceSummary | null;
  onNavigate?: (path: string) => void;
  onUpload?: () => void;
  onLoadSample?: () => void;
  onClearCbom?: () => void;
  onLoadCbomUpload?: (id: string) => void;
  /* Import flow (self-fetching) */
  cbomImportId?: string;
  onBack?: () => void;
}

export default function DashboardPage({
  cbom: propCbom,
  readinessScore: propScore,
  compliance: propCompliance,
  onNavigate,
  onUpload,
  onLoadSample,
  onClearCbom,
  onLoadCbomUpload,
  cbomImportId,
  onBack,
}: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  /* ── CBOM uploads list for welcome screen ──────────── */
  const { data: cbomUploads = [], isLoading: uploadsLoading } = useGetCbomUploadsQuery();
  const [uploadsPage, setUploadsPage] = useState(1);
  const uploadsPerPage = 5;

  const downloadCbomUpload = useCallback(async (id: string, name: string) => {
    try {
      const res = await fetch(`/api/cbom-uploads/${encodeURIComponent(id)}`);
      const json = await res.json();
      if (!json.success || !json.data?.cbomFile) return;
      const raw = atob(json.data.cbomFile);
      const blob = new Blob([raw], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${(name || 'cbom').replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  }, []);

  const fmtDate = (iso: string) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  /* ── Import-mode data fetching ─────────────────────── */
  const isImportMode = !!cbomImportId;
  const { data: cbomImport, isLoading, isError } = useGetCbomImportQuery(
    cbomImportId ?? '',
    { skip: !cbomImportId },
  );

  const importParsed = useMemo(() => {
    if (!cbomImport) return null;
    if (cbomImport.cbomFile) {
      try {
        const raw = atob(cbomImport.cbomFile);
        return parseCbomJson(raw, 'CBOM Import Analysis');
      } catch (e) {
        console.warn('Failed to parse cbomFile:', e);
      }
    }
    // Fallback empty
    const emptyDoc: CBOMDocument = {
      bomFormat: cbomImport.format?.includes('CycloneDX') ? 'CycloneDX' : (cbomImport.format ?? 'CycloneDX'),
      specVersion: cbomImport.specVersion ?? '1.7',
      version: 1,
      metadata: {
        timestamp: cbomImport.importDate,
        component: cbomImport.applicationName ? { name: cbomImport.applicationName, type: 'application' } : undefined,
      },
      components: [],
      cryptoAssets: [],
    };
    return {
      doc: emptyDoc,
      readinessScore: { score: 0, totalAssets: 0, quantumSafe: 0, notQuantumSafe: 0, conditional: 0, unknown: 0 } as QuantumReadinessScore,
      compliance: { isCompliant: true, policy: 'NIST Post-Quantum Cryptography', source: 'CBOM Import Analysis', totalAssets: 0, compliantAssets: 0, nonCompliantAssets: 0, unknownAssets: 0 } as ComplianceSummary,
    };
  }, [cbomImport]);

  /* ── Resolve active data (props vs import) ─────────── */
  const cbom = isImportMode ? (importParsed?.doc ?? null) : (propCbom ?? null);
  const readinessScore = isImportMode ? (importParsed?.readinessScore ?? null) : (propScore ?? null);
  const compliance = isImportMode ? (importParsed?.compliance ?? null) : (propCompliance ?? null);

  const assets = cbom?.cryptoAssets ?? [];
  const totalAssets = assets.length;
  const safe = assets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const notSafe = assets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
  const conditional = assets.filter((a) => a.quantumSafety === 'conditional').length;
  const unknown = assets.filter((a) => a.quantumSafety === 'unknown').length;
  const policyViolations = compliance ? compliance.nonCompliantAssets : notSafe;
  const uniqueAlgos = new Set(assets.map((a) => a.name)).size;
  const libCount = cbom?.thirdPartyLibraries?.length ?? 0;
  const libraries = cbom?.thirdPartyLibraries ?? [];

  const formatDate = (iso: string) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  /* ── Import-mode: loading / error states ───────────── */
  if (isImportMode && isLoading) {
    return (
      <div className={s.loading}>
        <div className={s.spinner} />
        <p>Loading CBOM analysis...</p>
      </div>
    );
  }

  if (isImportMode && (isError || !cbomImport)) {
    return (
      <div className={s.error}>
        <AlertTriangle size={40} strokeWidth={1.2} />
        <h3>CBOM import not found</h3>
        <p>The requested CBOM import could not be loaded.</p>
        {onBack && (
          <button className={s.backBtn} onClick={onBack}>
            <ArrowLeft size={16} /> Back to CBOM Imports
          </button>
        )}
      </div>
    );
  }

  /* ── Upload-mode: welcome screen when no data ──────── */
  if (!isImportMode && !cbom) {
    return (
      <div className="dc1-welcome">
        <div className="dc1-welcome-inner">
          <div className="dc1-welcome-header">
            <ShieldCheck size={48} strokeWidth={1.2} className="dc1-welcome-icon" />
            <h1>Quantum Readiness Advisor</h1>
            <p>Analyse your cryptographic inventory for post-quantum readiness. Upload a CBOM file to get started or explore with sample data.</p>
          </div>

          <div className="dc1-welcome-cards">
            <button className="dc1-welcome-card dc1-welcome-card-primary" onClick={onUpload}>
              <Upload size={32} strokeWidth={1.5} />
              <h3>Upload CBOM</h3>
              <p>Import your CycloneDX CBOM file (.json, .cdx, .xml) to analyse your project's cryptographic inventory</p>
            </button>

            <button className="dc1-welcome-card dc1-welcome-card-secondary" onClick={onLoadSample}>
              <Database size={32} strokeWidth={1.5} />
              <h3>Load Sample Data</h3>
              <p>Explore the dashboard with a pre-built sample dataset from the Keycloak open-source project</p>
            </button>
          </div>

          {/* ── Uploaded CBOMs ──────────────────────────────── */}
          {!uploadsLoading && cbomUploads.length > 0 && (() => {
            const totalPages = Math.ceil(cbomUploads.length / uploadsPerPage);
            const page = Math.min(uploadsPage, totalPages);
            const start = (page - 1) * uploadsPerPage;
            const pageItems = cbomUploads.slice(start, start + uploadsPerPage);
            return (
            <div className="dc1-card" style={{ marginTop: 32, width: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <h3 className="dc1-card-section-title" style={{ margin: 0 }}>Uploaded CBOMs</h3>
                <span style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>{cbomUploads.length} total</span>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--dc1-border)', textAlign: 'left' }}>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Component</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>File Name</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Upload Date</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Crypto Assets</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Quantum-safe</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Not Safe</th>
                    <th style={{ padding: '8px 10px', fontWeight: 600, color: 'var(--dc1-text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.5px', textAlign: 'center' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((item: CbomUploadItem) => (
                    <tr
                      key={item.id}
                      style={{ borderBottom: '1px solid var(--dc1-border)', cursor: 'pointer', transition: 'background 0.15s' }}
                      onClick={() => onLoadCbomUpload?.(item.id)}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--dc1-bg-hover, rgba(0,0,0,0.02))')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = '')}
                    >
                      <td style={{ padding: '10px 10px', fontWeight: 500 }}>{item.componentName || '—'}</td>
                      <td style={{ padding: '10px 10px', color: 'var(--dc1-text-muted)' }}>{item.fileName}</td>
                      <td style={{ padding: '10px 10px', color: 'var(--dc1-text-muted)' }}>{fmtDate(item.uploadDate)}</td>
                      <td style={{ padding: '10px 10px' }}>{item.totalAssets}</td>
                      <td style={{ padding: '10px 10px', color: 'var(--dc1-safe)' }}>{item.quantumSafe}</td>
                      <td style={{ padding: '10px 10px', color: item.notQuantumSafe > 0 ? 'var(--dc1-danger)' : undefined }}>{item.notQuantumSafe}</td>
                      <td style={{ padding: '10px 10px', textAlign: 'center' }}>
                        <button
                          title="Download CBOM"
                          onClick={(e) => { e.stopPropagation(); downloadCbomUpload(item.id, item.componentName || item.fileName); }}
                          style={{
                            background: 'none', border: '1px solid var(--dc1-border)', borderRadius: 6,
                            cursor: 'pointer', padding: '4px 8px', display: 'inline-flex', alignItems: 'center', gap: 4,
                            fontSize: 12, color: 'var(--dc1-text-muted)',
                          }}
                        >
                          <Download size={13} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* ── Pagination ──────────────────────────── */}
              {totalPages > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, paddingTop: 12, fontSize: 13 }}>
                  <button
                    disabled={page <= 1}
                    onClick={() => setUploadsPage((p) => Math.max(1, p - 1))}
                    style={{
                      background: 'none', border: '1px solid var(--dc1-border)', borderRadius: 6,
                      cursor: page <= 1 ? 'default' : 'pointer', padding: '4px 8px', display: 'inline-flex', alignItems: 'center',
                      opacity: page <= 1 ? 0.4 : 1, color: 'var(--dc1-text-muted)',
                    }}
                  >
                    <ChevronLeft size={14} />
                  </button>
                  <span style={{ color: 'var(--dc1-text-muted)' }}>Page {page} of {totalPages}</span>
                  <button
                    disabled={page >= totalPages}
                    onClick={() => setUploadsPage((p) => Math.min(totalPages, p + 1))}
                    style={{
                      background: 'none', border: '1px solid var(--dc1-border)', borderRadius: 6,
                      cursor: page >= totalPages ? 'default' : 'pointer', padding: '4px 8px', display: 'inline-flex', alignItems: 'center',
                      opacity: page >= totalPages ? 0.4 : 1, color: 'var(--dc1-text-muted)',
                    }}
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              )}
            </div>
            );
          })()}
        </div>
      </div>
    );
  }

  return (
    <div className="dc1-dashboard">
      {/* ── Import-mode: back button + import header ──── */}
      {isImportMode && cbomImport && (
        <>
          {onBack && (
            <button className={s.backBtn} onClick={onBack}>
              <ArrowLeft size={16} /> Back to CBOM Imports
            </button>
          )}

          <div className={s.header}>
            <div className={s.headerTop}>
              <div>
                <p className={s.breadcrumb}>Discovery / CBOM Imports</p>
                <h1 className={s.title}>{cbomImport.applicationName ?? cbomImport.fileName}</h1>
                <p className={s.subtitle}>{cbomImport.fileName}</p>
              </div>
              <CbomStatusBadge status={cbomImport.status} />
            </div>

            <div className={s.metaRow}>
              <span className={s.metaItem}>
                <FileCode2 size={14} />
                {cbomImport.format} {cbomImport.specVersion}
              </span>
              <span className={s.metaItem}>
                <Package size={14} />
                {cbomImport.totalComponents} components
              </span>
              <span className={s.metaItem}>
                <ShieldCheck size={14} />
                {totalAssets} crypto components
              </span>
              <span className={s.metaItem}>
                <Clock size={14} />
                Imported {formatDate(cbomImport.importDate)}
              </span>
            </div>

            <div className={s.pqcBar}>
              <span className={s.pqcLabel}>PQC Readiness</span>
              <ProgressBar value={safe} max={totalAssets} />
              <span className={s.pqcFraction}>
                {safe} / {totalAssets} quantum-safe
              </span>
            </div>
          </div>
        </>
      )}

      {/* ── Upload-mode: standard page header + CBOMHeader */}
      {!isImportMode && (
        <>
          <div className="dc1-page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div>
              <h1 className="dc1-page-title">CBOM Analyzer</h1>
              <p className="dc1-page-subtitle">Cryptographic inventory overview from your CBOM analysis</p>
            </div>
            {onClearCbom && (
              <button
                onClick={onClearCbom}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  background: 'none', border: '1px solid var(--dc1-border)', borderRadius: 8,
                  padding: '8px 16px', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                  color: 'var(--dc1-text-secondary)', transition: 'all 0.15s',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--dc1-blue)'; e.currentTarget.style.color = 'var(--dc1-blue)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--dc1-border)'; e.currentTarget.style.color = 'var(--dc1-text-secondary)'; }}
              >
                <ArrowLeft size={15} />
                Back
              </button>
            )}
          </div>

          <div className="dc1-card" style={{ marginBottom: 16 }}>
            <CBOMHeader cbom={cbom!} />
          </div>
        </>
      )}

      {/* ── Compliance Banner (both modes) ───────────── */}
      <div style={{ marginBottom: 16 }}>
        <ComplianceBanner compliance={compliance} />
      </div>

      {/* ── Tab bar ──────────────────────────────────── */}
      <div className="dc1-tabs-bar" style={{ marginBottom: 16 }}>
        <button
          className={`dc1-tab-btn ${activeTab === 'overview' ? 'dc1-tab-active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`dc1-tab-btn ${activeTab === 'inventory' ? 'dc1-tab-active' : ''}`}
          onClick={() => setActiveTab('inventory')}
        >
          Inventory ({totalAssets})
        </button>
      </div>

      {activeTab === 'overview' && (
        <>
          <CbomStatsRow
            totalAssets={totalAssets}
            quantumSafe={safe}
            notQuantumSafe={notSafe}
            policyViolations={policyViolations}
            onViewPolicies={onNavigate ? () => onNavigate('policies') : undefined}
          />

          <div className="dc1-two-col">
            <div className="dc1-card dc1-card-flush">
              <ReadinessScoreCard score={readinessScore} />
            </div>
            <div className="dc1-card dc1-card-flush">
              <QuantumSafetyDonut assets={assets} />
            </div>
          </div>

          {/* ── Visualize charts ─────────────────────── */}
          <div className="dc1-viz-grid">
            <div className="dc1-card dc1-card-flush">
              <PrimitivesDonut assets={assets} />
            </div>
            <div className="dc1-card dc1-card-flush">
              <FunctionsDonut assets={assets} />
            </div>
          </div>

          <div className="dc1-card dc1-card-flush" style={{ marginTop: 20 }}>
            <CryptoBubbleChart assets={assets} />
          </div>
        </>
      )}

      {activeTab === 'inventory' && (
        <>
          <AssetListView assets={assets} repository={cbom?.metadata?.repository} />
          {libraries.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <ThirdPartyLibrariesView libraries={libraries} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
