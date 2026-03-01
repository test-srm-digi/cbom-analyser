import { useState, useMemo } from 'react';
import { ArrowLeft, AlertTriangle, ShieldCheck, FileCode2, Clock, Package, Box, Link2, Bug } from 'lucide-react';
import { useGetCbomImportQuery } from '../../store/api';
import {
  ReadinessScoreCard,
  QuantumSafetyDonut,
  PrimitivesDonut,
  FunctionsDonut,
  CryptoBubbleChart,
  ComplianceBanner,
  AssetListView,
  CbomStatsRow,
  AssetBreakdown,
} from '../../components';
import { CbomStatusBadge, ProgressBar } from './components';
import { parseCbomJson } from '../../utils/cbomParser';
import type { QuantumReadinessScore, ComplianceSummary, CryptoAsset, CBOMDocument } from '../../types';
import s from './CbomDetailPage.module.scss';

/* ── Props ──────────────────────────────────────────────────── */

interface Props {
  cbomImportId: string;
  onBack: () => void;
}

/* ── Component ──────────────────────────────────────────────── */

type DetailTab = 'overview' | 'inventory' | 'sbom' | 'vulnerabilities' | 'xbom-crossrefs';

/** Software component extracted from SBOM/xBOM data */
interface SoftwareComponent {
  name: string;
  version: string;
  type: string;
  purl?: string;
  group?: string;
  licenses?: string[];
}

/** Cross-reference from xBOM linking software ↔ crypto */
interface CrossRef {
  softwareRef: string;
  softwareName: string;
  softwareVersion?: string;
  cryptoRefs: { ref: string; name: string; algorithm?: string; relationship?: string }[];
}

/** Vulnerability from SBOM */
interface VulnEntry {
  id: string;
  source?: string;
  severity: string;
  description: string;
  affects: string[];
}

export default function CbomDetailPage({ cbomImportId, onBack }: Props) {
  const { data: cbomImport, isLoading, isError } = useGetCbomImportQuery(cbomImportId);
  const [activeTab, setActiveTab] = useState<DetailTab>('overview');

  const { assets, readinessScore, compliance, cbomDoc, softwareComponents, vulnerabilities, crossReferences } = useMemo(() => {
    const empty = {
      assets: [] as CryptoAsset[],
      readinessScore: null as QuantumReadinessScore | null,
      compliance: null as ComplianceSummary | null,
      cbomDoc: null as CBOMDocument | null,
      softwareComponents: [] as SoftwareComponent[],
      vulnerabilities: [] as VulnEntry[],
      crossReferences: [] as CrossRef[],
    };
    if (!cbomImport) return empty;

    let rawJson: any = null;

    // If we have the artifact file stored, decode and parse it
    if (cbomImport.cbomFile) {
      try {
        const rawText = atob(cbomImport.cbomFile);
        rawJson = JSON.parse(rawText);
        const { doc, readinessScore: score, compliance: comp } = parseCbomJson(rawText, 'CBOM Import Analysis');

        // Extract SBOM software components (non-crypto)
        const allComps: any[] = rawJson.components || [];
        const swComps: SoftwareComponent[] = allComps
          .filter((c: any) => {
            const type = c.type || '';
            const hasCp = c.cryptoProperties || c['crypto-properties'] || c['crypto:properties'];
            return !hasCp && type !== 'crypto-asset';
          })
          .map((c: any) => ({
            name: c.name || 'unknown',
            version: c.version || '',
            type: c.type || 'library',
            purl: c.purl,
            group: c.group,
            licenses: (c.licenses || []).map((l: any) => l?.license?.id || l?.license?.name || l?.expression || '').filter(Boolean),
          }));

        // Extract vulnerabilities
        const vulns: VulnEntry[] = (rawJson.vulnerabilities || []).map((v: any) => ({
          id: v.id || 'unknown',
          source: v.source?.name || v.source?.url || '',
          severity: v.ratings?.[0]?.severity || 'unknown',
          description: v.description || '',
          affects: (v.affects || []).map((a: any) => a.ref || ''),
        }));

        // Extract xBOM cross-references
        const xrefs: CrossRef[] = (rawJson.crossReferences || []).map((cr: any) => ({
          softwareRef: cr.softwareRef || '',
          softwareName: cr.softwareName || '',
          softwareVersion: cr.softwareVersion || '',
          cryptoRefs: (cr.cryptoRefs || []).map((r: any) => ({
            ref: r.ref || '',
            name: r.name || '',
            algorithm: r.algorithm || '',
            relationship: r.relationship || 'uses',
          })),
        }));

        return {
          assets: doc.cryptoAssets,
          readinessScore: score,
          compliance: comp,
          cbomDoc: doc,
          softwareComponents: swComps,
          vulnerabilities: vulns,
          crossReferences: xrefs,
        };
      } catch (e) {
        console.warn('Failed to parse cbomFile, falling back to metadata:', e);
      }
    }

    // Fallback when no cbomContent is available — empty analysis
    const emptyDoc: CBOMDocument = {
      bomFormat: cbomImport.format.includes('CycloneDX') ? 'CycloneDX' : cbomImport.format,
      specVersion: cbomImport.specVersion,
      version: 1,
      metadata: {
        timestamp: cbomImport.importDate,
        component: cbomImport.applicationName
          ? { name: cbomImport.applicationName, type: 'application' }
          : undefined,
      },
      components: [],
      cryptoAssets: [],
    };

    return {
      ...empty,
      readinessScore: {
        score: 0,
        totalAssets: 0,
        quantumSafe: 0,
        notQuantumSafe: 0,
        conditional: 0,
        unknown: 0,
      } as QuantumReadinessScore,
      compliance: {
        isCompliant: true,
        policy: 'NIST Post-Quantum Cryptography',
        source: 'CBOM Import Analysis',
        totalAssets: 0,
        compliantAssets: 0,
        nonCompliantAssets: 0,
        unknownAssets: 0,
      } as ComplianceSummary,
      cbomDoc: emptyDoc,
    };
  }, [cbomImport]);

  if (isLoading) {
    return (
      <div className={s.loading}>
        <div className={s.spinner} />
        <p>Loading CBOM analysis...</p>
      </div>
    );
  }

  if (isError || !cbomImport) {
    return (
      <div className={s.error}>
        <AlertTriangle size={40} strokeWidth={1.2} />
        <h3>CBOM import not found</h3>
        <p>The requested CBOM import could not be loaded.</p>
        <button className={s.backBtn} onClick={onBack}>
          <ArrowLeft size={16} /> Back to CBOM Imports
        </button>
      </div>
    );
  }

  const formatDate = (iso: string) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  const policyViolations = compliance ? compliance.nonCompliantAssets : 0;
  const safe = readinessScore?.quantumSafe ?? 0;
  const notSafe = readinessScore?.notQuantumSafe ?? 0;
  const conditional = readinessScore?.conditional ?? 0;
  const unknown = readinessScore?.unknown ?? 0;
  const totalAssets = assets.length;

  return (
    <div className={s.page}>
      {/* ── Back navigation ─────────────────────────── */}
      <button className={s.backBtn} onClick={onBack}>
        <ArrowLeft size={16} /> Back to CBOM Imports
      </button>

      {/* ── Header ──────────────────────────────────── */}
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

      {/* ── Compliance Banner ───────────────────────── */}
      <div style={{ marginBottom: 16 }}>
        <ComplianceBanner compliance={compliance} />
      </div>

      {/* ── Tab bar ─────────────────────────────────── */}
      <div className="dc1-tabs-bar" style={{ marginBottom: 16, flexWrap: 'wrap' }}>
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
          Crypto Inventory ({totalAssets})
        </button>
        {/* ── SBOM tab — only if software components detected */}
        {softwareComponents.length > 0 && (
          <button
            className={`dc1-tab-btn ${activeTab === 'sbom' ? 'dc1-tab-active' : ''}`}
            onClick={() => setActiveTab('sbom')}
          >
            <Box size={13} style={{ marginRight: 4 }} />
            Software (SBOM)
            <span style={{ marginLeft: 6, fontSize: 11, background: '#dbeafe', color: '#1d4ed8', borderRadius: 10, padding: '1px 7px', fontWeight: 600 }}>
              {softwareComponents.length}
            </span>
          </button>
        )}
        {/* ── Vulnerabilities tab — only if vulnerability data present */}
        {vulnerabilities.length > 0 && (
          <button
            className={`dc1-tab-btn ${activeTab === 'vulnerabilities' ? 'dc1-tab-active' : ''}`}
            onClick={() => setActiveTab('vulnerabilities')}
          >
            <Bug size={13} style={{ marginRight: 4 }} />
            Vulnerabilities
            <span style={{
              marginLeft: 6, fontSize: 11, borderRadius: 10, padding: '1px 7px', fontWeight: 600,
              background: vulnerabilities.some(v => v.severity === 'critical') ? '#fee2e2' : '#fef3c7',
              color: vulnerabilities.some(v => v.severity === 'critical') ? '#dc2626' : '#d97706',
            }}>
              {vulnerabilities.length}
            </span>
          </button>
        )}
        {/* ── xBOM Cross-Refs tab — only if cross-reference data present */}
        {crossReferences.length > 0 && (
          <button
            className={`dc1-tab-btn ${activeTab === 'xbom-crossrefs' ? 'dc1-tab-active' : ''}`}
            onClick={() => setActiveTab('xbom-crossrefs')}
          >
            <Link2 size={13} style={{ marginRight: 4 }} />
            xBOM Cross-Refs
            <span style={{ marginLeft: 6, fontSize: 11, background: '#f0e8ff', color: '#7c3aed', borderRadius: 10, padding: '1px 7px', fontWeight: 600 }}>
              {crossReferences.length}
            </span>
          </button>
        )}
      </div>

      {activeTab === 'overview' && (
        <>
          {/* ── Stats Row (reusable) ────────────────────── */}
          <CbomStatsRow
            totalAssets={totalAssets}
            quantumSafe={safe}
            notQuantumSafe={notSafe}
            policyViolations={policyViolations}
          />

          {/* ── Charts Row ──────────────────────────────── */}
          <div className="dc1-two-col">
            <div className="dc1-card dc1-card-flush">
              <ReadinessScoreCard score={readinessScore} />
            </div>
            <div className="dc1-card dc1-card-flush">
              <QuantumSafetyDonut assets={assets} />
            </div>
          </div>

          {/* ── Asset Breakdown (reusable) ──────────────── */}
          <AssetBreakdown
            quantumSafe={safe}
            notQuantumSafe={notSafe}
            conditional={conditional}
            unknown={unknown}
            totalAssets={totalAssets}
          />

          {/* ── Visualize charts ─────────────────────────── */}
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
        <div className="dc1-card" style={{ marginTop: 0 }}>
          <AssetListView assets={assets} />
        </div>
      )}

      {/* ── SBOM: Software components (decoupled) ───────────────── */}
      {activeTab === 'sbom' && softwareComponents.length > 0 && (
        <SbomPanel components={softwareComponents} />
      )}

      {/* ── Vulnerabilities (decoupled) ─────────────────────────── */}
      {activeTab === 'vulnerabilities' && vulnerabilities.length > 0 && (
        <VulnerabilityPanel vulns={vulnerabilities} />
      )}

      {/* ── xBOM Cross-References (decoupled) ───────────────────── */}
      {activeTab === 'xbom-crossrefs' && crossReferences.length > 0 && (
        <CrossRefPanel refs={crossReferences} />
      )}
    </div>
  );
}

/* ================================================================== */
/*  SBOM Panel — Software component inventory (decoupled)             */
/* ================================================================== */

function SbomPanel({ components }: { components: SoftwareComponent[] }) {
  const [filter, setFilter] = useState('');
  const filtered = filter
    ? components.filter(c =>
        c.name.toLowerCase().includes(filter.toLowerCase()) ||
        c.type.toLowerCase().includes(filter.toLowerCase()) ||
        (c.purl || '').toLowerCase().includes(filter.toLowerCase())
      )
    : components;

  const byType = useMemo(() => {
    const m: Record<string, number> = {};
    for (const c of components) { m[c.type] = (m[c.type] || 0) + 1; }
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [components]);

  return (
    <>
      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1d4ed8' }}>{components.length}</div>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>Total Packages</div>
        </div>
        {byType.slice(0, 3).map(([type, count]) => (
          <div key={type} className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#475569' }}>{count}</div>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'capitalize' }}>{type}</div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="dc1-card" style={{ marginBottom: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
            <Box size={15} style={{ marginRight: 6, verticalAlign: -2 }} />
            Software Components
          </h3>
          <input
            type="text"
            placeholder="Filter by name, type, purl…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ padding: '6px 10px', fontSize: 12, borderRadius: 6, border: '1px solid var(--dc1-border)', width: 240 }}
          />
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--dc1-border)', textAlign: 'left' }}>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Package Name</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Version</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Type</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>License</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>PURL</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((c, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--dc1-border)', opacity: 0.95 }}>
                <td style={{ padding: '6px', fontWeight: 500 }}>
                  {c.group ? <span style={{ color: 'var(--dc1-text-muted)', fontSize: 11 }}>{c.group}/</span> : ''}
                  {c.name}
                </td>
                <td style={{ padding: '6px', fontFamily: 'var(--dc1-mono)', fontSize: 11 }}>{c.version || '—'}</td>
                <td style={{ padding: '6px' }}>
                  <span style={{ background: '#f1f5f9', color: '#475569', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 500, textTransform: 'capitalize' }}>
                    {c.type}
                  </span>
                </td>
                <td style={{ padding: '6px', fontSize: 11 }}>{c.licenses?.join(', ') || '—'}</td>
                <td style={{ padding: '6px', fontSize: 10, fontFamily: 'var(--dc1-mono)', color: 'var(--dc1-text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.purl || '—'}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={5} style={{ padding: 24, textAlign: 'center', color: 'var(--dc1-text-muted)' }}>No matching components</td></tr>
            )}
          </tbody>
        </table>
        {filtered.length > 200 && (
          <div style={{ padding: 8, textAlign: 'center', color: 'var(--dc1-text-muted)', fontSize: 12 }}>
            Showing 200 of {filtered.length} components
          </div>
        )}
      </div>
    </>
  );
}

/* ================================================================== */
/*  Vulnerability Panel (decoupled — only rendered when data present) */
/* ================================================================== */

function VulnerabilityPanel({ vulns }: { vulns: VulnEntry[] }) {
  const [sevFilter, setSevFilter] = useState<string>('all');
  const sevCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const v of vulns) { m[v.severity] = (m[v.severity] || 0) + 1; }
    return m;
  }, [vulns]);
  const filtered = sevFilter === 'all' ? vulns : vulns.filter(v => v.severity === sevFilter);

  const sevColor = (sev: string) => {
    switch (sev) {
      case 'critical': return { bg: '#fee2e2', text: '#dc2626' };
      case 'high': return { bg: '#ffedd5', text: '#ea580c' };
      case 'medium': return { bg: '#fef3c7', text: '#d97706' };
      case 'low': return { bg: '#dbeafe', text: '#2563eb' };
      default: return { bg: '#f1f5f9', text: '#64748b' };
    }
  };

  return (
    <>
      {/* Severity stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12, marginBottom: 16 }}>
        {['critical', 'high', 'medium', 'low'].map(sev => {
          const sc = sevColor(sev);
          const count = sevCounts[sev] || 0;
          return (
            <div
              key={sev}
              className="dc1-card"
              style={{ padding: 16, textAlign: 'center', cursor: 'pointer', border: sevFilter === sev ? `2px solid ${sc.text}` : undefined }}
              onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}
            >
              <div style={{ fontSize: 24, fontWeight: 700, color: sc.text }}>{count}</div>
              <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'capitalize' }}>{sev}</div>
            </div>
          );
        })}
      </div>

      <div className="dc1-card" style={{ marginBottom: 0 }}>
        <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600 }}>
          <Bug size={15} style={{ marginRight: 6, verticalAlign: -2 }} />
          Vulnerabilities ({filtered.length})
          {sevFilter !== 'all' && (
            <button onClick={() => setSevFilter('all')} style={{ marginLeft: 8, fontSize: 11, background: 'none', border: '1px solid var(--dc1-border)', borderRadius: 4, padding: '2px 8px', cursor: 'pointer' }}>
              Clear filter
            </button>
          )}
        </h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--dc1-border)', textAlign: 'left' }}>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>ID</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Severity</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Source</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Affected Components</th>
              <th style={{ padding: '8px 6px', fontWeight: 600 }}>Description</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((v, i) => {
              const sc = sevColor(v.severity);
              return (
                <tr key={i} style={{ borderBottom: '1px solid var(--dc1-border)' }}>
                  <td style={{ padding: '6px', fontWeight: 600, fontFamily: 'var(--dc1-mono)', fontSize: 12 }}>
                    {v.id.startsWith('CVE') ? (
                      <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer" style={{ color: '#2563eb', textDecoration: 'none' }}>
                        {v.id}
                      </a>
                    ) : v.id}
                  </td>
                  <td style={{ padding: '6px' }}>
                    <span style={{ background: sc.bg, color: sc.text, padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: 'capitalize' }}>
                      {v.severity}
                    </span>
                  </td>
                  <td style={{ padding: '6px', fontSize: 11, color: 'var(--dc1-text-muted)' }}>{v.source || '—'}</td>
                  <td style={{ padding: '6px', fontSize: 11 }}>
                    {v.affects.length > 0 ? v.affects.join(', ') : '—'}
                  </td>
                  <td style={{ padding: '6px', fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {v.description || '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length > 200 && (
          <div style={{ padding: 8, textAlign: 'center', color: 'var(--dc1-text-muted)', fontSize: 12 }}>
            Showing 200 of {filtered.length} vulnerabilities
          </div>
        )}
      </div>
    </>
  );
}

/* ================================================================== */
/*  xBOM Cross-Reference Panel (decoupled)                            */
/* ================================================================== */

function CrossRefPanel({ refs }: { refs: CrossRef[] }) {
  return (
    <>
      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#7c3aed' }}>{refs.length}</div>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>Cross-References</div>
        </div>
        <div className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1d4ed8' }}>{refs.reduce((s, r) => s + r.cryptoRefs.length, 0)}</div>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>Crypto Usages Mapped</div>
        </div>
      </div>

      <div className="dc1-card">
        <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600 }}>
          <Link2 size={15} style={{ marginRight: 6, verticalAlign: -2 }} />
          Software ↔ Crypto Mappings
        </h3>
        <p style={{ fontSize: 12, color: 'var(--dc1-text-muted)', marginBottom: 16 }}>
          These cross-references show which software components use which cryptographic assets — generated by the xBOM merge process.
        </p>
        {refs.map((cr, i) => (
          <div key={i} style={{ marginBottom: 12, padding: 12, borderRadius: 8, background: 'var(--dc1-bg-subtle, #f8fafc)', border: '1px solid var(--dc1-border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Box size={14} style={{ color: '#1d4ed8' }} />
              <span style={{ fontWeight: 600, fontSize: 13 }}>{cr.softwareName}</span>
              {cr.softwareVersion && (
                <span style={{ fontSize: 11, fontFamily: 'var(--dc1-mono)', color: 'var(--dc1-text-muted)' }}>v{cr.softwareVersion}</span>
              )}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, paddingLeft: 22 }}>
              {cr.cryptoRefs.map((c, j) => (
                <span key={j} style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '3px 10px', borderRadius: 6, fontSize: 11, fontWeight: 500,
                  background: '#f0e8ff', color: '#7c3aed', border: '1px solid #e8d5ff',
                }}>
                  <ShieldCheck size={11} />
                  {c.name}
                  {c.algorithm && c.algorithm !== c.name && ` (${c.algorithm})`}
                  {c.relationship && <span style={{ color: '#a78bfa', marginLeft: 2 }}>· {c.relationship}</span>}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
