import { useMemo } from 'react';
import { ArrowLeft, AlertTriangle, ShieldCheck, Layers, BarChart3, FileCode2, Clock, Package } from 'lucide-react';
import { useGetCbomImportQuery } from '../../store/api';
import { ReadinessScoreCard, QuantumSafetyDonut, ComplianceBanner, AssetListView } from '../../components';
import { CbomStatusBadge, ProgressBar } from './components';
import type { QuantumReadinessScore, ComplianceSummary, CryptoAsset, CBOMDocument } from '../../types';
import s from './CbomDetailPage.module.scss';

/* ── CBOM parsing helpers (mirrors App.tsx logic) ───────────── */

function buildDoc(data: any): CBOMDocument {
  return {
    bomFormat: data.bomFormat || 'CycloneDX',
    specVersion: data.specVersion || '1.7',
    serialNumber: data.serialNumber,
    version: data.version || 1,
    metadata: data.metadata || { timestamp: new Date().toISOString() },
    components: data.components || [],
    cryptoAssets: data.cryptoAssets || [],
    dependencies: data.dependencies,
    thirdPartyLibraries: data.thirdPartyLibraries,
  };
}

function parseCbomContent(jsonText: string): {
  doc: CBOMDocument;
  readinessScore: QuantumReadinessScore;
  compliance: ComplianceSummary;
} {
  let data = JSON.parse(jsonText);

  // Handle wrapped response format
  if (data.success !== undefined && data.cbom) {
    const wrappedScore = data.readinessScore;
    const wrappedCompliance = data.compliance;
    data = data.cbom;
    if (wrappedScore && wrappedCompliance) {
      return { doc: buildDoc(data), readinessScore: wrappedScore, compliance: wrappedCompliance };
    }
  }

  const doc = buildDoc(data);

  // Extract crypto assets from components if cryptoAssets array is empty
  if (doc.cryptoAssets.length === 0 && doc.components.length > 0) {
    for (const comp of doc.components as any[]) {
      const cp = comp.cryptoProperties || comp['crypto-properties'];
      if (cp) {
        doc.cryptoAssets.push({
          id: comp['bom-ref'] || crypto.randomUUID(),
          name: comp.name,
          type: comp.type || 'crypto-asset',
          cryptoProperties: {
            assetType: cp.assetType || cp['asset-type'] || 'algorithm',
            algorithmProperties: cp.algorithmProperties,
          },
          location: comp.evidence?.occurrences?.[0]
            ? { fileName: comp.evidence.occurrences[0].location || '', lineNumber: comp.evidence.occurrences[0].line }
            : undefined,
          quantumSafety: 'unknown' as any,
        });
      }
    }
  }

  const safe = doc.cryptoAssets.filter(a => a.quantumSafety === 'quantum-safe').length;
  const notSafe = doc.cryptoAssets.filter(a => a.quantumSafety === 'not-quantum-safe').length;
  const unknown = doc.cryptoAssets.filter(a => a.quantumSafety === 'unknown').length;
  const total = doc.cryptoAssets.length;

  const readinessScore: QuantumReadinessScore = {
    score: total > 0 ? Math.round(((safe + unknown * 0.5) / total) * 100) : 100,
    totalAssets: total,
    quantumSafe: safe,
    notQuantumSafe: notSafe,
    conditional: 0,
    unknown,
  };

  const compliance: ComplianceSummary = {
    isCompliant: notSafe === 0,
    policy: 'NIST Post-Quantum Cryptography',
    source: 'CBOM Import Analysis',
    totalAssets: total,
    compliantAssets: safe,
    nonCompliantAssets: notSafe,
    unknownAssets: unknown,
  };

  return { doc, readinessScore, compliance };
}

/* ── Props ──────────────────────────────────────────────────── */

interface Props {
  cbomImportId: string;
  onBack: () => void;
}

/* ── Component ──────────────────────────────────────────────── */

export default function CbomDetailPage({ cbomImportId, onBack }: Props) {
  const { data: cbomImport, isLoading, isError } = useGetCbomImportQuery(cbomImportId);

  const { assets, readinessScore, compliance, cbomDoc } = useMemo(() => {
    if (!cbomImport) return { assets: [] as CryptoAsset[], readinessScore: null, compliance: null, cbomDoc: null };

    // If we have the artifact file stored, decode and parse it
    if (cbomImport.cbomFile) {
      try {
        // Decode base64 → string (supports JSON files; ZIP handling can be added later)
        const raw = atob(cbomImport.cbomFile);
        const { doc, readinessScore: score, compliance: comp } = parseCbomContent(raw);
        return { assets: doc.cryptoAssets, readinessScore: score, compliance: comp, cbomDoc: doc };
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
      assets: [] as CryptoAsset[],
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
            {cbomImport.cryptoComponents} crypto components
          </span>
          <span className={s.metaItem}>
            <Clock size={14} />
            Imported {formatDate(cbomImport.importDate)}
          </span>
        </div>

        <div className={s.pqcBar}>
          <span className={s.pqcLabel}>PQC Readiness</span>
          <ProgressBar value={cbomImport.quantumSafeComponents} max={cbomImport.cryptoComponents} />
          <span className={s.pqcFraction}>
            {cbomImport.quantumSafeComponents} / {cbomImport.cryptoComponents} quantum-safe
          </span>
        </div>
      </div>

      {/* ── Compliance Banner ───────────────────────── */}
      <div style={{ marginBottom: 16 }}>
        <ComplianceBanner compliance={compliance} />
      </div>

      {/* ── Stats Row ───────────────────────────────── */}
      <div className="dc1-stats-row">
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-blue"><Layers size={20} /></div>
          <div>
            <span className="dc1-stat-card-number">{assets.length}</span>
            <span className="dc1-stat-card-label">Crypto Assets</span>
          </div>
        </div>
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-green"><ShieldCheck size={20} /></div>
          <div>
            <span className="dc1-stat-card-number dc1-text-success">{cbomImport.quantumSafeComponents}</span>
            <span className="dc1-stat-card-label">Quantum Safe</span>
          </div>
        </div>
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-red"><AlertTriangle size={20} /></div>
          <div>
            <span className="dc1-stat-card-number dc1-text-danger">{cbomImport.nonQuantumSafeComponents}</span>
            <span className="dc1-stat-card-label">Not Quantum Safe</span>
          </div>
        </div>
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-amber"><BarChart3 size={20} /></div>
          <div>
            <span className="dc1-stat-card-number dc1-text-warning">{policyViolations}</span>
            <span className="dc1-stat-card-label">Policy Violations</span>
          </div>
        </div>
      </div>

      {/* ── Charts Row ──────────────────────────────── */}
      <div className="dc1-two-col">
        <div className="dc1-card dc1-card-flush">
          <ReadinessScoreCard score={readinessScore} />
        </div>
        <div className="dc1-card dc1-card-flush">
          <QuantumSafetyDonut assets={assets} />
        </div>
      </div>

      {/* ── Asset Breakdown ─────────────────────────── */}
      <div className="dc1-card" style={{ marginBottom: 20 }}>
        <h3 className="dc1-card-section-title">Asset Breakdown</h3>
        <div className="dc1-breakdown-grid">
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-success)' }} />
            <span className="dc1-breakdown-label">Quantum Safe</span>
            <span className="dc1-breakdown-value">{cbomImport.quantumSafeComponents}</span>
            <span className="dc1-breakdown-pct">
              {cbomImport.cryptoComponents > 0 ? Math.round((cbomImport.quantumSafeComponents / cbomImport.cryptoComponents) * 100) : 0}%
            </span>
          </div>
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-danger)' }} />
            <span className="dc1-breakdown-label">Not Quantum Safe</span>
            <span className="dc1-breakdown-value">{cbomImport.nonQuantumSafeComponents}</span>
            <span className="dc1-breakdown-pct">
              {cbomImport.cryptoComponents > 0 ? Math.round((cbomImport.nonQuantumSafeComponents / cbomImport.cryptoComponents) * 100) : 0}%
            </span>
          </div>
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-text-muted)' }} />
            <span className="dc1-breakdown-label">Unknown</span>
            <span className="dc1-breakdown-value">
              {cbomImport.cryptoComponents - cbomImport.quantumSafeComponents - cbomImport.nonQuantumSafeComponents}
            </span>
            <span className="dc1-breakdown-pct">
              {cbomImport.cryptoComponents > 0
                ? Math.round(((cbomImport.cryptoComponents - cbomImport.quantumSafeComponents - cbomImport.nonQuantumSafeComponents) / cbomImport.cryptoComponents) * 100)
                : 0}%
            </span>
          </div>
        </div>
      </div>

      {/* ── Inventory ───────────────────────────────── */}
      <div className="dc1-card" style={{ marginTop: 0 }}>
        <AssetListView assets={assets} />
      </div>
    </div>
  );
}
