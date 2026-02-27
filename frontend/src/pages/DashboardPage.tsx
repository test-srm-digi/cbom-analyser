import { useState, useMemo } from 'react';
import {
  Upload,
  ShieldCheck,
  Database,
  ArrowLeft,
  AlertTriangle,
  FileCode2,
  Clock,
  Package,
} from 'lucide-react';
import type { CBOMDocument, QuantumReadinessScore, ComplianceSummary, CryptoAsset } from '../types';
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
import { useGetCbomImportQuery } from '../store/api';
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
  cbomImportId,
  onBack,
}: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');

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
          <div className="dc1-page-header">
            <h1 className="dc1-page-title">CBOM Analyzer</h1>
            <p className="dc1-page-subtitle">Cryptographic inventory overview from your CBOM analysis</p>
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
