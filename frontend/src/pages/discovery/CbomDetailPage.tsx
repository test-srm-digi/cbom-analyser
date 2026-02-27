import { useState, useMemo } from 'react';
import { ArrowLeft, AlertTriangle, ShieldCheck, FileCode2, Clock, Package } from 'lucide-react';
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

export default function CbomDetailPage({ cbomImportId, onBack }: Props) {
  const { data: cbomImport, isLoading, isError } = useGetCbomImportQuery(cbomImportId);
  const [activeTab, setActiveTab] = useState<'overview' | 'inventory'>('overview');

  const { assets, readinessScore, compliance, cbomDoc } = useMemo(() => {
    if (!cbomImport) return { assets: [] as CryptoAsset[], readinessScore: null, compliance: null, cbomDoc: null };

    // If we have the artifact file stored, decode and parse it
    if (cbomImport.cbomFile) {
      try {
        const raw = atob(cbomImport.cbomFile);
        const { doc, readinessScore: score, compliance: comp } = parseCbomJson(raw, 'CBOM Import Analysis');
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
    </div>
  );
}
