import { useState, useMemo } from 'react';
import { ArrowLeft, AlertTriangle, ShieldCheck, FileCode2, Clock, Package, Box, Link2, Bug, Download } from 'lucide-react';
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
import {
  SoftwarePanel,
  VulnerabilityPanel,
  CrossRefPanel,
  BomDownloadButtons,
} from '../../components/bom-panels';
import { CbomStatusBadge, ProgressBar } from './components';
import { parseCbomJson } from '../../utils/cbomParser';
import type { QuantumReadinessScore, ComplianceSummary, CryptoAsset, CBOMDocument, SBOMComponent, SBOMVulnerability, XBOMCrossReference } from '../../types';
import s from './CbomDetailPage.module.scss';

/* ── Props ──────────────────────────────────────────────────── */

interface Props {
  cbomImportId: string;
  onBack: () => void;
}

/* ── Component ──────────────────────────────────────────────── */

type DetailTab = 'overview' | 'inventory' | 'sbom' | 'vulnerabilities' | 'xbom-crossrefs';

export default function CbomDetailPage({ cbomImportId, onBack }: Props) {
  const { data: cbomImport, isLoading, isError } = useGetCbomImportQuery(cbomImportId);
  const [activeTab, setActiveTab] = useState<DetailTab>('overview');

  const { assets, readinessScore, compliance, cbomDoc, softwareComponents, vulnerabilities, crossReferences, rawJson } = useMemo(() => {
    const empty = {
      assets: [] as CryptoAsset[],
      readinessScore: null as QuantumReadinessScore | null,
      compliance: null as ComplianceSummary | null,
      cbomDoc: null as CBOMDocument | null,
      softwareComponents: [] as SBOMComponent[],
      vulnerabilities: [] as SBOMVulnerability[],
      crossReferences: [] as XBOMCrossReference[],
      rawJson: null as any,
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
        const swComps: SBOMComponent[] = allComps
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
            'bom-ref': c['bom-ref'],
            licenses: c.licenses,
          }));

        // Extract vulnerabilities
        const vulns: SBOMVulnerability[] = (rawJson.vulnerabilities || []).map((v: any) => ({
          id: v.id || 'unknown',
          source: v.source,
          ratings: v.ratings,
          description: v.description || '',
          recommendation: v.recommendation,
          affects: v.affects,
        }));

        // Extract xBOM cross-references
        const xrefs: XBOMCrossReference[] = (rawJson.crossReferences || []).map((cr: any) => ({
          softwareRef: cr.softwareRef || '',
          cryptoRefs: Array.isArray(cr.cryptoRefs) ? cr.cryptoRefs.map((r: any) => typeof r === 'string' ? r : r.ref || r.name || '') : [],
          linkMethod: cr.linkMethod || 'unknown',
        }));

        return {
          assets: doc.cryptoAssets,
          readinessScore: score,
          compliance: comp,
          cbomDoc: doc,
          softwareComponents: swComps,
          vulnerabilities: vulns,
          crossReferences: xrefs,
          rawJson,
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
          <ArrowLeft size={16} /> Back to BOM Imports
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
<ArrowLeft size={16} /> Back to BOM Imports
      </button>

      {/* ── Header ──────────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerTop}>
          <div>
            <p className={s.breadcrumb}>Discovery / BOM Imports</p>
            <h1 className={s.title}>{cbomImport.applicationName ?? cbomImport.fileName}</h1>
            <p className={s.subtitle}>{cbomImport.fileName}</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BomDownloadButtons
              compact
              items={[
                { label: 'CBOM', filename: `${cbomImport.applicationName || 'cbom'}-cbom.json`, data: rawJson },
                { label: 'SBOM', filename: `${cbomImport.applicationName || 'sbom'}-sbom.json`, data: softwareComponents.length ? { bomFormat: 'CycloneDX', components: softwareComponents } : null },
                { label: 'xBOM', filename: `${cbomImport.applicationName || 'xbom'}-xbom.json`, data: crossReferences.length ? { crossReferences } : null },
              ]}
            />
            <CbomStatusBadge status={cbomImport.status} />
          </div>
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
              background: vulnerabilities.some(v => (v.ratings?.[0]?.severity ?? '').toLowerCase() === 'critical') ? '#fee2e2' : '#fef3c7',
              color: vulnerabilities.some(v => (v.ratings?.[0]?.severity ?? '').toLowerCase() === 'critical') ? '#dc2626' : '#d97706',
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

      {/* ── SBOM: Software components (shared panel) ───────────────── */}
      {activeTab === 'sbom' && softwareComponents.length > 0 && (
        <SoftwarePanel components={softwareComponents} />
      )}

      {/* ── Vulnerabilities (shared panel) ─────────────────────────── */}
      {activeTab === 'vulnerabilities' && vulnerabilities.length > 0 && (
        <VulnerabilityPanel vulns={vulnerabilities} />
      )}

      {/* ── xBOM Cross-References (shared panel) ───────────────────── */}
      {activeTab === 'xbom-crossrefs' && crossReferences.length > 0 && (
        <CrossRefPanel refs={crossReferences} components={softwareComponents} cryptoAssets={assets} />
      )}
    </div>
  );
}


