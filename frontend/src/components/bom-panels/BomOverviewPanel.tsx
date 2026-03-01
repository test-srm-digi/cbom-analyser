/**
 * BomOverviewPanel — Shared overview stats for xBOM/CBOM detail pages
 * Shows summary cards, quantum readiness, and vulnerability summary
 */
import type { XBOMAnalytics, XBOMDocument, CryptoAsset } from '../../types';
import VulnSummaryGrid from './VulnSummaryGrid';

interface Props {
  xbom?: XBOMDocument;
  analytics?: XBOMAnalytics;
  /** For CBOM-only views where there's no full XBOMDocument */
  softwareCount?: number;
  cryptoCount?: number;
  vulnCount?: number;
  crossRefCount?: number;
  quantumSafe?: number;
  notQuantumSafe?: number;
  conditional?: number;
  readinessScore?: number;
}

export default function BomOverviewPanel(props: Props) {
  const { xbom, analytics } = props;

  const sw = props.softwareCount ?? analytics?.totalSoftwareComponents ?? xbom?.components?.length ?? 0;
  const crypto = props.cryptoCount ?? analytics?.totalCryptoAssets ?? xbom?.cryptoAssets?.length ?? 0;
  const vulns = props.vulnCount ?? analytics?.vulnerabilitySummary?.total ?? xbom?.vulnerabilities?.length ?? 0;
  const xrefs = props.crossRefCount ?? analytics?.totalCrossReferences ?? xbom?.crossReferences?.length ?? 0;

  const score = props.readinessScore ?? analytics?.quantumReadiness?.score;
  const qSafe = props.quantumSafe ?? analytics?.quantumReadiness?.quantumSafe ?? 0;
  const notSafe = props.notQuantumSafe ?? analytics?.quantumReadiness?.notQuantumSafe ?? 0;
  const cond = props.conditional ?? analytics?.quantumReadiness?.conditional ?? 0;

  return (
    <>
      {/* Overview stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, marginBottom: 16 }}>
        <StatCard label="Software Components" value={sw} />
        <StatCard label="Crypto Assets" value={crypto} />
        <StatCard label="Vulnerabilities" value={vulns} />
        <StatCard label="Cross-References" value={xrefs} />
      </div>

      {/* Quantum Readiness */}
      {(score !== undefined || crypto > 0) && (
        <div className="dc1-card" style={{ marginTop: 16 }}>
          <h3 className="dc1-card-section-title">Quantum Readiness</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
            <StatCard label="Readiness Score" value={score ?? '—'} />
            <BadgeCard label="Quantum Safe" value={qSafe} color="#16a34a" bg="#dcfce7" />
            <BadgeCard label="Not Quantum Safe" value={notSafe} color="#dc2626" bg="#fee2e2" />
            <BadgeCard label="Conditional" value={cond} color="#d97706" bg="#fef3c7" />
          </div>
        </div>
      )}

      {/* Vulnerability summary */}
      {analytics?.vulnerabilitySummary && analytics.vulnerabilitySummary.total > 0 && (
        <div className="dc1-card" style={{ marginTop: 16 }}>
          <h3 className="dc1-card-section-title">Vulnerability Summary</h3>
          <VulnSummaryGrid vuln={analytics.vulnerabilitySummary} />
        </div>
      )}
    </>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="dc1-card" style={{ padding: 16, textAlign: 'center', border: '1px solid var(--dc1-border)' }}>
      <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

function BadgeCard({ label, value, color, bg }: { label: string; value: number; color: string; bg: string }) {
  return (
    <div className="dc1-card" style={{ padding: 16, textAlign: 'center', border: '1px solid var(--dc1-border)' }}>
      <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>{label}</div>
      <span style={{ display: 'inline-block', fontSize: 18, fontWeight: 700, padding: '2px 12px', borderRadius: 8, background: bg, color }}>{value}</span>
    </div>
  );
}
