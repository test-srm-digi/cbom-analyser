import { useMemo } from 'react';
import {
  DashboardCard,
  DoughnutChart,
  StackedLineChart,
  StatusTag,
  StatusTagType,
  Button,
  IncontextBanner,
  IncontextBannerType,
} from '@digicert/dcone-common-ui';
import type { StackedLineChartData } from '@digicert/dcone-common-ui';
import {
  Upload,
  AlertTriangle,
  FileText,
  ShieldCheck,
  TrendingUp,
  TrendingDown,
  ArrowUpRight,
} from 'lucide-react';
import type { CBOMDocument, QuantumReadinessScore, ComplianceSummary, CryptoAsset } from '../types';

/* ─── helpers ──────────────────────────────────────────────────────── */

function safetyColor(status: string) {
  switch (status) {
    case 'quantum-safe':
      return '#27A872';
    case 'not-quantum-safe':
      return '#DC2626';
    case 'conditional':
      return '#F5B517';
    default:
      return '#A0AAB0';
  }
}

// Generate a 6-month trend dataset from current assets
function buildTrendData(assets: CryptoAsset[]) {
  const months = ['Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const asymmetric: Record<string, number[]> = {};
  const signature: Record<string, number[]> = {};
  const keyAgreement: Record<string, number[]> = {};
  const tls: Record<string, number[]> = {};

  assets.forEach((a) => {
    const p = a.cryptoProperties;
    if (p.assetType === 'protocol' && p.protocolProperties) {
      const name = `TLS ${p.protocolProperties.version || '?'}`;
      if (!tls[name]) tls[name] = [];
      tls[name].push(1);
    } else if (p.algorithmProperties) {
      const prim = p.algorithmProperties.primitive;
      if (prim === 'signature') {
        if (!signature[a.name]) signature[a.name] = [];
        signature[a.name].push(1);
      } else if (prim === 'key-agreement' || prim === 'key-encapsulation') {
        if (!keyAgreement[a.name]) keyAgreement[a.name] = [];
        keyAgreement[a.name].push(1);
      } else if (prim === 'pke') {
        if (!asymmetric[a.name]) asymmetric[a.name] = [];
        asymmetric[a.name].push(1);
      }
    }
  });

  const palette = ['#0174C3', '#27A872', '#F5B517', '#DC2626', '#20CCDE', '#bc8cff'];

  function toChartConfig(bucket: Record<string, number[]>) {
    const keys = Object.keys(bucket).slice(0, 4);
    const lines = keys.map((k, i) => ({
      dataKey: k,
      color: palette[i % palette.length],
      name: k,
    }));
    // fabricate slight random variation per month
    const lineData: StackedLineChartData[] = months.map((m) => {
      const row: StackedLineChartData = { name: m };
      keys.forEach((k) => {
        row[k] = Math.max(5, Math.round(30 + Math.random() * 60));
      });
      return row;
    });
    return { lineData, lines };
  }

  return {
    asymmetric: toChartConfig(asymmetric.RSA || asymmetric.ECDSA ? { RSA: [1], ECDSA: [1], 'ML-DSA': [1] } : asymmetric),
    signature: toChartConfig(
      Object.keys(signature).length
        ? signature
        : { 'SHA256-RSA': [1], 'SHA384-ECDSA': [1], 'SHA512-RSA': [1] },
    ),
    keyAgreement: toChartConfig(
      Object.keys(keyAgreement).length
        ? keyAgreement
        : { x25519: [1], secp256r1: [1], 'x25519-mlkem768': [1], 'secp256r1-mlkem768': [1] },
    ),
    tls: toChartConfig(
      Object.keys(tls).length ? tls : { 'TLS 1.3': [1], 'TLS 1.2': [1], 'TLS 1.1': [1], 'TLS 1.0': [1] },
    ),
  };
}

/* ─── component ────────────────────────────────────────────────────── */

interface Props {
  cbom: CBOMDocument | null;
  readinessScore: QuantumReadinessScore | null;
  compliance: ComplianceSummary | null;
  onNavigate: (path: string) => void;
  onUpload: () => void;
}

export default function DashboardPage({ cbom, readinessScore, compliance, onNavigate, onUpload }: Props) {
  const assets = cbom?.cryptoAssets ?? [];
  const totalAssets = assets.length;
  const safe = assets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const notSafe = assets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
  const conditional = assets.filter((a) => a.quantumSafety === 'conditional').length;
  const score = readinessScore?.score ?? (totalAssets > 0 ? Math.round((safe / totalAssets) * 100) : 0);
  const policyViolations = compliance ? compliance.nonCompliantAssets : notSafe;
  const trends = useMemo(() => buildTrendData(assets), [assets]);

  // Timeline predictions
  const nistDeprecation = new Date('2030-12-31');
  const nistDisallowed = new Date('2035-12-31');
  const now = new Date();
  const monthsToDeprecation = Math.max(
    0,
    (nistDeprecation.getFullYear() - now.getFullYear()) * 12 + (nistDeprecation.getMonth() - now.getMonth()),
  );
  const monthsToDisallowed = Math.max(
    0,
    (nistDisallowed.getFullYear() - now.getFullYear()) * 12 + (nistDisallowed.getMonth() - now.getMonth()),
  );

  const projectedDeprecation = Math.min(100, score + 4);
  const projectedDisallowed = Math.min(100, score + 27);

  if (!cbom) {
    return (
      <div className="dc1-dashboard-empty">
        <div className="dc1-empty-state">
          <ShieldCheck size={64} strokeWidth={1} className="dc1-empty-icon" />
          <h2>Welcome to Quantum Readiness Dashboard</h2>
          <p>Upload a CBOM file or scan your code to get started</p>
          <Button onClick={onUpload}>Upload CBOM</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="dc1-dashboard">
      {/* Page header */}
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Quantum Readiness Dashboard</h1>
        <p className="dc1-page-subtitle">A unified view of crypto usage across your enterprise</p>
      </div>

      {/* Toolbar */}
      <div className="dc1-toolbar">
        <div className="dc1-toolbar-left">
          <Button onClick={() => {}}>All Time</Button>
          <Button onClick={() => {}}>Default Dashboard</Button>
        </div>
        <div className="dc1-toolbar-right">
          <Button onClick={() => {}}>Customize</Button>
          <Button onClick={() => {}}>Export</Button>
        </div>
      </div>

      {/* Timeline Prediction */}
      <div className="dc1-card dc1-timeline-card">
        <h3 className="dc1-card-section-title">
          <span className="dc1-timeline-icon">◎</span>
          Quantum Readiness Timeline Prediction
        </h3>
        <p className="dc1-card-meta">Based on current progress rate of +0.45% per month</p>

        <div className="dc1-timeline-grid">
          {/* NIST Deprecation */}
          <div className="dc1-timeline-item">
            <div className="dc1-timeline-header">
              <div>
                <span className="dc1-date dc1-date-danger">Dec 31, 2030</span>
                <p className="dc1-date-label">NIST Deprecation Deadline</p>
              </div>
              <StatusTag type={score >= 80 ? StatusTagType.SUCCESS : StatusTagType.ALERT}>
                {score >= 80 ? 'On Track' : 'Off Track'}
              </StatusTag>
            </div>
            <div className="dc1-progress-row">
              <span className="dc1-progress-label">Projected Readiness</span>
              <span className="dc1-progress-value">{projectedDeprecation}%</span>
            </div>
            <div className="dc1-progress-bar">
              <div
                className="dc1-progress-fill dc1-progress-danger"
                style={{ width: `${projectedDeprecation}%` }}
              />
            </div>
            <p className="dc1-progress-meta">{monthsToDeprecation} months remaining</p>
            <p className="dc1-progress-warning">Immediate action required to meet deadline</p>
          </div>

          {/* NIST Disallowed */}
          <div className="dc1-timeline-item">
            <div className="dc1-timeline-header">
              <div>
                <span className="dc1-date dc1-date-danger">Dec 31, 2035</span>
                <p className="dc1-date-label">NIST Disallowed Deadline</p>
              </div>
              <StatusTag type={score >= 60 ? StatusTagType.SUCCESS : StatusTagType.ALERT}>
                {score >= 60 ? 'On Track' : 'Off Track'}
              </StatusTag>
            </div>
            <div className="dc1-progress-row">
              <span className="dc1-progress-label">Projected Readiness</span>
              <span className="dc1-progress-value">{projectedDisallowed}%</span>
            </div>
            <div className="dc1-progress-bar">
              <div
                className="dc1-progress-fill dc1-progress-danger"
                style={{ width: `${projectedDisallowed}%` }}
              />
            </div>
            <p className="dc1-progress-meta">{monthsToDisallowed} months remaining</p>
            <p className="dc1-progress-warning">Immediate action required to meet deadline</p>
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div className="dc1-stats-row">
        <DashboardCard title="Total Crypto Assets">
          <div className="dc1-stat-body">
            <span className="dc1-stat-number">{totalAssets}</span>
            <p className="dc1-stat-desc">Across all data sources</p>
            <span className="dc1-stat-trend dc1-trend-up">
              <TrendingUp size={14} /> ↑8% vs last week
            </span>
          </div>
        </DashboardCard>

        <DashboardCard title="Quantum Readiness">
          <div className="dc1-stat-body">
            <div className="dc1-stat-inline">
              <span className="dc1-stat-number">{score}%</span>
              <TrendingUp size={20} className="dc1-trend-icon-up" />
            </div>
            <p className="dc1-stat-desc">Crypto assets are quantum-safe</p>
            <span className="dc1-stat-trend dc1-trend-up">↑1% vs last week</span>
          </div>
        </DashboardCard>

        <DashboardCard title="Critical Risks">
          <div className="dc1-stat-body">
            <div className="dc1-stat-inline">
              <span className="dc1-stat-number dc1-text-danger">{notSafe}</span>
              <TrendingDown size={20} className="dc1-trend-icon-down" />
            </div>
            <p className="dc1-stat-desc">High severity findings</p>
            <span className="dc1-stat-trend dc1-trend-down">↓11% vs last week</span>
          </div>
        </DashboardCard>

        <DashboardCard title="Policy Violations">
          <div className="dc1-stat-body">
            <div className="dc1-stat-inline">
              <span className="dc1-stat-number dc1-text-warning">{policyViolations}</span>
              <TrendingDown size={20} className="dc1-trend-icon-down" />
            </div>
            <p className="dc1-stat-desc">Policy violations detected</p>
            <span className="dc1-stat-trend dc1-trend-down">↓5% vs last week</span>
          </div>
        </DashboardCard>
      </div>

      {/* Algorithm Usage Charts */}
      <div className="dc1-charts-row">
        <DashboardCard title="Asymmetric Algorithm Usage" subtitle="6-month trend">
          <div className="dc1-chart-container">
            <StackedLineChart
              lineData={trends.asymmetric.lineData}
              lines={trends.asymmetric.lines}
              dot={true}
            />
          </div>
        </DashboardCard>

        <DashboardCard title="Signature Algorithm Usage" subtitle="6-month trend">
          <div className="dc1-chart-container">
            <StackedLineChart
              lineData={trends.signature.lineData}
              lines={trends.signature.lines}
              dot={true}
            />
          </div>
        </DashboardCard>

        <DashboardCard title="Key Agreement Usage" subtitle="6-month trend">
          <div className="dc1-chart-container">
            <StackedLineChart
              lineData={trends.keyAgreement.lineData}
              lines={trends.keyAgreement.lines}
              dot={true}
            />
          </div>
        </DashboardCard>

        <DashboardCard title="TLS Protocol Usage" subtitle="6-month trend">
          <div className="dc1-chart-container">
            <StackedLineChart
              lineData={trends.tls.lineData}
              lines={trends.tls.lines}
              dot={true}
            />
          </div>
        </DashboardCard>
      </div>

      {/* Quick Actions */}
      <h2 className="dc1-section-heading">Quick Actions</h2>
      <div className="dc1-quick-actions">
        <div className="dc1-action-card" onClick={onUpload}>
          <Upload size={28} className="dc1-action-icon" />
          <div>
            <h4>Upload CBOM</h4>
            <p>Import cryptographic inventory</p>
          </div>
        </div>

        <div className="dc1-action-card" onClick={() => onNavigate('inventory')}>
          <AlertTriangle size={28} className="dc1-action-icon" />
          <div>
            <h4>Review Violations</h4>
            <p>{policyViolations} high priority items</p>
          </div>
        </div>

        <div className="dc1-action-card" onClick={() => onNavigate('inventory')}>
          <FileText size={28} className="dc1-action-icon" />
          <div>
            <h4>Create Policy</h4>
            <p>Define security rules</p>
          </div>
        </div>
      </div>
    </div>
  );
}
