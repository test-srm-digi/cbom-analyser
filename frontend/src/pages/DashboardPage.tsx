import {
  Upload,
  AlertTriangle,
  FileText,
  ShieldCheck,
  BarChart3,
  Layers,
  Database,
} from 'lucide-react';
import type { CBOMDocument, QuantumReadinessScore, ComplianceSummary } from '../types';
import { CBOMHeader, ReadinessScoreCard, QuantumSafetyDonut, ComplianceBanner } from '../components';

interface Props {
  cbom: CBOMDocument | null;
  readinessScore: QuantumReadinessScore | null;
  compliance: ComplianceSummary | null;
  onNavigate: (path: string) => void;
  onUpload: () => void;
  onLoadSample: () => void;
}

export default function DashboardPage({ cbom, readinessScore, compliance, onNavigate, onUpload, onLoadSample }: Props) {
  const assets = cbom?.cryptoAssets ?? [];
  const totalAssets = assets.length;
  const safe = assets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const notSafe = assets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
  const conditional = assets.filter((a) => a.quantumSafety === 'conditional').length;
  const unknown = assets.filter((a) => a.quantumSafety === 'unknown').length;
  const policyViolations = compliance ? compliance.nonCompliantAssets : notSafe;
  const uniqueAlgos = new Set(assets.map((a) => a.name)).size;
  const libCount = cbom?.thirdPartyLibraries?.length ?? 0;

  if (!cbom) {
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
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Quantum Readiness Dashboard</h1>
        <p className="dc1-page-subtitle">Cryptographic inventory overview from your CBOM analysis</p>
      </div>

      <div className="dc1-card" style={{ marginBottom: 16 }}>
        <CBOMHeader cbom={cbom} />
      </div>

      <div style={{ marginBottom: 16 }}>
        <ComplianceBanner compliance={compliance} />
      </div>

      <div className="dc1-stats-row">
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-blue"><Layers size={20} /></div>
          <div>
            <span className="dc1-stat-card-number">{totalAssets}</span>
            <span className="dc1-stat-card-label">Total Crypto Assets</span>
          </div>
        </div>
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-green"><ShieldCheck size={20} /></div>
          <div>
            <span className="dc1-stat-card-number dc1-text-success">{safe}</span>
            <span className="dc1-stat-card-label">Quantum Safe</span>
          </div>
        </div>
        <div className="dc1-stat-card">
          <div className="dc1-stat-card-icon dc1-stat-icon-red"><AlertTriangle size={20} /></div>
          <div>
            <span className="dc1-stat-card-number dc1-text-danger">{notSafe}</span>
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

      <div className="dc1-two-col">
        <div className="dc1-card dc1-card-flush">
          <ReadinessScoreCard score={readinessScore} />
        </div>
        <div className="dc1-card dc1-card-flush">
          <QuantumSafetyDonut assets={assets} />
        </div>
      </div>

      <div className="dc1-card" style={{ marginBottom: 20 }}>
        <h3 className="dc1-card-section-title">Asset Breakdown</h3>
        <div className="dc1-breakdown-grid">
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-success)' }} />
            <span className="dc1-breakdown-label">Quantum Safe</span>
            <span className="dc1-breakdown-value">{safe}</span>
            <span className="dc1-breakdown-pct">{totalAssets > 0 ? Math.round((safe / totalAssets) * 100) : 0}%</span>
          </div>
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-danger)' }} />
            <span className="dc1-breakdown-label">Not Quantum Safe</span>
            <span className="dc1-breakdown-value">{notSafe}</span>
            <span className="dc1-breakdown-pct">{totalAssets > 0 ? Math.round((notSafe / totalAssets) * 100) : 0}%</span>
          </div>
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-warning)' }} />
            <span className="dc1-breakdown-label">Conditional</span>
            <span className="dc1-breakdown-value">{conditional}</span>
            <span className="dc1-breakdown-pct">{totalAssets > 0 ? Math.round((conditional / totalAssets) * 100) : 0}%</span>
          </div>
          <div className="dc1-breakdown-item">
            <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-text-muted)' }} />
            <span className="dc1-breakdown-label">Unknown</span>
            <span className="dc1-breakdown-value">{unknown}</span>
            <span className="dc1-breakdown-pct">{totalAssets > 0 ? Math.round((unknown / totalAssets) * 100) : 0}%</span>
          </div>
        </div>
        <div className="dc1-breakdown-meta">
          {uniqueAlgos} unique algorithms &middot; {libCount} third-party libraries detected
        </div>
      </div>

      <h2 className="dc1-section-heading">Quick Actions</h2>
      <div className="dc1-quick-actions">
        <div className="dc1-action-card" onClick={onUpload}>
          <Upload size={28} className="dc1-action-icon" />
          <div><h4>Upload CBOM</h4><p>Import cryptographic inventory</p></div>
        </div>
        <div className="dc1-action-card" onClick={() => onNavigate('violations')}>
          <AlertTriangle size={28} className="dc1-action-icon" />
          <div><h4>Review Violations</h4><p>{policyViolations} items need attention</p></div>
        </div>
        <div className="dc1-action-card" onClick={() => onNavigate('visualize')}>
          <BarChart3 size={28} className="dc1-action-icon" />
          <div><h4>Visualize Assets</h4><p>Charts &amp; distributions</p></div>
        </div>
        <div className="dc1-action-card" onClick={() => onNavigate('inventory')}>
          <FileText size={28} className="dc1-action-icon" />
          <div><h4>Full Inventory</h4><p>Browse all {totalAssets} assets</p></div>
        </div>
      </div>
    </div>
  );
}
