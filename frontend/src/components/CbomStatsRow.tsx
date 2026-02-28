import {
  Layers,
  ShieldCheck,
  AlertTriangle,
  BarChart3,
} from 'lucide-react';

interface CbomStatsRowProps {
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  policyViolations: number;
  /** Optional callback — navigates to the Policies page when clicking the violations card */
  onViewPolicies?: () => void;
}

/**
 * Four-card stats row shared between DashboardPage and CbomDetailPage.
 */
export default function CbomStatsRow({
  totalAssets,
  quantumSafe,
  notQuantumSafe,
  policyViolations,
  onViewPolicies,
}: CbomStatsRowProps) {
  return (
    <div className="dc1-stats-row">
      <div className="dc1-stat-card">
        <div className="dc1-stat-card-icon dc1-stat-icon-blue"><Layers size={20} /></div>
        <div>
          <span className="dc1-stat-card-number">{totalAssets}</span>
          <span className="dc1-stat-card-label">Crypto Assets</span>
        </div>
      </div>
      <div className="dc1-stat-card">
        <div className="dc1-stat-card-icon dc1-stat-icon-green"><ShieldCheck size={20} /></div>
        <div>
          <span className="dc1-stat-card-number dc1-text-success">{quantumSafe}</span>
          <span className="dc1-stat-card-label">Quantum Safe</span>
        </div>
      </div>
      <div className="dc1-stat-card">
        <div className="dc1-stat-card-icon dc1-stat-icon-red"><AlertTriangle size={20} /></div>
        <div>
          <span className="dc1-stat-card-number dc1-text-danger">{notQuantumSafe}</span>
          <span className="dc1-stat-card-label">Not Quantum Safe</span>
        </div>
      </div>
      <div
        className="dc1-stat-card"
        style={onViewPolicies ? { cursor: 'pointer' } : undefined}
        onClick={onViewPolicies}
        title={onViewPolicies ? 'View Policies' : undefined}
      >
        <div className="dc1-stat-card-icon dc1-stat-icon-amber"><BarChart3 size={20} /></div>
        <div>
          <span className="dc1-stat-card-number dc1-text-warning">{policyViolations}</span>
          <span className="dc1-stat-card-label">Policy Violations</span>
        </div>
      </div>
    </div>
  );
}
