interface AssetBreakdownProps {
  quantumSafe: number;
  notQuantumSafe: number;
  conditional: number;
  unknown: number;
  totalAssets: number;
  /** Optional footer line (e.g. "5 unique algorithms · 3 third-party libraries detected") */
  footer?: string;
}

/**
 * Breakdown grid showing quantum-safety distribution.
 * Shared between DashboardPage and CbomDetailPage.
 */
export default function AssetBreakdown({
  quantumSafe,
  notQuantumSafe,
  conditional,
  unknown,
  totalAssets,
  footer,
}: AssetBreakdownProps) {
  const pct = (n: number) => (totalAssets > 0 ? Math.round((n / totalAssets) * 100) : 0);

  return (
    <div className="dc1-card" style={{ marginBottom: 20 }}>
      <h3 className="dc1-card-section-title">Asset Breakdown</h3>
      <div className="dc1-breakdown-grid">
        <div className="dc1-breakdown-item">
          <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-success)' }} />
          <span className="dc1-breakdown-label">Quantum Safe</span>
          <span className="dc1-breakdown-value">{quantumSafe}</span>
          <span className="dc1-breakdown-pct">{pct(quantumSafe)}%</span>
        </div>
        <div className="dc1-breakdown-item">
          <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-danger)' }} />
          <span className="dc1-breakdown-label">Not Quantum Safe</span>
          <span className="dc1-breakdown-value">{notQuantumSafe}</span>
          <span className="dc1-breakdown-pct">{pct(notQuantumSafe)}%</span>
        </div>
        <div className="dc1-breakdown-item">
          <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-warning)' }} />
          <span className="dc1-breakdown-label">Conditional</span>
          <span className="dc1-breakdown-value">{conditional}</span>
          <span className="dc1-breakdown-pct">{pct(conditional)}%</span>
        </div>
        <div className="dc1-breakdown-item">
          <span className="dc1-breakdown-dot" style={{ backgroundColor: 'var(--dc1-text-muted)' }} />
          <span className="dc1-breakdown-label">Unknown</span>
          <span className="dc1-breakdown-value">{unknown}</span>
          <span className="dc1-breakdown-pct">{pct(unknown)}%</span>
        </div>
      </div>
      {footer && <div className="dc1-breakdown-meta">{footer}</div>}
    </div>
  );
}
