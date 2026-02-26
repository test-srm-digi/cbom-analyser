import { useMemo } from 'react';
import { ShieldAlert } from 'lucide-react';
import type { CBOMDocument } from '../types';
import { AssetListView } from '../components';

interface Props {
  cbom: CBOMDocument | null;
}

export default function ViolationsPage({ cbom }: Props) {
  const allAssets = cbom?.cryptoAssets ?? [];

  const violatingAssets = useMemo(
    () => allAssets.filter((a) => a.quantumSafety === 'not-quantum-safe'),
    [allAssets],
  );

  const conditionalAssets = useMemo(
    () => allAssets.filter((a) => a.quantumSafety === 'conditional'),
    [allAssets],
  );

  const atRiskAssets = useMemo(
    () => [...violatingAssets, ...conditionalAssets],
    [violatingAssets, conditionalAssets],
  );

  return (
    <div>
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Violations</h1>
        <p className="dc1-page-subtitle">
          Cryptographic assets that do not meet quantum-safety requirements
        </p>
      </div>

      <div className="dc1-inv-summary" style={{ marginBottom: 20 }}>
        <div className="dc1-inv-card dc1-inv-card-violations">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Not Quantum Safe</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-danger">{violatingAssets.length}</span>
          <span className="dc1-inv-card-desc">Require immediate migration</span>
        </div>

        <div className="dc1-inv-card" style={{ borderLeft: '4px solid var(--dc1-warning)' }}>
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Conditional</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-warning">{conditionalAssets.length}</span>
          <span className="dc1-inv-card-desc">Require parameter review</span>
        </div>

        <div className="dc1-inv-card dc1-inv-card-primary">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Total At Risk</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-primary">{atRiskAssets.length}</span>
          <span className="dc1-inv-card-desc">Out of {allAssets.length} total assets</span>
        </div>
      </div>

      {atRiskAssets.length === 0 ? (
        <div className="dc1-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <ShieldAlert size={48} style={{ color: 'var(--dc1-success)', margin: '0 auto 12px' }} />
          <h3 style={{ margin: '0 0 4px', fontSize: 16, fontWeight: 600 }}>No Violations Found</h3>
          <p style={{ margin: 0, fontSize: 13, color: 'var(--dc1-text-secondary)' }}>
            All cryptographic assets in your CBOM are quantum-safe.
          </p>
        </div>
      ) : (
        <AssetListView assets={atRiskAssets} />
      )}
    </div>
  );
}
