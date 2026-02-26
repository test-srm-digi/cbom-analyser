import type { CBOMDocument } from '../types';
import { CryptoBubbleChart, PrimitivesDonut, FunctionsDonut, QuantumSafetyDonut } from '../components';

interface Props {
  cbom: CBOMDocument | null;
}

export default function VisualizePage({ cbom }: Props) {
  const assets = cbom?.cryptoAssets ?? [];

  if (assets.length === 0) {
    return (
      <div className="dc1-placeholder-page">
        <h2>No Data to Visualize</h2>
        <p>Upload a CBOM to see cryptographic asset distributions.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Visualize</h1>
        <p className="dc1-page-subtitle">
          Interactive charts and distributions of your cryptographic assets
        </p>
      </div>

      <div className="dc1-viz-grid">
        <div className="dc1-card dc1-card-flush">
          <QuantumSafetyDonut assets={assets} />
        </div>
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
    </div>
  );
}
