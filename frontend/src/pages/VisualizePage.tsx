import { Upload, Database, BarChart3 } from 'lucide-react';
import type { CBOMDocument } from '../types';
import { CryptoBubbleChart, PrimitivesDonut, FunctionsDonut, QuantumSafetyDonut } from '../components';

interface Props {
  cbom: CBOMDocument | null;
  onUpload: () => void;
  onLoadSample: () => void;
}

export default function VisualizePage({ cbom, onUpload, onLoadSample }: Props) {
  const assets = cbom?.cryptoAssets ?? [];

  if (assets.length === 0) {
    return (
      <div>
        <div className="dc1-page-header">
          <h1 className="dc1-page-title">Visualize</h1>
          <p className="dc1-page-subtitle">Interactive charts and distributions of your cryptographic assets</p>
        </div>
        <div className="dc1-empty-page">
          <BarChart3 size={40} strokeWidth={1.2} className="dc1-empty-page-icon" />
          <h3>No data to visualize</h3>
          <p>Upload a CBOM file or load sample data to see charts and distributions.</p>
          <div className="dc1-empty-page-actions">
            <button className="dc1-btn-primary" onClick={onUpload}><Upload size={15} /> Upload CBOM</button>
            <button className="dc1-btn-secondary" onClick={onLoadSample}><Database size={15} /> Load Sample Data</button>
          </div>
        </div>
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
