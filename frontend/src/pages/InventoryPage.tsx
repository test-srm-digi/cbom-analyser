import { useState } from 'react';
import type { CBOMDocument, QuantumReadinessScore } from '../types';
import { AssetListView, ThirdPartyLibrariesView } from '../components';

type Tab = 'assets' | 'libraries';

interface Props {
  cbom: CBOMDocument | null;
  readinessScore: QuantumReadinessScore | null;
}

export default function InventoryPage({ cbom, readinessScore }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('assets');

  const assets = cbom?.cryptoAssets ?? [];
  const libraries = cbom?.thirdPartyLibraries ?? [];
  const totalAssets = assets.length;
  const safeCerts = assets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const violations = assets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;

  return (
    <div className="dc1-inventory">
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Inventory</h1>
        <p className="dc1-page-subtitle">
          A comprehensive view of the cryptographic assets in your environment
        </p>
      </div>

      <div className="dc1-inv-summary">
        <div className="dc1-inv-card dc1-inv-card-primary">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Total Crypto Assets</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-primary">{totalAssets}</span>
          <span className="dc1-inv-card-desc">
            Across {Math.max(1, new Set(assets.map((a) => a.detectionSource)).size)} data sources
          </span>
        </div>

        <div className="dc1-inv-card dc1-inv-card-safe">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Quantum-safe</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-success">{safeCerts}</span>
          <span className="dc1-inv-card-desc">{safeCerts} of {totalAssets} assets</span>
        </div>

        <div className="dc1-inv-card dc1-inv-card-violations">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Policy Violations</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-danger">{violations}</span>
          <span className="dc1-inv-card-desc">Not quantum-safe assets</span>
        </div>
      </div>

      <div className="dc1-tabs-bar">
        <button
          className={`dc1-tab-btn ${activeTab === 'assets' ? 'dc1-tab-active' : ''}`}
          onClick={() => setActiveTab('assets')}
        >
          Crypto Assets ({totalAssets})
        </button>
        <button
          className={`dc1-tab-btn ${activeTab === 'libraries' ? 'dc1-tab-active' : ''}`}
          onClick={() => setActiveTab('libraries')}
        >
          Third-Party Libraries ({libraries.length})
        </button>
      </div>

      {activeTab === 'assets' && <AssetListView assets={assets} />}
      {activeTab === 'libraries' && <ThirdPartyLibrariesView libraries={libraries} />}
    </div>
  );
}
