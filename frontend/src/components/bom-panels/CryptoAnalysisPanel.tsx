/**
 * CryptoAnalysisPanel — Rich crypto analysis view reusing CBOM detail components.
 *
 * Replaces the simple CryptoPanel table with a full analysis view containing:
 *  • Readiness score + charts
 *  • Asset breakdown
 *  • Donut charts (Primitives, Functions)
 *  • Bubble chart
 *  • Compliance banner
 *  • Asset list view (table)
 */
import { useState, useMemo } from 'react';
import type { CryptoAsset, QuantumReadinessScore, ComplianceSummary, ThirdPartyCryptoLibrary } from '../../types';
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
  ThirdPartyLibrariesView,
} from '../../components';

type CryptoSubTab = 'overview' | 'inventory' | 'libraries';

interface Props {
  assets: CryptoAsset[];
  thirdPartyLibraries?: ThirdPartyCryptoLibrary[];
}

export default function CryptoAnalysisPanel({ assets, thirdPartyLibraries = [] }: Props) {
  const [subTab, setSubTab] = useState<CryptoSubTab>('overview');

  const { readinessScore, compliance, safe, notSafe, conditional, unknown, totalAssets } = useMemo(() => {
    const total = assets.length;
    const qSafe = assets.filter(a => a.quantumSafety === 'quantum-safe').length;
    const notSafe = assets.filter(a => a.quantumSafety === 'not-quantum-safe').length;
    const conditional = assets.filter(a => a.quantumSafety === 'conditional').length;
    const unknown = total - qSafe - notSafe - conditional;
    const score = total > 0 ? Math.round((qSafe / total) * 100) : 100;

    const readinessScore: QuantumReadinessScore = {
      score,
      totalAssets: total,
      quantumSafe: qSafe,
      notQuantumSafe: notSafe,
      conditional,
      unknown,
    };

    const compliance: ComplianceSummary = {
      isCompliant: notSafe === 0,
      policy: 'NIST Post-Quantum Cryptography',
      source: 'xBOM Analysis',
      totalAssets: total,
      compliantAssets: qSafe + conditional,
      nonCompliantAssets: notSafe,
      unknownAssets: unknown,
    };

    return { readinessScore, compliance, safe: qSafe, notSafe, conditional, unknown, totalAssets: total };
  }, [assets]);

  if (!assets.length) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: 'var(--dc1-text-muted)' }}>
        No cryptographic assets found.
      </div>
    );
  }

  return (
    <div>
      {/* Sub-tab bar within crypto */}
      <div className="dc1-tabs-bar" style={{ marginBottom: 16 }}>
        <button
          className={`dc1-tab-btn ${subTab === 'overview' ? 'dc1-tab-active' : ''}`}
          onClick={() => setSubTab('overview')}
        >
          Overview
        </button>
        <button
          className={`dc1-tab-btn ${subTab === 'inventory' ? 'dc1-tab-active' : ''}`}
          onClick={() => setSubTab('inventory')}
        >
          Crypto Inventory ({totalAssets})
        </button>
        {thirdPartyLibraries.length > 0 && (
          <button
            className={`dc1-tab-btn ${subTab === 'libraries' ? 'dc1-tab-active' : ''}`}
            onClick={() => setSubTab('libraries')}
          >
            Third-Party Libraries ({thirdPartyLibraries.length})
          </button>
        )}
      </div>

      {subTab === 'overview' && (
        <>
          {/* Compliance Banner */}
          <div style={{ marginBottom: 16 }}>
            <ComplianceBanner compliance={compliance} />
          </div>

          {/* Stats Row */}
          <CbomStatsRow
            totalAssets={totalAssets}
            quantumSafe={safe}
            notQuantumSafe={notSafe}
            policyViolations={compliance.nonCompliantAssets}
          />

          {/* Charts Row */}
          <div className="dc1-two-col">
            <div className="dc1-card dc1-card-flush">
              <ReadinessScoreCard score={readinessScore} />
            </div>
            <div className="dc1-card dc1-card-flush">
              <QuantumSafetyDonut assets={assets} />
            </div>
          </div>

          {/* Asset Breakdown */}
          <AssetBreakdown
            quantumSafe={safe}
            notQuantumSafe={notSafe}
            conditional={conditional}
            unknown={unknown}
            totalAssets={totalAssets}
          />

          {/* Donut Charts */}
          <div className="dc1-viz-grid">
            <div className="dc1-card dc1-card-flush">
              <PrimitivesDonut assets={assets} />
            </div>
            <div className="dc1-card dc1-card-flush">
              <FunctionsDonut assets={assets} />
            </div>
          </div>

          {/* Bubble Chart */}
          <div className="dc1-card dc1-card-flush" style={{ marginTop: 20 }}>
            <CryptoBubbleChart assets={assets} />
          </div>
        </>
      )}

      {subTab === 'inventory' && (
        <div className="dc1-card" style={{ marginTop: 0 }}>
          <AssetListView assets={assets} />
        </div>
      )}

      {subTab === 'libraries' && thirdPartyLibraries.length > 0 && (
        <ThirdPartyLibrariesView libraries={thirdPartyLibraries} />
      )}
    </div>
  );
}
