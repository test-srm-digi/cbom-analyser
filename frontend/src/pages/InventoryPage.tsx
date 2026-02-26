import { useState, useMemo } from 'react';
import {
  DashboardCard,
  StatusTag,
  StatusTagType,
  Button,
  Tabs,
  IncontextBanner,
  IncontextBannerType,
  Input,
} from '@digicert/dcone-common-ui';
import { Eye, ExternalLink, Search, Download, SlidersHorizontal, ChevronUp, ChevronDown } from 'lucide-react';
import type { CBOMDocument, CryptoAsset, QuantumReadinessScore } from '../types';
import CertificateDetailModal from './CertificateDetailModal';

/* ─── Types ──────────────────────────────────────────────────── */

type SortKey = 'name' | 'provider' | 'quantumSafety' | 'keyLength' | 'type';
type SortDir = 'asc' | 'desc';
type Tab = 'certificates' | 'endpoints' | 'software';

/* ─── Helpers ────────────────────────────────────────────────── */

function quantumLabel(qs: string) {
  switch (qs) {
    case 'quantum-safe': return 'Yes';
    case 'not-quantum-safe': return 'No';
    case 'conditional': return 'Conditional';
    default: return 'Unknown';
  }
}

function quantumTagType(qs: string) {
  switch (qs) {
    case 'quantum-safe': return StatusTagType.SUCCESS;
    case 'not-quantum-safe': return StatusTagType.ALERT;
    case 'conditional': return StatusTagType.WARNING;
    default: return StatusTagType.GENERIC;
  }
}

function algorithmName(a: CryptoAsset) {
  return a.name || 'Unknown';
}

function keyLengthStr(a: CryptoAsset) {
  if (a.keyLength) return `${a.keyLength} bits`;
  const p = a.cryptoProperties?.algorithmProperties?.parameterSetIdentifier;
  if (p) return p;
  const c = a.cryptoProperties?.algorithmProperties?.curve;
  if (c) return c;
  return '-';
}

function sourceName(a: CryptoAsset) {
  switch (a.detectionSource) {
    case 'sonar': return 'DigiCert Trust Lifecycle';
    case 'dependency': return 'Dependency Scanner';
    case 'network': return 'Network Scanner';
    default: return 'DigiCert Trust Lifecycle';
  }
}

/* ─── Component ──────────────────────────────────────────────── */

interface Props {
  cbom: CBOMDocument | null;
  readinessScore: QuantumReadinessScore | null;
}

export default function InventoryPage({ cbom, readinessScore }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('certificates');
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [selectedAsset, setSelectedAsset] = useState<CryptoAsset | null>(null);
  const [filterAlgo, setFilterAlgo] = useState('All');
  const [filterSafety, setFilterSafety] = useState('All');

  const assets = cbom?.cryptoAssets ?? [];

  const totalCerts = assets.length;
  const safeCerts = assets.filter((a) => a.quantumSafety === 'quantum-safe').length;
  const violations = assets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
  const mldsaCandidates = assets.filter(
    (a) => a.quantumSafety === 'not-quantum-safe' && a.recommendedPQC,
  ).length;

  const uniqueAlgorithms = useMemo(() => {
    const set = new Set(assets.map(algorithmName));
    return ['All', ...Array.from(set).sort()];
  }, [assets]);

  const filtered = useMemo(() => {
    let list = [...assets];
    if (search) {
      const s = search.toLowerCase();
      list = list.filter(
        (a) =>
          a.name.toLowerCase().includes(s) ||
          (a.location?.fileName || '').toLowerCase().includes(s) ||
          (a.provider || '').toLowerCase().includes(s),
      );
    }
    if (filterAlgo !== 'All') {
      list = list.filter((a) => algorithmName(a) === filterAlgo);
    }
    if (filterSafety !== 'All') {
      list = list.filter((a) => quantumLabel(a.quantumSafety) === filterSafety);
    }
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'provider': cmp = (a.provider || '').localeCompare(b.provider || ''); break;
        case 'quantumSafety': cmp = a.quantumSafety.localeCompare(b.quantumSafety); break;
        case 'keyLength': cmp = (a.keyLength || 0) - (b.keyLength || 0); break;
        case 'type': cmp = (a.cryptoProperties.assetType || '').localeCompare(b.cryptoProperties.assetType || ''); break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [assets, search, filterAlgo, filterSafety, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  }

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) return <ChevronUp size={12} className="dc1-sort-icon dc1-sort-inactive" />;
    return sortDir === 'asc' ? (
      <ChevronUp size={12} className="dc1-sort-icon" />
    ) : (
      <ChevronDown size={12} className="dc1-sort-icon" />
    );
  };

  return (
    <div className="dc1-inventory">
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Inventory</h1>
        <p className="dc1-page-subtitle">A comprehensive view of the cryptographic assets in your environment</p>
      </div>

      {/* Tabs */}
      <div className="dc1-tabs-bar">
        {(['certificates', 'endpoints', 'software'] as Tab[]).map((t) => (
          <button
            key={t}
            className={`dc1-tab-btn ${activeTab === t ? 'dc1-tab-active' : ''}`}
            onClick={() => setActiveTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Summary Cards */}
      <div className="dc1-inv-summary">
        <div className="dc1-inv-card dc1-inv-card-primary">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Total Certificates</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-primary">{totalCerts}</span>
          <span className="dc1-inv-card-desc">Across {Math.max(1, new Set(assets.map(a => a.detectionSource)).size)} data sources</span>
        </div>

        <div className="dc1-inv-card dc1-inv-card-safe">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Quantum-safe</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-success">{safeCerts}</span>
          <span className="dc1-inv-card-desc">{safeCerts} of {totalCerts} certificates</span>
        </div>

        <div className="dc1-inv-card dc1-inv-card-violations">
          <div className="dc1-inv-card-header">
            <span className="dc1-inv-card-title">Policy Violations</span>
          </div>
          <span className="dc1-inv-card-number dc1-text-danger">{violations}</span>
          <span className="dc1-inv-card-desc">Certificates with violations</span>
        </div>
      </div>

      {/* ML-DSA Upgrade Banner */}
      {mldsaCandidates > 0 && (
        <div className="dc1-upgrade-banner">
          <span className="dc1-upgrade-icon">⚡</span>
          <span>
            We have identified <strong>{mldsaCandidates} certificates</strong> that are strong candidates
            to upgrade to ML-DSA based on the endpoint information we have collected.
          </span>
          <Button onClick={() => {}} className="dc1-show-me-btn">
            Show me
          </Button>
        </div>
      )}

      {/* Search & Export */}
      <div className="dc1-inv-toolbar">
        <div className="dc1-search-box">
          <Search size={16} className="dc1-search-icon" />
          <input
            className="dc1-search-input"
            placeholder="Search by IP address, hostname, common name, or application..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="dc1-inv-toolbar-right">
          <Button onClick={() => {}}>
            <Download size={14} /> Export
          </Button>
          <button className="dc1-filter-btn">
            <SlidersHorizontal size={16} />
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="dc1-table-section">
        <h3 className="dc1-table-heading">Certificates ({filtered.length})</h3>
        <div className="dc1-table-wrapper">
          <table className="dc1-table">
            <thead>
              <tr>
                <th onClick={() => toggleSort('name')}>
                  Common Name <SortIcon col="name" />
                </th>
                <th onClick={() => toggleSort('provider')}>
                  CA Vendor <SortIcon col="provider" />
                </th>
                <th>Status</th>
                <th onClick={() => toggleSort('type')}>
                  Key Algorithm <SortIcon col="type" />
                </th>
                <th onClick={() => toggleSort('keyLength')}>
                  Key Length <SortIcon col="keyLength" />
                </th>
                <th onClick={() => toggleSort('quantumSafety')}>
                  Quantum-safe <SortIcon col="quantumSafety" />
                </th>
                <th>Source</th>
                <th>Actions</th>
              </tr>
              <tr className="dc1-filter-row">
                <td>
                  <input className="dc1-col-filter" placeholder="Filter..." onChange={(e) => setSearch(e.target.value)} />
                </td>
                <td>
                  <input className="dc1-col-filter" placeholder="Filter..." />
                </td>
                <td>
                  <select className="dc1-col-filter">
                    <option>All</option>
                    <option>Issued</option>
                  </select>
                </td>
                <td>
                  <select className="dc1-col-filter" value={filterAlgo} onChange={(e) => setFilterAlgo(e.target.value)}>
                    {uniqueAlgorithms.map((a) => (
                      <option key={a}>{a}</option>
                    ))}
                  </select>
                </td>
                <td>
                  <select className="dc1-col-filter">
                    <option>All</option>
                  </select>
                </td>
                <td>
                  <select className="dc1-col-filter" value={filterSafety} onChange={(e) => setFilterSafety(e.target.value)}>
                    <option>All</option>
                    <option>Yes</option>
                    <option>No</option>
                    <option>Conditional</option>
                  </select>
                </td>
                <td>
                  <select className="dc1-col-filter"><option>All</option></select>
                </td>
                <td />
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset) => (
                <tr key={asset.id}>
                  <td className="dc1-cell-name">{asset.name}</td>
                  <td>{asset.provider || 'DigiCert'}</td>
                  <td>
                    <StatusTag type={StatusTagType.SUCCESS}>Issued</StatusTag>
                  </td>
                  <td>{algorithmName(asset)}</td>
                  <td>{keyLengthStr(asset)}</td>
                  <td>
                    <StatusTag type={quantumTagType(asset.quantumSafety)}>
                      {asset.quantumSafety === 'quantum-safe' && '◉ '}
                      {quantumLabel(asset.quantumSafety)}
                    </StatusTag>
                  </td>
                  <td className="dc1-cell-source">{sourceName(asset)}</td>
                  <td className="dc1-cell-actions">
                    {asset.quantumSafety === 'not-quantum-safe' && (
                      <button className="dc1-upgrade-btn">
                        ↑ Upgrade to Quantum-Safe
                      </button>
                    )}
                    <button
                      className="dc1-icon-btn"
                      title="View details"
                      onClick={() => setSelectedAsset(asset)}
                    >
                      <Eye size={16} />
                    </button>
                    <button className="dc1-icon-btn" title="Open in new tab">
                      <ExternalLink size={16} />
                    </button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="dc1-empty-row">
                    No certificates found. Upload a CBOM to populate inventory.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedAsset && (
        <CertificateDetailModal
          asset={selectedAsset}
          onClose={() => setSelectedAsset(null)}
        />
      )}
    </div>
  );
}
