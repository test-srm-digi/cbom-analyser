import { useState, useMemo } from 'react';
import {
  Search, Download, SlidersHorizontal, ArrowUpDown, Eye, ExternalLink,
  Zap, ShieldCheck, ShieldAlert, AlertTriangle, Database, Wifi, Box,
} from 'lucide-react';
import type { DiscoveryCertificate, DiscoveryEndpoint, DiscoverySoftware } from '../types';
import { SAMPLE_CERTIFICATES, SAMPLE_ENDPOINTS, SAMPLE_SOFTWARE } from '../sampleDiscoveryData';
import s from './DiscoveryPage.module.scss';

type Tab = 'certificates' | 'endpoints' | 'software';

/* ═══════════════════════════════════════════════════════════════
   DiscoveryPage – Certificates / Endpoints / Software
   ═══════════════════════════════════════════════════════════════ */

export default function DiscoveryPage() {
  const [activeTab, setActiveTab] = useState<Tab>('certificates');
  const [search, setSearch] = useState('');

  return (
    <div>
      {/* Tabs */}
      <div className={s.tabs}>
        {([
          { id: 'certificates' as Tab, label: 'Certificates',  icon: <ShieldCheck size={15} /> },
          { id: 'endpoints'    as Tab, label: 'Endpoints',     icon: <Wifi size={15} /> },
          { id: 'software'     as Tab, label: 'Software',      icon: <Box size={15} /> },
        ]).map((t) => (
          <button
            key={t.id}
            className={activeTab === t.id ? s.tabActive : s.tab}
            onClick={() => { setActiveTab(t.id); setSearch(''); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'certificates' && <CertificatesTab search={search} setSearch={setSearch} />}
      {activeTab === 'endpoints'    && <EndpointsTab    search={search} setSearch={setSearch} />}
      {activeTab === 'software'     && <SoftwareTab     search={search} setSearch={setSearch} />}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Certificates Tab
   ═══════════════════════════════════════════════════════════════ */

function CertificatesTab({ search, setSearch }: { search: string; setSearch: (v: string) => void }) {
  const certs = SAMPLE_CERTIFICATES;
  const total  = certs.length;
  const qsSafe = certs.filter((c) => c.quantumSafe).length;
  const violations = total - qsSafe;

  const filtered = useMemo(() => {
    if (!search) return certs;
    const q = search.toLowerCase();
    return certs.filter(
      (c) =>
        c.commonName.toLowerCase().includes(q) ||
        c.caVendor.toLowerCase().includes(q) ||
        c.keyAlgorithm.toLowerCase().includes(q) ||
        c.source.toLowerCase().includes(q),
    );
  }, [search, certs]);

  const upgradeCount = certs.filter((c) => !c.quantumSafe).length;

  return (
    <>
      {/* Stat cards */}
      <div className={s.stats}>
        <div className={s.statCard}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Total Certificates</span>
            <Database className={s.statIcon} />
          </div>
          <span className={s.statValue}>{total}</span>
          <span className={s.statSub}>Across 4 data sources</span>
        </div>
        <div className={s.statCardSuccess}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Quantum-safe</span>
            <ShieldCheck className={s.statIconSuccess} />
          </div>
          <span className={s.statValueSuccess}>{qsSafe}</span>
          <span className={s.statSub}>{qsSafe} of {total} certificates</span>
        </div>
        <div className={s.statCardDanger}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Policy Violations</span>
            <AlertTriangle className={s.statIconDanger} />
          </div>
          <span className={s.statValueDanger}>{violations}</span>
          <span className={s.statSub}>Certificates with violations</span>
        </div>
      </div>

      {/* AI banner */}
      {upgradeCount > 0 && (
        <div className={s.aiBanner}>
          <Zap className={s.aiBannerIcon} />
          <span className={s.aiBannerText}>
            We have identified <strong>{upgradeCount} certificates</strong> that are strong candidates to upgrade to ML-DSA based on the endpoint information we have collected.
          </span>
          <button className={s.aiBannerBtn}>Show me</button>
        </div>
      )}

      {/* Toolbar */}
      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by IP address, hostname, common name, or application..."
      />

      {/* Table */}
      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Certificates ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Common Name <ArrowUpDown className={s.sortIcon} /></th>
              <th>CA Vendor <ArrowUpDown className={s.sortIcon} /></th>
              <th>Status <ArrowUpDown className={s.sortIcon} /></th>
              <th>Key Algorithm <ArrowUpDown className={s.sortIcon} /></th>
              <th>Key Length <ArrowUpDown className={s.sortIcon} /></th>
              <th>Quantum-safe</th>
              <th>Source</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => (
              <tr key={c.id}>
                <td style={{ fontWeight: 500 }}>{c.commonName}</td>
                <td>{c.caVendor}</td>
                <td><StatusBadge status={c.status} /></td>
                <td>{c.keyAlgorithm}</td>
                <td>{c.keyLength}</td>
                <td><QsBadge safe={c.quantumSafe} /></td>
                <td><span className={s.sourceLink}>{c.source}</span></td>
                <td>
                  <div className={s.actions}>
                    {!c.quantumSafe && (
                      <button className={s.upgradeBtn}>
                        <Zap className={s.upgradeIcon} />
                        Upgrade to Quantum-Safe
                      </button>
                    )}
                    <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
                    <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Endpoints Tab
   ═══════════════════════════════════════════════════════════════ */

function EndpointsTab({ search, setSearch }: { search: string; setSearch: (v: string) => void }) {
  const endpoints = SAMPLE_ENDPOINTS;
  const total = endpoints.length;
  const qsSafe = endpoints.filter((e) => e.quantumSafe).length;
  const qsPct = total > 0 ? Math.round((qsSafe / total) * 100) : 0;
  const violations = endpoints.filter((e) => !e.quantumSafe && (e.tlsVersion === 'TLS 1.1' || e.tlsVersion === 'TLS 1.0')).length;

  const filtered = useMemo(() => {
    if (!search) return endpoints;
    const q = search.toLowerCase();
    return endpoints.filter(
      (e) =>
        e.hostname.toLowerCase().includes(q) ||
        e.ipAddress.includes(q) ||
        e.keyAgreement.toLowerCase().includes(q) ||
        e.source.toLowerCase().includes(q),
    );
  }, [search, endpoints]);

  return (
    <>
      {/* Stat cards */}
      <div className={s.stats}>
        <div className={s.statCard}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Total Endpoints</span>
            <Database className={s.statIcon} />
          </div>
          <span className={s.statValue}>{total}</span>
          <span className={s.statSub}>Across 4 data sources</span>
        </div>
        <div className={s.statCardSuccess}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Quantum-safe</span>
            <ShieldCheck className={s.statIconSuccess} />
          </div>
          <span className={s.statValueSuccess}>{qsPct}%</span>
          <span className={s.statSub}>{qsSafe} of {total} endpoints protected against harvest-now, decrypt later</span>
        </div>
        <div className={s.statCardDanger}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Policy Violations</span>
            <AlertTriangle className={s.statIconDanger} />
          </div>
          <span className={s.statValueDanger}>{violations}</span>
          <span className={s.statSub}>Endpoints with violations</span>
        </div>
      </div>

      {/* Toolbar */}
      <Toolbar search={search} setSearch={setSearch} placeholder="Search by IP or hostname..." />

      {/* Table */}
      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Endpoints ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Hostname <ArrowUpDown className={s.sortIcon} /></th>
              <th>IP Address <ArrowUpDown className={s.sortIcon} /></th>
              <th>Port <ArrowUpDown className={s.sortIcon} /></th>
              <th>TLS Version <ArrowUpDown className={s.sortIcon} /></th>
              <th>Key Agreement <ArrowUpDown className={s.sortIcon} /></th>
              <th>Quantum-safe</th>
              <th>Source</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.id}>
                <td style={{ fontWeight: 500 }}>{e.hostname}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{e.ipAddress}</td>
                <td>{e.port}</td>
                <td><span className={s.tlsPill}>{e.tlsVersion}</span></td>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{e.keyAgreement}</td>
                <td><QsBadge safe={e.quantumSafe} /></td>
                <td><span className={s.sourceLink}>{e.source}</span></td>
                <td>
                  <div className={s.actions}>
                    <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
                    <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Software Tab
   ═══════════════════════════════════════════════════════════════ */

function SoftwareTab({ search, setSearch }: { search: string; setSearch: (v: string) => void }) {
  const software = SAMPLE_SOFTWARE;
  const total = software.length;
  const qsSafe = software.filter((sw) => sw.quantumSafe).length;
  const violations = total - qsSafe;

  const filtered = useMemo(() => {
    if (!search) return software;
    const q = search.toLowerCase();
    return software.filter(
      (sw) =>
        sw.name.toLowerCase().includes(q) ||
        sw.vendor.toLowerCase().includes(q) ||
        sw.version.includes(q),
    );
  }, [search, software]);

  return (
    <>
      {/* Stat cards */}
      <div className={s.stats}>
        <div className={s.statCard}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Total Software</span>
            <Database className={s.statIcon} />
          </div>
          <span className={s.statValue}>{total}</span>
          <span className={s.statSub}>Across software scans</span>
        </div>
        <div className={s.statCardSuccess}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Quantum-safe</span>
            <ShieldCheck className={s.statIconSuccess} />
          </div>
          <span className={s.statValueSuccess}>{qsSafe}</span>
          <span className={s.statSub}>{qsSafe} of {total} libraries</span>
        </div>
        <div className={s.statCardDanger}>
          <div className={s.statHeader}>
            <span className={s.statTitle}>Non Quantum-safe</span>
            <AlertTriangle className={s.statIconDanger} />
          </div>
          <span className={s.statValueDanger}>{violations}</span>
          <span className={s.statSub}>Libraries need upgrade</span>
        </div>
      </div>

      {/* Toolbar */}
      <Toolbar search={search} setSearch={setSearch} placeholder="Search by library name or vendor..." />

      {/* Table */}
      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Software ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              <th>Name <ArrowUpDown className={s.sortIcon} /></th>
              <th>Version <ArrowUpDown className={s.sortIcon} /></th>
              <th>Vendor <ArrowUpDown className={s.sortIcon} /></th>
              <th>Crypto Libraries</th>
              <th>Quantum-safe</th>
              <th>Source</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((sw) => (
              <tr key={sw.id}>
                <td style={{ fontWeight: 500 }}>{sw.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{sw.version}</td>
                <td>{sw.vendor}</td>
                <td>
                  <div className={s.libChips}>
                    {sw.cryptoLibraries.map((lib) => (
                      <span key={lib} className={s.libChip}>{lib}</span>
                    ))}
                  </div>
                </td>
                <td><QsBadge safe={sw.quantumSafe} /></td>
                <td><span className={s.sourceLink}>{sw.source}</span></td>
                <td>
                  <div className={s.actions}>
                    <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
                    <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Shared components
   ═══════════════════════════════════════════════════════════════ */

function Toolbar({ search, setSearch, placeholder }: { search: string; setSearch: (v: string) => void; placeholder: string }) {
  return (
    <div className={s.toolbar}>
      <div className={s.searchBar}>
        <Search className={s.searchIcon} />
        <input
          className={s.searchInput}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={placeholder}
        />
      </div>
      <button className={s.exportBtn}>
        <Download className={s.exportIcon} />
        Export
      </button>
      <button className={s.filterToggle}>
        <SlidersHorizontal className={s.filterIcon} />
      </button>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'Issued'  ? s.badgeIssued  :
    status === 'Expired' ? s.badgeExpired  :
    status === 'Revoked' ? s.badgeRevoked  : s.badgePending;
  return <span className={cls}>{status}</span>;
}

function QsBadge({ safe }: { safe: boolean }) {
  return safe ? (
    <span className={s.qsYes}>
      <span className={s.qsDot} />
      Yes
    </span>
  ) : (
    <span className={s.qsNo}>No</span>
  );
}
