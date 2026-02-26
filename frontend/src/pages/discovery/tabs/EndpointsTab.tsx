import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, TlsPill } from '../components';
import { ENDPOINTS } from '../data';
import type { DiscoveryEndpoint, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

export default function EndpointsTab({ search, setSearch }: Props) {
  const total      = ENDPOINTS.length;
  const qsSafe     = ENDPOINTS.filter((e) => e.quantumSafe).length;
  const qsPct      = total > 0 ? Math.round((qsSafe / total) * 100) : 0;
  const deprecated = ENDPOINTS.filter((e) => e.tlsVersion === 'TLS 1.1' || e.tlsVersion === 'TLS 1.0').length;

  const filtered = useMemo(() => {
    if (!search) return ENDPOINTS;
    const q = search.toLowerCase();
    return ENDPOINTS.filter(
      (e) =>
        e.hostname.toLowerCase().includes(q) ||
        e.ipAddress.includes(q) ||
        e.keyAgreement.toLowerCase().includes(q) ||
        e.cipherSuite.toLowerCase().includes(q),
    );
  }, [search]);

  const stats: StatCardConfig[] = [
    { title: 'Total Endpoints',   value: total,       sub: 'Discovered via Network TLS Scanner',                                         variant: 'default' },
    { title: 'Quantum-safe',      value: `${qsPct}%`, sub: `${qsSafe} of ${total} endpoints using PQC key agreement`,                    variant: 'success' },
    { title: 'Deprecated TLS',    value: deprecated,   sub: 'Endpoints on TLS 1.0 / 1.1 — immediate upgrade required',                   variant: 'danger' },
  ];

  const columns = [
    { key: 'hostname',     label: 'Hostname',       render: (e: DiscoveryEndpoint) => <span style={{ fontWeight: 500 }}>{e.hostname}</span> },
    { key: 'ipAddress',    label: 'IP Address',     render: (e: DiscoveryEndpoint) => <span className={s.mono}>{e.ipAddress}</span> },
    { key: 'port',         label: 'Port',           render: (e: DiscoveryEndpoint) => e.port },
    { key: 'tlsVersion',   label: 'TLS Version',   render: (e: DiscoveryEndpoint) => <TlsPill version={e.tlsVersion} /> },
    { key: 'cipherSuite',  label: 'Cipher Suite',  render: (e: DiscoveryEndpoint) => <span className={s.mono} style={{ fontSize: 11 }}>{e.cipherSuite}</span> },
    { key: 'keyAgreement', label: 'Key Agreement', render: (e: DiscoveryEndpoint) => <span className={s.mono}>{e.keyAgreement}</span> },
    { key: 'quantumSafe',  label: 'Quantum-safe',  render: (e: DiscoveryEndpoint) => <QsBadge safe={e.quantumSafe} />, sortable: false },
    { key: 'source',       label: 'Source',         render: (e: DiscoveryEndpoint) => <span className={s.sourceLink}>{e.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (_e: DiscoveryEndpoint) => (
        <div className={s.actions}>
          <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
          <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
        </div>
      ),
    },
  ];

  return (
    <>
      <StatCards cards={stats} />

      {deprecated > 0 && (
        <AiBanner>
          <strong>{deprecated} endpoints</strong> are running deprecated TLS versions (1.0/1.1). Upgrade to TLS 1.3 with <strong>ML-KEM key exchange</strong> for quantum-safe protection.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by hostname, IP address, cipher, or key agreement..."
      />

      <DataTable
        title="Endpoints"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(e) => e.id}
      />
    </>
  );
}
