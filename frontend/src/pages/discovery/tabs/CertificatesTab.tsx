import { useState, useMemo } from 'react';
import { Zap, Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, CertStatusBadge, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { CERTIFICATES } from '../data';
import type { DiscoveryCertificate, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

/* ── Integration setup steps ──────────────────────────────── */
const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page from the sidebar and locate "DigiCert Trust Lifecycle Manager" in the catalog.' },
  { step: 2, title: 'Configure API credentials', description: 'Enter your DigiCert ONE tenant URL, API key, account ID, and optionally a division ID to scope the import.' },
  { step: 3, title: 'Test connection & sync', description: 'Click "Test Connection" to verify API access, then "Save & Sync" to run the first certificate import.' },
  { step: 4, title: 'Review discovered certificates', description: 'Certificates, CA hierarchies, and TLS endpoint data will appear here automatically after the sync completes.' },
];

export default function CertificatesTab({ search, setSearch }: Props) {
  const [data, setData] = useState<DiscoveryCertificate[]>([]);
  const loaded = data.length > 0;

  const total      = data.length;
  const qsSafe     = data.filter((c) => c.quantumSafe).length;
  const violations = total - qsSafe;

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (c) =>
        c.commonName.toLowerCase().includes(q) ||
        c.caVendor.toLowerCase().includes(q) ||
        c.keyAlgorithm.toLowerCase().includes(q) ||
        c.source.toLowerCase().includes(q),
    );
  }, [search, data]);

  const upgradeCount = data.filter((c) => !c.quantumSafe).length;

  const stats: StatCardConfig[] = [
    { title: 'Total Certificates', value: total,      sub: `Discovered via DigiCert Trust Lifecycle Manager`, variant: 'default' },
    { title: 'Quantum-safe',       value: qsSafe,     sub: `${qsSafe} of ${total} certificates`,             variant: 'success' },
    { title: 'Policy Violations',  value: violations, sub: 'Non PQC-ready certificates',                     variant: 'danger' },
  ];

  const columns = [
    { key: 'commonName',     label: 'Common Name',       render: (c: DiscoveryCertificate) => <span style={{ fontWeight: 500 }}>{c.commonName}</span> },
    { key: 'caVendor',       label: 'CA Vendor',         render: (c: DiscoveryCertificate) => c.caVendor },
    { key: 'status',         label: 'Status',            render: (c: DiscoveryCertificate) => <CertStatusBadge status={c.status} /> },
    { key: 'keyAlgorithm',   label: 'Key Algorithm',     render: (c: DiscoveryCertificate) => c.keyAlgorithm },
    { key: 'keyLength',      label: 'Key Length',        render: (c: DiscoveryCertificate) => c.keyLength },
    { key: 'signatureAlgo',  label: 'Signature',         render: (c: DiscoveryCertificate) => <span className={s.mono}>{c.signatureAlgorithm ?? '—'}</span> },
    { key: 'quantumSafe',    label: 'Quantum-safe',      render: (c: DiscoveryCertificate) => <QsBadge safe={c.quantumSafe} />, sortable: false },
    { key: 'source',         label: 'Source',            render: (c: DiscoveryCertificate) => <span className={s.sourceLink}>{c.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (c: DiscoveryCertificate) => (
        <div className={s.actions}>
          {!c.quantumSafe && (
            <button className={s.upgradeBtn}>
              <Zap className={s.upgradeIcon} />
              Upgrade
            </button>
          )}
          <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
          <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
        </div>
      ),
    },
  ];

  if (!loaded) {
    return (
      <EmptyState
        title="Certificates"
        integrationName="DigiCert Trust Lifecycle Manager"
        integrationDescription="Import TLS/PKI certificates, CA hierarchies, and endpoint data via the TLM REST API. Automatically track key algorithms, expiry dates, and PQC-readiness across your managed certificate infrastructure."
        steps={STEPS}
        onLoadSample={() => setData([...CERTIFICATES])}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {upgradeCount > 0 && (
        <AiBanner>
          We identified <strong>{upgradeCount} certificates</strong> that are strong candidates to upgrade to <strong>ML-DSA</strong> based on TLM endpoint data.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by common name, CA vendor, algorithm, or source..."
      />

      <DataTable
        title="Certificates"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(c) => c.id}
      />
    </>
  );
}
