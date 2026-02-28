import { useMemo, useState } from 'react';
import { Eye, ExternalLink, Zap, Ticket } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, LibChips, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { SOFTWARE } from '../data';
import { useGetSoftwareListQuery, useBulkCreateSoftwareMutation, useDeleteAllSoftwareMutation } from '../../../store/api';
import type { DiscoverySoftware, StatCardConfig } from '../types';
import { CreateTicketModal } from '../../tracking';
import type { TicketContext } from '../../tracking';
import { useCreateTicketMutation } from '../../../store/api/trackingApi';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onGoToIntegrations?: () => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "DigiCert Software Trust Manager" in the catalog.' },
  { step: 2, title: 'Enter STM credentials', description: 'Provide your DigiCert ONE tenant URL, API key, and select the environment (Production or Staging).' },
  { step: 3, title: 'Test & sync', description: 'Click "Test Connection" to verify STM API access, then "Save & Sync" to import signing certificates and release metadata.' },
  { step: 4, title: 'Review software releases', description: 'Code-signing certificates, signing algorithms, hash algorithms, and crypto library data will appear here after sync.' },
];

export default function SoftwareTab({ search, setSearch, onGoToIntegrations }: Props) {
  const { data: apiData = [], isLoading } = useGetSoftwareListQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateSoftwareMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllSoftwareMutation();
  const data = apiData;
  const loaded = data.length > 0;

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((sw) => !sw.integrationId);

  /* ── Create-ticket modal state ─────────────────────────── */
  const [ticketCtx, setTicketCtx] = useState<TicketContext | null>(null);
  const [createTicket] = useCreateTicketMutation();

  const total      = data.length;
  const qsSafe     = data.filter((sw) => sw.quantumSafe).length;
  const violations = total - qsSafe;

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (sw) =>
        sw.name.toLowerCase().includes(q) ||
        sw.vendor.toLowerCase().includes(q) ||
        sw.signingAlgorithm.toLowerCase().includes(q) ||
        sw.cryptoLibraries.some((lib) => lib.toLowerCase().includes(q)),
    );
  }, [search, data]);

  const stats: StatCardConfig[] = [
    { title: 'Software Releases',  value: total,      sub: 'Code-signing inventory from DigiCert Software Trust Manager', variant: 'default' },
    { title: 'PQC-signed',         value: qsSafe,     sub: `${qsSafe} of ${total} releases signed with quantum-safe algorithms`, variant: 'success' },
    { title: 'Legacy Signing',     value: violations, sub: 'Releases using classical signing algorithms',               variant: 'danger' },
  ];

  const columns = [
    { key: 'name',              label: 'Release Name',       render: (sw: DiscoverySoftware) => <span style={{ fontWeight: 500 }}>{sw.name}</span> },
    { key: 'version',           label: 'Version',            render: (sw: DiscoverySoftware) => <span className={s.mono}>{sw.version}</span> },
    { key: 'signingAlgorithm',  label: 'Signing Algorithm',  render: (sw: DiscoverySoftware) => sw.signingAlgorithm },
    { key: 'signingKeyLength',  label: 'Key Length',         render: (sw: DiscoverySoftware) => sw.signingKeyLength },
    { key: 'hashAlgorithm',     label: 'Hash Algorithm',     render: (sw: DiscoverySoftware) => <span className={s.mono}>{sw.hashAlgorithm}</span> },
    { key: 'cryptoLibraries',   label: 'Crypto Libraries',   render: (sw: DiscoverySoftware) => <LibChips libs={sw.cryptoLibraries} />, sortable: false },
    { key: 'quantumSafe',       label: 'PQC-signed',         render: (sw: DiscoverySoftware) => <QsBadge safe={sw.quantumSafe} />, sortable: false },
    { key: 'source',            label: 'Source',             render: (sw: DiscoverySoftware) => <span className={s.sourceLink}>{sw.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (sw: DiscoverySoftware) => (
        <div className={s.actions}>
          {!sw.quantumSafe && (
            <>
              <button className={s.upgradeBtn}>
                <Zap className={s.upgradeIcon} />
                Re-sign
              </button>
              <button
                className={s.createTicketBtn}
                title="Create remediation ticket"
                onClick={(ev) => {
                  ev.stopPropagation();
                  setTicketCtx({
                    entityType: 'Software',
                    entityName: `${sw.name} v${sw.version}`,
                    quantumSafe: sw.quantumSafe,
                    problemStatement: `Software release "${sw.name} v${sw.version}" is signed with ${sw.signingAlgorithm} (${sw.signingKeyLength}) which is not quantum-safe. Hash: ${sw.hashAlgorithm}.`,
                    details: { signingAlgorithm: sw.signingAlgorithm, signingKeyLength: sw.signingKeyLength, hashAlgorithm: sw.hashAlgorithm, vendor: sw.vendor, cryptoLibraries: sw.cryptoLibraries.join(', ') },
                    severity: 'Medium',
                  });
                }}
              >
                <Ticket className={s.createTicketIcon} />
                Create Ticket
              </button>
            </>
          )}
          <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
          <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
        </div>
      ),
    },
  ];

  if (isLoading) return null;

  if (!loaded) {
    return (
      <EmptyState
        title="Software Releases"
        integrationName="DigiCert Software Trust Manager"
        integrationDescription="Import code signing certificates, software hashes, and SBOM-linked cryptographic assets from STM. Analyze signing algorithms used across your software supply chain and plan PQC migration."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ items: SOFTWARE.map(({ id, ...rest }) => rest) })}
        onGoToIntegrations={onGoToIntegrations}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {violations > 0 && (
        <AiBanner>
          <strong>{violations} software releases</strong> are signed with classical algorithms. Migrate signing keys to <strong>ML-DSA</strong> via Software Trust Manager to achieve PQC-ready code signing.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by release name, vendor, algorithm, or library..."
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      <DataTable
        title="Software Releases"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(sw) => sw.id}
      />

      {/* Create Ticket Modal */}
      {ticketCtx && (
        <CreateTicketModal
          open
          context={ticketCtx}
          onClose={() => setTicketCtx(null)}
          allowedTypes={['JIRA', 'ServiceNow']}
          onSubmit={(payload) => {
            createTicket(payload);
            setTicketCtx(null);
          }}
        />
      )}
    </>
  );
}
