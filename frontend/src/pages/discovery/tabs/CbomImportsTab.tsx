import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, CbomStatusBadge, ProgressBar, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { CBOM_IMPORTS } from '../data';
import { useGetCbomImportsQuery, useBulkCreateCbomImportsMutation, useDeleteAllCbomImportsMutation } from '../../../store/api';
import type { DiscoveryCbomImport, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onViewCbom?: (id: string) => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "CBOM File Import" in the catalog.' },
  { step: 2, title: 'Choose import method', description: 'Select how to import: upload a local CBOM file (JSON/XML), fetch from a URL, or pull from a CI/CD build artifact.' },
  { step: 3, title: 'Parse & validate', description: 'The system will parse the CBOM (CycloneDX or SPDX format), validate the schema, and extract cryptographic component inventory.' },
  { step: 4, title: 'Review imported data', description: 'Component counts, crypto algorithms, PQC readiness scores, and processing status will appear here after import.' },
];

export default function CbomImportsTab({ search, setSearch, onViewCbom }: Props) {
  const { data: apiData = [], isLoading } = useGetCbomImportsQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateCbomImportsMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllCbomImportsMutation();
  const data = apiData;
  const loaded = data.length > 0;

  const total         = data.length;
  const processed     = data.filter((cb) => cb.status === 'Processed').length;
  const failed        = data.filter((cb) => cb.status === 'Failed' || cb.status === 'Partial').length;
  const totalCrypto   = data.reduce((sum, cb) => sum + cb.cryptoComponents, 0);
  const totalQsSafe   = data.reduce((sum, cb) => sum + cb.quantumSafeComponents, 0);

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (cb) =>
        cb.fileName.toLowerCase().includes(q) ||
        (cb.applicationName?.toLowerCase().includes(q) ?? false) ||
        cb.format.toLowerCase().includes(q) ||
        cb.specVersion.includes(q),
    );
  }, [search, data]);

  const stats: StatCardConfig[] = [
    { title: 'CBOM Files Imported', value: total,       sub: `${processed} processed successfully — ${totalCrypto} crypto components found`, variant: 'default' },
    { title: 'PQC Components',     value: totalQsSafe,  sub: `${totalQsSafe} of ${totalCrypto} crypto components are quantum-safe`,          variant: 'success' },
    { title: 'Import Issues',      value: failed,       sub: 'Failed or partially processed imports',                                        variant: 'danger' },
  ];

  const formatDate = (iso: string) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  const columns = [
    { key: 'applicationName', label: 'Application',       render: (cb: DiscoveryCbomImport) => <span style={{ fontWeight: 500 }}>{cb.applicationName ?? '—'}</span> },
    { key: 'fileName',        label: 'File Name',         render: (cb: DiscoveryCbomImport) => <span className={s.mono} style={{ fontSize: 11 }}>{cb.fileName}</span> },
    { key: 'format',          label: 'Format',            render: (cb: DiscoveryCbomImport) => cb.format },
    { key: 'specVersion',     label: 'Spec',              render: (cb: DiscoveryCbomImport) => cb.specVersion },
    { key: 'totalComponents', label: 'Components',        render: (cb: DiscoveryCbomImport) => cb.totalComponents },
    { key: 'cryptoComponents', label: 'Crypto',           render: (cb: DiscoveryCbomImport) => cb.cryptoComponents },
    { key: 'pqcReadiness',    label: 'PQC Readiness',    render: (cb: DiscoveryCbomImport) => <ProgressBar value={cb.quantumSafeComponents} max={cb.cryptoComponents} />, sortable: false },
    { key: 'status',          label: 'Status',            render: (cb: DiscoveryCbomImport) => <CbomStatusBadge status={cb.status} /> },
    { key: 'importDate',      label: 'Imported',          render: (cb: DiscoveryCbomImport) => formatDate(cb.importDate) },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (_cb: DiscoveryCbomImport) => (
        <div className={s.actions}>
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
        title="CBOM Imports"
        integrationName="CBOM File Import"
        integrationDescription="Import Cryptography Bill of Materials (CBOM) files in CycloneDX or SPDX format. Parse, validate, and analyze cryptographic component inventories to assess PQC readiness across your applications."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ items: CBOM_IMPORTS.map(({ id, ...rest }) => rest) })}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {totalCrypto > 0 && (
        <AiBanner>
          Across {total} CBOM imports, <strong>{totalCrypto - totalQsSafe} cryptographic components</strong> are not quantum-safe.
          Link these CBOMs to your CI/CD pipeline to automatically track PQC migration progress per release.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by application name, file name, format, or spec version..."
        onReset={() => deleteAll()}
        resetLoading={isResetLoading}
      />

      <DataTable
        title="CBOM Imports"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(cb) => cb.id}
        onRowClick={onViewCbom ? (cb) => onViewCbom(cb.id) : undefined}
      />
    </>
  );
}
