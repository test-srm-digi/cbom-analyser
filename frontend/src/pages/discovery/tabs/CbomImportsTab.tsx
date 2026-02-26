import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, CbomStatusBadge, ProgressBar } from '../components';
import { CBOM_IMPORTS } from '../data';
import type { DiscoveryCbomImport, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

export default function CbomImportsTab({ search, setSearch }: Props) {
  const total         = CBOM_IMPORTS.length;
  const processed     = CBOM_IMPORTS.filter((cb) => cb.status === 'Processed').length;
  const failed        = CBOM_IMPORTS.filter((cb) => cb.status === 'Failed' || cb.status === 'Partial').length;
  const totalCrypto   = CBOM_IMPORTS.reduce((sum, cb) => sum + cb.cryptoComponents, 0);
  const totalQsSafe   = CBOM_IMPORTS.reduce((sum, cb) => sum + cb.quantumSafeComponents, 0);

  const filtered = useMemo(() => {
    if (!search) return CBOM_IMPORTS;
    const q = search.toLowerCase();
    return CBOM_IMPORTS.filter(
      (cb) =>
        cb.fileName.toLowerCase().includes(q) ||
        (cb.applicationName?.toLowerCase().includes(q) ?? false) ||
        cb.format.toLowerCase().includes(q) ||
        cb.specVersion.includes(q),
    );
  }, [search]);

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
      />

      <DataTable
        title="CBOM Imports"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(cb) => cb.id}
      />
    </>
  );
}
