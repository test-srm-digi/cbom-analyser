import { useMemo } from 'react';
import { Eye, ExternalLink, Zap } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, LibChips } from '../components';
import { SOFTWARE } from '../data';
import type { DiscoverySoftware, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

export default function SoftwareTab({ search, setSearch }: Props) {
  const total      = SOFTWARE.length;
  const qsSafe     = SOFTWARE.filter((sw) => sw.quantumSafe).length;
  const violations = total - qsSafe;

  const filtered = useMemo(() => {
    if (!search) return SOFTWARE;
    const q = search.toLowerCase();
    return SOFTWARE.filter(
      (sw) =>
        sw.name.toLowerCase().includes(q) ||
        sw.vendor.toLowerCase().includes(q) ||
        sw.signingAlgorithm.toLowerCase().includes(q) ||
        sw.cryptoLibraries.some((lib) => lib.toLowerCase().includes(q)),
    );
  }, [search]);

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
            <button className={s.upgradeBtn}>
              <Zap className={s.upgradeIcon} />
              Re-sign
            </button>
          )}
          <button className={s.actionBtn}><Eye className={s.actionIcon} /></button>
          <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
        </div>
      ),
    },
  ];

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
      />

      <DataTable
        title="Software Releases"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(sw) => sw.id}
      />
    </>
  );
}
