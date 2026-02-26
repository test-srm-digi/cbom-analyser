import { useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, SeverityBadge } from '../components';
import { CODE_FINDINGS } from '../data';
import type { DiscoveryCodeFinding, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

export default function CodeAnalysisTab({ search, setSearch }: Props) {
  const total      = CODE_FINDINGS.length;
  const qsSafe     = CODE_FINDINGS.filter((f) => f.quantumSafe).length;
  const critical   = CODE_FINDINGS.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const repos      = new Set(CODE_FINDINGS.map((f) => f.repository)).size;

  const filtered = useMemo(() => {
    if (!search) return CODE_FINDINGS;
    const q = search.toLowerCase();
    return CODE_FINDINGS.filter(
      (f) =>
        f.repository.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.cryptoApi.toLowerCase().includes(q) ||
        f.algorithm.toLowerCase().includes(q) ||
        f.language.toLowerCase().includes(q),
    );
  }, [search]);

  const stats: StatCardConfig[] = [
    { title: 'Crypto API Calls',   value: total,    sub: `Found across ${repos} repositories via GitHub Scanner`,   variant: 'default' },
    { title: 'PQC-ready Calls',    value: qsSafe,   sub: `${qsSafe} of ${total} using quantum-safe algorithms`,     variant: 'success' },
    { title: 'Critical / High',    value: critical,  sub: 'Findings requiring immediate migration attention',        variant: 'danger' },
  ];

  const columns = [
    { key: 'repository',  label: 'Repository',   render: (f: DiscoveryCodeFinding) => <span style={{ fontWeight: 500 }}>{f.repository}</span> },
    { key: 'filePath',    label: 'File',          render: (f: DiscoveryCodeFinding) => <span className={s.mono} style={{ fontSize: 11 }}>{f.filePath}:{f.lineNumber}</span> },
    { key: 'language',    label: 'Language',       render: (f: DiscoveryCodeFinding) => f.language },
    { key: 'cryptoApi',   label: 'Crypto API',    render: (f: DiscoveryCodeFinding) => <span className={s.mono} style={{ fontSize: 11 }}>{f.cryptoApi}</span> },
    { key: 'algorithm',   label: 'Algorithm',      render: (f: DiscoveryCodeFinding) => f.algorithm },
    { key: 'keySize',     label: 'Key Size',       render: (f: DiscoveryCodeFinding) => f.keySize ?? '—' },
    { key: 'severity',    label: 'Severity',       render: (f: DiscoveryCodeFinding) => <SeverityBadge severity={f.severity} /> },
    { key: 'quantumSafe', label: 'Quantum-safe',  render: (f: DiscoveryCodeFinding) => <QsBadge safe={f.quantumSafe} />, sortable: false },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (_f: DiscoveryCodeFinding) => (
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

      {critical > 0 && (
        <AiBanner>
          <strong>{critical} code locations</strong> use quantum-vulnerable crypto APIs (RSA key generation, ECDSA signing). Replace with <strong>ML-DSA / ML-KEM</strong> equivalents from liboqs or provider libraries.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by repository, file path, language, API, or algorithm..."
      />

      <DataTable
        title="Code Analysis Findings"
        count={filtered.length}
        columns={columns}
        data={filtered}
        rowKey={(f) => f.id}
      />
    </>
  );
}
