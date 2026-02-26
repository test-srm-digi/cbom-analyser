import { useState, useMemo } from 'react';
import { Eye, ExternalLink } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, SeverityBadge, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { CODE_FINDINGS } from '../data';
import type { DiscoveryCodeFinding, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "GitHub Crypto Scanner" in the catalog.' },
  { step: 2, title: 'Connect GitHub repositories', description: 'Provide a GitHub personal access token (repo scope), then select the organizations and repositories to scan.' },
  { step: 3, title: 'Configure scan settings', description: 'Choose target branches, file path patterns, and languages. Enable deep scan to detect transitive crypto dependencies.' },
  { step: 4, title: 'Review code findings', description: 'Crypto API calls, algorithms, key sizes, and severity ratings will appear here after the scan completes.' },
];

export default function CodeAnalysisTab({ search, setSearch }: Props) {
  const [data, setData] = useState<DiscoveryCodeFinding[]>([]);
  const loaded = data.length > 0;

  const total      = data.length;
  const qsSafe     = data.filter((f) => f.quantumSafe).length;
  const critical   = data.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const repos      = new Set(data.map((f) => f.repository)).size;

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (f) =>
        f.repository.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.cryptoApi.toLowerCase().includes(q) ||
        f.algorithm.toLowerCase().includes(q) ||
        f.language.toLowerCase().includes(q),
    );
  }, [search, data]);

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

  if (!loaded) {
    return (
      <EmptyState
        title="Code Analysis Findings"
        integrationName="GitHub Crypto Scanner"
        integrationDescription="Scan your GitHub repositories for cryptographic API usage. Detect vulnerable algorithms, weak key sizes, and deprecated crypto libraries across your codebase to plan PQC migration."
        steps={STEPS}
        onLoadSample={() => setData([...CODE_FINDINGS])}
      />
    );
  }

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
