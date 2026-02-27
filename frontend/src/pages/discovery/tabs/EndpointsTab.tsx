import { useMemo, useState, useCallback } from 'react';
import { Eye, ExternalLink, Sparkles, Loader2 } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, TlsPill, EmptyState } from '../components';
import type { IntegrationStep } from '../components';
import { ENDPOINTS } from '../data';
import { useGetEndpointsQuery, useBulkCreateEndpointsMutation, useDeleteAllEndpointsMutation } from '../../../store/api';
import type { DiscoveryEndpoint, StatCardConfig } from '../types';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onGoToIntegrations?: () => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "Network TLS Scanner" in the catalog.' },
  { step: 2, title: 'Define target ranges', description: 'Enter CIDR ranges (e.g. 10.0.0.0/24) and ports to scan (443, 8443, 636). Set concurrency and timeout limits.' },
  { step: 3, title: 'Run the scan', description: 'Click "Save & Run" to initiate TLS probing across all defined targets. The scanner performs TLS handshakes and collects cipher suite data.' },
  { step: 4, title: 'Review discovered endpoints', description: 'TLS endpoints, cipher suites, key exchange algorithms, and certificate chains will appear here after the scan completes.' },
];

export default function EndpointsTab({ search, setSearch, onGoToIntegrations }: Props) {
  const { data: apiData = [], isLoading } = useGetEndpointsQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateEndpointsMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllEndpointsMutation();
  const data = apiData;
  const loaded = data.length > 0;

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((e) => !e.integrationId);

  /* ── AI suggestion state ────────────────────────────────── */
  const [suggestions, setSuggestions] = useState<Record<string, {
    loading?: boolean;
    fix?: string;
    codeSnippet?: string;
    confidence?: 'high' | 'medium' | 'low';
    error?: string;
  }>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchSuggestion = useCallback(async (ep: DiscoveryEndpoint) => {
    const key = ep.id;
    setSuggestions(prev => ({ ...prev, [key]: { loading: true } }));
    setExpandedId(key);
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: ep.tlsVersion,
          primitive: 'key-agreement',
          quantumSafety: ep.quantumSafe ? 'quantum-safe' : 'not-quantum-safe',
          assetType: 'protocol',
          description: `TLS endpoint ${ep.hostname}:${ep.port} using ${ep.cipherSuite} with ${ep.keyAgreement} key exchange`,
          recommendedPQC: ep.quantumSafe ? undefined : 'ML-KEM-768 (hybrid with X25519)',
          mode: ep.cipherSuite,
          curve: ep.keyAgreement,
        }),
      });
      const json = await res.json();
      if (json.success) {
        setSuggestions(prev => ({ ...prev, [key]: { fix: json.suggestedFix, codeSnippet: json.codeSnippet, confidence: json.confidence, loading: false } }));
      } else {
        setSuggestions(prev => ({ ...prev, [key]: { loading: false, error: 'No suggestion available' } }));
      }
    } catch {
      setSuggestions(prev => ({ ...prev, [key]: { loading: false, error: 'Failed to fetch suggestion' } }));
    }
  }, []);

  const total      = data.length;
  const qsSafe     = data.filter((e) => e.quantumSafe).length;
  const qsPct      = total > 0 ? Math.round((qsSafe / total) * 100) : 0;
  const deprecated = data.filter((e) => e.tlsVersion === 'TLS 1.1' || e.tlsVersion === 'TLS 1.0').length;

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (e) =>
        e.hostname.toLowerCase().includes(q) ||
        e.ipAddress.includes(q) ||
        e.keyAgreement.toLowerCase().includes(q) ||
        e.cipherSuite.toLowerCase().includes(q),
    );
  }, [search, data]);

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
      render: (e: DiscoveryEndpoint) => {
        const sg = suggestions[e.id];
        return (
          <div className={s.actions}>
            {!e.quantumSafe && (
              <button
                className={s.aiFixBtn}
                title="Get AI-powered quantum-safe migration suggestion"
                disabled={sg?.loading}
                onClick={(ev) => { ev.stopPropagation(); fetchSuggestion(e); }}
              >
                {sg?.loading ? <Loader2 className={s.aiFixIcon} /> : <Sparkles className={s.aiFixIcon} />}
                AI Fix
              </button>
            )}
            <button className={s.actionBtn} onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}>
              <Eye className={s.actionIcon} />
            </button>
            <button className={s.actionBtn}><ExternalLink className={s.actionIcon} /></button>
          </div>
        );
      },
    },
  ];

  if (isLoading) return null;

  if (!loaded) {
    return (
      <EmptyState
        title="Endpoints"
        integrationName="Network TLS Scanner"
        integrationDescription="Scan your network to discover TLS endpoints, cipher suites, certificate chains, and key exchange algorithms. Identify hosts using quantum-vulnerable cryptography before Q-Day."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ items: ENDPOINTS.map(({ id, ...rest }) => rest) })}
        onGoToIntegrations={onGoToIntegrations}
      />
    );
  }

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
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Endpoints ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} style={col.headerStyle}>{col.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((ep) => {
              const sg = suggestions[ep.id];
              const isExpanded = expandedId === ep.id && sg && !sg.loading;
              return (
                <>{/* Fragment needed for adjacent rows */}
                  <tr key={ep.id}>
                    {columns.map((col) => (
                      <td key={col.key} style={'cellStyle' in col ? (col as { cellStyle?: React.CSSProperties }).cellStyle : undefined}>{col.render(ep)}</td>
                    ))}
                  </tr>
                  {/* AI suggestion expandable row */}
                  {expandedId === ep.id && sg && (
                    <tr key={`${ep.id}-ai`} className={s.aiSuggestionRow}>
                      <td colSpan={columns.length}>
                        {sg.loading ? (
                          <div className={s.aiLoading}>
                            <Loader2 size={16} /> Generating AI suggestion for {ep.hostname}:{ep.port}…
                          </div>
                        ) : sg.error ? (
                          <div className={s.aiSuggestionPanel}>
                            <div className={s.aiSuggestionHeader}>
                              <Sparkles />
                              <span className={s.aiSuggestionTitle}>AI Suggestion</span>
                            </div>
                            <p className={s.aiSuggestionText}>{sg.error}</p>
                            <button className={s.aiFixBtn} onClick={() => fetchSuggestion(ep)}>
                              <Sparkles className={s.aiFixIcon} /> Retry
                            </button>
                          </div>
                        ) : sg.fix ? (
                          <div className={s.aiSuggestionPanel}>
                            <div className={s.aiSuggestionHeader}>
                              <Sparkles />
                              <span className={s.aiSuggestionTitle}>AI Migration Suggestion</span>
                              {sg.confidence && (
                                <span className={`${s.aiConfidence} ${
                                  sg.confidence === 'high' ? s.confidenceHigh
                                    : sg.confidence === 'medium' ? s.confidenceMedium
                                    : s.confidenceLow
                                }`}>
                                  {sg.confidence} confidence
                                </span>
                              )}
                            </div>
                            <p className={s.aiSuggestionText}>{sg.fix}</p>
                            {sg.codeSnippet && (
                              <pre className={s.aiCodeBlock}>{sg.codeSnippet}</pre>
                            )}
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
