import { useMemo, useState, useCallback } from 'react';
import { Sparkles, Loader2, ShieldCheck, ShieldX, Ticket, X, AlertTriangle, CheckCircle } from 'lucide-react';
import { fetchWithUser } from '../../../utils/fetchWithUser';
import { useColumnResize } from '../../../hooks/useColumnResize';
import { CreateTicketModal } from '../../tracking';
import type { TicketContext } from '../../tracking';
import { useCreateTicketMutation } from '../../../store/api/trackingApi';
import { StatCards, Toolbar, AiBanner, DataTable, QsBadge, TlsPill, EmptyState, PolicyViolationCell } from '../components';
import type { IntegrationStep } from '../components';
import { ENDPOINTS } from '../data';
import { useGetEndpointsQuery, useBulkCreateEndpointsMutation, useDeleteAllEndpointsMutation, useGetPoliciesQuery } from '../../../store/api';
import type { DiscoveryEndpoint, StatCardConfig } from '../types';
import { evaluateSingleEndpointPolicies } from '../../policies';
import type { CbomPolicyResult } from '../../policies';
import Pagination from '../../../components/Pagination';
import { exportTableToCSV } from '../utils/exportCsv';
import s from '../components/shared.module.scss';

/* ── Helper components for endpoint columns ─────────────────── */

function SecurityRatingBadge({ rating }: { rating?: string | null }) {
  if (!rating) return <span style={{ color: '#999' }}>—</span>;
  const upper = rating.toUpperCase().replace(/_/g, ' ');
  const colorMap: Record<string, { bg: string; fg: string }> = {
    'SECURE':    { bg: '#dcfce7', fg: '#166534' },
    'AT RISK':   { bg: '#fef2f2', fg: '#991b1b' },
    'NOT RATED': { bg: '#f3f4f6', fg: '#6b7280' },
  };
  const c = colorMap[upper] || { bg: '#fef9c3', fg: '#854d0e' };
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 600, background: c.bg, color: c.fg,
      whiteSpace: 'nowrap',
    }}>
      {upper}
    </span>
  );
}

function AutomationStatusBadge({ status }: { status?: string | null }) {
  if (!status) return <span style={{ color: '#999' }}>—</span>;
  const display = status.replace(/_/g, ' ');
  const isError = /FAIL|ERROR/i.test(status);
  const isOk = /CONFIGURED|COMPLETE|SUCCESS/i.test(status);
  const bg = isError ? '#fef2f2' : isOk ? '#dcfce7' : '#f3f4f6';
  const fg = isError ? '#991b1b' : isOk ? '#166534' : '#374151';
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 500, background: bg, color: fg,
      whiteSpace: 'nowrap', textTransform: 'capitalize',
    }}>
      {display.toLowerCase()}
    </span>
  );
}

function formatExpiryDate(dateStr?: string | null): JSX.Element {
  if (!dateStr) return <span style={{ color: '#999' }}>—</span>;
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const isExpired = d < now;
    const formatted = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    return (
      <span style={{ color: isExpired ? '#dc2626' : '#374151', fontWeight: isExpired ? 600 : 400 }}>
        {formatted}{isExpired && ' ⚠'}
      </span>
    );
  } catch {
    return <span>{dateStr}</span>;
  }
}

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

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Filter state
  type QsFilter = 'all' | 'safe' | 'not-safe';
  type RiskFilter = 'all' | 'AT_RISK' | 'SECURE';
  const [qsFilter, setQsFilter] = useState<QsFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((e) => !e.integrationId);

  // Column resize
  const COL_MIN: Record<number, number> = { 0: 150, 1: 150, 2: 90, 3: 120, 4: 150, 5: 150, 6: 120, 7: 120, 8: 120, 9: 120, 10: 120, 11: 120, 12: 200 };
  const { colWidths, onResizeStart } = useColumnResize(COL_MIN);

  /* ── Create-ticket modal state ───────────────────────── */
  const [ticketCtx, setTicketCtx] = useState<TicketContext | null>(null);
  const [createTicket] = useCreateTicketMutation();

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
      const res = await fetchWithUser('/api/ai-suggest', {
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
  const atRisk     = data.filter((e) => e.securityRating === 'AT_RISK').length;
  const expired    = data.filter((e) => {
    if (!e.expiryDate) return false;
    try { return new Date(e.expiryDate) < new Date(); } catch { return false; }
  }).length;

  /* ── Policy evaluation per endpoint ────────────────── */
  const { data: dbPolicies = [] } = useGetPoliciesQuery();

  const policyResultsMap = useMemo<Map<string, CbomPolicyResult>>(() => {
    const map = new Map<string, CbomPolicyResult>();
    for (const ep of data) {
      map.set(ep.id, evaluateSingleEndpointPolicies(dbPolicies, ep));
    }
    return map;
  }, [data, dbPolicies]);

  const totalPolicyViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) count += r.totalViolations;
    return count;
  }, [policyResultsMap]);

  const endpointsWithViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) if (r.totalViolations > 0) count++;
    return count;
  }, [policyResultsMap]);

  const filtered = useMemo(() => {
    let result = data;
    // Quantum-safe filter
    if (qsFilter === 'safe') result = result.filter(e => e.quantumSafe);
    else if (qsFilter === 'not-safe') result = result.filter(e => !e.quantumSafe);
    // Risk filter
    if (riskFilter !== 'all') result = result.filter(e => e.securityRating === riskFilter);
    // Text search
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.hostname.toLowerCase().includes(q) ||
          e.ipAddress.includes(q) ||
          (e.caVendor || '').toLowerCase().includes(q) ||
          (e.osName || '').toLowerCase().includes(q) ||
          (e.sensorName || '').toLowerCase().includes(q) ||
          (e.securityRating || '').toLowerCase().includes(q),
      );
    }
    return result;
  }, [search, data, qsFilter, riskFilter]);

  // Reset page when filter changes
  const filteredLen = filtered.length;
  const [prevFilteredLen, setPrevFilteredLen] = useState(filteredLen);
  if (filteredLen !== prevFilteredLen) { setPrevFilteredLen(filteredLen); setPage(1); }

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  const stats: StatCardConfig[] = [
    { title: 'Total Endpoints',   value: total,       sub: 'Discovered via DigiCert TLM',                                                variant: 'default' },
    { title: 'At Risk',           value: atRisk,      sub: `${atRisk} of ${total} endpoints flagged AT_RISK`,                             variant: atRisk > 0 ? 'danger' : 'success' },
    { title: 'Expired Certs',     value: expired,     sub: `${expired} of ${total} endpoints have expired certificates`,                  variant: expired > 0 ? 'danger' : 'success' },
    { title: 'Policy Violations', value: totalPolicyViolations, sub: `${endpointsWithViolations} of ${total} endpoints have policy violations`, variant: totalPolicyViolations > 0 ? 'danger' : 'success' },
  ];

  const columns = [
    { key: 'hostname',     label: 'Hostname',         render: (e: DiscoveryEndpoint) => <span style={{ fontWeight: 500 }}>{e.hostname}</span> },
    { key: 'ipAddress',    label: 'IP Address',       render: (e: DiscoveryEndpoint) => <span className={s.mono}>{e.ipAddress}</span> },
    { key: 'port',         label: 'Port',             render: (e: DiscoveryEndpoint) => e.port },
    { key: 'securityRating', label: 'Security Rating', render: (e: DiscoveryEndpoint) => <SecurityRatingBadge rating={e.securityRating} /> },
    { key: 'caVendor',    label: 'CA Vendor',          render: (e: DiscoveryEndpoint) => e.caVendor || '—' },
    { key: 'expiryDate',  label: 'Cert Expiry',        render: (e: DiscoveryEndpoint) => formatExpiryDate(e.expiryDate) },
    { key: 'automationStatus', label: 'Automation',    render: (e: DiscoveryEndpoint) => <AutomationStatusBadge status={e.automationStatus} /> },
    { key: 'osName',      label: 'OS',                 render: (e: DiscoveryEndpoint) => <span style={{ fontSize: 12, textTransform: 'capitalize' }}>{e.osName || '—'}</span> },
    { key: 'sensorName',  label: 'Sensor',             render: (e: DiscoveryEndpoint) => e.sensorName || '—' },
    { key: 'quantumSafe',  label: 'Quantum-safe',      render: (e: DiscoveryEndpoint) => <QsBadge safe={e.quantumSafe} />, sortable: false },
    { key: 'policiesViolated', label: 'Policies Violated', sortable: false, render: (e: DiscoveryEndpoint) => {
      const result = policyResultsMap.get(e.id);
      return (
        <PolicyViolationCell
          result={result}
          enableAi
          aiContext={{
            type: 'endpoint',
            hostname: e.hostname,
            port: e.port,
            tlsVersion: e.tlsVersion,
            cipherSuite: e.cipherSuite,
            keyAgreement: e.keyAgreement,
            quantumSafe: e.quantumSafe,
            securityRating: e.securityRating ?? undefined,
            caVendor: e.caVendor ?? undefined,
            expiryDate: e.expiryDate ?? undefined,
            automationStatus: e.automationStatus ?? undefined,
            osName: e.osName ?? undefined,
            sensorName: e.sensorName ?? undefined,
            violatedPolicies: result?.violatedPolicies?.map((p) => p.policyName) ?? [],
          }}
        />
      );
    }},
    { key: 'source',       label: 'Source',         render: (e: DiscoveryEndpoint) => <span className={s.sourceLink}>{e.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'center' as const },
      render: (e: DiscoveryEndpoint) => {
        const sg = suggestions[e.id];
        return (
          <div className={s.actions}>
            {!e.quantumSafe && (
              <>
                <button
                  className={s.aiFixBtn}
                  title="Get AI-powered quantum-safe migration suggestion"
                  disabled={sg?.loading}
                  onClick={(ev) => { ev.stopPropagation(); fetchSuggestion(e); }}
                >
                  {sg?.loading ? <Loader2 className={s.aiFixIcon} /> : <Sparkles className={s.aiFixIcon} />}
                  AI Fix
                </button>
                <button
                  className={s.createTicketBtn}
                  title="Create remediation ticket"
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setTicketCtx({
                      entityType: 'Endpoint',
                      entityName: `${e.hostname}:${e.port}`,
                      quantumSafe: e.quantumSafe,
                      problemStatement: `Endpoint ${e.hostname}:${e.port} uses ${e.tlsVersion} with ${e.cipherSuite} cipher and ${e.keyAgreement} key exchange which is not quantum-safe.`,
                      details: { tlsVersion: e.tlsVersion, cipherSuite: e.cipherSuite, keyAgreement: e.keyAgreement, ipAddress: e.ipAddress },
                      severity: e.tlsVersion === 'TLS 1.0' || e.tlsVersion === 'TLS 1.1' ? 'Critical' : 'High',
                      aiSuggestion: sg?.fix,
                    });
                  }}
                >
                  <Ticket className={s.createTicketIcon} />
                  Create Ticket
                </button>
              </>
            )}
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

      {atRisk > 0 && (
        <AiBanner>
          <strong>{atRisk} endpoints</strong> are flagged as AT_RISK by DigiCert.{' '}
          {expired > 0 && <><strong>{expired} endpoints</strong> have expired certificates. </>}
          Review and remediate vulnerable endpoints for quantum-safe compliance.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by hostname, IP, CA vendor, OS, sensor, or risk..."
        onExport={() => exportTableToCSV(filtered as unknown as Record<string, unknown>[], [
          { key: 'hostname', label: 'Hostname' },
          { key: 'ipAddress', label: 'IP Address' },
          { key: 'port', label: 'Port' },
          { key: 'securityRating', label: 'Security Rating' },
          { key: 'caVendor', label: 'CA Vendor' },
          { key: 'expiryDate', label: 'Cert Expiry' },
          { key: 'automationStatus', label: 'Automation Status' },
          { key: 'osName', label: 'OS' },
          { key: 'sensorName', label: 'Sensor' },
          { key: 'quantumSafe', label: 'Quantum-safe' },
          { key: 'source', label: 'Source' },
        ], 'endpoints')}
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      {/* Filter pills */}
      <div className={s.filterPills}>
        <button className={`${s.filterPill} ${qsFilter === 'all' && riskFilter === 'all' ? s.filterPillActive : ''}`} onClick={() => { setQsFilter('all'); setRiskFilter('all'); }}>All</button>
        <button className={`${s.filterPill} ${qsFilter === 'safe' ? s.filterPillActive : ''}`} onClick={() => setQsFilter(qsFilter === 'safe' ? 'all' : 'safe')}><ShieldCheck size={14} /> Quantum-safe</button>
        <button className={`${s.filterPill} ${qsFilter === 'not-safe' ? s.filterPillActive : ''}`} onClick={() => setQsFilter(qsFilter === 'not-safe' ? 'all' : 'not-safe')}><ShieldX size={14} /> Not Safe</button>
        <button className={`${s.filterPill} ${riskFilter === 'AT_RISK' ? s.filterPillActive : ''}`} onClick={() => setRiskFilter(riskFilter === 'AT_RISK' ? 'all' : 'AT_RISK')}><AlertTriangle size={14} /> At Risk</button>
        <button className={`${s.filterPill} ${riskFilter === 'SECURE' ? s.filterPillActive : ''}`} onClick={() => setRiskFilter(riskFilter === 'SECURE' ? 'all' : 'SECURE')}><CheckCircle size={14} /> Secure</button>
      </div>

      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Endpoints ({filtered.length})</h3>
        <table className={s.table}>
          <colgroup>
            {columns.map((_, i) => (
              <col key={i} style={{ width: colWidths[i] || COL_MIN[i], minWidth: COL_MIN[i] }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {columns.map((col, colIdx) => (
                <th key={col.key} style={col.headerStyle}>
                  {col.label}
                  <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, colIdx)} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paged.map((ep) => {
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
                            <button className={s.aiCloseBtn} onClick={() => setExpandedId(null)} title="Close"><X size={14} /></button>
                          </div>
                        ) : sg.error ? (
                          <div className={s.aiSuggestionPanel}>
                            <div className={s.aiSuggestionHeader}>
                              <Sparkles />
                              <span className={s.aiSuggestionTitle}>AI Suggestion</span>
                              <button className={s.aiCloseBtn} onClick={() => setExpandedId(null)} title="Close"><X size={14} /></button>
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
                              <button className={s.aiCloseBtn} onClick={() => setExpandedId(null)} title="Close"><X size={14} /></button>
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
        <Pagination
          page={page}
          total={filtered.length}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={(sz) => { setPageSize(sz); setPage(1); }}
        />
      </div>

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
