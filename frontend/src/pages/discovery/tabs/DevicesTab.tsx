import { useMemo, useState, useCallback } from 'react';
import { Ticket, Sparkles, Loader2, X } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, QsBadge, DeviceStatusBadge, EmptyState, PolicyViolationCell } from '../components';
import { ArrowUpDown } from 'lucide-react';
import Pagination from '../../../components/Pagination';
import type { IntegrationStep } from '../components';
import { DEVICES } from '../data';
import { useGetDevicesQuery, useBulkCreateDevicesMutation, useDeleteAllDevicesMutation, useGetPoliciesQuery } from '../../../store/api';
import type { DiscoveryDevice, StatCardConfig } from '../types';
import { evaluateSingleDevicePolicies } from '../../policies';
import type { CbomPolicyResult } from '../../policies';
import { CreateTicketModal } from '../../tracking';
import type { TicketContext } from '../../tracking';
import { useCreateTicketMutation } from '../../../store/api/trackingApi';
import { exportTableToCSV } from '../utils/exportCsv';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onGoToIntegrations?: () => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "DigiCert Device Trust Manager" in the catalog.' },
  { step: 2, title: 'Enter DTM credentials', description: 'Provide your DigiCert ONE tenant URL, API key, and optionally filter by device group or enrollment profile.' },
  { step: 3, title: 'Test & sync', description: 'Click "Test Connection" to verify DTM API access, then "Save & Sync" to import your IoT/OT device fleet.' },
  { step: 4, title: 'Review device inventory', description: 'Device certificates, firmware versions, enrollment status, and PQC readiness will appear here after sync.' },
];

export default function DevicesTab({ search, setSearch, onGoToIntegrations }: Props) {
  const { data: apiData = [], isLoading } = useGetDevicesQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateDevicesMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllDevicesMutation();
  const data = apiData;
  const loaded = data.length > 0;

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((d) => !d.integrationId);

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  /* ── Create-ticket modal state ─────────────────────────── */
  const [ticketCtx, setTicketCtx] = useState<TicketContext | null>(null);
  const [createTicket] = useCreateTicketMutation();

  /* ── AI suggestion state (per-device "AI Fix") ─────────── */
  const [suggestions, setSuggestions] = useState<Record<string, {
    loading?: boolean;
    fix?: string;
    codeSnippet?: string;
    confidence?: 'high' | 'medium' | 'low';
    error?: string;
  }>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchSuggestion = useCallback(async (dev: DiscoveryDevice) => {
    const key = dev.id;
    setSuggestions(prev => ({ ...prev, [key]: { loading: true } }));
    setExpandedId(key);
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: dev.certAlgorithm,
          primitive: 'digital-signature',
          quantumSafety: dev.quantumSafe ? 'quantum-safe' : 'not-quantum-safe',
          assetType: 'certificate',
          description: `IoT/OT device "${dev.deviceName}" (${dev.deviceType}) by ${dev.manufacturer} using ${dev.certAlgorithm} ${dev.keyLength} certificate. Firmware: ${dev.firmwareVersion}.`,
          recommendedPQC: dev.quantumSafe ? undefined : 'ML-DSA-65 (or hybrid with ECDSA P-256)',
          keyLength: dev.keyLength,
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
  const qsSafe     = data.filter((d) => d.quantumSafe).length;
  const violations = data.filter((d) => !d.quantumSafe).length;
  const weakKeys   = data.filter((d) => d.keyLength === '1024 bits').length;

  /* ── Policy evaluation per device ──────────────────── */
  const { data: dbPolicies = [] } = useGetPoliciesQuery();

  const policyResultsMap = useMemo<Map<string, CbomPolicyResult>>(() => {
    const map = new Map<string, CbomPolicyResult>();
    for (const dev of data) {
      map.set(dev.id, evaluateSingleDevicePolicies(dbPolicies, dev));
    }
    return map;
  }, [data, dbPolicies]);

  const totalPolicyViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) count += r.totalViolations;
    return count;
  }, [policyResultsMap]);

  const devicesWithViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) if (r.totalViolations > 0) count++;
    return count;
  }, [policyResultsMap]);

  const filtered = useMemo(() => {
    if (!search) return data;
    const q = search.toLowerCase();
    return data.filter(
      (d) =>
        d.deviceName.toLowerCase().includes(q) ||
        d.manufacturer.toLowerCase().includes(q) ||
        d.deviceType.toLowerCase().includes(q) ||
        d.certAlgorithm.toLowerCase().includes(q),
    );
  }, [search, data]);

  const stats: StatCardConfig[] = [
    { title: 'Total Devices',     value: total,      sub: 'Managed by DigiCert Device Trust Manager',                       variant: 'default' },
    { title: 'Quantum-ready',     value: qsSafe,     sub: `${qsSafe} of ${total} devices with PQC certificates/firmware`,   variant: 'success' },
    { title: 'Vulnerable Devices', value: violations, sub: `Includes ${weakKeys} devices with 1024-bit keys`,               variant: 'danger' },
    { title: 'Policy Violations', value: totalPolicyViolations, sub: `${devicesWithViolations} of ${total} devices have policy violations`, variant: totalPolicyViolations > 0 ? 'danger' : 'success' },
  ];

  const columns = [
    { key: 'deviceName',       label: 'Device Name',        render: (d: DiscoveryDevice) => <span style={{ fontWeight: 500 }}>{d.deviceName}</span> },
    { key: 'deviceType',       label: 'Type',               render: (d: DiscoveryDevice) => d.deviceType },
    { key: 'manufacturer',     label: 'Manufacturer',       render: (d: DiscoveryDevice) => d.manufacturer },
    { key: 'firmwareVersion',  label: 'Firmware',           render: (d: DiscoveryDevice) => <span className={s.mono}>{d.firmwareVersion}</span> },
    { key: 'certAlgorithm',   label: 'Cert Algorithm',     render: (d: DiscoveryDevice) => d.certAlgorithm },
    { key: 'keyLength',       label: 'Key Length',          render: (d: DiscoveryDevice) => d.keyLength },
    { key: 'enrollmentStatus', label: 'Status',             render: (d: DiscoveryDevice) => <DeviceStatusBadge status={d.enrollmentStatus} /> },
    { key: 'quantumSafe',     label: 'Quantum-safe',       render: (d: DiscoveryDevice) => <QsBadge safe={d.quantumSafe} />, sortable: false },
    { key: 'policiesViolated', label: 'Policies Violated', sortable: false, render: (d: DiscoveryDevice) => {
      const result = policyResultsMap.get(d.id);
      return (
        <PolicyViolationCell
          result={result}
          enableAi
          aiContext={{
            type: 'device',
            deviceName: d.deviceName,
            deviceType: d.deviceType,
            manufacturer: d.manufacturer,
            certAlgorithm: d.certAlgorithm,
            keyLength: d.keyLength,
            quantumSafe: d.quantumSafe,
            violatedPolicies: result?.violatedPolicies?.map((p) => p.policyName) ?? [],
          }}
        />
      );
    }},
    { key: 'source',          label: 'Source',              render: (d: DiscoveryDevice) => <span className={s.sourceLink}>{d.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'center' as const },
      render: (_d: DiscoveryDevice) => {
        const sg = suggestions[_d.id];
        return (
          <div className={s.actions}>
            {!_d.quantumSafe && (
              <>
                <button
                  className={s.aiFixBtn}
                  title="Get AI-powered quantum-safe migration suggestion"
                  disabled={sg?.loading}
                  onClick={(ev) => { ev.stopPropagation(); fetchSuggestion(_d); }}
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
                      entityType: 'Device',
                      entityName: _d.deviceName,
                      quantumSafe: _d.quantumSafe,
                      problemStatement: `Device "${_d.deviceName}" (${_d.deviceType}) uses ${_d.certAlgorithm} ${_d.keyLength} certificate which is not quantum-safe. Manufacturer: ${_d.manufacturer}, Firmware: ${_d.firmwareVersion}.`,
                      details: { certAlgorithm: _d.certAlgorithm, keyLength: _d.keyLength, manufacturer: _d.manufacturer, firmwareVersion: _d.firmwareVersion, deviceType: _d.deviceType },
                      severity: _d.keyLength === '1024 bits' ? 'Critical' : 'High',
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

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  if (isLoading) return null;

  if (!loaded) {
    return (
      <EmptyState
        title="Devices"
        integrationName="DigiCert Device Trust Manager"
        integrationDescription="Import your IoT and OT device fleet from DTM. Discover device certificates, firmware crypto capabilities, enrollment status, and identify devices needing PQC migration."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ items: DEVICES.map(({ id, ...rest }) => rest) })}
        onGoToIntegrations={onGoToIntegrations}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {weakKeys > 0 && (
        <AiBanner>
          <strong>{weakKeys} devices</strong> use <strong>1024-bit RSA keys</strong> — these are critically weak and should be re-enrolled with ML-DSA or at minimum 2048-bit RSA certificates via Device Trust Manager.
        </AiBanner>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by device name, type, manufacturer, or algorithm..."
        onExport={() => exportTableToCSV(filtered as unknown as Record<string, unknown>[], [
          { key: 'deviceName', label: 'Device Name' },
          { key: 'deviceType', label: 'Type' },
          { key: 'manufacturer', label: 'Manufacturer' },
          { key: 'firmwareVersion', label: 'Firmware' },
          { key: 'certAlgorithm', label: 'Cert Algorithm' },
          { key: 'keyLength', label: 'Key Length' },
          { key: 'enrollmentStatus', label: 'Status' },
          { key: 'quantumSafe', label: 'Quantum-safe' },
          { key: 'source', label: 'Source' },
        ], 'devices')}
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Devices ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} style={col.headerStyle}>
                  {col.label}
                  {col.sortable !== false && <ArrowUpDown className={s.sortIcon} />}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paged.map((dev) => {
              const sg = suggestions[dev.id];
              return (
                <>{/* Fragment needed for adjacent rows */}
                  <tr key={dev.id}>
                    {columns.map((col) => (
                      <td key={col.key} style={'cellStyle' in col ? (col as { cellStyle?: React.CSSProperties }).cellStyle : undefined}>{col.render(dev)}</td>
                    ))}
                  </tr>
                  {/* AI suggestion expandable row */}
                  {expandedId === dev.id && sg && (
                    <tr key={`${dev.id}-ai`} className={s.aiSuggestionRow}>
                      <td colSpan={columns.length}>
                        {sg.loading ? (
                          <div className={s.aiLoading}>
                            <Loader2 size={16} /> Generating AI suggestion for {dev.deviceName}…
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
                            <button className={s.aiFixBtn} onClick={() => fetchSuggestion(dev)}>
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
