import { useMemo, useState, useCallback } from 'react';
import { Eye, ExternalLink, Sparkles, Loader2, BarChart3, AlertTriangle, TrendingUp, Clock, X, ShieldCheck, ShieldX } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, QsBadge, CertStatusBadge, EmptyState, PolicyViolationCell } from '../components';
import type { IntegrationStep } from '../components';
import { CERTIFICATES } from '../data';
import { useGetCertificatesQuery, useBulkCreateCertificatesMutation, useDeleteAllCertificatesMutation, useGetPoliciesQuery } from '../../../store/api';
import type { DiscoveryCertificate, StatCardConfig } from '../types';
import { evaluateSingleCertPolicies } from '../../policies';
import type { CbomPolicyResult } from '../../policies';
import s from '../components/shared.module.scss';

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onGoToIntegrations?: () => void;
}

/* ── AI types ─────────────────────────────────────────────── */
interface ProjectInsight {
  riskLevel: string;
  headline: string;
  summary: string;
  priorities: { action: string; impact: string; effort: string }[];
  riskScore: number;
  migrationEstimate: string;
}

interface InsightState {
  loading: boolean;
  data?: ProjectInsight | null;
  error?: string;
}

/* ── Integration setup steps ──────────────────────────────── */
const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page from the sidebar and locate "DigiCert Trust Lifecycle Manager" in the catalog.' },
  { step: 2, title: 'Configure API credentials', description: 'Enter your DigiCert ONE tenant URL, API key, account ID, and optionally a division ID to scope the import.' },
  { step: 3, title: 'Test connection & sync', description: 'Click "Test Connection" to verify API access, then "Save & Sync" to run the first certificate import.' },
  { step: 4, title: 'Review discovered certificates', description: 'Certificates, CA hierarchies, and TLS endpoint data will appear here automatically after the sync completes.' },
];

export default function CertificatesTab({ search, setSearch, onGoToIntegrations }: Props) {
  const { data: apiData = [], isLoading } = useGetCertificatesQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateCertificatesMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllCertificatesMutation();
  const data = apiData;
  const loaded = data.length > 0;

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((c) => !c.integrationId);

  /* ── AI insight state (banner "Show me") ────────────────── */
  const [insight, setInsight] = useState<InsightState>({ loading: false });

  /* ── AI suggestion state (per-cert "AI Fix") ────────────── */
  const [suggestions, setSuggestions] = useState<Record<string, {
    loading?: boolean;
    fix?: string;
    codeSnippet?: string;
    confidence?: 'high' | 'medium' | 'low';
    error?: string;
  }>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const total      = data.length;
  const qsSafe     = data.filter((c) => c.quantumSafe).length;
  const violations = total - qsSafe;

  /* ── Policy evaluation per certificate ──────────────── */
  const { data: dbPolicies = [] } = useGetPoliciesQuery();

  const policyResultsMap = useMemo<Map<string, CbomPolicyResult>>(() => {
    const map = new Map<string, CbomPolicyResult>();
    for (const cert of data) {
      map.set(cert.id, evaluateSingleCertPolicies(dbPolicies, cert));
    }
    return map;
  }, [data, dbPolicies]);

  const totalPolicyViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) count += r.totalViolations;
    return count;
  }, [policyResultsMap]);

  const certsWithViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) if (r.totalViolations > 0) count++;
    return count;
  }, [policyResultsMap]);

  /* ── Fetch project-level AI insight ─────────────────────── */
  const fetchCertInsight = useCallback(async () => {
    setInsight({ loading: true });
    try {
      const topNotSafe = data
        .filter((c) => !c.quantumSafe)
        .slice(0, 10)
        .map((c) => ({ name: `${c.commonName} (${c.keyAlgorithm} ${c.keyLength})`, count: 1 }));

      const algoCounts: Record<string, number> = {};
      data.filter((c) => !c.quantumSafe).forEach((c) => {
        const key = `${c.keyAlgorithm}-${c.keyLength}`;
        algoCounts[key] = (algoCounts[key] || 0) + 1;
      });
      const unknownAlgos = Object.entries(algoCounts).map(([name, count]) => ({ name, count }));

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          counts: { notSafe: violations, conditional: 0, safe: qsSafe, unknown: 0 },
          topNotSafe,
          topConditional: [],
          unknownAlgos,
          totalAssets: total,
          uniqueFiles: new Set(data.map((c) => c.commonName)).size,
          detectionSources: { 'digicert-tlm': total },
        }),
      });
      const result = await res.json();
      if (result.success) {
        setInsight({ loading: false, data: result });
      } else {
        setInsight({ loading: false, error: result.error || 'Failed to generate insight' });
      }
    } catch {
      setInsight({ loading: false, error: 'Failed to fetch AI insight' });
    }
  }, [data, total, qsSafe, violations]);

  /* ── Fetch per-certificate AI suggestion ────────────────── */
  const fetchSuggestion = useCallback(async (cert: DiscoveryCertificate) => {
    const key = cert.id;
    setSuggestions(prev => ({ ...prev, [key]: { loading: true } }));
    setExpandedId(key);
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: cert.keyAlgorithm,
          primitive: 'public-key',
          keyLength: cert.keyLength,
          quantumSafety: cert.quantumSafe ? 'quantum-safe' : 'not-quantum-safe',
          assetType: 'certificate',
          description: `TLS certificate ${cert.commonName} using ${cert.keyAlgorithm}-${cert.keyLength} signed with ${cert.signatureAlgorithm ?? 'unknown'}`,
          recommendedPQC: cert.quantumSafe ? undefined : 'ML-DSA-65 (Dilithium)',
          mode: cert.signatureAlgorithm ?? '',
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

  const stats: StatCardConfig[] = [
    { title: 'Total Certificates', value: total,      sub: `Discovered via DigiCert Trust Lifecycle Manager`, variant: 'default' },
    { title: 'Quantum-safe',       value: qsSafe,     sub: `${qsSafe} of ${total} certificates`,             variant: 'success' },
    { title: 'PQC Violations',     value: violations, sub: 'Non PQC-ready certificates',                     variant: 'danger' },
    { title: 'Policy Violations',  value: totalPolicyViolations, sub: `${certsWithViolations} of ${total} certificates have policy violations`, variant: totalPolicyViolations > 0 ? 'danger' : 'success' },
  ];

  const columns = [
    { key: 'commonName',     label: 'Common Name',   render: (c: DiscoveryCertificate) => <span style={{ fontWeight: 500 }}>{c.commonName}</span> },
    { key: 'caVendor',       label: 'CA Vendor',     render: (c: DiscoveryCertificate) => c.caVendor },
    { key: 'status',         label: 'Status',        render: (c: DiscoveryCertificate) => <CertStatusBadge status={c.status} /> },
    { key: 'keyAlgorithm',   label: 'Key Algorithm', render: (c: DiscoveryCertificate) => c.keyAlgorithm },
    { key: 'keyLength',      label: 'Key Length',    render: (c: DiscoveryCertificate) => c.keyLength },
    { key: 'signatureAlgo',  label: 'Signature',     render: (c: DiscoveryCertificate) => <span className={s.mono}>{c.signatureAlgorithm ?? '—'}</span> },
    { key: 'quantumSafe',    label: 'Quantum-safe',  render: (c: DiscoveryCertificate) => <QsBadge safe={c.quantumSafe} />, sortable: false },
    { key: 'policiesViolated', label: 'Policies Violated', sortable: false, render: (c: DiscoveryCertificate) => {
      const result = policyResultsMap.get(c.id);
      return (
        <PolicyViolationCell
          result={result}
          enableAi
          aiContext={{
            type: 'certificate',
            commonName: c.commonName,
            keyAlgorithm: c.keyAlgorithm,
            keyLength: c.keyLength,
            signatureAlgorithm: c.signatureAlgorithm,
            quantumSafe: c.quantumSafe,
            caVendor: c.caVendor,
            expiryDate: c.expiryDate,
            violatedPolicies: result?.violatedPolicies?.map((p) => p.policyName) ?? [],
          }}
        />
      );
    }},
    { key: 'source',         label: 'Source',        render: (c: DiscoveryCertificate) => <span className={s.sourceLink}>{c.source}</span> },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      headerStyle: { textAlign: 'right' as const },
      render: (c: DiscoveryCertificate) => {
        const sg = suggestions[c.id];
        return (
          <div className={s.actions}>
            {!c.quantumSafe && (
              <button
                className={s.aiFixBtn}
                title="Get AI-powered quantum-safe migration suggestion"
                disabled={sg?.loading}
                onClick={(ev) => { ev.stopPropagation(); fetchSuggestion(c); }}
              >
                {sg?.loading ? <Loader2 className={s.aiFixIcon} /> : <Sparkles className={s.aiFixIcon} />}
                Upgrade
              </button>
            )}
            <button className={s.actionBtn} onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}>
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
        title="Certificates"
        integrationName="DigiCert Trust Lifecycle Manager"
        integrationDescription="Import TLS/PKI certificates, CA hierarchies, and endpoint data via the TLM REST API. Automatically track key algorithms, expiry dates, and PQC-readiness across your managed certificate infrastructure."
        steps={STEPS}
        loading={isSampleLoading}
        onLoadSample={() => bulkCreate({ items: CERTIFICATES.map(({ id, ...rest }) => rest) })}
        onGoToIntegrations={onGoToIntegrations}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {violations > 0 && (
        <AiBanner onShowMe={fetchCertInsight} loading={insight.loading}>
          We identified <strong>{violations} certificates</strong> that are strong candidates to upgrade to <strong>ML-DSA</strong> based on TLM endpoint data.
        </AiBanner>
      )}

      {/* ── AI Insight Panel ─────────────────────────────────── */}
      {(insight.loading || insight.data || insight.error) && (
        <div className={s.cbomInsightWrap}>
          {insight.loading && (
            <div className={s.cbomInsightLoading}>
              <Loader2 className={s.cbomInsightLoadIcon} />
              <div className={s.cbomInsightPulseBar}>
                <div className={s.cbomInsightPulseBarBig} />
                <div className={s.cbomInsightPulseBarSmall} />
              </div>
            </div>
          )}

          {insight.error && (
            <div className={s.cbomInsightError}>
              <span className={s.cbomInsightErrorMsg}>{insight.error}</span>
              <button onClick={() => setInsight({ loading: false })} className={s.cbomDismissBtn}>
                <X className={s.cbomDismissIcon} />
              </button>
            </div>
          )}

          {insight.data && (() => {
            const d = insight.data!;
            const riskCap = d.riskLevel.charAt(0).toUpperCase() + d.riskLevel.slice(1);
            const panelBg = s[`cbomRiskBg${riskCap}`] || s.cbomRiskBgModerate;
            const textCls = s[`cbomRiskText${riskCap}`] || s.cbomRiskTextModerate;
            const barCls  = s[`cbomRiskBar${riskCap}`]  || s.cbomRiskBarModerate;
            const badgeCls = (level: string) => {
              const cap = level.charAt(0).toUpperCase() + level.slice(1);
              return s[`cbomRiskBadge${cap}`] || s.cbomRiskBadgeMedium;
            };

            return (
              <div className={`${s.cbomInsightPanel} ${panelBg}`}>
                {/* Top bar */}
                <div className={s.cbomInsightTopBar}>
                  <div className={s.cbomInsightTopLeft}>
                    <div className={s.cbomInsightTopTitle}>
                      <BarChart3 className={`${s.cbomInsightTopTitleIcon} ${textCls}`} />
                      <span className={s.cbomInsightTopTitleText}>Certificate Quantum Risk Assessment</span>
                    </div>
                    <span className={`${s.cbomInsightRiskBadge} ${badgeCls(d.riskLevel)}`}>
                      <AlertTriangle className={s.cbomBadgeIcon} />
                      {d.riskLevel}
                    </span>
                  </div>
                  <button onClick={() => setInsight({ loading: false })} className={s.cbomDismissBtn}>
                    <X className={s.cbomDismissIcon} />
                  </button>
                </div>

                {/* Risk score bar */}
                <div className={s.cbomInsightScoreBar}>
                  <div className={s.cbomInsightScoreRow}>
                    <div className={s.cbomInsightTrack}>
                      <div className={`${s.cbomInsightFill} ${barCls}`} style={{ width: `${d.riskScore}%` }} />
                    </div>
                    <span className={`${s.cbomInsightScoreText} ${textCls}`}>{d.riskScore}/100</span>
                  </div>
                </div>

                {/* Headline */}
                <p className={`${s.cbomInsightHeadline} ${textCls}`}>{d.headline}</p>

                {/* Summary */}
                <p className={s.cbomInsightSummary}>{d.summary}</p>

                {/* Priorities */}
                <div className={s.cbomInsightPriorities}>
                  <div className={s.cbomInsightPrioritiesLabel}>
                    <TrendingUp className={s.cbomInsightPrioritiesLabelIcon} />
                    Prioritized Actions
                  </div>
                  {d.priorities.map((p, i) => (
                    <div key={i} className={s.cbomInsightPriorityRow}>
                      <span className={`${s.cbomInsightImpactBadge} ${badgeCls(p.impact)}`}>
                        {p.impact}
                      </span>
                      <span className={s.cbomInsightPriorityAction}>{p.action}</span>
                      <span className={s.cbomInsightPriorityEffort}>
                        <Clock className={s.cbomInsightClockIcon} />
                        {p.effort}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Migration estimate */}
                <div className={s.cbomInsightMigration}>
                  <Clock className={`${s.cbomInsightMigrationIcon} ${textCls}`} />
                  <span className={s.cbomInsightMigrationText}>
                    <span className={s.cbomInsightMigrationLabel}>Migration Estimate:</span> {d.migrationEstimate}
                  </span>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      <Toolbar
        search={search}
        setSearch={setSearch}
        placeholder="Search by common name, CA vendor, algorithm, or source..."
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      {/* ── Inline table with expandable AI suggestion rows ── */}
      <div className={s.tableCard}>
        <h3 className={s.tableTitle}>Certificates ({filtered.length})</h3>
        <table className={s.table}>
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key} style={col.headerStyle}>{col.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((cert) => {
              const sg = suggestions[cert.id];
              return (
                <>{/* Fragment needed for adjacent rows */}
                  <tr key={cert.id}>
                    {columns.map((col) => (
                      <td key={col.key}>{col.render(cert)}</td>
                    ))}
                  </tr>
                  {/* AI suggestion expandable row */}
                  {expandedId === cert.id && sg && (
                    <tr key={`${cert.id}-ai`} className={s.aiSuggestionRow}>
                      <td colSpan={columns.length}>
                        {sg.loading ? (
                          <div className={s.aiLoading}>
                            <Loader2 size={16} /> Generating AI suggestion for {cert.commonName}…
                          </div>
                        ) : sg.error ? (
                          <div className={s.aiSuggestionPanel}>
                            <div className={s.aiSuggestionHeader}>
                              <Sparkles />
                              <span className={s.aiSuggestionTitle}>AI Suggestion</span>
                            </div>
                            <p className={s.aiSuggestionText}>{sg.error}</p>
                            <button className={s.aiFixBtn} onClick={() => fetchSuggestion(cert)}>
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
