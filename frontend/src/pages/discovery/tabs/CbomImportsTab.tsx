import { useMemo, useState, useCallback } from 'react';
import { ShieldAlert, ShieldCheck, TrendingUp as TrendUp, TrendingDown, Loader2, X, BarChart3, AlertTriangle, TrendingUp, Clock, GitBranch, FileText, ArrowUpRight, ShieldX } from 'lucide-react';
import { StatCards, Toolbar, AiBanner, DataTable, CbomStatusBadge, ProgressBar, EmptyState, PolicyViolationCell } from '../components';
import type { IntegrationStep } from '../components';
import { CBOM_IMPORTS } from '../data';
import { useGetCbomImportsQuery, useBulkCreateCbomImportsMutation, useDeleteAllCbomImportsMutation, useGetPoliciesQuery } from '../../../store/api';
import type { DiscoveryCbomImport, StatCardConfig } from '../types';
import { evaluatePolicies } from '../../policies';
import type { CbomPolicyResult } from '../../policies';
import { parseCbomJson } from '../../../utils/cbomParser';
import s from '../components/shared.module.scss';

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
  data?: ProjectInsight;
  error?: string;
}

interface Props {
  search: string;
  setSearch: (v: string) => void;
  onViewCbom?: (id: string) => void;
  onViewRepo?: (name: string) => void;
  onGoToIntegrations?: () => void;
}

const STEPS: IntegrationStep[] = [
  { step: 1, title: 'Navigate to Integrations', description: 'Go to the Integrations page and locate "CBOM File Import" in the catalog.' },
  { step: 2, title: 'Choose import method', description: 'Select how to import: upload a local CBOM file (JSON/XML), fetch from a URL, or pull from a CI/CD build artifact.' },
  { step: 3, title: 'Parse & validate', description: 'The system will parse the CBOM (CycloneDX or SPDX format), validate the schema, and extract cryptographic component inventory.' },
  { step: 4, title: 'Review imported data', description: 'Component counts, crypto algorithms, PQC readiness scores, and processing status will appear here after import.' },
];

export default function CbomImportsTab({ search, setSearch, onViewCbom, onViewRepo, onGoToIntegrations }: Props) {
  const { data: apiData = [], isLoading } = useGetCbomImportsQuery();
  const [bulkCreate, { isLoading: isSampleLoading }] = useBulkCreateCbomImportsMutation();
  const [deleteAll, { isLoading: isResetLoading }] = useDeleteAllCbomImportsMutation();
  const [insight, setInsight] = useState<InsightState>({ loading: false });
  const [activeSubTab, setActiveSubTab] = useState<'imports' | 'repositories'>('imports');
  const data = apiData;
  const loaded = data.length > 0;

  // Data from a real integration has integrationId set — hide reset for integration-sourced data
  const isSampleData = loaded && data.every((cb) => !cb.integrationId);

  const total         = data.length;
  const processed     = data.filter((cb) => cb.status === 'Processed').length;
  const failed        = data.filter((cb) => cb.status === 'Failed' || cb.status === 'Partial').length;
  const totalCrypto   = data.reduce((sum, cb) => sum + cb.cryptoComponents, 0);
  const totalQsSafe   = data.reduce((sum, cb) => sum + cb.quantumSafeComponents, 0);
  const totalNotSafe  = data.reduce((sum, cb) => sum + cb.nonQuantumSafeComponents, 0);
  const totalConditional = data.reduce((sum, cb) => sum + cb.conditionalComponents, 0);

  /* ── Policy evaluation per CBOM import ────────────────── */
  const { data: dbPolicies = [] } = useGetPoliciesQuery();

  const policyResultsMap = useMemo<Map<string, CbomPolicyResult>>(() => {
    const map = new Map<string, CbomPolicyResult>();
    for (const cb of data) {
      if (!cb.cbomFile) {
        // No raw CBOM to parse — use approximate evaluation from aggregate counts
        const hasViolation = cb.nonQuantumSafeComponents > 0;
        const violatedPolicies = hasViolation
          ? dbPolicies
              .filter((p) => p.status === 'active' && p.rules.some((r) => r.field === 'quantumSafe'))
              .map((p) => ({
                policyId: p.id,
                policyName: p.name,
                severity: p.severity,
                violated: true,
                violatingAssetCount: cb.nonQuantumSafeComponents,
                violations: [],
              }))
          : [];

        map.set(cb.id, {
          totalViolations: violatedPolicies.length,
          violatedPolicies,
          passedPolicies: [],
        });
        continue;
      }
      try {
        const raw = atob(cb.cbomFile);
        const { doc } = parseCbomJson(raw, cb.fileName);
        const result = evaluatePolicies(dbPolicies, doc.cryptoAssets);
        map.set(cb.id, result);
      } catch {
        // Parse failed — fall back to aggregate-based evaluation
        map.set(cb.id, { totalViolations: 0, violatedPolicies: [], passedPolicies: [] });
      }
    }
    return map;
  }, [data, dbPolicies]);

  const totalPolicyViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) count += r.totalViolations;
    return count;
  }, [policyResultsMap]);

  const importsWithViolations = useMemo(() => {
    let count = 0;
    for (const r of policyResultsMap.values()) if (r.totalViolations > 0) count++;
    return count;
  }, [policyResultsMap]);

  const fetchCbomInsight = useCallback(async () => {
    setInsight({ loading: true });
    try {
      const counts = {
        notSafe: totalNotSafe,
        conditional: totalConditional,
        safe: totalQsSafe,
        unknown: 0,
      };

      // Build top not-safe entries from CBOM file names
      const topNotSafe = data
        .filter((cb) => cb.nonQuantumSafeComponents > 0)
        .sort((a, b) => b.nonQuantumSafeComponents - a.nonQuantumSafeComponents)
        .slice(0, 10)
        .map((cb) => ({ name: cb.applicationName || cb.fileName, count: cb.nonQuantumSafeComponents }));

      const uniqueFiles = new Set(data.map((cb) => cb.fileName)).size;
      const detectionSources: Record<string, number> = { 'cbom-import': totalCrypto };

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          counts,
          topNotSafe,
          topConditional: [],
          unknownAlgos: [],
          totalAssets: totalCrypto,
          uniqueFiles,
          detectionSources,
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
  }, [data, totalCrypto, totalQsSafe]);

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

  /* ── Aggregate by repository (applicationName) ─────────── */
  interface RepoSummary {
    name: string;
    cbomCount: number;
    totalComponents: number;
    cryptoComponents: number;
    quantumSafe: number;
    notSafe: number;
    conditional: number;
    pqcPct: number;
    riskReduced: number; // not-safe assets mitigated relative to total crypto
    latestImport: string;
    failedCount: number;
  }

  const repos = useMemo<RepoSummary[]>(() => {
    const map = new Map<string, RepoSummary>();
    for (const cb of data) {
      const key = cb.applicationName || cb.fileName.replace(/-cbom.*$/, '');
      const existing = map.get(key);
      if (existing) {
        existing.cbomCount += 1;
        existing.totalComponents += cb.totalComponents;
        existing.cryptoComponents += cb.cryptoComponents;
        existing.quantumSafe += cb.quantumSafeComponents;
        existing.notSafe += cb.nonQuantumSafeComponents;
        existing.conditional += cb.conditionalComponents;
        if (cb.importDate > existing.latestImport) existing.latestImport = cb.importDate;
        if (cb.status === 'Failed' || cb.status === 'Partial') existing.failedCount += 1;
      } else {
        map.set(key, {
          name: key,
          cbomCount: 1,
          totalComponents: cb.totalComponents,
          cryptoComponents: cb.cryptoComponents,
          quantumSafe: cb.quantumSafeComponents,
          notSafe: cb.nonQuantumSafeComponents,
          conditional: cb.conditionalComponents,
          pqcPct: 0,
          riskReduced: 0,
          latestImport: cb.importDate,
          failedCount: (cb.status === 'Failed' || cb.status === 'Partial') ? 1 : 0,
        });
      }
    }
    // Compute derived metrics
    for (const r of map.values()) {
      r.pqcPct = r.cryptoComponents > 0 ? Math.round((r.quantumSafe / r.cryptoComponents) * 100) : 0;
      r.riskReduced = r.cryptoComponents > 0 ? Math.round(((r.cryptoComponents - r.notSafe) / r.cryptoComponents) * 100) : 0;
    }
    return Array.from(map.values()).sort((a, b) => b.cryptoComponents - a.cryptoComponents);
  }, [data]);

  const filteredRepos = useMemo(() => {
    if (!search) return repos;
    const q = search.toLowerCase();
    return repos.filter((r) => r.name.toLowerCase().includes(q));
  }, [search, repos]);

  const stats: StatCardConfig[] = [
    { title: 'CBOM Files Imported', value: total,       sub: `${processed} processed successfully — ${totalCrypto} crypto components found`, variant: 'default' },
    { title: 'PQC Components',     value: totalQsSafe,  sub: `${totalQsSafe} of ${totalCrypto} crypto components are quantum-safe`,          variant: 'success' },
    { title: 'Import Issues',      value: failed,       sub: 'Failed or partially processed imports',                                        variant: 'danger' },
    { title: 'Policy Violations',  value: totalPolicyViolations, sub: `${importsWithViolations} of ${total} imports have policy violations`, variant: totalPolicyViolations > 0 ? 'danger' : 'success' },
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
    { key: 'notSafe',          label: 'Not Safe',          render: (cb: DiscoveryCbomImport) => (
      <span className={cb.nonQuantumSafeComponents > 0 ? s.notSafeCount : s.safeCount}>
        {cb.nonQuantumSafeComponents > 0 && <ShieldAlert className={s.notSafeIcon} />}
        {cb.nonQuantumSafeComponents}
      </span>
    ) },
    { key: 'policiesViolated', label: 'Policies Violated', sortable: false, render: (cb: DiscoveryCbomImport) => {
      const result = policyResultsMap.get(cb.id);
      return (
        <PolicyViolationCell
          result={result}
          enableAi
          aiContext={{
            type: 'cbom-import',
            name: cb.applicationName ?? cb.fileName,
            cryptoComponents: cb.cryptoComponents,
            nonQuantumSafe: cb.nonQuantumSafeComponents,
            quantumSafe: cb.quantumSafeComponents,
            violatedPolicies: result?.violatedPolicies?.map((p) => p.policyName) ?? [],
          }}
        />
      );
    }},
    { key: 'status',          label: 'Status',            render: (cb: DiscoveryCbomImport) => <CbomStatusBadge status={cb.status} /> },
    { key: 'importDate',      label: 'Imported',          render: (cb: DiscoveryCbomImport) => formatDate(cb.importDate) },
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
        onGoToIntegrations={onGoToIntegrations}
      />
    );
  }

  return (
    <>
      <StatCards cards={stats} />

      {totalCrypto > 0 && (
        <AiBanner onShowMe={fetchCbomInsight} loading={insight.loading}>
          Across {total} CBOM imports, <strong>{totalNotSafe} cryptographic components</strong> are not quantum-safe.
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
                      <span className={s.cbomInsightTopTitleText}>CBOM Quantum Risk Assessment</span>
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
        placeholder={activeSubTab === 'imports' ? 'Search by application name, file name, format, or spec version...' : 'Search by repository name...'}
        onReset={isSampleData ? () => deleteAll() : undefined}
        resetLoading={isSampleData ? isResetLoading : undefined}
      />

      {/* ── Sub-tab switcher ─────────────────────────────────── */}
      <div className={s.subTabBar}>
        <button
          className={`${s.subTabBtn} ${activeSubTab === 'imports' ? s.subTabBtnActive : ''}`}
          onClick={() => setActiveSubTab('imports')}
        >
          <FileText className={s.subTabIcon} />
          All Imports
          <span className={s.subTabCount}>{filtered.length}</span>
        </button>
        <button
          className={`${s.subTabBtn} ${activeSubTab === 'repositories' ? s.subTabBtnActive : ''}`}
          onClick={() => setActiveSubTab('repositories')}
        >
          <GitBranch className={s.subTabIcon} />
          Repositories
          <span className={s.subTabCount}>{repos.length}</span>
        </button>
      </div>

      {/* ── Tab: All Imports ─────────────────────────────────── */}
      {activeSubTab === 'imports' && (
        <DataTable
          title="CBOM Imports"
          count={filtered.length}
          columns={columns}
          data={filtered}
          rowKey={(cb) => cb.id}
          onRowClick={onViewCbom ? (cb) => onViewCbom(cb.id) : undefined}
        />
      )}

      {/* ── Tab: Repositories ────────────────────────────────── */}
      {activeSubTab === 'repositories' && (
        <div className={s.tableCard}>
          <h3 className={s.tableTitle}>Repositories ({filteredRepos.length})</h3>
          <table className={s.table}>
            <thead>
              <tr>
                <th>Repository</th>
                <th>CBOM Scans</th>
                <th>Crypto Assets</th>
                <th style={{ textAlign: 'center' }}>PQC Readiness</th>
                <th style={{ textAlign: 'center' }}>Quantum Safe</th>
                <th style={{ textAlign: 'center' }}>Not Safe</th>
                <th style={{ textAlign: 'center' }}>Risk Mitigated</th>
                <th>Latest Scan</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredRepos.map((repo) => {
                const canNavigate = onViewRepo && repo.cbomCount >= 2;
                return (
                  <tr
                    key={repo.name}
                    style={{ cursor: canNavigate ? 'pointer' : 'default', opacity: repo.cbomCount < 2 ? 0.7 : 1 }}
                    onClick={() => canNavigate && onViewRepo(repo.name)}
                    title={repo.cbomCount < 2 ? 'At least 2 CBOM scans required for comparison' : undefined}
                  >
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <GitBranch size={14} style={{ color: '#7C3AED', flexShrink: 0 }} />
                        <span style={{ fontWeight: 600 }}>{repo.name}</span>
                        {canNavigate && <ArrowUpRight size={12} style={{ color: '#94a3b8' }} />}
                      </div>
                      <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>
                        {repo.totalComponents} total components
                        {repo.cbomCount < 2 && <span style={{ marginLeft: 6, fontSize: 10, color: '#d97706' }}>· Min 2 scans needed</span>}
                      </div>
                    </td>
                    <td><span className={s.mono}>{repo.cbomCount}</span></td>
                    <td><span style={{ fontWeight: 600 }}>{repo.cryptoComponents}</span></td>
                    <td style={{ textAlign: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
                        <ProgressBar value={repo.quantumSafe} max={repo.cryptoComponents} />
                        <span style={{ fontWeight: 600, fontSize: 12, color: repo.pqcPct >= 50 ? '#16a34a' : repo.pqcPct >= 20 ? '#d97706' : '#dc2626', minWidth: 32 }}>
                          {repo.pqcPct}%
                        </span>
                      </div>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={s.safeCount}>
                        <ShieldCheck size={13} style={{ color: '#16a34a' }} />
                        {repo.quantumSafe}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={repo.notSafe > 0 ? s.notSafeCount : s.safeCount}>
                        {repo.notSafe > 0 && <ShieldAlert className={s.notSafeIcon} />}
                        {repo.notSafe}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 12, fontWeight: 600,
                        color: repo.riskReduced >= 80 ? '#16a34a' : repo.riskReduced >= 50 ? '#d97706' : '#dc2626',
                      }}>
                        {repo.riskReduced >= 50 ? <TrendUp size={13} /> : <TrendingDown size={13} />}
                        {repo.riskReduced}%
                      </span>
                    </td>
                    <td>{formatDate(repo.latestImport)}</td>
                    <td>
                      {repo.failedCount > 0
                        ? <CbomStatusBadge status="Partial" />
                        : <CbomStatusBadge status="Processed" />}
                    </td>
                  </tr>
                );
              })}
              {filteredRepos.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: 32, color: '#94a3b8' }}>
                    No repositories match your search
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
