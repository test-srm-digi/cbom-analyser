import { useMemo, useState, useCallback } from 'react';
import {
  ArrowLeft, GitBranch, ShieldCheck, ShieldAlert,
  TrendingUp, TrendingDown, BarChart3, AlertTriangle,
  Clock, Loader2, X, Sparkles,
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { useGetCbomImportsQuery } from '../../store/api';
import { CbomStatusBadge } from './components';
import type { DiscoveryCbomImport } from './types';
import s from './RepoOverviewPage.module.scss';
import shared from './components/shared.module.scss';

/* ── Types ───────────────────────────────────────────────────── */

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
  repoName: string;
  onBack: () => void;
  onViewCbom?: (id: string) => void;
}

/* ── Helpers ─────────────────────────────────────────────────── */

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  });
}

function formatDateShort(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function formatDateFull(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function pqcPct(qs: number, crypto: number) {
  return crypto > 0 ? Math.round((qs / crypto) * 100) : 0;
}

function deltaColor(val: number, positiveIsGood = true) {
  if (val === 0) return '#94a3b8';
  return (val > 0) === positiveIsGood ? '#16a34a' : '#dc2626';
}

/* ── Chart colours ───────────────────────────────────────────── */
const CHART_COLORS = {
  safe:        '#16a34a',
  notSafe:     '#dc2626',
  conditional: '#d97706',
  crypto:      '#2563eb',
  total:       '#7C3AED',
  pqc:         '#16a34a',
  safePct:     '#22c55e',
  notSafePct:  '#ef4444',
  condPct:     '#f59e0b',
};

/* ═════════════════════════════════════════════════════════════════
   RepoOverviewPage
   ═════════════════════════════════════════════════════════════════ */

export default function RepoOverviewPage({ repoName, onBack, onViewCbom }: Props) {
  const { data: allImports = [] } = useGetCbomImportsQuery();
  const [insight, setInsight] = useState<InsightState>({ loading: false });

  /* ── Filter imports for this repo ──────────────────────── */
  const repoImports = useMemo(() => {
    return allImports
      .filter((cb) => {
        const key = cb.applicationName || cb.fileName.replace(/-cbom.*$/, '');
        return key === repoName;
      })
      .sort((a, b) => new Date(a.importDate).getTime() - new Date(b.importDate).getTime());
  }, [allImports, repoName]);

  /* ── Aggregate stats ───────────────────────────────────── */
  const agg = useMemo(() => {
    const total = repoImports.length;
    const totalComponents = repoImports.reduce((s, c) => s + c.totalComponents, 0);
    const crypto = repoImports.reduce((s, c) => s + c.cryptoComponents, 0);
    const safe = repoImports.reduce((s, c) => s + c.quantumSafeComponents, 0);
    const notSafe = repoImports.reduce((s, c) => s + c.nonQuantumSafeComponents, 0);
    const conditional = repoImports.reduce((s, c) => s + c.conditionalComponents, 0);
    const processed = repoImports.filter((c) => c.status === 'Processed').length;
    const failed = repoImports.filter((c) => c.status === 'Failed' || c.status === 'Partial').length;
    const pct = pqcPct(safe, crypto);
    return { total, totalComponents, crypto, safe, notSafe, conditional, processed, failed, pct };
  }, [repoImports]);

  /* ── Latest & previous scan for trend deltas ───────────── */
  const latest = repoImports.length > 0 ? repoImports[repoImports.length - 1] : null;
  const prev   = repoImports.length > 1 ? repoImports[repoImports.length - 2] : null;

  /* ── Stat cards with trend data ────────────────────────── */
  const statCards = useMemo(() => {
    const latestCrypto   = latest?.cryptoComponents ?? 0;
    const prevCrypto     = prev?.cryptoComponents ?? latestCrypto;
    const latestPqc      = pqcPct(latest?.quantumSafeComponents ?? 0, latestCrypto);
    const prevPqc        = pqcPct(prev?.quantumSafeComponents ?? 0, prevCrypto);
    const latestNotSafe  = latest?.nonQuantumSafeComponents ?? 0;
    const prevNotSafe    = prev?.nonQuantumSafeComponents ?? latestNotSafe;
    const latestCond     = latest?.conditionalComponents ?? 0;
    const prevCond       = prev?.conditionalComponents ?? latestCond;

    return [
      {
        label: 'Total Crypto Assets',
        value: latestCrypto,
        sub: `${agg.totalComponents} total components`,
        delta: prevCrypto ? Math.round(((latestCrypto - prevCrypto) / prevCrypto) * 100) : 0,
        deltaRaw: latestCrypto - prevCrypto,
        positiveIsGood: true,
      },
      {
        label: 'Quantum Readiness',
        value: `${latestPqc}%`,
        sub: `${latest?.quantumSafeComponents ?? 0} safe of ${latestCrypto}`,
        delta: latestPqc - prevPqc,
        deltaRaw: latestPqc - prevPqc,
        positiveIsGood: true,
      },
      {
        label: 'Not Quantum Safe',
        value: latestNotSafe,
        sub: `${latestCrypto > 0 ? Math.round((latestNotSafe / latestCrypto) * 100) : 0}% need migration`,
        delta: prevNotSafe ? Math.round(((latestNotSafe - prevNotSafe) / prevNotSafe) * 100) : 0,
        deltaRaw: latestNotSafe - prevNotSafe,
        positiveIsGood: false,
      },
      {
        label: 'Conditional',
        value: latestCond,
        sub: 'Require configuration review',
        delta: prevCond ? Math.round(((latestCond - prevCond) / prevCond) * 100) : 0,
        deltaRaw: latestCond - prevCond,
        positiveIsGood: false,
      },
    ];
  }, [latest, prev, agg]);

  /* ── Chart data (one point per scan) ───────────────────── */
  const chartData = useMemo(() => {
    return repoImports.map((cb) => {
      const cr = cb.cryptoComponents || 1;
      return {
        name: formatDateShort(cb.importDate),
        pqcPct: pqcPct(cb.quantumSafeComponents, cb.cryptoComponents),
        safe: cb.quantumSafeComponents,
        notSafe: cb.nonQuantumSafeComponents,
        conditional: cb.conditionalComponents,
        crypto: cb.cryptoComponents,
        total: cb.totalComponents,
        safePct: Math.round((cb.quantumSafeComponents / cr) * 100),
        notSafePct: Math.round((cb.nonQuantumSafeComponents / cr) * 100),
        condPct: Math.round((cb.conditionalComponents / cr) * 100),
      };
    });
  }, [repoImports]);

  /* ── Table display (newest first) ──────────────────────── */
  const displayImports = useMemo(() => [...repoImports].reverse(), [repoImports]);

  /* ── AI insight ────────────────────────────────────────── */
  const fetchRepoInsight = useCallback(async () => {
    setInsight({ loading: true });
    try {
      const counts = {
        notSafe: agg.notSafe,
        conditional: agg.conditional,
        safe: agg.safe,
        unknown: 0,
      };
      const topNotSafe = repoImports
        .filter((cb) => cb.nonQuantumSafeComponents > 0)
        .sort((a, b) => b.nonQuantumSafeComponents - a.nonQuantumSafeComponents)
        .slice(0, 10)
        .map((cb) => ({ name: cb.fileName, count: cb.nonQuantumSafeComponents }));

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          counts,
          topNotSafe,
          topConditional: [],
          unknownAlgos: [],
          totalAssets: agg.crypto,
          uniqueFiles: repoImports.length,
          detectionSources: { 'cbom-import': agg.crypto },
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
  }, [repoImports, agg]);

  /* ── Render ────────────────────────────────────────────── */

  if (repoImports.length === 0) {
    return (
      <div className={s.page}>
        <button className={s.backBtn} onClick={onBack}>
          <ArrowLeft size={16} /> Back to CBOM Imports
        </button>
        <div className={s.emptyState}>
          <GitBranch size={48} strokeWidth={1} />
          <h3>Repository not found</h3>
          <p>No CBOM imports found for "{repoName}".</p>
        </div>
      </div>
    );
  }

  return (
    <div className={s.page}>
      {/* ── Back ─────────────────────────────────────── */}
      <button className={s.backBtn} onClick={onBack}>
        <ArrowLeft size={16} /> Back to CBOM Imports
      </button>

      {/* ── Header ───────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerTop}>
          <div>
            <p className={s.breadcrumb}>Discovery / CBOM Imports / Repositories</p>
            <h1 className={s.title}>
              <GitBranch size={24} className={s.titleIcon} />
              {repoName}
            </h1>
            <p className={s.subtitle}>
              {agg.total} CBOM scan{agg.total !== 1 && 's'} · {agg.totalComponents} components · {agg.crypto} crypto assets
            </p>
          </div>
          <div className={s.headerBadge}>
            <span className={`${s.pqcBadge} ${agg.pct >= 50 ? s.pqcGood : agg.pct >= 20 ? s.pqcWarn : s.pqcDanger}`}>
              {agg.pct}% PQC Ready
            </span>
          </div>
        </div>
      </div>

      {/* ── Stat Cards with trends ────────────────────── */}
      <div className={s.statsGrid}>
        {statCards.map((card, i) => {
          const clr = deltaColor(card.deltaRaw, card.positiveIsGood);
          const up  = card.deltaRaw > 0;
          return (
            <div key={i} className={s.statCard}>
              <div className={s.statTop}>
                <span className={s.statLabel}>{card.label}</span>
                {card.deltaRaw !== 0 && (
                  <span className={s.statTrend} style={{ color: clr }}>
                    {up ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                  </span>
                )}
              </div>
              <div className={s.statRow}>
                <span className={s.statValue}>{card.value}</span>
              </div>
              <div className={s.statSub}>{card.sub}</div>
              {card.delta !== 0 && (
                <div className={s.statChange} style={{ color: clr }}>
                  {up ? '↑' : '↓'} {Math.abs(card.delta)}% vs prev scan
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Charts Grid (2 × 2) ─────────────────────── */}
      {chartData.length >= 2 && (
        <div className={s.chartsGrid}>
          {/* 1 ▸ PQC Readiness Trend */}
          <div className={s.chartCard}>
            <div className={s.chartHeader}>
              <span className={s.chartTitle}>PQC Readiness Trend</span>
              <span className={s.chartSubtitle}>% quantum-safe over time</span>
            </div>
            <div className={s.chartBody}>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.06)" />
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="pqcPct" name="PQC %" stroke={CHART_COLORS.pqc} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'top', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.pqc, formatter: (v: number) => `${v}%` }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className={s.chartLegend}>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.pqc }} /> PQC Readiness %</span>
            </div>
          </div>

          {/* 2 ▸ Component Breakdown */}
          <div className={s.chartCard}>
            <div className={s.chartHeader}>
              <span className={s.chartTitle}>Component Breakdown</span>
              <span className={s.chartSubtitle}>Safe vs Not Safe vs Conditional</span>
            </div>
            <div className={s.chartBody}>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.06)" />
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} domain={[(min: number) => Math.floor(min * 0.9), (max: number) => Math.ceil(max * 1.05)]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="safe" name="Safe" stroke={CHART_COLORS.safe} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'top', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.safe }} />
                  <Line type="monotone" dataKey="notSafe" name="Not Safe" stroke={CHART_COLORS.notSafe} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'top', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.notSafe }} />
                  <Line type="monotone" dataKey="conditional" name="Conditional" stroke={CHART_COLORS.conditional} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'bottom', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.conditional }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className={s.chartLegend}>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.safe }} /> Safe</span>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.notSafe }} /> Not Safe</span>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.conditional }} /> Conditional</span>
            </div>
          </div>

          {/* 3 ▸ Crypto Asset Growth */}
          <div className={s.chartCard}>
            <div className={s.chartHeader}>
              <span className={s.chartTitle}>Crypto Asset Growth</span>
              <span className={s.chartSubtitle}>Crypto vs Total components over time</span>
            </div>
            <div className={s.chartBody}>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.06)" />
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} domain={[(min: number) => Math.floor(min * 0.9), (max: number) => Math.ceil(max * 1.05)]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="crypto" name="Crypto" stroke={CHART_COLORS.crypto} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'bottom', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.crypto }} />
                  <Line type="monotone" dataKey="total" name="Total" stroke={CHART_COLORS.total} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'top', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.total }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className={s.chartLegend}>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.crypto }} /> Crypto</span>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.total }} /> Total</span>
            </div>
          </div>

          {/* 4 ▸ Safety Distribution */}
          <div className={s.chartCard}>
            <div className={s.chartHeader}>
              <span className={s.chartTitle}>Safety Distribution</span>
              <span className={s.chartSubtitle}>% breakdown of safety categories</span>
            </div>
            <div className={s.chartBody}>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.06)" />
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="safePct" name="Safe %" stroke={CHART_COLORS.safePct} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'bottom', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.safePct, formatter: (v: number) => `${v}%` }} />
                  <Line type="monotone" dataKey="notSafePct" name="Not Safe %" stroke={CHART_COLORS.notSafePct} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'top', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.notSafePct, formatter: (v: number) => `${v}%` }} />
                  <Line type="monotone" dataKey="condPct" name="Conditional %" stroke={CHART_COLORS.condPct} strokeWidth={2} dot={{ r: 5, strokeWidth: 2 }} label={{ position: 'bottom', fontSize: 11, fontWeight: 600, fill: CHART_COLORS.condPct, formatter: (v: number) => `${v}%` }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className={s.chartLegend}>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.safePct }} /> Safe %</span>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.notSafePct }} /> Not Safe %</span>
              <span className={s.legendItem}><span className={s.legendDot} style={{ background: CHART_COLORS.condPct }} /> Conditional %</span>
            </div>
          </div>
        </div>
      )}

      {/* ── AI Analysis ──────────────────────────────── */}
      <div className={s.aiSection}>
        <div className={s.aiHeader}>
          <div>
            <h3 className={s.sectionTitle}>
              <Sparkles size={18} className={s.aiIcon} />
              AI Repository Analysis
            </h3>
            <p className={s.sectionSub}>
              Get an AI-powered risk assessment and migration recommendations for this repository
            </p>
          </div>
          <button
            className={s.aiBtn}
            onClick={fetchRepoInsight}
            disabled={insight.loading}
          >
            {insight.loading ? (
              <><Loader2 size={14} className={s.spinning} /> Analysing…</>
            ) : (
              <><Sparkles size={14} /> Analyse Repository</>
            )}
          </button>
        </div>

        {insight.error && (
          <div className={shared.cbomInsightError}>
            <span className={shared.cbomInsightErrorMsg}>{insight.error}</span>
            <button onClick={() => setInsight({ loading: false })} className={shared.cbomDismissBtn}>
              <X className={shared.cbomDismissIcon} />
            </button>
          </div>
        )}

        {insight.data && (() => {
          const d = insight.data!;
          const riskCap = d.riskLevel.charAt(0).toUpperCase() + d.riskLevel.slice(1);
          const textCls = shared[`cbomRiskText${riskCap}`] || shared.cbomRiskTextModerate;
          const barCls  = shared[`cbomRiskBar${riskCap}`]  || shared.cbomRiskBarModerate;
          const panelBg = shared[`cbomRiskBg${riskCap}`]   || shared.cbomRiskBgModerate;
          const badgeCls = (level: string) => {
            const cap = level.charAt(0).toUpperCase() + level.slice(1);
            return shared[`cbomRiskBadge${cap}`] || shared.cbomRiskBadgeMedium;
          };

          return (
            <div className={`${shared.cbomInsightPanel} ${panelBg}`}>
              <div className={shared.cbomInsightTopBar}>
                <div className={shared.cbomInsightTopLeft}>
                  <div className={shared.cbomInsightTopTitle}>
                    <BarChart3 className={`${shared.cbomInsightTopTitleIcon} ${textCls}`} />
                    <span className={shared.cbomInsightTopTitleText}>Repository Quantum Risk Assessment</span>
                  </div>
                  <span className={`${shared.cbomInsightRiskBadge} ${badgeCls(d.riskLevel)}`}>
                    <AlertTriangle className={shared.cbomBadgeIcon} />
                    {d.riskLevel}
                  </span>
                </div>
                <button onClick={() => setInsight({ loading: false })} className={shared.cbomDismissBtn}>
                  <X className={shared.cbomDismissIcon} />
                </button>
              </div>

              <div className={shared.cbomInsightScoreBar}>
                <div className={shared.cbomInsightScoreRow}>
                  <div className={shared.cbomInsightTrack}>
                    <div className={`${shared.cbomInsightFill} ${barCls}`} style={{ width: `${d.riskScore}%` }} />
                  </div>
                  <span className={`${shared.cbomInsightScoreText} ${textCls}`}>{d.riskScore}/100</span>
                </div>
              </div>

              <p className={`${shared.cbomInsightHeadline} ${textCls}`}>{d.headline}</p>
              <p className={shared.cbomInsightSummary}>{d.summary}</p>

              <div className={shared.cbomInsightPriorities}>
                <div className={shared.cbomInsightPrioritiesLabel}>
                  <TrendingUp className={shared.cbomInsightPrioritiesLabelIcon} />
                  Prioritized Actions
                </div>
                {d.priorities.map((p, i) => (
                  <div key={i} className={shared.cbomInsightPriorityRow}>
                    <span className={`${shared.cbomInsightImpactBadge} ${badgeCls(p.impact)}`}>
                      {p.impact}
                    </span>
                    <span className={shared.cbomInsightPriorityAction}>{p.action}</span>
                    <span className={shared.cbomInsightPriorityEffort}>
                      <Clock className={shared.cbomInsightClockIcon} />
                      {p.effort}
                    </span>
                  </div>
                ))}
              </div>

              <div className={shared.cbomInsightMigration}>
                <Clock className={`${shared.cbomInsightMigrationIcon} ${textCls}`} />
                <span className={shared.cbomInsightMigrationText}>
                  <span className={shared.cbomInsightMigrationLabel}>Migration Estimate:</span> {d.migrationEstimate}
                </span>
              </div>
            </div>
          );
        })()}
      </div>

      {/* ── CBOM Scan History ────────────────────────── */}
      <div className={s.timelineSection}>
        <h3 className={s.sectionTitle}>
          <Clock size={18} className={s.sectionIcon} />
          CBOM Scan History
        </h3>
        <p className={s.sectionSub}>Track PQC readiness progression across scans</p>

        {/* Table of all CBOMs */}
        <div className={shared.tableCard} style={{ marginTop: 16 }}>
          <h3 className={shared.tableTitle}>All CBOM Scans ({repoImports.length})</h3>
          <table className={shared.table}>
            <thead>
              <tr>
                <th>File Name</th>
                <th>Format</th>
                <th>Spec</th>
                <th>Components</th>
                <th>Crypto</th>
                <th style={{ textAlign: 'center' }}>PQC %</th>
                <th style={{ textAlign: 'center' }}>Safe</th>
                <th style={{ textAlign: 'center' }}>Not Safe</th>
                <th style={{ textAlign: 'center' }}>Conditional</th>
                <th>Imported</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {displayImports.map((cb) => {
                const cbPct = pqcPct(cb.quantumSafeComponents, cb.cryptoComponents);
                const origIdx = repoImports.findIndex((r) => r.id === cb.id);
                const prev = origIdx > 0 ? repoImports[origIdx - 1] : null;
                const prevPct = prev ? pqcPct(prev.quantumSafeComponents, prev.cryptoComponents) : null;
                const pctChange = prevPct !== null ? cbPct - prevPct : null;
                return (
                  <tr
                    key={cb.id}
                    style={{ cursor: onViewCbom ? 'pointer' : undefined }}
                    onClick={() => onViewCbom?.(cb.id)}
                  >
                    <td>
                      <span className={shared.mono} style={{ fontSize: 11 }}>{cb.fileName}</span>
                    </td>
                    <td>{cb.format}</td>
                    <td>{cb.specVersion}</td>
                    <td>{cb.totalComponents}</td>
                    <td>{cb.cryptoComponents}</td>
                    <td style={{ textAlign: 'center' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontWeight: 600, fontSize: 12,
                        color: cbPct >= 50 ? '#16a34a' : cbPct >= 20 ? '#d97706' : '#dc2626',
                      }}>
                        {cbPct}%
                        {pctChange !== null && pctChange !== 0 && (
                          <span style={{ fontSize: 10, color: deltaColor(pctChange) }}>
                            ({pctChange > 0 ? '+' : ''}{pctChange})
                          </span>
                        )}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={shared.safeCount}>{cb.quantumSafeComponents}</span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={cb.nonQuantumSafeComponents > 0 ? shared.notSafeCount : shared.safeCount}>
                        {cb.nonQuantumSafeComponents > 0 && <ShieldAlert className={shared.notSafeIcon} />}
                        {cb.nonQuantumSafeComponents}
                      </span>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={shared.mono}>{cb.conditionalComponents}</span>
                    </td>
                    <td>{formatDateFull(cb.importDate)}</td>
                    <td><CbomStatusBadge status={cb.status} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
