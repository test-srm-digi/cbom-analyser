import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import {
  ExternalLink, ChevronLeft, ChevronRight, SlidersHorizontal,
  Github, GitBranch, FolderOpen, Sparkles, Loader2,
  X, Copy, Check, Zap, ShieldCheck, ChevronDown, ChevronUp,
  ShieldAlert, ShieldQuestion, Package, Filter,
  BarChart3, AlertTriangle, TrendingUp, Clock, Ticket,
} from 'lucide-react';
import { CryptoAsset, QuantumSafetyStatus, ComplianceStatus, PQCReadinessVerdict, CBOMRepository } from '../types';
import { useGetPoliciesQuery } from '../store/api';
import { evaluateSingleAssetPolicies } from '../pages/policies';
import type { CbomPolicyResult } from '../pages/policies';
import PolicyViolationCell from '../pages/discovery/components/PolicyViolationCell';
import { CreateTicketModal } from '../pages/tracking';
import type { TicketContext } from '../pages/tracking';
import { useCreateTicketMutation } from '../store/api/trackingApi';
import s from './AssetListView.module.scss';

interface AssetListViewProps {
  assets: CryptoAsset[];
  repository?: CBOMRepository;
}

interface SuggestionState {
  fix?: string;
  codeSnippet?: string;
  confidence?: string;
  loading: boolean;
  error?: string;
  collapsed?: boolean;
}

interface ProjectInsight {
  riskLevel: 'critical' | 'high' | 'moderate' | 'low';
  headline: string;
  summary: string;
  priorities: { action: string; impact: 'critical' | 'high' | 'medium' | 'low'; effort: string }[];
  riskScore: number;
  migrationEstimate: string;
}

interface InsightState {
  loading: boolean;
  data?: ProjectInsight;
  error?: string;
}

const ITEMS_PER_PAGE_OPTIONS = [10, 25, 50];

function getPrimitiveLabel(primitive?: string): string {
  if (!primitive) return '—';
  const labels: Record<string, string> = {
    'hash': 'HASH\nHash Function',
    'block-cipher': 'BLOCK-CIPHER\nBlock Cipher',
    'pke': 'PKE\nPublic Key Encryption',
    'signature': 'SIGNATURE\nDigital Signature',
    'keygen': 'KEYGEN\nKey Generation',
    'digest': 'DIGEST\nDigest',
    'mac': 'MAC\nMessage Auth Code',
    'ae': 'AE\nAuthenticated Encryption',
    'stream-cipher': 'STREAM\nStream Cipher',
    'other': 'OTHER\nOther',
  };
  return labels[primitive] || primitive.toUpperCase();
}

function getStatusLabel(status?: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return 'Safe';
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return 'Not Safe';
    case QuantumSafetyStatus.CONDITIONAL: return 'Conditional';
    default: return 'Unknown';
  }
}

function getStatusBg(status?: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return s.safeBadge;
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return s.notSafeBadge;
    case QuantumSafetyStatus.CONDITIONAL: return s.condBadge;
    default: return s.unknownBadge;
  }
}

function getStatusIcon(status?: QuantumSafetyStatus) {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return ShieldCheck;
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return ShieldAlert;
    case QuantumSafetyStatus.CONDITIONAL: return ShieldQuestion;
    default: return ShieldQuestion;
  }
}

function confidenceBadge(level?: string) {
  if (!level) return null;
  const map: Record<string, string> = {
    high: s.confHigh,
    medium: s.confMedium,
    low: s.confLow,
  };
  return (
    <span className={map[level] || s.confLow}>
      <ShieldCheck className={s.badgeIcon} />
      {level}
    </span>
  );
}

function PqcVerdictBadge({ asset }: { asset: CryptoAsset }) {
  const v = asset.pqcVerdict;
  const cardRef = useRef<HTMLDivElement>(null);
  const [hovered, setHovered] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  useEffect(() => {
    if (hovered && cardRef.current) {
      const rect = cardRef.current.getBoundingClientRect();
      setPos({ top: rect.top, left: rect.left });
    }
  }, [hovered]);

  if (!v) return null;

  const config: Record<string, { labelCls: string; stripCls: string; arcCls: string; label: string }> = {
    [PQCReadinessVerdict.PQC_READY]: { labelCls: s.verdictLabelSafe, stripCls: s.verdictStripSafe, arcCls: s.verdictRingArcSafe, label: 'PQC Ready' },
    [PQCReadinessVerdict.NOT_PQC_READY]: { labelCls: s.verdictLabelDanger, stripCls: s.verdictStripDanger, arcCls: s.verdictRingArcDanger, label: 'Not Ready' },
    [PQCReadinessVerdict.REVIEW_NEEDED]: { labelCls: s.verdictLabelWarn, stripCls: s.verdictStripWarning, arcCls: s.verdictRingArcWarn, label: 'Review' },
  };

  const c = config[v.verdict] || config[PQCReadinessVerdict.REVIEW_NEEDED];
  const circumference = 2 * Math.PI * 12;
  const offset = circumference - (circumference * v.confidence) / 100;
  const source = asset.detectionSource || '';

  const tooltip = (
    <div className={s.tooltipBody}>
      {v.reasons.map((r: string, i: number) => (
        <div key={i} className={s.tooltipRow}>
          <span className={s.tooltipBullet}>{r.includes('✓') ? '✓' : r.includes('✗') ? '✗' : '•'}</span>
          <span>{r}</span>
        </div>
      ))}
      {v.parameters && Object.keys(v.parameters).length > 0 && (
        <div className={s.tooltipParams}>
          <span className={s.tooltipParamsTitle}>Detected Parameters</span>
          <div className={s.tooltipParamsGrid}>
            {Object.entries(v.parameters).map(([k, val]) => (
              <div key={k}>
                <span className={s.tooltipParamKey}>{k}: </span>
                <span className={s.tooltipParamVal}>{String(val)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {v.recommendation && (
        <div className={s.tooltipRec}>
          {v.recommendation}
        </div>
      )}
    </div>
  );

  return (
    <div
      className={s.verdictGroup}
      ref={cardRef}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div className={s.verdictCard}>
        <div className={c.stripCls} />
        <div className={s.verdictCardBody}>
          <div className={s.verdictRing}>
            <svg className={s.verdictRingSvg} viewBox="0 0 32 32">
              <circle className={s.verdictRingBg} cx="16" cy="16" r="12" />
              <circle
                className={c.arcCls}
                cx="16" cy="16" r="12"
                strokeDasharray={circumference}
                strokeDashoffset={offset}
              />
            </svg>
            <span className={s.verdictRingPct}>{v.confidence}</span>
          </div>
          <div className={s.verdictInfo}>
            <span className={c.labelCls}>{c.label}</span>
            {source && <span className={s.verdictSrc}>{source}</span>}
          </div>
        </div>
      </div>
      {hovered && pos && createPortal(
        <div
          className={s.verdictTooltipPortal}
          style={{ top: pos.top, left: pos.left }}
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
        >
          <div className={s.verdictTooltipInner}>
            {tooltip}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}

function detectionSourceBadge(source?: string) {
  if (!source) return null;
  const map: Record<string, string> = {
    sonar: s.srcSonar,
    regex: s.srcRegex,
    dependency: s.srcDependency,
    network: s.srcNetwork,
  };
  return (
    <span className={map[source] || s.srcRegex}>
      {source === 'dependency' && <Package className={s.srcIcon} />}
      {source}
    </span>
  );
}

function buildGitHubFileUrl(repoUrl: string, branch: string, basePath: string, fileName: string, lineNumber?: number): string {
  const base = repoUrl.replace(/\/$/, '');
  const prefix = basePath.replace(/^\//, '').replace(/\/$/, '');
  const filePart = fileName.replace(/^\//, '');
  const fullPath = prefix ? `${prefix}/${filePart}` : filePart;
  const url = `${base}/blob/${branch}/${fullPath}`;
  return lineNumber ? `${url}#L${lineNumber}` : url;
}

export default function AssetListView({ assets, repository }: AssetListViewProps) {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [sortField, setSortField] = useState<'name' | 'primitive' | 'location' | 'safety'>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [filterText, setFilterText] = useState('');
  const [safetyFilter, setSafetyFilter] = useState<Set<QuantumSafetyStatus | 'unknown'>>(new Set());
  const [repoUrl, setRepoUrl] = useState(repository?.url ?? '');
  const [branch, setBranch] = useState(() => {
    const b = repository?.branch ?? 'main';
    if (['main', 'master', 'develop'].includes(b)) return b;
    return 'custom';
  });
  const [customBranch, setCustomBranch] = useState(() => {
    const b = repository?.branch ?? '';
    return ['main', 'master', 'develop'].includes(b) ? '' : b;
  });
  const [basePath, setBasePath] = useState('');
  const [suggestions, setSuggestions] = useState<Record<string, SuggestionState>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [insight, setInsight] = useState<InsightState>({ loading: false });
  const [ticketCtx, setTicketCtx] = useState<TicketContext | null>(null);
  const [createTicket] = useCreateTicketMutation();
  const [colWidths, setColWidths] = useState<Record<number, number>>({});
  const resizingCol = useRef<{ idx: number; startX: number; startW: number } | null>(null);

  // Per-column minimum widths (index-matched to colgroup order)
  const COL_MIN: Record<number, number> = { 0: 120, 1: 170, 2: 100, 3: 140, 4: 170, 5: 120, 6: 240, 7: 110 };

  /* ── Policy evaluation per asset ──────────────────────── */
  const { data: dbPolicies = [] } = useGetPoliciesQuery();
  const policyResultsMap = useMemo<Map<string, CbomPolicyResult>>(() => {
    const map = new Map<string, CbomPolicyResult>();
    if (dbPolicies.length === 0) return map;
    for (const asset of assets) {
      map.set(asset.id, evaluateSingleAssetPolicies(dbPolicies, asset));
    }
    return map;
  }, [assets, dbPolicies]);

  const onResizeStart = useCallback((e: React.MouseEvent, colIdx: number) => {
    e.preventDefault();
    e.stopPropagation();
    const th = (e.target as HTMLElement).parentElement!;
    const startW = th.offsetWidth;
    resizingCol.current = { idx: colIdx, startX: e.clientX, startW };

    const onMove = (ev: MouseEvent) => {
      if (!resizingCol.current) return;
      const diff = ev.clientX - resizingCol.current.startX;
      const min = COL_MIN[colIdx] ?? 80;
      const newW = Math.max(min, resizingCol.current.startW + diff);
      setColWidths(prev => ({ ...prev, [colIdx]: newW }));
    };

    const onUp = () => {
      resizingCol.current = null;
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, []);

  const effectiveBranch = branch === 'custom' ? customBranch : branch;

  const fetchSuggestion = useCallback(async (asset: CryptoAsset) => {
    const key = asset.id;
    setSuggestions(prev => ({ ...prev, [key]: { loading: true } }));
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: asset.name,
          primitive: asset.cryptoProperties?.algorithmProperties?.primitive,
          keyLength: asset.keyLength,
          fileName: asset.location?.fileName,
          lineNumber: asset.location?.lineNumber,
          quantumSafety: asset.quantumSafety,
          recommendedPQC: asset.recommendedPQC,
          // CycloneDX 1.7 fields
          assetType: asset.cryptoProperties?.assetType,
          detectionSource: asset.detectionSource,
          description: asset.description,
          mode: asset.cryptoProperties?.algorithmProperties?.mode,
          curve: asset.cryptoProperties?.algorithmProperties?.curve,
          pqcVerdict: asset.pqcVerdict ? {
            verdict: asset.pqcVerdict.verdict,
            confidence: asset.pqcVerdict.confidence,
            reasons: asset.pqcVerdict.reasons,
            parameters: asset.pqcVerdict.parameters,
            recommendation: asset.pqcVerdict.recommendation,
          } : undefined,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setSuggestions(prev => ({ ...prev, [key]: { fix: data.suggestedFix, codeSnippet: data.codeSnippet, confidence: data.confidence, loading: false } }));
      } else {
        setSuggestions(prev => ({ ...prev, [key]: { loading: false, error: 'No suggestion available' } }));
      }
    } catch {
      setSuggestions(prev => ({ ...prev, [key]: { loading: false, error: 'Failed to fetch' } }));
    }
  }, []);

  const fetchProjectInsight = useCallback(async () => {
    setInsight({ loading: true });
    try {
      // Build aggregated stats from all assets
      const counts = { notSafe: 0, conditional: 0, safe: 0, unknown: 0 };
      const algoCount: Record<string, { count: number; status: QuantumSafetyStatus | undefined; recommendedPQC?: string }> = {};
      const fileSet = new Set<string>();
      const sourceCount: Record<string, number> = {};

      for (const a of assets) {
        switch (a.quantumSafety) {
          case QuantumSafetyStatus.QUANTUM_SAFE: counts.safe++; break;
          case QuantumSafetyStatus.NOT_QUANTUM_SAFE: counts.notSafe++; break;
          case QuantumSafetyStatus.CONDITIONAL: counts.conditional++; break;
          default: counts.unknown++;
        }
        const entry = algoCount[a.name] || { count: 0, status: a.quantumSafety, recommendedPQC: a.recommendedPQC };
        entry.count++;
        algoCount[a.name] = entry;
        if (a.location?.fileName) fileSet.add(a.location.fileName);
        const src = a.detectionSource || 'unknown';
        sourceCount[src] = (sourceCount[src] || 0) + 1;
      }

      const topNotSafe = Object.entries(algoCount)
        .filter(([, v]) => v.status === QuantumSafetyStatus.NOT_QUANTUM_SAFE)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10)
        .map(([name, v]) => ({ name, count: v.count, recommendedPQC: v.recommendedPQC }));

      const topConditional = Object.entries(algoCount)
        .filter(([, v]) => v.status === QuantumSafetyStatus.CONDITIONAL)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10)
        .map(([name, v]) => ({ name, count: v.count }));

      const unknownAlgos = Object.entries(algoCount)
        .filter(([, v]) => !v.status || v.status === QuantumSafetyStatus.UNKNOWN)
        .map(([name]) => name);

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          counts,
          topNotSafe,
          topConditional,
          unknownAlgos,
          totalAssets: assets.length,
          uniqueFiles: fileSet.size,
          detectionSources: sourceCount,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setInsight({ loading: false, data });
      } else {
        setInsight({ loading: false, error: data.error || 'Failed to generate insight' });
      }
    } catch {
      setInsight({ loading: false, error: 'Failed to fetch project insight' });
    }
  }, [assets]);

  const toggleCollapse = useCallback((id: string) => {
    setSuggestions(prev => {
      const entry = prev[id];
      if (!entry) return prev;
      return { ...prev, [id]: { ...entry, collapsed: !entry.collapsed } };
    });
  }, []);

  const dismissSuggestion = useCallback((id: string) => {
    setSuggestions(prev => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }, []);

  const copySnippet = useCallback((id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  }, []);

  // Compute safety category counts from full asset list (before filtering)
  const safetyCounts = useMemo(() => {
    const counts = { safe: 0, notSafe: 0, conditional: 0, unknown: 0 };
    for (const a of assets) {
      switch (a.quantumSafety) {
        case QuantumSafetyStatus.QUANTUM_SAFE: counts.safe++; break;
        case QuantumSafetyStatus.NOT_QUANTUM_SAFE: counts.notSafe++; break;
        case QuantumSafetyStatus.CONDITIONAL: counts.conditional++; break;
        default: counts.unknown++;
      }
    }
    return counts;
  }, [assets]);

  const toggleSafetyFilter = useCallback((key: QuantumSafetyStatus | 'unknown') => {
    setSafetyFilter(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
    setPage(1);
  }, []);

  const filtered = useMemo(() => {
    let list = [...assets];

    // Quantum safety chip filter
    if (safetyFilter.size > 0) {
      list = list.filter(a => {
        if (!a.quantumSafety || a.quantumSafety === QuantumSafetyStatus.UNKNOWN) {
          return safetyFilter.has('unknown');
        }
        return safetyFilter.has(a.quantumSafety);
      });
    }

    if (filterText) {
      const q = filterText.toLowerCase();
      list = list.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.location?.fileName.toLowerCase().includes(q) ||
        a.cryptoProperties?.algorithmProperties?.primitive?.toLowerCase().includes(q) ||
        getStatusLabel(a.quantumSafety).toLowerCase().includes(q)
      );
    }

    const safetyOrder: Record<string, number> = {
      [QuantumSafetyStatus.NOT_QUANTUM_SAFE]: 0,
      [QuantumSafetyStatus.CONDITIONAL]: 1,
      'unknown': 2,
      [QuantumSafetyStatus.QUANTUM_SAFE]: 3,
    };

    list.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'name') cmp = a.name.localeCompare(b.name);
      else if (sortField === 'primitive') {
        const pa = a.cryptoProperties?.algorithmProperties?.primitive || '';
        const pb = b.cryptoProperties?.algorithmProperties?.primitive || '';
        cmp = pa.localeCompare(pb);
      } else if (sortField === 'safety') {
        const sa = safetyOrder[a.quantumSafety ?? 'unknown'] ?? 2;
        const sb = safetyOrder[b.quantumSafety ?? 'unknown'] ?? 2;
        cmp = sa - sb;
      } else {
        const la = a.location?.fileName || '';
        const lb = b.location?.fileName || '';
        cmp = la.localeCompare(lb);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [assets, filterText, sortField, sortDir, safetyFilter]);

  const totalPages = Math.ceil(filtered.length / perPage);
  const paged = filtered.slice((page - 1) * perPage, page * perPage);

  function toggleSort(field: 'name' | 'primitive' | 'location' | 'safety') {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  }

  return (
    <div className={s.card}>
      {/* Header */}
      <div className={s.headerSection}>
        <div className={s.headerRow}>
          <h3 className={s.headerTitle}>List of all assets</h3>
          <div className={s.headerControls}>
          <div className={s.githubBar}>
            <div className={s.githubField} title="GitHub repository URL">
              <Github className={s.githubFieldIcon} />
              <input
                type="text"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value.trim())}
                className={s.fieldInput}
              />
            </div>
            <span className={s.fieldSep}>|</span>
            <div className={s.githubField} title="Branch name">
              <GitBranch className={s.githubFieldIconSm} />
              <select
                value={branch}
                onChange={e => setBranch(e.target.value)}
                className={s.fieldSelect}
              >
                <option value="main">main</option>
                <option value="master">master</option>
                <option value="develop">develop</option>
                <option value="custom">custom...</option>
              </select>
              {branch === 'custom' && (
                <input
                  type="text"
                  placeholder="branch-name"
                  value={customBranch}
                  onChange={e => setCustomBranch(e.target.value.trim())}
                  className={s.fieldInputShort}
                  autoFocus
                />
              )}
            </div>
            <span className={s.fieldSep}>|</span>
            <div className={s.githubField} title="Base path prefix (e.g. ui/ or src/) — leave empty if scanning from repo root">
              <FolderOpen className={s.githubFieldIconSm} />
              <input
                type="text"
                value={basePath}
                onChange={e => setBasePath(e.target.value.trim())}
                className={s.fieldInputShort}
                placeholder="/"
              />
            </div>
          </div>
          <input
            type="text"
            placeholder="Filter assets..."
            value={filterText}
            onChange={e => { setFilterText(e.target.value); setPage(1); }}
            className={s.filterInput}
          />
          <button
            onClick={fetchProjectInsight}
            disabled={insight.loading}
            className={s.insightBtn}
            title="Get a project-level quantum readiness insight"
          >
            {insight.loading ? <Loader2 className={s.insightBtnSpin} /> : <BarChart3 className={s.insightBtnIcon} />}
            Project Insight
          </button>
          <SlidersHorizontal className={s.slidersIcon} />
        </div>
        </div>

        {/* Quantum Safety Filter Chips */}
        <div className={s.filterChips}>
            <Filter className={s.filterIcon} />
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.NOT_QUANTUM_SAFE)}
              className={`${s.chip} ${safetyFilter.has(QuantumSafetyStatus.NOT_QUANTUM_SAFE) ? s.chipNotSafeActive : s.chipNotSafe}`}
            >
              <ShieldAlert className={s.chipIcon} />
              Not Safe
              <span className={s.chipCount}>{safetyCounts.notSafe}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.CONDITIONAL)}
              className={`${s.chip} ${safetyFilter.has(QuantumSafetyStatus.CONDITIONAL) ? s.chipConditionalActive : s.chipConditional}`}
            >
              <ShieldQuestion className={s.chipIcon} />
              Conditional
              <span className={s.chipCount}>{safetyCounts.conditional}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.QUANTUM_SAFE)}
              className={`${s.chip} ${safetyFilter.has(QuantumSafetyStatus.QUANTUM_SAFE) ? s.chipSafeActive : s.chipSafe}`}
            >
              <ShieldCheck className={s.chipIcon} />
              Safe
              <span className={s.chipCount}>{safetyCounts.safe}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter('unknown' as any)}
              className={`${s.chip} ${safetyFilter.has('unknown' as any) ? s.chipUnknownActive : s.chipUnknown}`}
            >
              Unknown
              <span className={s.chipCount}>{safetyCounts.unknown}</span>
            </button>
            {safetyFilter.size > 0 && (
              <button
                onClick={() => { setSafetyFilter(new Set()); setPage(1); }}
                className={s.chipClear}
              >
                clear
              </button>
            )}
          </div>
      </div>

      {/* ── Project Insight Panel ─────────────────────────────── */}
      {(insight.loading || insight.data || insight.error) && (
        <div className={s.insightWrap}>
          {insight.loading && (
            <div className={s.insightLoading}>
              <Loader2 className={s.insightLoadIcon} />
              <div className={s.insightPulseBar}>
                <div className={s.insightPulseBarBig} />
                <div className={s.insightPulseBarSmall} />
              </div>
            </div>
          )}

          {insight.error && (
            <div className={s.insightError}>
              <span className={s.insightErrorMsg}>{insight.error}</span>
              <button onClick={() => setInsight({ loading: false })} className={s.dismissBtn}>
                <X className={s.dismissIcon} />
              </button>
            </div>
          )}

          {insight.data && (() => {
            const d = insight.data!;
            const riskCap = d.riskLevel.charAt(0).toUpperCase() + d.riskLevel.slice(1);
            const panelBg = s[`riskBg${riskCap}`] || s.riskBgModerate;
            const textCls = s[`riskText${riskCap}`] || s.riskTextModerate;
            const barCls = s[`riskBar${riskCap}`] || s.riskBarModerate;
            const badgeCls = (level: string) => {
              const cap = level.charAt(0).toUpperCase() + level.slice(1);
              return s[`riskBadge${cap}`] || s.riskBadgeMedium;
            };

            return (
              <div className={`${s.insightPanel} ${panelBg}`}>
                {/* Top bar with risk score and dismiss */}
                <div className={s.insightTopBar}>
                  <div className={s.insightTopLeft}>
                    <div className={s.insightTopTitle}>
                      <BarChart3 className={`${s.insightTopTitleIcon} ${textCls}`} />
                      <span className={s.insightTopTitleText}>Project Quantum Risk Assessment</span>
                    </div>
                    <span className={`${s.insightRiskBadge} ${badgeCls(d.riskLevel)}`}>
                      <AlertTriangle className={s.badgeIcon} />
                      {d.riskLevel}
                    </span>
                  </div>
                  <button onClick={() => setInsight({ loading: false })} className={s.dismissBtn}>
                    <X className={s.dismissIcon} />
                  </button>
                </div>

                {/* Risk score bar */}
                <div className={s.insightScoreBar}>
                  <div className={s.insightScoreRow}>
                    <div className={s.insightTrack}>
                      <div className={`${s.insightFill} ${barCls}`} style={{ width: `${d.riskScore}%` }} />
                    </div>
                    <span className={`${s.insightScoreText} ${textCls}`}>{d.riskScore}/100</span>
                  </div>
                </div>

                {/* Headline */}
                <p className={`${s.insightHeadline} ${textCls}`}>{d.headline}</p>

                {/* Summary */}
                <p className={s.insightSummary}>{d.summary}</p>

                {/* Priorities */}
                <div className={s.insightPriorities}>
                  <div className={s.insightPrioritiesLabel}>
                    <TrendingUp className={s.insightPrioritiesLabelIcon} />
                    Prioritized Actions
                  </div>
                  {d.priorities.map((p, i) => (
                    <div key={i} className={s.insightPriorityRow}>
                      <span className={`${s.insightImpactBadge} ${badgeCls(p.impact)}`}>
                        {p.impact}
                      </span>
                      <span className={s.insightPriorityAction}>{p.action}</span>
                      <span className={s.insightPriorityEffort}>
                        <Clock className={s.insightClockIcon} />
                        {p.effort}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Migration estimate */}
                <div className={s.insightMigration}>
                  <Clock className={`${s.insightMigrationIcon} ${textCls}`} />
                  <span className={s.insightMigrationText}>
                    <span className={s.insightMigrationLabel}>Migration Estimate:</span> {d.migrationEstimate}
                  </span>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Table */}
      <div className={s.tableWrap}>
        <table className={s.table}>
          <colgroup>
            <col style={{ width: colWidths[0] || COL_MIN[0], minWidth: COL_MIN[0] }} />
            <col style={{ width: colWidths[1] || COL_MIN[1], minWidth: COL_MIN[1] }} />
            <col style={{ width: colWidths[2] || COL_MIN[2], minWidth: COL_MIN[2] }} />
            <col style={{ width: colWidths[3] || COL_MIN[3], minWidth: COL_MIN[3] }} />
            <col style={{ width: colWidths[4] || COL_MIN[4], minWidth: COL_MIN[4] }} />
            <col style={{ width: colWidths[5] || COL_MIN[5], minWidth: COL_MIN[5] }} />
            <col style={{ width: colWidths[6] || COL_MIN[6], minWidth: COL_MIN[6] }} />
          </colgroup>
          <thead className={s.thead}>
            <tr>
              <th className={s.th} onClick={() => toggleSort('safety')}>
                Quantum Safety {sortField === 'safety' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 0)} />
              </th>
              <th className={s.th} onClick={() => toggleSort('name')}>
                Cryptographic asset {sortField === 'name' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 1)} />
              </th>
              <th className={s.th} onClick={() => toggleSort('primitive')}>
                Primitive {sortField === 'primitive' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 2)} />
              </th>
              <th className={s.th}>
                PQC Verdict
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 3)} />
              </th>
              <th className={s.th} onClick={() => toggleSort('location')}>
                Location {sortField === 'location' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 4)} />
              </th>
              <th className={s.th}>
                Policy Violations
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 5)} />
              </th>
              <th className={s.thAi}>
                <span className={s.thAiInner}>
                  <Sparkles className={s.aiSparkle} />
                  <span className={s.aiLabel}>AI Suggested Fix</span>
                </span>
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 6)} />
              </th>
              <th className={s.th}>
                Actions
                <span className={s.resizeHandle} onMouseDown={(e) => onResizeStart(e, 7)} />
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.map((asset) => (
              <tr key={asset.id} className={s.tr}>
                {/* Quantum Safety badge */}
                <td className={s.td}>
                  {(() => {
                    const Icon = getStatusIcon(asset.quantumSafety);
                    return (
                      <span className={getStatusBg(asset.quantumSafety)}>
                        <Icon className={s.badgeIcon} />
                        {getStatusLabel(asset.quantumSafety)}
                      </span>
                    );
                  })()}
                </td>

                {/* Algorithm name */}
                <td className={s.td}>
                  <span className={s.algoName}>{asset.name}</span>
                  {asset.keyLength && (
                    <span className={s.keyLength}>({asset.keyLength}-bit)</span>
                  )}
                  {asset.description && (
                    <p className={s.description} title={asset.description}>
                      {asset.description.length > 120 ? asset.description.slice(0, 117) + '…' : asset.description}
                    </p>
                  )}
                </td>

                {/* Primitive */}
                <td className={s.td}>
                  <div className={s.primitiveWrap}>
                    {getPrimitiveLabel(asset.cryptoProperties?.algorithmProperties?.primitive).split('\n').map((line, i) => (
                      <div key={i} className={i === 0 ? s.primitiveName : s.primitiveSub}>
                        {line}
                      </div>
                    ))}
                  </div>
                </td>

                {/* PQC Verdict */}
                <td className={s.td}>
                  <div className={s.verdictCell}>
                    <PqcVerdictBadge asset={asset} />
                  </div>
                </td>

                {/* Location */}
                <td className={s.td}>
                  {asset.location ? (
                    <div className={s.locationWrap}>
                      {asset.detectionSource === 'dependency' && asset.provider && (
                        <span className={s.providerBadge}>
                          <Package className={s.providerIcon} />
                          {asset.provider}
                        </span>
                      )}
                      {repoUrl ? (
                        <a
                          href={buildGitHubFileUrl(repoUrl, effectiveBranch, basePath, asset.location.fileName, asset.location.lineNumber)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={s.fileLink}
                          title={`${asset.location.fileName}${asset.location.lineNumber ? `:${asset.location.lineNumber}` : ''}`}
                        >
                          {asset.location.fileName}
                          {asset.location.lineNumber ? `:${asset.location.lineNumber}` : ''}
                          <ExternalLink className={s.ghLinkIcon} />
                        </a>
                      ) : (
                        <span
                          className={s.fileLink}
                          title={`${asset.location.fileName}${asset.location.lineNumber ? `:${asset.location.lineNumber}` : ''}`}
                        >
                          {asset.location.fileName}
                          {asset.location.lineNumber ? `:${asset.location.lineNumber}` : ''}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className={s.noDash}>—</span>
                  )}
                </td>

                {/* Policy Violations */}
                <td className={s.td}>
                  <PolicyViolationCell
                    result={policyResultsMap.get(asset.id)}
                    enableAi
                    aiContext={{
                      type: 'crypto-asset',
                      name: asset.name,
                      algorithm: asset.name,
                      keyLength: asset.keyLength,
                      primitive: asset.cryptoProperties?.algorithmProperties?.primitive,
                      quantumSafety: asset.quantumSafety,
                      pqcVerdict: asset.pqcVerdict?.verdict,
                      violatedPolicies: policyResultsMap.get(asset.id)?.violatedPolicies?.map((p) => p.policyName) ?? [],
                    }}
                  />
                </td>

                {/* Suggested Fix */}
                <td className={s.td} style={{ minWidth: 260 }}>
                  {(() => {
                    const sg = suggestions[asset.id];

                    /* ---------- Loading ---------- */
                    if (sg?.loading) {
                      return (
                        <div className={s.suggLoading}>
                          <Loader2 className={s.suggSpinner} />
                          <div className={s.suggPulse}>
                            <div className={s.suggPulseBar1} />
                            <div className={s.suggPulseBar2} />
                          </div>
                        </div>
                      );
                    }

                    /* ---------- Result ---------- */
                    if (sg?.fix) {
                      return (
                        <div className={s.suggResult}>
                          {/* Top row: confidence badge + actions */}
                          <div className={s.suggTopRow}>
                            {confidenceBadge(sg.confidence)}
                            <div className={s.suggActions}>
                              <button onClick={() => toggleCollapse(asset.id)} className={s.suggActionBtn} title={sg.collapsed ? 'Expand' : 'Collapse'}>
                                {sg.collapsed ? <ChevronDown className={s.suggActionIcon} /> : <ChevronUp className={s.suggActionIcon} />}
                              </button>
                              <button onClick={() => dismissSuggestion(asset.id)} className={s.suggActionBtn} title="Dismiss">
                                <X className={s.suggActionIcon} />
                              </button>
                            </div>
                          </div>

                          {!sg.collapsed && (
                            <>
                              <p className={s.suggText}>{sg.fix}</p>
                              {sg.codeSnippet && (
                                <div className={s.suggCode}>
                                  <pre className={s.suggPre}>{sg.codeSnippet}</pre>
                                  <button
                                    onClick={() => copySnippet(asset.id, sg.codeSnippet!)}
                                    className={s.copyBtn}
                                    title="Copy code"
                                  >
                                    {copiedId === asset.id ? <Check className={s.copyIconDone} /> : <Copy className={s.copyIcon} />}
                                  </button>
                                </div>
                              )}
                            </>
                          )}

                          {sg.collapsed && (
                            <p className={s.suggTextCollapsed}>{sg.fix}</p>
                          )}
                        </div>
                      );
                    }

                    /* ---------- Error ---------- */
                    if (sg?.error) {
                      return (
                        <button
                          onClick={() => fetchSuggestion(asset)}
                          className={s.retryBtn}
                        >
                          <Sparkles className={s.retryIcon} /> Retry
                        </button>
                      );
                    }

                    /* ---------- Idle (show PQC hint + button) ---------- */
                    return (
                      <div className={s.suggIdle}>
                        {asset.recommendedPQC && (
                          <span className={s.suggHint}>
                            Migrate to <span className={s.suggHintAlgo}>{asset.recommendedPQC}</span>
                          </span>
                        )}
                        <button
                          onClick={() => fetchSuggestion(asset)}
                          className={s.aiFixBtn}
                          title="Get AI-powered migration suggestion"
                        >
                          <Sparkles className={s.aiFixIcon} />
                          AI Fix
                        </button>
                      </div>
                    );
                  })()}
                </td>

                {/* Create Ticket — only for non-quantum-safe assets */}
                <td className={s.td}>
                  {asset.quantumSafety !== QuantumSafetyStatus.QUANTUM_SAFE && (
                  <button
                    className={s.ticketBtn}
                    title="Create remediation ticket"
                    onClick={() => {
                      const sg = suggestions[asset.id];
                      setTicketCtx({
                        entityType: 'Software',
                        entityName: asset.name,
                        quantumSafe: asset.quantumSafety === 'quantum-safe',
                        problemStatement: `Cryptographic asset "${asset.name}" is classified as ${getStatusLabel(asset.quantumSafety)}.${asset.keyLength ? ` Key length: ${asset.keyLength}-bit.` : ''}${asset.cryptoProperties?.algorithmProperties?.primitive ? ` Primitive: ${asset.cryptoProperties.algorithmProperties.primitive}.` : ''}`,
                        details: {
                          algorithm: asset.name,
                          keyLength: asset.keyLength != null ? String(asset.keyLength) : undefined,
                          primitive: asset.cryptoProperties?.algorithmProperties?.primitive,
                          quantumSafety: asset.quantumSafety,
                          pqcVerdict: asset.pqcVerdict?.verdict,
                          location: asset.location ? `${asset.location.fileName}${asset.location.lineNumber ? ':' + asset.location.lineNumber : ''}` : undefined,
                          source: asset.provider,
                        },
                        severity: asset.quantumSafety === 'not-quantum-safe' ? 'Critical' : asset.quantumSafety === 'conditional' ? 'High' : 'Medium',
                        aiSuggestion: sg?.fix,
                      });
                    }}
                  >
                    <Ticket className={s.ticketBtnIcon} />
                    Create Ticket
                  </button>
                  )}
                </td>

              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create Ticket Modal */}
      {ticketCtx && (
        <CreateTicketModal
          open
          context={ticketCtx}
          onClose={() => setTicketCtx(null)}
          onSubmit={(payload) => {
            createTicket(payload);
            setTicketCtx(null);
          }}
        />
      )}

      {/* Pagination */}
      <div className={s.pagination}>
        <div className={s.paginationLeft}>
          <span>Items per page:</span>
          <select
            value={perPage}
            onChange={e => { setPerPage(Number(e.target.value)); setPage(1); }}
            className={s.paginationSelect}
          >
            {ITEMS_PER_PAGE_OPTIONS.map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <span className={s.paginationInfo}>
            {(page - 1) * perPage + 1}-{Math.min(page * perPage, filtered.length)} of {filtered.length} items
          </span>
        </div>
        <div className={s.paginationRight}>
          <span>{page}</span>
          <span>of {totalPages} pages</span>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page <= 1}
            className={s.pageBtn}
          >
            <ChevronLeft className={s.pageBtnIcon} />
          </button>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className={s.pageBtn}
          >
            <ChevronRight className={s.pageBtnIcon} />
          </button>
        </div>
      </div>
    </div>
  );
}
