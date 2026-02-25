import { useState, useMemo, useCallback } from 'react';
import {
  ExternalLink, ChevronLeft, ChevronRight, SlidersHorizontal,
  Github, GitBranch, FolderOpen, Sparkles, Loader2,
  X, Copy, Check, Zap, ShieldCheck, ChevronDown, ChevronUp,
  ShieldAlert, ShieldQuestion, Package, Filter,
} from 'lucide-react';
import { CryptoAsset, QuantumSafetyStatus, ComplianceStatus, PQCReadinessVerdict } from '../types';

interface AssetListViewProps {
  assets: CryptoAsset[];
}

interface SuggestionState {
  fix?: string;
  codeSnippet?: string;
  confidence?: string;
  loading: boolean;
  error?: string;
  collapsed?: boolean;
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
    case QuantumSafetyStatus.QUANTUM_SAFE: return 'bg-green-500/15 ring-green-500/30 text-green-400';
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return 'bg-red-500/15 ring-red-500/30 text-red-400';
    case QuantumSafetyStatus.CONDITIONAL: return 'bg-cyan-500/15 ring-cyan-500/30 text-cyan-400';
    default: return 'bg-gray-500/15 ring-gray-500/30 text-gray-400';
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
  const styles: Record<string, string> = {
    high: 'bg-green-500/15 text-green-400 ring-green-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 ring-yellow-500/30',
    low: 'bg-gray-500/15 text-gray-400 ring-gray-500/30',
  };
  const cls = styles[level] || styles.low;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full ring-1 ${cls}`}>
      <ShieldCheck className="w-2.5 h-2.5" />
      {level}
    </span>
  );
}

function pqcVerdictBadge(asset: CryptoAsset) {
  const v = asset.pqcVerdict;
  if (!v) return null;

  const config: Record<string, { icon: typeof ShieldCheck; cls: string; label: string }> = {
    [PQCReadinessVerdict.PQC_READY]: {
      icon: ShieldCheck,
      cls: 'bg-green-500/15 text-green-400 ring-green-500/30',
      label: 'PQC Ready',
    },
    [PQCReadinessVerdict.NOT_PQC_READY]: {
      icon: ShieldAlert,
      cls: 'bg-red-500/15 text-red-400 ring-red-500/30',
      label: 'Not PQC Ready',
    },
    [PQCReadinessVerdict.REVIEW_NEEDED]: {
      icon: ShieldQuestion,
      cls: 'bg-yellow-500/15 text-yellow-400 ring-yellow-500/30',
      label: 'Review Needed',
    },
  };

  const c = config[v.verdict] || config[PQCReadinessVerdict.REVIEW_NEEDED];
  const Icon = c.icon;

  return (
    <div className="group/verdict relative">
      <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full ring-1 cursor-help ${c.cls}`}>
        <Icon className="w-2.5 h-2.5" />
        {c.label}
        <span className="text-[9px] opacity-70">{v.confidence}%</span>
      </span>
      {/* Tooltip with reasons */}
      <div className="absolute z-[999] bottom-full left-0 mb-2 w-72 p-3 bg-qg-dark border border-qg-border rounded-lg shadow-xl opacity-0 pointer-events-none group-hover/verdict:opacity-100 group-hover/verdict:pointer-events-auto transition-opacity">
        <div className="text-[11px] text-gray-300 space-y-1.5">
          {v.reasons.map((r: string, i: number) => (
            <div key={i} className="flex gap-1.5">
              <span className="text-gray-500 flex-shrink-0">{r.includes('✓') ? '✓' : r.includes('✗') ? '✗' : '•'}</span>
              <span>{r}</span>
            </div>
          ))}
          {v.parameters && Object.keys(v.parameters).length > 0 && (
            <div className="mt-2 pt-2 border-t border-qg-border/50">
              <span className="text-gray-500 text-[10px] font-medium uppercase tracking-wider">Detected Parameters</span>
              <div className="mt-1 grid grid-cols-2 gap-x-2 gap-y-0.5">
                {Object.entries(v.parameters).map(([k, val]) => (
                  <div key={k}>
                    <span className="text-gray-500">{k}: </span>
                    <span className="text-gray-300 font-mono text-[10px]">{String(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {v.recommendation && (
            <div className="mt-2 pt-2 border-t border-qg-border/50 text-[10px] text-blue-400">
              {v.recommendation}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function detectionSourceBadge(source?: string) {
  if (!source) return null;
  const styles: Record<string, string> = {
    sonar: 'bg-blue-500/10 text-blue-400/80',
    regex: 'bg-gray-500/10 text-gray-400/80',
    dependency: 'bg-amber-500/10 text-amber-400/80',
    network: 'bg-purple-500/10 text-purple-400/80',
  };
  return (
    <span className={`inline-flex items-center gap-0.5 text-[9px] font-medium px-1 py-0.5 rounded ${styles[source] || styles.regex}`}>
      {source === 'dependency' && <Package className="w-2 h-2" />}
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

export default function AssetListView({ assets }: AssetListViewProps) {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [sortField, setSortField] = useState<'name' | 'primitive' | 'location' | 'safety'>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [filterText, setFilterText] = useState('');
  const [safetyFilter, setSafetyFilter] = useState<Set<QuantumSafetyStatus | 'unknown'>>(new Set());
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [customBranch, setCustomBranch] = useState('');
  const [basePath, setBasePath] = useState('');
  const [suggestions, setSuggestions] = useState<Record<string, SuggestionState>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

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
          // CycloneDX 1.6 fields
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

  const fetchAllSuggestions = useCallback(async (assetList: CryptoAsset[]) => {
    const pending = assetList.filter(a => !suggestions[a.id]?.fix && !suggestions[a.id]?.loading);
    for (const asset of pending) {
      fetchSuggestion(asset);
      // stagger requests slightly
      await new Promise(r => setTimeout(r, 150));
    }
  }, [suggestions, fetchSuggestion]);

  const toggleCollapse = useCallback((id: string) => {
    setSuggestions(prev => {
      const s = prev[id];
      if (!s) return prev;
      return { ...prev, [id]: { ...s, collapsed: !s.collapsed } };
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
    <div className="bg-qg-card border border-qg-border rounded-lg animate-fade-in">
      {/* Header */}
      <div className="px-4 py-3 border-b border-qg-border space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-200">List of all assets</h3>
          <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-qg-dark border border-qg-border rounded px-2.5 py-1.5">
            <div className="flex items-center gap-1.5" title="GitHub repository URL">
              <Github className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
              <input
                type="text"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value.trim())}
                className="bg-transparent text-xs text-gray-300 w-48 focus:outline-none placeholder:text-gray-600"
              />
            </div>
            <span className="text-gray-700">|</span>
            <div className="flex items-center gap-1.5" title="Branch name">
              <GitBranch className="w-3 h-3 text-gray-500 flex-shrink-0" />
              <select
                value={branch}
                onChange={e => setBranch(e.target.value)}
                className="bg-transparent text-xs text-gray-400 focus:outline-none cursor-pointer appearance-none pr-1"
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
                  className="bg-transparent text-xs text-gray-300 w-20 focus:outline-none placeholder:text-gray-600"
                  autoFocus
                />
              )}
            </div>
            <span className="text-gray-700">|</span>
            <div className="flex items-center gap-1.5" title="Base path prefix (e.g. ui/ or src/) — leave empty if scanning from repo root">
              <FolderOpen className="w-3 h-3 text-gray-500 flex-shrink-0" />
              <input
                type="text"
                value={basePath}
                onChange={e => setBasePath(e.target.value.trim())}
                className="bg-transparent text-xs text-gray-400 w-14 focus:outline-none"
                placeholder="/"
              />
            </div>
          </div>
          <input
            type="text"
            placeholder="Filter assets..."
            value={filterText}
            onChange={e => { setFilterText(e.target.value); setPage(1); }}
            className="bg-qg-dark border border-qg-border rounded px-2 py-1 text-xs text-gray-300 w-48 focus:outline-none focus:border-qg-accent"
          />
          <button
            onClick={() => fetchAllSuggestions(paged)}
            className="flex items-center gap-1.5 bg-gradient-to-r from-purple-600/80 to-blue-600/80 hover:from-purple-500 hover:to-blue-500 text-white text-[11px] font-medium px-3 py-1.5 rounded-md transition-all shadow-sm hover:shadow-purple-500/20 hover:shadow-md"
            title="Get AI suggestions for all assets on this page"
          >
            <Zap className="w-3 h-3" />
            Scan Page
          </button>
          <SlidersHorizontal className="w-4 h-4 text-gray-500" />
        </div>
        </div>

        {/* Quantum Safety Filter Chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
            <Filter className="w-3 h-3 text-gray-500 flex-shrink-0" />
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.NOT_QUANTUM_SAFE)}
              className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded-full ring-1 transition-all ${
                safetyFilter.has(QuantumSafetyStatus.NOT_QUANTUM_SAFE)
                  ? 'bg-red-500/25 ring-red-500/60 text-red-300 shadow-sm shadow-red-500/10'
                  : 'bg-red-500/10 ring-red-500/20 text-red-400/70 hover:ring-red-500/40'
              }`}
            >
              <ShieldAlert className="w-2.5 h-2.5" />
              Not Safe
              <span className="text-[9px] opacity-70">{safetyCounts.notSafe}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.CONDITIONAL)}
              className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded-full ring-1 transition-all ${
                safetyFilter.has(QuantumSafetyStatus.CONDITIONAL)
                  ? 'bg-cyan-500/25 ring-cyan-500/60 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : 'bg-cyan-500/10 ring-cyan-500/20 text-cyan-400/70 hover:ring-cyan-500/40'
              }`}
            >
              <ShieldQuestion className="w-2.5 h-2.5" />
              Conditional
              <span className="text-[9px] opacity-70">{safetyCounts.conditional}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter(QuantumSafetyStatus.QUANTUM_SAFE)}
              className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded-full ring-1 transition-all ${
                safetyFilter.has(QuantumSafetyStatus.QUANTUM_SAFE)
                  ? 'bg-green-500/25 ring-green-500/60 text-green-300 shadow-sm shadow-green-500/10'
                  : 'bg-green-500/10 ring-green-500/20 text-green-400/70 hover:ring-green-500/40'
              }`}
            >
              <ShieldCheck className="w-2.5 h-2.5" />
              Safe
              <span className="text-[9px] opacity-70">{safetyCounts.safe}</span>
            </button>
            <button
              onClick={() => toggleSafetyFilter('unknown' as any)}
              className={`inline-flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded-full ring-1 transition-all ${
                safetyFilter.has('unknown' as any)
                  ? 'bg-gray-500/25 ring-gray-500/60 text-gray-300 shadow-sm shadow-gray-500/10'
                  : 'bg-gray-500/10 ring-gray-500/20 text-gray-400/70 hover:ring-gray-500/40'
              }`}
            >
              Unknown
              <span className="text-[9px] opacity-70">{safetyCounts.unknown}</span>
            </button>
            {safetyFilter.size > 0 && (
              <button
                onClick={() => { setSafetyFilter(new Set()); setPage(1); }}
                className="text-[10px] text-gray-500 hover:text-gray-300 ml-0.5 underline"
              >
                clear
              </button>
            )}
          </div>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'clip', overflowY: 'visible' }}>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 text-xs border-b border-qg-border">
              <th
                className="px-4 py-2 cursor-pointer hover:text-gray-300 whitespace-nowrap"
                onClick={() => toggleSort('safety')}
              >
                Quantum Safety {sortField === 'safety' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
              </th>
              <th
                className="px-4 py-2 cursor-pointer hover:text-gray-300"
                onClick={() => toggleSort('name')}
              >
                Cryptographic asset {sortField === 'name' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
              </th>
              <th
                className="px-4 py-2 cursor-pointer hover:text-gray-300"
                onClick={() => toggleSort('primitive')}
              >
                Primitive {sortField === 'primitive' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
              </th>
              <th className="px-4 py-2">PQC Verdict</th>
              <th
                className="px-4 py-2 cursor-pointer hover:text-gray-300"
                onClick={() => toggleSort('location')}
              >
                Location {sortField === 'location' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
              </th>
              <th className="px-4 py-2 min-w-[260px]">
                <span className="flex items-center gap-1.5">
                  <span className="relative flex h-3 w-3">
                    <Sparkles className="w-3 h-3 text-purple-400" />
                  </span>
                  <span className="bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent font-semibold">AI Suggested Fix</span>
                </span>
              </th>
              <th className="px-4 py-2 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {paged.map((asset) => (
              <tr
                key={asset.id}
                className="border-b border-qg-border/50 hover:bg-qg-dark/50 transition-colors"
              >
                {/* Quantum Safety badge */}
                <td className="px-4 py-3">
                  {(() => {
                    const Icon = getStatusIcon(asset.quantumSafety);
                    return (
                      <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full ring-1 ${getStatusBg(asset.quantumSafety)}`}>
                        <Icon className="w-2.5 h-2.5" />
                        {getStatusLabel(asset.quantumSafety)}
                      </span>
                    );
                  })()}
                </td>

                {/* Algorithm name */}
                <td className="px-4 py-3">
                  <span className="text-gray-200 font-medium">{asset.name}</span>
                  {asset.keyLength && (
                    <span className="text-gray-500 text-xs ml-2">({asset.keyLength}-bit)</span>
                  )}
                </td>

                {/* Primitive */}
                <td className="px-4 py-3">
                  <div className="text-xs">
                    {getPrimitiveLabel(asset.cryptoProperties?.algorithmProperties?.primitive).split('\n').map((line, i) => (
                      <div key={i} className={i === 0 ? 'text-gray-300 font-medium' : 'text-gray-500'}>
                        {line}
                      </div>
                    ))}
                  </div>
                </td>

                {/* PQC Verdict */}
                <td className="px-4 py-3">
                  <div className="flex flex-col gap-1">
                    {pqcVerdictBadge(asset)}
                    {detectionSourceBadge(asset.detectionSource)}
                  </div>
                </td>

                {/* Location */}
                <td className="px-4 py-3">
                  {asset.location ? (
                    <span className="text-qg-accent text-xs hover:underline cursor-pointer">
                      {asset.location.fileName}
                      {asset.location.lineNumber ? `:${asset.location.lineNumber}` : ''}
                    </span>
                  ) : (
                    <span className="text-gray-600 text-xs">—</span>
                  )}
                </td>

                {/* Suggested Fix */}
                <td className="px-4 py-3 min-w-[260px]">
                  {(() => {
                    const s = suggestions[asset.id];

                    /* ---------- Loading ---------- */
                    if (s?.loading) {
                      return (
                        <div className="flex items-center gap-2">
                          <Loader2 className="w-3.5 h-3.5 text-purple-400 animate-spin" />
                          <div className="space-y-1.5 flex-1">
                            <div className="h-2 w-3/4 rounded bg-purple-500/10 animate-pulse" />
                            <div className="h-2 w-1/2 rounded bg-purple-500/10 animate-pulse" />
                          </div>
                        </div>
                      );
                    }

                    /* ---------- Result ---------- */
                    if (s?.fix) {
                      return (
                        <div className="relative border-l-2 border-purple-500/60 pl-3 pr-1 py-0.5 group/card">
                          {/* Top row: confidence badge + actions */}
                          <div className="flex items-center justify-between mb-1.5">
                            {confidenceBadge(s.confidence)}
                            <div className="flex items-center gap-0.5 opacity-0 group-hover/card:opacity-100 transition-opacity">
                              <button onClick={() => toggleCollapse(asset.id)} className="p-0.5 rounded hover:bg-qg-border/60 text-gray-500 hover:text-gray-300" title={s.collapsed ? 'Expand' : 'Collapse'}>
                                {s.collapsed ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />}
                              </button>
                              <button onClick={() => dismissSuggestion(asset.id)} className="p-0.5 rounded hover:bg-qg-border/60 text-gray-500 hover:text-gray-300" title="Dismiss">
                                <X className="w-3 h-3" />
                              </button>
                            </div>
                          </div>

                          {!s.collapsed && (
                            <>
                              <p className="text-[11px] text-gray-300 leading-relaxed mb-1.5">{s.fix}</p>
                              {s.codeSnippet && (
                                <div className="relative group/snippet">
                                  <pre className="text-[10px] leading-relaxed bg-qg-dark/80 border border-qg-border/50 rounded-md px-2.5 py-2 text-green-400 overflow-x-auto max-h-24 font-mono">{s.codeSnippet}</pre>
                                  <button
                                    onClick={() => copySnippet(asset.id, s.codeSnippet!)}
                                    className="absolute top-1.5 right-1.5 p-1 rounded bg-qg-dark/90 border border-qg-border/50 text-gray-500 hover:text-gray-200 opacity-0 group-hover/snippet:opacity-100 transition-opacity"
                                    title="Copy code"
                                  >
                                    {copiedId === asset.id ? <Check className="w-2.5 h-2.5 text-green-400" /> : <Copy className="w-2.5 h-2.5" />}
                                  </button>
                                </div>
                              )}
                            </>
                          )}

                          {s.collapsed && (
                            <p className="text-[10px] text-gray-500 truncate">{s.fix}</p>
                          )}
                        </div>
                      );
                    }

                    /* ---------- Error ---------- */
                    if (s?.error) {
                      return (
                        <button
                          onClick={() => fetchSuggestion(asset)}
                          className="flex items-center gap-1.5 text-[11px] text-red-400 hover:text-red-300 bg-red-500/5 hover:bg-red-500/10 border border-red-500/20 rounded-md px-2.5 py-1.5 transition-colors"
                        >
                          <Sparkles className="w-3 h-3" /> Retry
                        </button>
                      );
                    }

                    /* ---------- Idle (show PQC hint + button) ---------- */
                    return (
                      <div className="flex flex-col gap-1">
                        {asset.recommendedPQC && (
                          <span className="text-[10px] text-gray-500 leading-snug">
                            Migrate to <span className="text-gray-400 font-medium">{asset.recommendedPQC}</span>
                          </span>
                        )}
                        <button
                          onClick={() => fetchSuggestion(asset)}
                          className="group/btn flex items-center gap-1.5 w-fit text-[11px] font-medium bg-gradient-to-r from-purple-600/20 to-blue-600/20 hover:from-purple-600/40 hover:to-blue-600/40 text-purple-300 hover:text-white border border-purple-500/20 hover:border-purple-500/40 rounded-md px-2.5 py-1 transition-all hover:shadow-sm hover:shadow-purple-500/10"
                          title="Get AI-powered migration suggestion"
                        >
                          <Sparkles className="w-3 h-3 group-hover/btn:animate-pulse" />
                          AI Fix
                        </button>
                      </div>
                    );
                  })()}
                </td>

                {/* Action — link to file on GitHub */}
                <td className="px-4 py-3">
                  {repoUrl && asset.location?.fileName ? (
                    <a
                      href={buildGitHubFileUrl(repoUrl, effectiveBranch, basePath, asset.location.fileName, asset.location.lineNumber)}
                      target="_blank"
                      rel="noopener noreferrer"
                      title="View on GitHub"
                    >
                      <ExternalLink className="w-3.5 h-3.5 text-qg-accent hover:text-white cursor-pointer" />
                    </a>
                  ) : (
                    <ExternalLink className="w-3.5 h-3.5 text-gray-600 cursor-not-allowed" />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-4 py-3 text-xs text-gray-500 border-t border-qg-border">
        <div className="flex items-center gap-2">
          <span>Items per page:</span>
          <select
            value={perPage}
            onChange={e => { setPerPage(Number(e.target.value)); setPage(1); }}
            className="bg-qg-dark border border-qg-border rounded px-1 py-0.5 text-gray-300"
          >
            {ITEMS_PER_PAGE_OPTIONS.map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <span className="ml-4">
            {(page - 1) * perPage + 1}-{Math.min(page * perPage, filtered.length)} of {filtered.length} items
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span>{page}</span>
          <span>of {totalPages} pages</span>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="p-1 rounded hover:bg-qg-border disabled:opacity-30"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="p-1 rounded hover:bg-qg-border disabled:opacity-30"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
