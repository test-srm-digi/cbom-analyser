import { useState, useMemo } from 'react';
import { ExternalLink, ChevronLeft, ChevronRight, SlidersHorizontal, Github, GitBranch, FolderOpen } from 'lucide-react';
import { CryptoAsset, QuantumSafetyStatus, ComplianceStatus } from '../types';

interface AssetListViewProps {
  assets: CryptoAsset[];
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

function getStatusColor(status?: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return 'text-qg-green';
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return 'text-qg-red';
    default: return 'text-gray-500';
  }
}

function getStatusDash(status?: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return '●●●';
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return '— —';
    default: return '· · ·';
  }
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
  const [sortField, setSortField] = useState<'name' | 'primitive' | 'location'>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [filterText, setFilterText] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [customBranch, setCustomBranch] = useState('');
  const [basePath, setBasePath] = useState('');

  const effectiveBranch = branch === 'custom' ? customBranch : branch;

  const filtered = useMemo(() => {
    let list = [...assets];
    if (filterText) {
      const q = filterText.toLowerCase();
      list = list.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.location?.fileName.toLowerCase().includes(q) ||
        a.cryptoProperties?.algorithmProperties?.primitive?.toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'name') cmp = a.name.localeCompare(b.name);
      else if (sortField === 'primitive') {
        const pa = a.cryptoProperties?.algorithmProperties?.primitive || '';
        const pb = b.cryptoProperties?.algorithmProperties?.primitive || '';
        cmp = pa.localeCompare(pb);
      } else {
        const la = a.location?.fileName || '';
        const lb = b.location?.fileName || '';
        cmp = la.localeCompare(lb);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [assets, filterText, sortField, sortDir]);

  const totalPages = Math.ceil(filtered.length / perPage);
  const paged = filtered.slice((page - 1) * perPage, page * perPage);

  function toggleSort(field: 'name' | 'primitive' | 'location') {
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
      <div className="flex items-center justify-between px-4 py-3 border-b border-qg-border">
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
          <SlidersHorizontal className="w-4 h-4 text-gray-500" />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 text-xs border-b border-qg-border">
              <th className="px-4 py-2 w-8"></th>
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
              <th
                className="px-4 py-2 cursor-pointer hover:text-gray-300"
                onClick={() => toggleSort('location')}
              >
                Location {sortField === 'location' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
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
                {/* Status indicator */}
                <td className="px-4 py-3">
                  <span className={`text-xs ${getStatusColor(asset.quantumSafety)}`}>
                    {getStatusDash(asset.quantumSafety)}
                  </span>
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
