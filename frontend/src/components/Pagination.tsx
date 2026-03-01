/**
 * Pagination — Shared pagination control for tables and lists
 * Shows page navigation, items-per-page selector, and result count.
 */
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

interface Props {
  /** Current page (1-based) */
  page: number;
  /** Total items */
  total: number;
  /** Items per page */
  pageSize: number;
  /** Callback when page changes */
  onPageChange: (page: number) => void;
  /** Callback when page-size changes */
  onPageSizeChange?: (size: number) => void;
  /** Available page-size options (default: [10, 25, 50, 100]) */
  pageSizeOptions?: number[];
}

export default function Pagination({
  page,
  total,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 25, 50, 100],
}: Props) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const start = Math.min((page - 1) * pageSize + 1, total);
  const end = Math.min(page * pageSize, total);

  /** Generate page numbers with ellipsis */
  const pages = (): (number | '...')[] => {
    if (totalPages <= 7) return Array.from({ length: totalPages }, (_, i) => i + 1);
    const result: (number | '...')[] = [1];
    if (page > 3) result.push('...');
    for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) result.push(i);
    if (page < totalPages - 2) result.push('...');
    result.push(totalPages);
    return result;
  };

  if (total === 0) return null;

  const btnBase: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
    minWidth: 28, height: 28, fontSize: 12, fontWeight: 500,
    border: '1px solid var(--dc1-border)', borderRadius: 4,
    background: 'var(--dc1-bg-card, #fff)', color: 'var(--dc1-text)',
    cursor: 'pointer', padding: '0 6px', transition: 'background 0.12s',
  };

  const btnDisabled: React.CSSProperties = { ...btnBase, opacity: 0.4, cursor: 'default', pointerEvents: 'none' };
  const btnActive: React.CSSProperties = { ...btnBase, background: 'var(--dc1-primary, #2563eb)', color: '#fff', borderColor: 'var(--dc1-primary, #2563eb)' };

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '8px 0', gap: 12, flexWrap: 'wrap', fontSize: 12,
      color: 'var(--dc1-text-muted)',
    }}>
      {/* Left: result count + page-size selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span>{start}–{end} of {total}</span>
        {onPageSizeChange && (
          <select
            value={pageSize}
            onChange={e => { onPageSizeChange(Number(e.target.value)); onPageChange(1); }}
            style={{
              fontSize: 12, padding: '3px 6px', borderRadius: 4,
              border: '1px solid var(--dc1-border)', background: 'var(--dc1-bg-card, #fff)',
              color: 'var(--dc1-text)', cursor: 'pointer',
            }}
          >
            {pageSizeOptions.map(n => <option key={n} value={n}>{n} / page</option>)}
          </select>
        )}
      </div>

      {/* Right: page buttons */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <button style={page === 1 ? btnDisabled : btnBase} onClick={() => onPageChange(1)} title="First page">
            <ChevronsLeft size={14} />
          </button>
          <button style={page === 1 ? btnDisabled : btnBase} onClick={() => onPageChange(page - 1)} title="Previous">
            <ChevronLeft size={14} />
          </button>
          {pages().map((p, i) =>
            p === '...'
              ? <span key={`e${i}`} style={{ padding: '0 4px' }}>…</span>
              : <button key={p} style={p === page ? btnActive : btnBase} onClick={() => onPageChange(p)}>{p}</button>
          )}
          <button style={page === totalPages ? btnDisabled : btnBase} onClick={() => onPageChange(page + 1)} title="Next">
            <ChevronRight size={14} />
          </button>
          <button style={page === totalPages ? btnDisabled : btnBase} onClick={() => onPageChange(totalPages)} title="Last page">
            <ChevronsRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
