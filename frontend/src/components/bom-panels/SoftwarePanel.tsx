/**
 * SoftwarePanel — Shared SBOM software component table
 * Used in both CbomDetailPage and XBOMPage
 */
import { useState, useMemo } from 'react';
import { Box } from 'lucide-react';
import type { SBOMComponent } from '../../types';
import Pagination from '../Pagination';

interface Props {
  components: SBOMComponent[];
}

export default function SoftwarePanel({ components }: Props) {
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const filtered = useMemo(() => {
    if (!filter) return components;
    const q = filter.toLowerCase();
    return components.filter(c =>
      c.name.toLowerCase().includes(q) ||
      c.type.toLowerCase().includes(q) ||
      (c.purl || '').toLowerCase().includes(q) ||
      (c.group || '').toLowerCase().includes(q)
    );
  }, [components, filter]);

  const byType = useMemo(() => {
    const m: Record<string, number> = {};
    for (const c of components) { m[c.type] = (m[c.type] || 0) + 1; }
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [components]);

  // Reset page when filter changes
  const filteredLen = filtered.length;
  const [prevFilteredLen, setPrevFilteredLen] = useState(filteredLen);
  if (filteredLen !== prevFilteredLen) { setPrevFilteredLen(filteredLen); setPage(1); }

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  if (!components.length) {
    return <div style={{ padding: 32, textAlign: 'center', color: 'var(--dc1-text-muted)' }}>No software components found.</div>;
  }

  return (
    <>
      {/* Type stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#1d4ed8' }}>{components.length}</div>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)' }}>Total Packages</div>
        </div>
        {byType.slice(0, 3).map(([type, count]) => (
          <div key={type} className="dc1-card" style={{ padding: 16, textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#475569' }}>{count}</div>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'capitalize' }}>{type}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="dc1-card" style={{ marginBottom: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
            <Box size={15} style={{ marginRight: 6, verticalAlign: -2 }} />
            Software Components
          </h3>
          <input
            type="text"
            placeholder="Filter by name, type, purl…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ padding: '6px 10px', fontSize: 12, borderRadius: 6, border: '1px solid var(--dc1-border)', width: 240 }}
          />
        </div>
        <div className="dc1-table-wrapper">
          <table className="dc1-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>Package Name</th>
                <th>Version</th>
                <th>Type</th>
                <th>Group</th>
                <th>License</th>
                <th>PURL</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((c, i) => (
                <tr key={c['bom-ref'] ?? i}>
                  <td className="dc1-cell-name">
                    {c.group ? <span style={{ color: 'var(--dc1-text-muted)', fontSize: 11 }}>{c.group}/</span> : ''}
                    {c.name}
                  </td>
                  <td style={{ fontFamily: 'var(--dc1-mono)', fontSize: 11 }}>{c.version || '—'}</td>
                  <td>
                    <span style={{ background: '#f1f5f9', color: '#475569', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 500, textTransform: 'capitalize' }}>
                      {c.type}
                    </span>
                  </td>
                  <td style={{ fontSize: 11 }}>{c.group ?? '—'}</td>
                  <td style={{ fontSize: 11 }}>
                    {c.licenses?.map(l => l.license?.id ?? l.license?.name ?? l.expression).filter(Boolean).join(', ') || '—'}
                  </td>
                  <td style={{ fontSize: 10, fontFamily: 'var(--dc1-mono)', color: 'var(--dc1-text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {c.purl || '—'}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={6} style={{ padding: 24, textAlign: 'center', color: 'var(--dc1-text-muted)' }}>No matching components</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination
          page={page}
          total={filtered.length}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </div>
    </>
  );
}
