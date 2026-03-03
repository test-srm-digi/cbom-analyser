import { useState, useMemo } from 'react';
import { Trash2, ShieldCheck, ShieldX, Clock, Wifi } from 'lucide-react';
import type { NetworkScanResult } from '../types';
import { NetworkScanner } from '../components';
import {
  useGetNetworkScansQuery,
  useDeleteNetworkScanMutation,
  useDeleteAllNetworkScansMutation,
} from '../store/api';
import { useColumnResize } from '../hooks/useColumnResize';
import Pagination from '../components/Pagination';
import { COL_MIN, PAGE_SIZE } from './network/constants';
import { ScanDetailView } from './network/components';

/* ── Main Network page ────────────────────────────────────── */

export default function NetworkPage() {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const { data: scans = [], isLoading, refetch } = useGetNetworkScansQuery();
  const [deleteScan] = useDeleteNetworkScanMutation();
  const [deleteAll] = useDeleteAllNetworkScansMutation();
  const { colWidths, onResizeStart } = useColumnResize(COL_MIN);

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    if (!search) return scans;
    const q = search.toLowerCase();
    return scans.filter(s =>
      s.host.toLowerCase().includes(q) ||
      s.protocol.toLowerCase().includes(q) ||
      s.cipherSuite.toLowerCase().includes(q) ||
      s.keyExchange.toLowerCase().includes(q),
    );
  }, [scans, search]);

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  // Stats
  const total = scans.length;
  const qsSafe = scans.filter(s => s.isQuantumSafe).length;
  const vulnerable = total - qsSafe;
  const uniqueHosts = new Set(scans.map(s => s.host)).size;

  function handleScanComplete(_result: NetworkScanResult) {
    refetch();
  }

  async function handleDelete(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    await deleteScan(id);
  }

  async function handleDeleteAll() {
    if (window.confirm('Delete all scan history?')) {
      await deleteAll();
    }
  }

  // If a scan is selected, show detail view
  if (selectedScanId) {
    return <ScanDetailView scanId={selectedScanId} onBack={() => setSelectedScanId(null)} />;
  }

  return (
    <div>
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">Network Scanner</h1>
        <p className="dc1-page-subtitle">
          Scan endpoints to discover their TLS configuration and quantum readiness
        </p>
      </div>

      <div style={{ maxWidth: 600 }}>
        <NetworkScanner onScanComplete={handleScanComplete} />
      </div>

      {/* Stats */}
      {total > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, margin: '24px 0' }}>
          <div className="dc1-card" style={{ padding: '14px 18px', borderLeft: '3px solid var(--dc1-primary)' }}>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)' }}>Total Scans</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--dc1-primary)' }}>{total}</div>
            <div style={{ fontSize: 11, color: 'var(--dc1-text-secondary)' }}>{uniqueHosts} unique hosts</div>
          </div>
          <div className="dc1-card" style={{ padding: '14px 18px', borderLeft: '3px solid var(--dc1-success)' }}>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)' }}>Quantum-safe</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--dc1-success)' }}>{qsSafe}</div>
            <div style={{ fontSize: 11, color: 'var(--dc1-text-secondary)' }}>{total > 0 ? Math.round((qsSafe / total) * 100) : 0}% of scans</div>
          </div>
          <div className="dc1-card" style={{ padding: '14px 18px', borderLeft: '3px solid var(--dc1-danger)' }}>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)' }}>Vulnerable</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--dc1-danger)' }}>{vulnerable}</div>
            <div style={{ fontSize: 11, color: 'var(--dc1-text-secondary)' }}>Not quantum-safe</div>
          </div>
        </div>
      )}

      {/* Scan history table */}
      {total > 0 && (
        <div className="dc1-card" style={{ marginTop: 8 }}>
          {/* Toolbar */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '12px 16px', borderBottom: '1px solid var(--dc1-border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>
                Scan History ({filtered.length})
              </h3>
              <input
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search by host, protocol, cipher suite…"
                style={{
                  padding: '6px 12px', border: '1px solid var(--dc1-border)',
                  borderRadius: 6, fontSize: 13, width: 300,
                  outline: 'none',
                }}
              />
            </div>
            <button
              onClick={handleDeleteAll}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 12px', fontSize: 12, fontWeight: 500,
                border: '1px solid var(--dc1-border)', borderRadius: 6,
                background: 'none', cursor: 'pointer', color: 'var(--dc1-danger)',
              }}
            >
              <Trash2 size={13} /> Clear All
            </button>
          </div>

          {/* Table */}
          <div style={{ overflowX: 'auto' }}>
            <table className="dc1-table" style={{ minWidth: 900 }}>
              <colgroup>
                {[0,1,2,3,4,5,6,7].map(i => (
                  <col key={i} style={{ width: colWidths[i] || COL_MIN[i], minWidth: COL_MIN[i] }} />
                ))}
              </colgroup>
              <thead>
                <tr>
                  <th>Host<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 0)} /></th>
                  <th>Port<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 1)} /></th>
                  <th>Protocol<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 2)} /></th>
                  <th>Cipher Suite<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 3)} /></th>
                  <th>Key Exchange<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 4)} /></th>
                  <th>Encryption<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 5)} /></th>
                  <th>Quantum Safe<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 6)} /></th>
                  <th style={{ textAlign: 'center' }}>Actions<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 7)} /></th>
                </tr>
              </thead>
              <tbody>
                {paged.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => setSelectedScanId(s.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td style={{ fontWeight: 500 }}>{s.host}</td>
                    <td>{s.port}</td>
                    <td>
                      <span style={{
                        display: 'inline-block', padding: '2px 8px',
                        borderRadius: 4, fontSize: 12, fontWeight: 600,
                        background: s.protocol.includes('1.3') ? '#dcfce7' : s.protocol.includes('1.2') ? '#fef3c7' : '#fee2e2',
                        color: s.protocol.includes('1.3') ? '#15803d' : s.protocol.includes('1.2') ? '#92400e' : '#dc2626',
                      }}>
                        {s.protocol}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, fontFamily: 'monospace' }}>{s.cipherSuite}</td>
                    <td style={{ fontSize: 13 }}>{s.keyExchange}</td>
                    <td style={{ fontSize: 13 }}>{s.encryption}</td>
                    <td>
                      {s.isQuantumSafe ? (
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          fontSize: 12, fontWeight: 600, color: '#15803d',
                          background: '#dcfce7', padding: '2px 10px', borderRadius: 12,
                        }}>
                          <ShieldCheck size={13} /> Yes
                        </span>
                      ) : (
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          fontSize: 12, fontWeight: 600, color: '#dc2626',
                          background: '#fee2e2', padding: '2px 10px', borderRadius: 12,
                        }}>
                          <ShieldX size={13} /> No
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, color: 'var(--dc1-text-secondary)' }}>
                          <Clock size={11} style={{ verticalAlign: 'text-bottom', marginRight: 3 }} />
                          {new Date(s.scannedAt).toLocaleDateString()}
                        </span>
                        <button
                          onClick={(e) => handleDelete(s.id, e)}
                          title="Delete scan"
                          style={{
                            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                            width: 24, height: 24, borderRadius: 4,
                            border: '1px solid var(--dc1-border)',
                            background: 'none', cursor: 'pointer', color: 'var(--dc1-text-secondary)',
                          }}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <Pagination
            page={page}
            total={filtered.length}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
          />
        </div>
      )}

      {/* Empty state */}
      {!isLoading && total === 0 && (
        <div className="dc1-card" style={{ marginTop: 24, padding: 32, textAlign: 'center' }}>
          <Wifi size={40} style={{ color: 'var(--dc1-text-secondary)', marginBottom: 12, opacity: 0.4 }} />
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No scans yet</h3>
          <p style={{ fontSize: 14, color: 'var(--dc1-text-secondary)' }}>
            Use the scanner above to scan an endpoint. Results will be saved here automatically.
          </p>
        </div>
      )}
    </div>
  );
}
