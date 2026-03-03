import { useState, useMemo, useCallback } from 'react';
import { Trash2, Loader2, ShieldCheck, ShieldX, ArrowLeft, Info, ChevronDown, ChevronUp, Sparkles, Clock, Globe, Wifi } from 'lucide-react';
import type { NetworkScanResult } from '../types';
import { NetworkScanner } from '../components';
import { useGetNetworkScansQuery, useDeleteNetworkScanMutation, useDeleteAllNetworkScansMutation, useGetNetworkScanQuery } from '../store/api';
import type { NetworkScanRecord, CipherBreakdown } from '../store/api';
import { useColumnResize } from '../hooks/useColumnResize';
import Pagination from '../components/Pagination';

const COL_MIN: Record<number, number> = { 0: 160, 1: 80, 2: 100, 3: 180, 4: 110, 5: 100, 6: 100, 7: 80 };
const PAGE_SIZE = 15;

/* ── Helper: parse cipher breakdown from JSON string ──────── */
function parseBreakdown(raw: string | null): CipherBreakdown | null {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

/* ── Detail view for a single scan ────────────────────────── */
function ScanDetailView({ scanId, onBack }: { scanId: string; onBack: () => void }) {
  const { data: scan, isLoading, error } = useGetNetworkScanQuery(scanId);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [aiSuggestion, setAiSuggestion] = useState<{ loading?: boolean; fix?: string; codeSnippet?: string; confidence?: string; error?: string } | null>(null);

  const breakdown = useMemo(() => scan ? parseBreakdown(scan.cipherBreakdown) : null, [scan]);

  const fetchAiFix = useCallback(async () => {
    if (!scan) return;
    setAiSuggestion({ loading: true });
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: scan.cipherSuite,
          primitive: 'key-agreement',
          quantumSafety: scan.isQuantumSafe ? 'quantum-safe' : 'not-quantum-safe',
          assetType: 'protocol',
          description: `TLS endpoint ${scan.host}:${scan.port} using ${scan.protocol} with cipher suite ${scan.cipherSuite}. Key exchange is vulnerable to quantum attacks.`,
          recommendedPQC: scan.isQuantumSafe ? undefined : 'ML-KEM-768 (hybrid with X25519)',
          mode: scan.cipherSuite,
        }),
      });
      const json = await res.json();
      if (json.success) {
        setAiSuggestion({ fix: json.suggestedFix, codeSnippet: json.codeSnippet, confidence: json.confidence });
      } else {
        setAiSuggestion({ error: json.error || 'No suggestion available' });
      }
    } catch {
      setAiSuggestion({ error: 'Failed to fetch AI suggestion' });
    }
  }, [scan]);

  if (isLoading) return <div className="dc1-card" style={{ padding: 32, textAlign: 'center' }}><Loader2 className="spin" style={{ animation: 'spin 1s linear infinite' }} /> Loading scan details…</div>;
  if (error || !scan) return <div className="dc1-card" style={{ padding: 32 }}><p>Scan not found.</p><button className="dc1-btn dc1-btn-secondary" onClick={onBack}>Back</button></div>;

  return (
    <div>
      {/* Back button */}
      <button
        onClick={onBack}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          background: 'none', border: 'none', color: 'var(--dc1-primary)',
          cursor: 'pointer', fontSize: 14, marginBottom: 16, padding: 0,
        }}
      >
        <ArrowLeft size={16} /> Back to Scan History
      </button>

      <div className="dc1-page-header">
        <h1 className="dc1-page-title">
          <Globe size={22} style={{ marginRight: 8, verticalAlign: 'text-bottom' }} />
          {scan.host}:{scan.port}
        </h1>
        <p className="dc1-page-subtitle">
          Scanned on {new Date(scan.scannedAt).toLocaleString()}
        </p>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)', marginBottom: 4 }}>Protocol</div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>{scan.protocol}</div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)', marginBottom: 4 }}>Cipher Suite</div>
          <div style={{ fontSize: 14, fontWeight: 600, fontFamily: 'monospace' }}>{scan.cipherSuite}</div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)', marginBottom: 4 }}>Quantum Safe</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: scan.isQuantumSafe ? 'var(--dc1-success)' : 'var(--dc1-danger)' }}>
            {scan.isQuantumSafe ? 'Yes' : 'No'}
          </div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--dc1-text-secondary)', marginBottom: 4 }}>Key Exchange</div>
          <div style={{ fontSize: 14, fontWeight: 600 }}>{scan.keyExchange}</div>
        </div>
      </div>

      {/* Cipher components detail */}
      <div className="dc1-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>Cipher Suite Components</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16 }}>
          <div>
            <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Key Exchange</div>
            <div style={{ fontWeight: 600 }}>{scan.keyExchange}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Encryption</div>
            <div style={{ fontWeight: 600 }}>{scan.encryption}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Hash / PRF</div>
            <div style={{ fontWeight: 600 }}>{scan.hashFunction}</div>
          </div>
        </div>
      </div>

      {/* Cipher breakdown (collapsible) */}
      {breakdown && breakdown.components.length > 0 && (
        <div className="dc1-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <button
            onClick={() => setDetailsOpen(o => !o)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, width: '100%',
              background: 'none', border: 'none', cursor: 'pointer',
              fontSize: 15, fontWeight: 600, padding: 0, color: 'inherit',
            }}
          >
            <Info size={16} />
            <span>Cipher Suite Breakdown ({breakdown.components.length} components)</span>
            {detailsOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>

          {detailsOpen && (
            <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {breakdown.components.map((c, i) => (
                <div key={i} style={{
                  padding: '12px 16px',
                  borderRadius: 8,
                  border: '1px solid var(--dc1-border)',
                  background: 'var(--dc1-bg-secondary, #fafafa)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
                    <span style={{
                      fontSize: 10, textTransform: 'uppercase', letterSpacing: 1,
                      color: 'var(--dc1-text-secondary)', fontWeight: 600,
                    }}>
                      {c.role}
                    </span>
                    <span style={{ fontWeight: 700, fontFamily: 'monospace', fontSize: 14 }}>{c.name}</span>
                    {c.quantumSafe ? (
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, fontWeight: 600, color: '#15803d',
                        background: '#dcfce7', padding: '2px 8px', borderRadius: 12,
                      }}>
                        <ShieldCheck size={12} /> Safe
                      </span>
                    ) : (
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, fontWeight: 600, color: '#dc2626',
                        background: '#fee2e2', padding: '2px 8px', borderRadius: 12,
                      }}>
                        <ShieldX size={12} /> Not Safe
                      </span>
                    )}
                  </div>
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--dc1-text-secondary)' }}>{c.notes}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Certificate info (if available) */}
      {(scan.certCommonName || scan.certIssuer || scan.certExpiry) && (
        <div className="dc1-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>Certificate Information</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
            {scan.certCommonName && <div>
              <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Common Name</div>
              <div style={{ fontWeight: 600 }}>{scan.certCommonName}</div>
            </div>}
            {scan.certIssuer && <div>
              <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Issuer</div>
              <div style={{ fontWeight: 600 }}>{scan.certIssuer}</div>
            </div>}
            {scan.certExpiry && <div>
              <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--dc1-text-secondary)', letterSpacing: 1, marginBottom: 4 }}>Expiry</div>
              <div style={{ fontWeight: 600 }}>{scan.certExpiry}</div>
            </div>}
          </div>
        </div>
      )}

      {/* AI Fix section */}
      {!scan.isQuantumSafe && (
        <div className="dc1-card" style={{ padding: '20px 24px' }}>
          {!aiSuggestion && (
            <button
              onClick={fetchAiFix}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                width: '100%', padding: '10px 16px',
                background: 'linear-gradient(135deg, #eff6ff, #f5f3ff)',
                border: '1px solid var(--dc1-border)',
                borderRadius: 8, cursor: 'pointer', fontSize: 14, fontWeight: 600,
                color: 'var(--dc1-primary)',
              }}
            >
              <Sparkles size={14} /> Get AI Migration Fix
            </button>
          )}

          {aiSuggestion?.loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: 12, fontSize: 14, color: 'var(--dc1-text-secondary)' }}>
              <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Generating quantum-safe migration plan…
            </div>
          )}

          {aiSuggestion?.error && (
            <div style={{ padding: 12, color: 'var(--dc1-danger)', fontSize: 14 }}>{aiSuggestion.error}</div>
          )}

          {aiSuggestion?.fix && (
            <div style={{ padding: 12 }}>
              <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>AI Migration Suggestion</h4>
              <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.6 }}>{aiSuggestion.fix}</div>
              {aiSuggestion.codeSnippet && (
                <pre style={{
                  marginTop: 12, padding: 12, background: '#1e293b', color: '#e2e8f0',
                  borderRadius: 8, fontSize: 12, overflow: 'auto',
                }}>
                  {aiSuggestion.codeSnippet}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

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
