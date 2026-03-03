import { useState } from 'react';
import type { NetworkScanResult } from '../types';
import { NetworkScanner } from '../components';
import { useColumnResize } from '../hooks/useColumnResize';

const NET_COL_MIN: Record<number, number> = { 0: 140, 1: 80, 2: 120, 3: 90, 4: 120 };

export default function NetworkPage() {
  const [scanResults, setScanResults] = useState<NetworkScanResult[]>([]);
  const { colWidths, onResizeStart } = useColumnResize(NET_COL_MIN);

  function handleScanComplete(result: NetworkScanResult) {
    setScanResults((prev) => [result, ...prev]);
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

      {scanResults.length > 1 && (
        <div className="dc1-card" style={{ marginTop: 20 }}>
          <h3 className="dc1-card-section-title">Scan History</h3>
          <div className="dc1-table-wrapper">
            <table className="dc1-table">
              <colgroup>
                {[0,1,2,3,4].map(i => <col key={i} style={{ width: colWidths[i] || NET_COL_MIN[i], minWidth: NET_COL_MIN[i] }} />)}
              </colgroup>
              <thead>
                <tr>
                  <th>URL<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 0)} /></th>
                  <th>Protocol<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 1)} /></th>
                  <th>Cipher Suite<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 2)} /></th>
                  <th>Quantum Safe<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 3)} /></th>
                  <th>Scanned<span className="dc1-resize-handle" onMouseDown={e => onResizeStart(e, 4)} /></th>
                </tr>
              </thead>
              <tbody>
                {scanResults.map((r, i) => (
                  <tr key={i}>
                    <td className="dc1-cell-name">{r.host}:{r.port}</td>
                    <td>{r.protocol}</td>
                    <td style={{ fontSize: 12, fontFamily: 'monospace' }}>{r.cipherSuite}</td>
                    <td>
                      <span style={{
                        color: r.isQuantumSafe ? 'var(--dc1-success)' : 'var(--dc1-danger)',
                        fontWeight: 600,
                      }}>
                        {r.isQuantumSafe ? 'Yes' : 'No'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--dc1-text-secondary)' }}>
                      {new Date(r.lastScanned).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
