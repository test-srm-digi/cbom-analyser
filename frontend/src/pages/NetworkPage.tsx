import { useState } from 'react';
import type { NetworkScanResult } from '../types';
import { NetworkScanner } from '../components';

export default function NetworkPage() {
  const [scanResults, setScanResults] = useState<NetworkScanResult[]>([]);

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
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Protocol</th>
                  <th>Cipher Suite</th>
                  <th>Quantum Safe</th>
                  <th>Scanned</th>
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
