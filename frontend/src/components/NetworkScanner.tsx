import { useState } from 'react';
import { Globe, Loader2, Wifi } from 'lucide-react';
import { NetworkScanResult } from '../types';

interface NetworkScannerProps {
  onScanComplete: (result: NetworkScanResult) => void;
}

export default function NetworkScanner({ onScanComplete }: NetworkScannerProps) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<NetworkScanResult | null>(null);

  async function handleScan() {
    if (!url) return;
    setIsScanning(true);
    setError(null);

    try {
      const resp = await fetch('/api/scan-network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await resp.json();
      if (data.success) {
        setLastResult(data.result);
        onScanComplete(data.result);
      } else {
        setError(data.error || 'Scan failed');
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <div className="bg-qg-card border border-qg-border rounded-lg p-4 animate-fade-in">
      <h3 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
        <Globe className="w-4 h-4" />
        Network TLS Scanner
      </h3>

      <div className="flex gap-2 mb-3">
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="Enter URL or IP (e.g., google.com)"
          className="flex-1 bg-qg-dark border border-qg-border rounded px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-qg-accent"
          onKeyDown={e => e.key === 'Enter' && handleScan()}
        />
        <button
          onClick={handleScan}
          disabled={isScanning || !url}
          className="bg-qg-accent/20 text-qg-accent border border-qg-accent/30 rounded px-4 py-2 text-sm font-medium hover:bg-qg-accent/30 disabled:opacity-40 transition-colors flex items-center gap-2"
        >
          {isScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />}
          Scan
        </button>
      </div>

      {error && (
        <div className="text-qg-red text-xs bg-qg-red/10 border border-qg-red/20 rounded px-3 py-2 mb-3">
          {error}
        </div>
      )}

      {lastResult && (
        <div className="bg-qg-dark rounded border border-qg-border p-3 text-xs space-y-1.5">
          <div className="flex justify-between">
            <span className="text-gray-500">Protocol:</span>
            <span className="text-gray-200 font-mono">{lastResult.protocol}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Cipher Suite:</span>
            <span className="text-gray-200 font-mono text-right">{lastResult.cipherSuite}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Quantum Safe:</span>
            <span className={lastResult.isQuantumSafe ? 'text-qg-green' : 'text-qg-red'}>
              {lastResult.isQuantumSafe ? 'Yes' : 'No'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Scanned:</span>
            <span className="text-gray-400">{new Date(lastResult.lastScanned).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}
