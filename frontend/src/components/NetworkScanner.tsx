import { useState } from 'react';
import { Globe, Loader2, Wifi } from 'lucide-react';
import { NetworkScanResult } from '../types';
import styles from './NetworkScanner.module.scss';

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
    <div className={styles.card}>
      <h3 className={styles.title}>
        <Globe className={styles.titleIcon} />
        Network TLS Scanner
      </h3>

      <div className={styles.row}>
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="Enter URL or IP (e.g., google.com)"
          className={styles.input}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
        />
        <button
          onClick={handleScan}
          disabled={isScanning || !url}
          className={styles.scanBtn}
        >
          {isScanning ? <Loader2 className={styles.spinIcon} /> : <Wifi className={styles.scanIcon} />}
          Scan
        </button>
      </div>

      {error && <div className={styles.error}>{error}</div>}

      {lastResult && (
        <div className={styles.result}>
          <div className={styles.resultRow}>
            <span className={styles.resultLabel}>Protocol:</span>
            <span className={styles.resultValue}>{lastResult.protocol}</span>
          </div>
          <div className={styles.resultRow}>
            <span className={styles.resultLabel}>Cipher Suite:</span>
            <span className={styles.resultValue} style={{ textAlign: 'right' }}>{lastResult.cipherSuite}</span>
          </div>
          <div className={styles.resultRow}>
            <span className={styles.resultLabel}>Quantum Safe:</span>
            <span className={lastResult.isQuantumSafe ? styles.resultSafe : styles.resultNotSafe}>
              {lastResult.isQuantumSafe ? 'Yes' : 'No'}
            </span>
          </div>
          <div className={styles.resultRow}>
            <span className={styles.resultLabel}>Scanned:</span>
            <span className={styles.resultLabel}>{new Date(lastResult.lastScanned).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}
