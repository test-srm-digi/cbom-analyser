import { useState, useCallback } from 'react';
import { Globe, Loader2, Wifi, ShieldCheck, ShieldX, ChevronDown, ChevronUp, Sparkles, Info } from 'lucide-react';
import { NetworkScanResult } from '../types';
import styles from './NetworkScanner.module.scss';

interface CipherComponent {
  name: string;
  role: string;
  quantumSafe: boolean;
  notes: string;
}

interface CipherBreakdown {
  components: CipherComponent[];
  allSafe: boolean;
  anyNotSafe: boolean;
}

interface AiSuggestion {
  loading?: boolean;
  fix?: string;
  codeSnippet?: string;
  confidence?: 'high' | 'medium' | 'low';
  error?: string;
}

interface NetworkScannerProps {
  onScanComplete: (result: NetworkScanResult) => void;
}

export default function NetworkScanner({ onScanComplete }: NetworkScannerProps) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<NetworkScanResult | null>(null);
  const [breakdown, setBreakdown] = useState<CipherBreakdown | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [aiSuggestion, setAiSuggestion] = useState<AiSuggestion | null>(null);

  async function handleScan() {
    if (!url) return;
    setIsScanning(true);
    setError(null);
    setAiSuggestion(null);

    try {
      const resp = await fetch('/api/scan-network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await resp.json();
      if (data.success) {
        setLastResult(data.result);
        setBreakdown(data.cipherBreakdown ?? null);
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

  const fetchAiFix = useCallback(async () => {
    if (!lastResult) return;
    setAiSuggestion({ loading: true });

    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: lastResult.cipherSuite,
          primitive: 'key-agreement',
          quantumSafety: lastResult.isQuantumSafe ? 'quantum-safe' : 'not-quantum-safe',
          assetType: 'protocol',
          description: `TLS endpoint ${lastResult.host}:${lastResult.port} using ${lastResult.protocol} with cipher suite ${lastResult.cipherSuite}. Key exchange is vulnerable to quantum attacks.`,
          recommendedPQC: lastResult.isQuantumSafe ? undefined : 'ML-KEM-768 (hybrid with X25519)',
          mode: lastResult.cipherSuite,
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
  }, [lastResult]);

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
        <div className={styles.resultContainer}>
          {/* ── Summary row ── */}
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

          {/* ── Cipher breakdown ── */}
          {breakdown && breakdown.components.length > 0 && (
            <div className={styles.breakdownSection}>
              <button
                className={styles.breakdownToggle}
                onClick={() => setDetailsOpen(o => !o)}
              >
                <Info size={14} />
                <span>Cipher Suite Breakdown ({breakdown.components.length} components)</span>
                {detailsOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>

              {detailsOpen && (
                <div className={styles.breakdownList}>
                  {breakdown.components.map((c, i) => (
                    <div key={i} className={styles.breakdownItem}>
                      <div className={styles.breakdownHeader}>
                        <span className={styles.breakdownRole}>{c.role}</span>
                        <span className={styles.breakdownAlgo}>{c.name}</span>
                        {c.quantumSafe ? (
                          <span className={styles.qsBadgeSafe}><ShieldCheck size={12} /> Safe</span>
                        ) : (
                          <span className={styles.qsBadgeNotSafe}><ShieldX size={12} /> Not Safe</span>
                        )}
                      </div>
                      <p className={styles.breakdownNotes}>{c.notes}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── AI Fix button ── */}
          {!lastResult.isQuantumSafe && (
            <div className={styles.aiSection}>
              {!aiSuggestion && (
                <button className={styles.aiBtn} onClick={fetchAiFix}>
                  <Sparkles size={14} />
                  Get AI Migration Fix
                </button>
              )}

              {aiSuggestion?.loading && (
                <div className={styles.aiLoading}>
                  <Loader2 size={14} className={styles.spinIcon} />
                  <span>Generating quantum-safe migration plan…</span>
                </div>
              )}

              {aiSuggestion?.error && (
                <div className={styles.aiError}>{aiSuggestion.error}</div>
              )}

              {aiSuggestion?.fix && (
                <div className={styles.aiPanel}>
                  <div className={styles.aiPanelHeader}>
                    <Sparkles size={14} />
                    <span className={styles.aiPanelTitle}>AI Migration Suggestion</span>
                    {aiSuggestion.confidence && (
                      <span className={`${styles.aiConfidence} ${
                        aiSuggestion.confidence === 'high' ? styles.confidenceHigh :
                        aiSuggestion.confidence === 'medium' ? styles.confidenceMedium :
                        styles.confidenceLow
                      }`}>
                        {aiSuggestion.confidence}
                      </span>
                    )}
                  </div>
                  <p className={styles.aiText}>{aiSuggestion.fix}</p>
                  {aiSuggestion.codeSnippet && (
                    <pre className={styles.aiCode}>{aiSuggestion.codeSnippet}</pre>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
