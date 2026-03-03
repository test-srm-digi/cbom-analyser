import { useState, useMemo, useCallback } from 'react';
import {
  Loader2,
  ShieldCheck,
  ShieldX,
  ArrowLeft,
  Info,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Globe,
} from 'lucide-react';
import { fetchWithUser } from '../../../utils/fetchWithUser';
import { useGetNetworkScanQuery } from '../../../store/api';
import { parseBreakdown } from '../utils';
import type { AiSuggestion } from '../types';

export default function ScanDetailView({
  scanId,
  onBack,
}: {
  scanId: string;
  onBack: () => void;
}) {
  const { data: scan, isLoading, error } = useGetNetworkScanQuery(scanId);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [aiSuggestion, setAiSuggestion] = useState<AiSuggestion | null>(null);

  const breakdown = useMemo(
    () => (scan ? parseBreakdown(scan.cipherBreakdown) : null),
    [scan],
  );

  const fetchAiFix = useCallback(async () => {
    if (!scan) return;
    setAiSuggestion({ loading: true });
    try {
      const res = await fetchWithUser('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: scan.cipherSuite,
          primitive: 'key-agreement',
          quantumSafety: scan.isQuantumSafe
            ? 'quantum-safe'
            : 'not-quantum-safe',
          assetType: 'protocol',
          description: `TLS endpoint ${scan.host}:${scan.port} using ${scan.protocol} with cipher suite ${scan.cipherSuite}. Key exchange is vulnerable to quantum attacks.`,
          recommendedPQC: scan.isQuantumSafe
            ? undefined
            : 'ML-KEM-768 (hybrid with X25519)',
          mode: scan.cipherSuite,
        }),
      });
      const json = await res.json();
      if (json.success) {
        setAiSuggestion({
          fix: json.suggestedFix,
          codeSnippet: json.codeSnippet,
          confidence: json.confidence,
        });
      } else {
        setAiSuggestion({ error: json.error || 'No suggestion available' });
      }
    } catch {
      setAiSuggestion({ error: 'Failed to fetch AI suggestion' });
    }
  }, [scan]);

  if (isLoading)
    return (
      <div
        className="dc1-card"
        style={{ padding: 32, textAlign: 'center' }}
      >
        <Loader2
          className="spin"
          style={{ animation: 'spin 1s linear infinite' }}
        />{' '}
        Loading scan details…
      </div>
    );
  if (error || !scan)
    return (
      <div className="dc1-card" style={{ padding: 32 }}>
        <p>Scan not found.</p>
        <button className="dc1-btn dc1-btn-secondary" onClick={onBack}>
          Back
        </button>
      </div>
    );

  return (
    <div>
      {/* Back button */}
      <button
        onClick={onBack}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          background: 'none',
          border: 'none',
          color: 'var(--dc1-primary)',
          cursor: 'pointer',
          fontSize: 14,
          marginBottom: 16,
          padding: 0,
        }}
      >
        <ArrowLeft size={16} /> Back to Scan History
      </button>

      <div className="dc1-page-header">
        <h1 className="dc1-page-title">
          <Globe
            size={22}
            style={{ marginRight: 8, verticalAlign: 'text-bottom' }}
          />
          {scan.host}:{scan.port}
        </h1>
        <p className="dc1-page-subtitle">
          Scanned on {new Date(scan.scannedAt).toLocaleString()}
        </p>
      </div>

      {/* Stat cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 16,
          marginBottom: 24,
        }}
      >
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div
            style={{
              fontSize: 12,
              color: 'var(--dc1-text-secondary)',
              marginBottom: 4,
            }}
          >
            Protocol
          </div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>{scan.protocol}</div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div
            style={{
              fontSize: 12,
              color: 'var(--dc1-text-secondary)',
              marginBottom: 4,
            }}
          >
            Cipher Suite
          </div>
          <div
            style={{ fontSize: 14, fontWeight: 600, fontFamily: 'monospace' }}
          >
            {scan.cipherSuite}
          </div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div
            style={{
              fontSize: 12,
              color: 'var(--dc1-text-secondary)',
              marginBottom: 4,
            }}
          >
            Quantum Safe
          </div>
          <div
            style={{
              fontSize: 20,
              fontWeight: 700,
              color: scan.isQuantumSafe
                ? 'var(--dc1-success)'
                : 'var(--dc1-danger)',
            }}
          >
            {scan.isQuantumSafe ? 'Yes' : 'No'}
          </div>
        </div>
        <div className="dc1-card" style={{ padding: '16px 20px' }}>
          <div
            style={{
              fontSize: 12,
              color: 'var(--dc1-text-secondary)',
              marginBottom: 4,
            }}
          >
            Key Exchange
          </div>
          <div style={{ fontSize: 14, fontWeight: 600 }}>
            {scan.keyExchange}
          </div>
        </div>
      </div>

      {/* Cipher components detail */}
      <div
        className="dc1-card"
        style={{ padding: '20px 24px', marginBottom: 24 }}
      >
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>
          Cipher Suite Components
        </h3>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: 16,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: 'uppercase',
                color: 'var(--dc1-text-secondary)',
                letterSpacing: 1,
                marginBottom: 4,
              }}
            >
              Key Exchange
            </div>
            <div style={{ fontWeight: 600 }}>{scan.keyExchange}</div>
          </div>
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: 'uppercase',
                color: 'var(--dc1-text-secondary)',
                letterSpacing: 1,
                marginBottom: 4,
              }}
            >
              Encryption
            </div>
            <div style={{ fontWeight: 600 }}>{scan.encryption}</div>
          </div>
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: 'uppercase',
                color: 'var(--dc1-text-secondary)',
                letterSpacing: 1,
                marginBottom: 4,
              }}
            >
              Hash / PRF
            </div>
            <div style={{ fontWeight: 600 }}>{scan.hashFunction}</div>
          </div>
        </div>
      </div>

      {/* Cipher breakdown (collapsible) */}
      {breakdown && breakdown.components.length > 0 && (
        <div
          className="dc1-card"
          style={{ padding: '20px 24px', marginBottom: 24 }}
        >
          <button
            onClick={() => setDetailsOpen((o) => !o)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              width: '100%',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              fontSize: 15,
              fontWeight: 600,
              padding: 0,
              color: 'inherit',
            }}
          >
            <Info size={16} />
            <span>
              Cipher Suite Breakdown ({breakdown.components.length} components)
            </span>
            {detailsOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>

          {detailsOpen && (
            <div
              style={{
                marginTop: 16,
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
              }}
            >
              {breakdown.components.map((c, i) => (
                <div
                  key={i}
                  style={{
                    padding: '12px 16px',
                    borderRadius: 8,
                    border: '1px solid var(--dc1-border)',
                    background: 'var(--dc1-bg-secondary, #fafafa)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      marginBottom: 6,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 10,
                        textTransform: 'uppercase',
                        letterSpacing: 1,
                        color: 'var(--dc1-text-secondary)',
                        fontWeight: 600,
                      }}
                    >
                      {c.role}
                    </span>
                    <span
                      style={{
                        fontWeight: 700,
                        fontFamily: 'monospace',
                        fontSize: 14,
                      }}
                    >
                      {c.name}
                    </span>
                    {c.quantumSafe ? (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: 11,
                          fontWeight: 600,
                          color: '#15803d',
                          background: '#dcfce7',
                          padding: '2px 8px',
                          borderRadius: 12,
                        }}
                      >
                        <ShieldCheck size={12} /> Safe
                      </span>
                    ) : (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: 11,
                          fontWeight: 600,
                          color: '#dc2626',
                          background: '#fee2e2',
                          padding: '2px 8px',
                          borderRadius: 12,
                        }}
                      >
                        <ShieldX size={12} /> Not Safe
                      </span>
                    )}
                  </div>
                  <p
                    style={{
                      margin: 0,
                      fontSize: 13,
                      color: 'var(--dc1-text-secondary)',
                    }}
                  >
                    {c.notes}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Certificate info (if available) */}
      {(scan.certCommonName || scan.certIssuer || scan.certExpiry) && (
        <div
          className="dc1-card"
          style={{ padding: '20px 24px', marginBottom: 24 }}
        >
          <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>
            Certificate Information
          </h3>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: 16,
            }}
          >
            {scan.certCommonName && (
              <div>
                <div
                  style={{
                    fontSize: 11,
                    textTransform: 'uppercase',
                    color: 'var(--dc1-text-secondary)',
                    letterSpacing: 1,
                    marginBottom: 4,
                  }}
                >
                  Common Name
                </div>
                <div style={{ fontWeight: 600 }}>{scan.certCommonName}</div>
              </div>
            )}
            {scan.certIssuer && (
              <div>
                <div
                  style={{
                    fontSize: 11,
                    textTransform: 'uppercase',
                    color: 'var(--dc1-text-secondary)',
                    letterSpacing: 1,
                    marginBottom: 4,
                  }}
                >
                  Issuer
                </div>
                <div style={{ fontWeight: 600 }}>{scan.certIssuer}</div>
              </div>
            )}
            {scan.certExpiry && (
              <div>
                <div
                  style={{
                    fontSize: 11,
                    textTransform: 'uppercase',
                    color: 'var(--dc1-text-secondary)',
                    letterSpacing: 1,
                    marginBottom: 4,
                  }}
                >
                  Expiry
                </div>
                <div style={{ fontWeight: 600 }}>{scan.certExpiry}</div>
              </div>
            )}
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
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
                width: '100%',
                padding: '10px 16px',
                background: 'linear-gradient(135deg, #eff6ff, #f5f3ff)',
                border: '1px solid var(--dc1-border)',
                borderRadius: 8,
                cursor: 'pointer',
                fontSize: 14,
                fontWeight: 600,
                color: 'var(--dc1-primary)',
              }}
            >
              <Sparkles size={14} /> Get AI Migration Fix
            </button>
          )}

          {aiSuggestion?.loading && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: 12,
                fontSize: 14,
                color: 'var(--dc1-text-secondary)',
              }}
            >
              <Loader2
                size={14}
                style={{ animation: 'spin 1s linear infinite' }}
              />{' '}
              Generating quantum-safe migration plan…
            </div>
          )}

          {aiSuggestion?.error && (
            <div
              style={{
                padding: 12,
                color: 'var(--dc1-danger)',
                fontSize: 14,
              }}
            >
              {aiSuggestion.error}
            </div>
          )}

          {aiSuggestion?.fix && (
            <div style={{ padding: 12 }}>
              <h4
                style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}
              >
                AI Migration Suggestion
              </h4>
              <div
                style={{
                  whiteSpace: 'pre-wrap',
                  fontSize: 13,
                  lineHeight: 1.6,
                }}
              >
                {aiSuggestion.fix}
              </div>
              {aiSuggestion.codeSnippet && (
                <pre
                  style={{
                    marginTop: 12,
                    padding: 12,
                    background: '#1e293b',
                    color: '#e2e8f0',
                    borderRadius: 8,
                    fontSize: 12,
                    overflow: 'auto',
                  }}
                >
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
