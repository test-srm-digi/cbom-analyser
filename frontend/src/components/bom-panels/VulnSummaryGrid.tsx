/**
 * VulnSummaryGrid — Clickable severity cards (shared)
 */

interface Props {
  vuln: { total: number; critical: number; high: number; medium: number; low: number; info: number };
  activeSev?: string;
  onToggle?: (sev: string) => void;
}

const COLORS: Record<string, { text: string; border: string; bg: string }> = {
  critical: { text: '#991b1b', border: '#ef4444', bg: '#fee2e2' },
  high:     { text: '#ef4444', border: '#ef4444', bg: '#ffedd5' },
  medium:   { text: '#f59e0b', border: '#f59e0b', bg: '#fef3c7' },
  low:      { text: '#3b82f6', border: '#3b82f6', bg: '#dbeafe' },
  info:     { text: '#94a3b8', border: '#94a3b8', bg: '#f1f5f9' },
};

export default function VulnSummaryGrid({ vuln, activeSev, onToggle }: Props) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12, marginBottom: 16 }}>
      {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
        const c = COLORS[sev];
        const count = vuln[sev] ?? 0;
        const isActive = activeSev === sev;
        return (
          <div
            key={sev}
            className="dc1-card"
            style={{
              padding: 16, textAlign: 'center',
              cursor: onToggle ? 'pointer' : undefined,
              borderColor: isActive ? c.border : undefined,
              borderWidth: isActive ? 2 : undefined,
              borderStyle: isActive ? 'solid' : undefined,
            }}
            onClick={() => onToggle?.(sev)}
          >
            <div style={{ fontSize: 24, fontWeight: 700, color: c.text }}>{count}</div>
            <div style={{ fontSize: 12, color: 'var(--dc1-text-muted)', textTransform: 'capitalize' }}>{sev}</div>
          </div>
        );
      })}
    </div>
  );
}
