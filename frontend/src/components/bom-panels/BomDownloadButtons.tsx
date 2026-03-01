/**
 * BomDownloadButtons — Download CBOM, SBOM, and/or xBOM as JSON files
 */
import { Download } from 'lucide-react';

interface BomData {
  label: string;
  filename: string;
  data: object | undefined | null;
}

interface Props {
  /** Array of download items to show */
  items: BomData[];
  /** Optional: compact mode (icon-only buttons) */
  compact?: boolean;
}

function downloadJson(data: object, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function BomDownloadButtons({ items, compact }: Props) {
  const available = items.filter(i => i.data);
  if (!available.length) return null;

  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
      {available.map(item => (
        <button
          key={item.filename}
          onClick={() => downloadJson(item.data!, item.filename)}
          title={`Download ${item.label}`}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: compact ? '4px 10px' : '6px 14px',
            fontSize: compact ? 11 : 12,
            fontWeight: 500,
            background: 'var(--dc1-bg-card, #fff)',
            border: '1px solid var(--dc1-border)',
            borderRadius: 6,
            cursor: 'pointer',
            color: 'var(--dc1-text)',
            transition: 'background 0.15s',
          }}
          onMouseEnter={e => { (e.target as HTMLElement).style.background = 'var(--dc1-bg-hover, #f1f5f9)'; }}
          onMouseLeave={e => { (e.target as HTMLElement).style.background = 'var(--dc1-bg-card, #fff)'; }}
        >
          <Download size={compact ? 12 : 14} />
          <span style={{ fontWeight: 600 }}>{item.label}</span>
        </button>
      ))}
    </div>
  );
}
