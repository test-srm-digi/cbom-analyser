import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { CryptoAsset } from '../types';
import styles from './ChartCard.module.scss';

interface CryptoBubbleChartProps {
  assets: CryptoAsset[];
}

const BUBBLE_COLORS = [
  '#58a6ff', '#bc8cff', '#f0883e', '#3fb950', '#f85149',
  '#d29922', '#f778ba', '#79c0ff', '#56d364', '#a371f7',
  '#7ee787', '#ffa657',
];

function computeBubbleData(assets: CryptoAsset[]) {
  const counts: Record<string, number> = {};
  for (const asset of assets) {
    const name = asset.name;
    counts[name] = (counts[name] || 0) + 1;
  }

  return Object.entries(counts)
    .map(([name, count], idx) => ({
      name,
      x: (idx % 6) * 20 + 10 + Math.random() * 10,
      y: Math.floor(idx / 6) * 25 + 15 + Math.random() * 10,
      z: count * 100,
      count,
      color: BUBBLE_COLORS[idx % BUBBLE_COLORS.length],
    }))
    .sort((a, b) => b.count - a.count);
}

interface BubbleTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: { name: string; count: number; color: string } }>;
}

function BubbleTooltip({ active, payload }: BubbleTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  
  const data = payload[0].payload;
  return (
    <div
      style={{
        backgroundColor: '#FFFFFF',
        border: '1px solid #E2E5EA',
        borderRadius: '8px',
        padding: '8px 12px',
        color: '#353535',
      }}
    >
      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: '50%',
            backgroundColor: data.color,
          }}
        />
        {data.name}
      </div>
      <div style={{ fontSize: 12, marginTop: 2 }}>Count: {data.count}</div>
    </div>
  );
}

export default function CryptoBubbleChart({ assets }: CryptoBubbleChartProps) {
  const data = computeBubbleData(assets);

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>
        Algorithm Distribution ({data.length} types of crypto assets)
      </h3>
      <div style={{ height: 250 }}>
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 10, bottom: 10, left: 10 }}>
            <XAxis type="number" dataKey="x" hide domain={[0, 120]} />
            <YAxis type="number" dataKey="y" hide domain={[0, 80]} />
            <ZAxis type="number" dataKey="z" range={[100, 2000]} />
            <Tooltip cursor={false} content={<BubbleTooltip />} />
            <Scatter data={data} shape="circle">
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} fillOpacity={0.7} />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      <div className={styles.legend}>
        {data.slice(0, 14).map(({ name, color }) => (
          <div key={name} className={styles.legendItem}>
            <span className={styles.legendDot} style={{ backgroundColor: color }} />
            {name}
          </div>
        ))}
      </div>
    </div>
  );
}
