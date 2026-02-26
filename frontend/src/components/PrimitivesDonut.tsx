import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { CryptoAsset } from '../types';
import { TOOLTIP_STYLE, CHART_BLUE, CHART_PURPLE, CHART_ORANGE, CHART_YELLOW, CHART_GREEN, CHART_PINK, CHART_GRAY } from '../styles/dsTokens';
import styles from './ChartCard.module.scss';

interface PrimitivesDonutProps {
  assets: CryptoAsset[];
}

const PRIMITIVE_COLORS: Record<string, string> = {
  'hash': CHART_BLUE,
  'block-cipher': CHART_PURPLE,
  'pke': CHART_ORANGE,
  'signature': CHART_YELLOW,
  'keygen': CHART_GREEN,
  'digest': '#56d364',
  'mac': CHART_PINK,
  'stream-cipher': '#79c0ff',
  'key-encapsulation': '#a371f7',
  'key-agreement': '#7ee787',
  'ae': '#ffa657',
  'other': CHART_GRAY,
};

function computePrimitiveData(assets: CryptoAsset[]) {
  const counts: Record<string, number> = {};
  for (const asset of assets) {
    const primitive = asset.cryptoProperties?.algorithmProperties?.primitive || 'other';
    counts[primitive] = (counts[primitive] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([name, value]) => ({
      name,
      value,
      color: PRIMITIVE_COLORS[name] || CHART_GRAY,
    }))
    .sort((a, b) => b.value - a.value);
}

function getPrimitiveLabel(key: string): string {
  const labels: Record<string, string> = {
    'hash': 'Hash',
    'block-cipher': 'Block-cipher',
    'pke': 'Pke',
    'signature': 'Signature',
    'keygen': 'Keygen',
    'digest': 'Digest',
    'mac': 'Mac',
    'stream-cipher': 'Stream-cipher',
    'ae': 'Ae',
    'other': 'Other',
  };
  return labels[key] || key;
}

export default function PrimitivesDonut({ assets }: PrimitivesDonutProps) {
  const data = computePrimitiveData(assets);
  const total = new Set(data.map(d => d.name)).size;

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Crypto Primitives</h3>
      <div className={styles.chartWrap} style={{ height: 250 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
              label={({ percent }) => percent > 0.05 ? `${(percent * 100).toFixed(1)}%` : null}
              labelLine={false}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              formatter={(value: number, name: string) => [value, getPrimitiveLabel(name)]}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className={styles.centerLabel}>
          <span className={styles.centerNumber}>{total}</span>
          <span className={styles.centerText}>Crypto Primitives</span>
        </div>
      </div>
      <div className={styles.legend}>
        {data.map(({ name, color }) => (
          <div key={name} className={styles.legendItem}>
            <span className={styles.legendSquare} style={{ backgroundColor: color }} />
            {getPrimitiveLabel(name)}
          </div>
        ))}
      </div>
    </div>
  );
}
