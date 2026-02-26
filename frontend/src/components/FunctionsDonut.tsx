import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { CryptoAsset } from '../types';
import { TOOLTIP_STYLE, CHART_BLUE, CHART_PURPLE, CHART_ORANGE, CHART_YELLOW, CHART_GREEN, CHART_PINK, CHART_GRAY } from '../styles/dsTokens';
import styles from './ChartCard.module.scss';

interface FunctionsDonutProps {
  assets: CryptoAsset[];
}

const FUNCTION_COLORS: Record<string, string> = {
  'Hash Function': CHART_BLUE,
  'Keygen': CHART_GREEN,
  'Encrypt': CHART_ORANGE,
  'Decrypt': CHART_YELLOW,
  'Sign': CHART_PURPLE,
  'Verify': '#a371f7',
  'Key Exchange': '#7ee787',
  'Digest': '#56d364',
  'Tag': CHART_PINK,
  'Other': CHART_GRAY,
};

function computeFunctionData(assets: CryptoAsset[]) {
  const counts: Record<string, number> = {};
  for (const asset of assets) {
    const fns = asset.cryptoProperties?.algorithmProperties?.cryptoFunctions;
    if (fns && fns.length > 0) {
      for (const fn of fns) {
        counts[fn] = (counts[fn] || 0) + 1;
      }
    } else {
      counts['Other'] = (counts['Other'] || 0) + 1;
    }
  }
  return Object.entries(counts)
    .map(([name, value]) => ({
      name,
      value,
      color: FUNCTION_COLORS[name] || '#8b949e',
    }))
    .sort((a, b) => b.value - a.value);
}

export default function FunctionsDonut({ assets }: FunctionsDonutProps) {
  const data = computeFunctionData(assets);
  const total = new Set(data.map(d => d.name)).size;

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Crypto Functions</h3>
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
            <Tooltip contentStyle={TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>
        <div className={styles.centerLabel}>
          <span className={styles.centerNumber}>{total}</span>
          <span className={styles.centerText}>Crypto Functions</span>
        </div>
      </div>
      <div className={styles.legend}>
        {data.map(({ name, color }) => (
          <div key={name} className={styles.legendItem}>
            <span className={styles.legendSquare} style={{ backgroundColor: color }} />
            {name}
          </div>
        ))}
      </div>
    </div>
  );
}
