import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { CryptoAsset, QuantumSafetyStatus, DonutChartData } from '../types';
import styles from './ChartCard.module.scss';

interface QuantumSafetyDonutProps {
  assets: CryptoAsset[];
}

const COLORS: Record<string, string> = {
  'Quantum Safe': '#27A872',
  'Not Quantum Safe': '#DC2626',
  'Conditional': '#22d3ee',
  'Unknown': '#8b949e',
};

function computeData(assets: CryptoAsset[]): DonutChartData[] {
  const quantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE).length;
  const notQuantumSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE).length;
  const conditional = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.CONDITIONAL).length;
  const unknown = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.UNKNOWN).length;

  return [
    { name: 'Quantum Safe', value: quantumSafe, color: COLORS['Quantum Safe'] },
    { name: 'Not Quantum Safe', value: notQuantumSafe, color: COLORS['Not Quantum Safe'] },
    { name: 'Conditional', value: conditional, color: COLORS['Conditional'] },
    { name: 'Unknown', value: unknown, color: COLORS['Unknown'] },
  ].filter(d => d.value > 0);
}

function renderCustomLabel({ name, percent }: { name: string; percent: number }) {
  if (percent < 0.05) return null;
  return `${(percent * 100).toFixed(1)}%`;
}

export default function QuantumSafetyDonut({ assets }: QuantumSafetyDonutProps) {
  const data = computeData(assets);
  const total = assets.length;

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Crypto Assets</h3>
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
              label={renderCustomLabel}
              labelLine={false}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                  backgroundColor: '#FFFFFF',
                border: '1px solid #E2E5EA',
                borderRadius: '8px',
                color: '#353535',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className={styles.centerLabel}>
          <span className={styles.centerNumber}>{total}</span>
          <span className={styles.centerText}>Crypto Assets*</span>
        </div>
      </div>
      <div className={styles.legend}>
        {Object.entries(COLORS).map(([label, color]) => (
          <div key={label} className={styles.legendItem}>
            <span className={styles.legendSquare} style={{ backgroundColor: color }} />
            {label}
          </div>
        ))}
      </div>
      <p className={styles.footnote}>
        * This compliance data is approximate and given for illustrative purposes only.
      </p>
    </div>
  );
}
