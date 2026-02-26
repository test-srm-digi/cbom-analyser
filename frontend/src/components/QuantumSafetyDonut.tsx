import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { CryptoAsset, QuantumSafetyStatus, DonutChartData } from '../types';

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
    <div className="bg-qg-card border border-qg-border rounded-lg p-4 animate-fade-in">
      <h3 className="text-sm font-medium text-gray-500 mb-2">Crypto Assets</h3>
      <div className="relative" style={{ height: 250 }}>
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
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl font-bold text-gray-800">{total}</span>
          <span className="text-xs text-gray-500">Crypto Assets*</span>
        </div>
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-3 mt-2 justify-center">
        {Object.entries(COLORS).map(([label, color]) => (
          <div key={label} className="flex items-center gap-1.5 text-xs text-gray-500">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
            {label}
          </div>
        ))}
      </div>
      <p className="text-[10px] text-gray-600 mt-2">
        * This compliance data is approximate and given for illustrative purposes only.
      </p>
    </div>
  );
}
