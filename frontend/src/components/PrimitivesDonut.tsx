import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { CryptoAsset } from '../types';

interface PrimitivesDonutProps {
  assets: CryptoAsset[];
}

const PRIMITIVE_COLORS: Record<string, string> = {
  'hash': '#58a6ff',
  'block-cipher': '#bc8cff',
  'pke': '#f0883e',
  'signature': '#d29922',
  'keygen': '#3fb950',
  'digest': '#56d364',
  'mac': '#f778ba',
  'stream-cipher': '#79c0ff',
  'key-encapsulation': '#a371f7',
  'key-agreement': '#7ee787',
  'ae': '#ffa657',
  'other': '#8b949e',
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
      color: PRIMITIVE_COLORS[name] || '#8b949e',
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
    <div className="bg-qg-card border border-qg-border rounded-lg p-4 animate-fade-in">
      <h3 className="text-sm font-medium text-gray-400 mb-2">Crypto Primitives</h3>
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
              label={({ percent }) => percent > 0.05 ? `${(percent * 100).toFixed(1)}%` : null}
              labelLine={false}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#161b22',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#e6edf3',
              }}
              formatter={(value: number, name: string) => [value, getPrimitiveLabel(name)]}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl font-bold text-white">{total}</span>
          <span className="text-xs text-gray-400">Crypto Primitives</span>
        </div>
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-2 mt-2 justify-center">
        {data.map(({ name, color }) => (
          <div key={name} className="flex items-center gap-1 text-xs text-gray-400">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
            {getPrimitiveLabel(name)}
          </div>
        ))}
      </div>
    </div>
  );
}
