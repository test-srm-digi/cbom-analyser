import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { CryptoAsset } from '../types';

interface FunctionsDonutProps {
  assets: CryptoAsset[];
}

const FUNCTION_COLORS: Record<string, string> = {
  'Hash Function': '#58a6ff',
  'Keygen': '#3fb950',
  'Encrypt': '#f0883e',
  'Decrypt': '#d29922',
  'Sign': '#bc8cff',
  'Verify': '#a371f7',
  'Key Exchange': '#7ee787',
  'Digest': '#56d364',
  'Tag': '#f778ba',
  'Other': '#8b949e',
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
    <div className="bg-qg-card border border-qg-border rounded-lg p-4 animate-fade-in">
      <h3 className="text-sm font-medium text-gray-400 mb-2">Crypto Functions</h3>
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
                 backgroundColor: '#e6edf3',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#161b22',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl font-bold text-white">{total}</span>
          <span className="text-xs text-gray-400">Crypto Functions</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 mt-2 justify-center">
        {data.map(({ name, color }) => (
          <div key={name} className="flex items-center gap-1 text-xs text-gray-400">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
            {name}
          </div>
        ))}
      </div>
    </div>
  );
}
