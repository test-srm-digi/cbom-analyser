import { QuantumReadinessScore } from '../types';

interface ReadinessScoreCardProps {
  score: QuantumReadinessScore | null;
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#3fb950';
  if (score >= 50) return '#d29922';
  return '#f85149';
}

function getScoreLabel(score: number): string {
  if (score >= 80) return 'Good';
  if (score >= 50) return 'Moderate';
  return 'At Risk';
}

export default function ReadinessScoreCard({ score }: ReadinessScoreCardProps) {
  if (!score) return null;

  const color = getScoreColor(score.score);
  const label = getScoreLabel(score.score);
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score.score / 100) * circumference;

  return (
    <div className="bg-qg-card border border-qg-border rounded-lg p-4 animate-fade-in">
      <h3 className="text-sm font-medium text-gray-400 mb-3">Quantum Readiness Score</h3>
      <div className="flex items-center gap-6">
        {/* Circular progress */}
        <div className="relative w-28 h-28 flex-shrink-0">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50" cy="50" r="45"
              fill="none"
              stroke="#30363d"
              strokeWidth="8"
            />
            <circle
              cx="50" cy="50" r="45"
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold" style={{ color }}>{score.score}</span>
            <span className="text-[10px] text-gray-500">{label}</span>
          </div>
        </div>

        {/* Stats */}
        <div className="flex flex-col gap-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-qg-green" />
            <span className="text-gray-400">Quantum Safe:</span>
            <span className="text-white font-semibold">{score.quantumSafe}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-qg-red" />
            <span className="text-gray-400">Not Safe:</span>
            <span className="text-white font-semibold">{score.notQuantumSafe}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full" style={{ backgroundColor: '#22d3ee' }} />
            <span className="text-gray-400">Conditional:</span>
            <span className="text-white font-semibold">{score.conditional}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-gray-600" />
            <span className="text-gray-400">Unknown:</span>
            <span className="text-white font-semibold">{score.unknown}</span>
          </div>
          <div className="text-xs text-gray-600 mt-1">
            Total: {score.totalAssets} assets
          </div>
        </div>
      </div>
    </div>
  );
}
