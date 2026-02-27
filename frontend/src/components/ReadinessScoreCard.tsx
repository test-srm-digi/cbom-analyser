import { QuantumReadinessScore } from '../types';
import { DC1_SUCCESS, DC1_WARNING, DC1_DANGER, DIGICERT_CYAN, CHART_GRAY, NEUTRAL_200 } from '../styles/dsTokens';
import styles from './ReadinessScoreCard.module.scss';

interface ReadinessScoreCardProps {
  score: QuantumReadinessScore | null;
}

function getScoreColor(score: number): string {
  if (score >= 80) return DC1_SUCCESS;
  if (score >= 50) return DC1_WARNING;
  return DC1_DANGER;
}

function getScoreLabel(score: number): string {
  if (score >= 80) return 'Good';
  if (score >= 50) return 'Moderate';
  return 'At Risk';
}

function getScoreDescription(score: number): string {
  if (score >= 80) return 'Your cryptographic inventory is well-prepared for post-quantum migration.';
  if (score >= 50) return 'Some cryptographic assets need attention to improve quantum readiness.';
  return 'Significant portion of cryptographic assets are not quantum-safe and need migration.';
}

export default function ReadinessScoreCard({ score }: ReadinessScoreCardProps) {
  if (!score) return null;

  const { quantumSafe, notQuantumSafe, conditional, unknown, totalAssets } = score;
  const color = getScoreColor(score.score);
  const label = getScoreLabel(score.score);
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score.score / 100) * circumference;

  const segments = [
    { value: quantumSafe, color: DC1_SUCCESS, label: 'Safe' },
    { value: conditional, color: DIGICERT_CYAN, label: 'Conditional' },
    { value: unknown, color: CHART_GRAY, label: 'Unknown' },
    { value: notQuantumSafe, color: DC1_DANGER, label: 'Not Safe' },
  ];

  let cumPercent = 0;

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Quantum Readiness Score</h3>
      <div className={styles.body}>
        <div className={styles.gauge}>
          <svg className={styles.gaugeSvg} viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="45" fill="none" stroke={NEUTRAL_200} strokeWidth="8" />
            <circle
              cx="50" cy="50" r="45"
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              style={{ transition: 'all 1s ease-out' }}
            />
          </svg>
          <div className={styles.gaugeCenter}>
            <span className={styles.gaugeScore} style={{ color }}>{score.score}</span>
            <span className={styles.gaugeLabel}>{label}</span>
          </div>
        </div>

        <p className={styles.description}>{getScoreDescription(score.score)}</p>

        {/* Stacked horizontal bar */}
        <div className={styles.barSection}>
          <div className={styles.barTrack}>
            {segments.map((seg) => {
              const pct = totalAssets > 0 ? (seg.value / totalAssets) * 100 : 0;
              const el = pct > 0 ? (
                <div
                  key={seg.label}
                  className={styles.barSegment}
                  style={{ width: `${pct}%`, backgroundColor: seg.color }}
                  title={`${seg.label}: ${seg.value}`}
                />
              ) : null;
              cumPercent += pct;
              return el;
            })}
          </div>
          <div className={styles.barLegend}>
            {segments.filter(s => s.value > 0).map((seg) => (
              <span key={seg.label} className={styles.barLegendItem}>
                <span className={styles.barDot} style={{ backgroundColor: seg.color }} />
                {seg.label}
              </span>
            ))}
          </div>
        </div>

        <p className={styles.hint}>
          {quantumSafe} of {totalAssets} assets are quantum-safe
        </p>
      </div>
    </div>
  );
}
