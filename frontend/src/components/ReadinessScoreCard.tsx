import { QuantumReadinessScore } from '../types';
import styles from './ReadinessScoreCard.module.scss';

interface ReadinessScoreCardProps {
  score: QuantumReadinessScore | null;
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#27A872';
  if (score >= 50) return '#F5B517';
  return '#DC2626';
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
    <div className={styles.card}>
      <h3 className={styles.title}>Quantum Readiness Score</h3>
      <div className={styles.body}>
        <div className={styles.gauge}>
          <svg className={styles.gaugeSvg} viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="45" fill="none" stroke="#E2E5EA" strokeWidth="8" />
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

        <div className={styles.stats}>
          <div className={styles.statRow}>
            <span className={`${styles.dot} ${styles.dotGreen}`} />
            <span className={styles.statLabel}>Quantum Safe:</span>
            <span className={styles.statValue}>{score.quantumSafe}</span>
          </div>
          <div className={styles.statRow}>
            <span className={`${styles.dot} ${styles.dotRed}`} />
            <span className={styles.statLabel}>Not Safe:</span>
            <span className={styles.statValue}>{score.notQuantumSafe}</span>
          </div>
          <div className={styles.statRow}>
            <span className={`${styles.dot} ${styles.dotCyan}`} />
            <span className={styles.statLabel}>Conditional:</span>
            <span className={styles.statValue}>{score.conditional}</span>
          </div>
          <div className={styles.statRow}>
            <span className={`${styles.dot} ${styles.dotGray}`} />
            <span className={styles.statLabel}>Unknown:</span>
            <span className={styles.statValue}>{score.unknown}</span>
          </div>
          <div className={styles.total}>
            Total: {score.totalAssets} assets
          </div>
        </div>
      </div>
    </div>
  );
}
