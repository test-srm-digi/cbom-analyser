import { AlertTriangle, CheckCircle, Info } from 'lucide-react';
import { ComplianceSummary } from '../types';
import styles from './ComplianceBanner.module.scss';

interface ComplianceBannerProps {
  compliance: ComplianceSummary | null;
}

export default function ComplianceBanner({ compliance }: ComplianceBannerProps) {
  if (!compliance) return null;

  const isCompliant = compliance.isCompliant;

  return (
    <div className={`${styles.banner} ${isCompliant ? styles.compliant : styles.nonCompliant}`}>
      {isCompliant ? (
        <CheckCircle className={styles.iconGreen} />
      ) : (
        <AlertTriangle className={styles.iconRed} />
      )}

      <div className={styles.body}>
        <span className={isCompliant ? styles.statusGreen : styles.statusRed}>
          {isCompliant ? 'Compliant' : 'Not compliant'}
        </span>
        <span className={styles.separator}>–</span>
        <span className={styles.message}>
          {isCompliant
            ? `This CBOM complies with the policy "${compliance.policy}".`
            : `This CBOM does not comply with the policy "${compliance.policy}".`}
        </span>
      </div>

      <div className={styles.meta}>
        <Info className={styles.metaIcon} />
        <span>Source: {compliance.source}</span>
      </div>
    </div>
  );
}
