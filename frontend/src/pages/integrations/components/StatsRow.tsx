import s from '../IntegrationsPage.module.scss';
import { INTEGRATION_CATALOG } from '../constants';

interface StatsRowProps {
  totalIntegrations: number;
  connectedCount: number;
  totalItems: number;
}

export default function StatsRow({ totalIntegrations, connectedCount, totalItems }: StatsRowProps) {
  return (
    <div className={s.stats}>
      <div className={s.statCard}>
        <div className={s.statValue}>{totalIntegrations}</div>
        <div className={s.statLabel}>Configured</div>
      </div>
      <div className={s.statCard}>
        <div className={`${s.statValue} ${s.statSuccess}`}>{connectedCount}</div>
        <div className={s.statLabel}>Connected</div>
      </div>
      <div className={s.statCard}>
        <div className={s.statValue}>{totalItems}</div>
        <div className={s.statLabel}>Assets Imported</div>
      </div>
      <div className={s.statCard}>
        <div className={s.statValue}>{INTEGRATION_CATALOG.length}</div>
        <div className={s.statLabel}>Available Types</div>
      </div>
    </div>
  );
}
