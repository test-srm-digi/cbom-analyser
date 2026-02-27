import { INTEGRATION_CATALOG } from '../constants';
import { categoryIcon } from '../utils';
import type { Integration } from '../types';
import s from '../IntegrationsPage.module.scss';

interface TypeBreakdownProps {
  integrations: Integration[];
  selectedType: string | null;
  onSelectType: (type: string) => void;
}

export default function TypeBreakdown({ integrations, selectedType, onSelectType }: TypeBreakdownProps) {
  return (
    <div className={s.section}>
      <h2 className={s.sectionTitle}>Available Integration Types</h2>
      <div className={s.typeGrid}>
        {INTEGRATION_CATALOG.map((tpl) => {
          const instances = integrations.filter((i) => i.templateType === tpl.type);
          const configured = instances.length;
          const connected = instances.filter((i) => i.status === 'connected').length;
          const items = instances.reduce((sum, i) => sum + (i.lastSyncItems || 0), 0);
          const isSelected = selectedType === tpl.type;

          return (
            <div
              key={tpl.type}
              className={`${s.typeCard} ${isSelected ? s.typeCardSelected : ''}`}
              onClick={() => onSelectType(tpl.type)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelectType(tpl.type); } }}
            >
              <div className={s.typeCardHeader}>
                <span className={s.typeIcon}>{categoryIcon(tpl.category)}</span>
                <div className={s.typeInfo}>
                  <div className={s.typeName}>{tpl.name}</div>
                  <div className={s.typeVendor}>{tpl.vendor}</div>
                </div>
              </div>

              <div className={s.typeMetrics}>
                <div className={s.typeMetric}>
                  <span className={s.typeMetricValue}>{configured}</span>
                  <span className={s.typeMetricLabel}>Configured</span>
                </div>
                <div className={s.typeMetric}>
                  <span className={`${s.typeMetricValue} ${connected > 0 ? s.statSuccess : ''}`}>
                    {connected}
                  </span>
                  <span className={s.typeMetricLabel}>Connected</span>
                </div>
                <div className={s.typeMetric}>
                  <span className={s.typeMetricValue}>{items}</span>
                  <span className={s.typeMetricLabel}>Items</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
