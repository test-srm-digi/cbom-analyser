import {
  X,
  ExternalLink,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Info,
} from 'lucide-react';
import type { ConfigPanelState, TestStatus, ImportScope, SyncSchedule } from '../types';
import { SCHEDULE_OPTIONS } from '../constants';
import { categoryIcon } from '../utils';
import ConfigField from './ConfigField';
import s from './ConfigDrawer.module.scss';

interface ConfigDrawerProps {
  panel: ConfigPanelState;
  configValues: Record<string, string>;
  configScope: ImportScope[];
  configSchedule: SyncSchedule;
  configName: string;
  testStatus: TestStatus;
  onConfigValuesChange: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  onConfigScopeChange: React.Dispatch<React.SetStateAction<ImportScope[]>>;
  onConfigScheduleChange: React.Dispatch<React.SetStateAction<SyncSchedule>>;
  onConfigNameChange: React.Dispatch<React.SetStateAction<string>>;
  onTestConnection: () => void;
  onSave: () => void;
  onClose: () => void;
}

export default function ConfigDrawer({
  panel,
  configValues,
  configScope,
  configSchedule,
  configName,
  testStatus,
  onConfigValuesChange,
  onConfigScopeChange,
  onConfigScheduleChange,
  onConfigNameChange,
  onTestConnection,
  onSave,
  onClose,
}: ConfigDrawerProps) {
  const { template, integration } = panel;

  return (
    <div className={s.overlay} onClick={onClose}>
      <div className={s.drawer} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className={s.drawerHeader}>
          <div className={s.drawerHeaderIcon}>{categoryIcon(template.category)}</div>
          <div>
            <h2>{integration ? 'Edit Integration' : 'New Integration'}</h2>
            <p>{template.name}</p>
          </div>
          <button className={s.closeBtn} onClick={onClose}><X size={18} /></button>
        </div>

        <div className={s.drawerBody}>
          {/* Step 1: Name */}
          <div className={s.configSection}>
            <h3 className={s.configSectionTitle}>
              <span className={s.configStepBadge}>1</span>
              Integration Name
            </h3>
            <input
              className={s.configInput}
              value={configName}
              onChange={(e) => onConfigNameChange(e.target.value)}
              placeholder="Give this integration a name"
            />
          </div>

          {/* Step 2: Connection Settings */}
          <div className={s.configSection}>
            <h3 className={s.configSectionTitle}>
              <span className={s.configStepBadge}>2</span>
              Connection Settings
            </h3>
            {template.docsUrl && (
              <a href={template.docsUrl} target="_blank" rel="noreferrer" className={s.docsLink}>
                <ExternalLink size={13} />
                View setup documentation
              </a>
            )}

            <div className={s.configFields}>
              {template.fields
                .filter((field) => {
                  if (!field.visibleWhen) return true;
                  const depValue = configValues[field.visibleWhen.field] || '';
                  return field.visibleWhen.values.includes(depValue);
                })
                .map((field) => (
                  <ConfigField
                    key={field.key}
                    field={field}
                    value={configValues[field.key] || ''}
                    onChange={(val) => onConfigValuesChange((prev) => ({ ...prev, [field.key]: val }))}
                  />
                ))}
            </div>

            {/* Test Connection */}
            <div className={s.testRow}>
              <button
                className={s.testBtn}
                onClick={onTestConnection}
                disabled={testStatus === 'testing'}
              >
                {testStatus === 'testing' ? (
                  <><Loader2 size={14} className={s.spin} /> Testing…</>
                ) : testStatus === 'success' ? (
                  <><CheckCircle2 size={14} /> Connected</>
                ) : testStatus === 'error' ? (
                  <><XCircle size={14} /> Failed — Retry</>
                ) : (
                  <><Play size={14} /> Test Connection</>
                )}
              </button>
              {testStatus === 'success' && <span className={s.testSuccess}>Connection successful</span>}
              {testStatus === 'error' && <span className={s.testError}>Check credentials and try again</span>}
            </div>
          </div>

          {/* Step 3: Import Scope */}
          <div className={s.configSection}>
            <h3 className={s.configSectionTitle}>
              <span className={s.configStepBadge}>3</span>
              Import Scope
            </h3>
            <p className={s.configHint}>Select the types of assets to import from this source</p>
            <div className={s.scopeGrid}>
              {template.scopeOptions.map((opt) => {
                const active = configScope.includes(opt.value);
                return (
                  <button
                    key={opt.value}
                    className={active ? s.scopeChipActive : s.scopeChip}
                    onClick={() =>
                      onConfigScopeChange((prev) =>
                        active ? prev.filter((v) => v !== opt.value) : [...prev, opt.value],
                      )
                    }
                  >
                    <span className={s.scopeChipLabel}>{opt.label}</span>
                    <span className={s.scopeChipDesc}>{opt.description}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Step 4: Sync Schedule */}
          <div className={s.configSection}>
            <h3 className={s.configSectionTitle}>
              <span className={s.configStepBadge}>4</span>
              Sync Schedule
            </h3>
            <p className={s.configHint}>How often should this integration pull new data?</p>
            <div className={s.scheduleRow}>
              {SCHEDULE_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  className={configSchedule === opt.value ? s.scheduleBtnActive : s.scheduleBtn}
                  onClick={() => onConfigScheduleChange(opt.value)}
                >
                  <Clock size={13} />
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Capabilities */}
          <div className={s.configSection}>
            <h3 className={s.configSectionTitle}>
              <Info size={16} />
              What This Integration Provides
            </h3>
            <ul className={s.capList}>
              {template.capabilities.map((cap, i) => (
                <li key={i}>
                  <CheckCircle2 size={14} className={s.capIcon} />
                  {cap}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className={s.drawerFooter}>
          <button className={s.cancelBtn} onClick={onClose}>Cancel</button>
          <button
            className={s.saveBtn}
            onClick={onSave}
            disabled={!configName.trim()}
          >
            {integration ? 'Save Changes' : 'Add Integration'}
          </button>
        </div>
      </div>
    </div>
  );
}
