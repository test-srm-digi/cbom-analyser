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
import { useState } from 'react';
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

  /* Track which collapsible sections are collapsed */
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    template.fields.forEach((f) => {
      if (f.type === 'section-header' && f.collapsed) {
        initial[f.key] = true;
      }
    });
    return initial;
  });

  const toggleSection = (key: string) => {
    setCollapsedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  /**
   * Determine which fields are visible, respecting both `visibleWhen`
   * and collapsible sections (fields after a collapsed section-header
   * until the next section-header are hidden).
   */
  const getVisibleFields = () => {
    const fields = template.fields;
    const result: typeof fields = [];
    let currentSection: string | null = null;

    for (const field of fields) {
      // Check visibleWhen
      if (field.visibleWhen) {
        const depValue = configValues[field.visibleWhen.field] || '';
        // For multi-select values, check if any selected value matches
        const depValues = depValue.split(',');
        const matches = field.visibleWhen.values.some((v) => depValues.includes(v));
        if (!matches) continue;
      }

      if (field.type === 'section-header') {
        currentSection = field.key;
        result.push(field);
        continue;
      }

      // If inside a collapsed section, skip
      if (currentSection && collapsedSections[currentSection]) {
        continue;
      }

      result.push(field);
    }
    return result;
  };

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
              {getVisibleFields().map((field) => (
                  <ConfigField
                    key={field.key}
                    field={field}
                    value={configValues[field.key] || ''}
                    onChange={(val) => onConfigValuesChange((prev) => ({ ...prev, [field.key]: val }))}
                    allValues={configValues}
                    onToggleSection={toggleSection}
                    isSectionCollapsed={field.type === 'section-header' ? !!collapsedSections[field.key] : undefined}
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
