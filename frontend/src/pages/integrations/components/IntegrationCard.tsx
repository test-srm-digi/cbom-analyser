import {
  Plus,
  Settings,
  Database,
  RefreshCw,
  Loader2,
  AlertTriangle,
  Trash2,
  ExternalLink,
} from 'lucide-react';
import type { Integration, IntegrationTemplate } from '../types';
import { INTEGRATION_CATALOG, SCHEDULE_OPTIONS } from '../constants';
import { categoryIcon, statusLabel, statusCls, resolveScopeLabel } from '../utils';
import s from './IntegrationCard.module.scss';

/* ── Single active-integration card ───────────────────────── */

interface IntegrationCardProps {
  integration: Integration;
  onEdit: (integration: Integration) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string) => void;
  onSync: (id: string) => void;
}

export default function IntegrationCard({
  integration: intg,
  onEdit,
  onDelete,
  onToggle,
  onSync,
}: IntegrationCardProps) {
  const template = INTEGRATION_CATALOG.find((t) => t.type === intg.templateType);

  return (
    <div className={`${s.card} ${!intg.enabled ? s.cardDisabled : ''}`}>
      {/* Header */}
      <div className={s.cardHeader}>
        <div className={s.cardIcon}>
          {template ? categoryIcon(template.category) : <Database size={20} />}
        </div>
        <div className={s.cardMeta}>
          <h3 className={s.cardName}>{intg.name}</h3>
          <span className={s.cardVendor}>{template?.vendor}</span>
        </div>
        <span className={statusCls(intg.status, s)}>
          {intg.status === 'testing' && <Loader2 size={12} className={s.spin} />}
          {statusLabel(intg.status)}
        </span>
      </div>

      {/* Body — field rows */}
      <div className={s.cardBody}>
        {intg.config?.githubRepo && (() => {
          const repoSlug = intg.config.githubRepo.replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/, '');
          const repoUrl = `https://github.com/${repoSlug}`;
          const branches = intg.config.branches
            ? intg.config.branches.split(',').map((b: string) => b.trim()).filter(Boolean)
            : [];
          return (
            <>
              <div className={s.fieldRow}>
                <span className={s.fieldLabel}>Repository</span>
                <a href={repoUrl} target="_blank" rel="noopener noreferrer" className={s.repoLink} title={repoSlug}>
                  <span className={s.repoText}>{repoSlug}</span>
                  <ExternalLink size={11} className={s.repoExtIcon} />
                </a>
              </div>
              {branches.length > 0 && (
                <div className={s.fieldRow}>
                  <span className={s.fieldLabel}>Branches</span>
                  <div className={s.branchList}>
                    {branches.map((b: string) => (
                      <span key={b} className={s.branchTag}>{b}</span>
                    ))}
                  </div>
                </div>
              )}
            </>
          );
        })()}
        <div className={s.fieldRow}>
          <span className={s.fieldLabel}>Sync Schedule</span>
          <span className={s.fieldValue}>
            {SCHEDULE_OPTIONS.find((o) => o.value === intg.syncSchedule)?.label || intg.syncSchedule}
          </span>
        </div>
        {intg.importScope.length > 0 && (
          <div className={s.fieldRow}>
            <span className={s.fieldLabel}>Import Scope</span>
            <span className={s.fieldValue}>
              {intg.importScope
                .map((sc) => resolveScopeLabel(sc, template?.scopeOptions))
                .join(', ')}
            </span>
          </div>
        )}
        {intg.lastSync && (
          <div className={s.fieldRow}>
            <span className={s.fieldLabel}>Last Sync</span>
            <span className={s.fieldValue}>
              {new Date(intg.lastSync).toLocaleString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit',
              })}
              {intg.lastSyncItems != null && (
                <span className={s.syncBadge}>{intg.lastSyncItems} items</span>
              )}
            </span>
          </div>
        )}
        {intg.errorMessage && (
          <div className={s.error}>
            <AlertTriangle size={14} />
            {intg.errorMessage}
          </div>
        )}
      </div>

      {/* Footer — actions */}
      <div className={s.cardFooter}>
        <div className={s.actions}>
          <button className={s.toggleWrap} onClick={() => onToggle(intg.id)} title={intg.enabled ? 'Disable' : 'Enable'}>
            <span className={intg.enabled ? s.toggleOn : s.toggle} />
            <span className={s.toggleLabel}>{intg.enabled ? 'Enabled' : 'Disabled'}</span>
          </button>
        </div>
        <div className={s.actions}>
          <button
            className={s.iconBtn}
            onClick={() => onSync(intg.id)}
            disabled={!intg.enabled || intg.status === 'testing'}
            title="Sync Now"
          >
            <RefreshCw size={14} className={intg.status === 'testing' ? s.spin : ''} />
          </button>
          <button className={s.iconBtn} onClick={() => onEdit(intg)} title="Configure">
            <Settings size={14} />
          </button>
          <button className={`${s.iconBtn} ${s.iconBtnDanger}`} onClick={() => onDelete(intg.id)} title="Delete">
            <Trash2 size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── "Add more" placeholder card ──────────────────────────── */

export function AddCard({ onClick }: { onClick: () => void }) {
  return (
    <button className={s.addCard} onClick={onClick}>
      <Plus size={24} />
      <span>Add Integration</span>
    </button>
  );
}
