import { X, ChevronRight } from 'lucide-react';
import type { IntegrationTemplate } from '../types';
import { INTEGRATION_CATALOG } from '../constants';
import { categoryIcon } from '../utils';
import s from './CatalogOverlay.module.scss';

interface CatalogOverlayProps {
  /** When set, show only this integration type in the catalog */
  filterType?: string | null;
  onSelect: (template: IntegrationTemplate) => void;
  onClose: () => void;
}

export default function CatalogOverlay({ filterType, onSelect, onClose }: CatalogOverlayProps) {
  const visibleCatalog = filterType
    ? INTEGRATION_CATALOG.filter((t) => t.type === filterType)
    : INTEGRATION_CATALOG;

  return (
    <div className={s.overlay} onClick={onClose}>
      <div className={s.panel} onClick={(e) => e.stopPropagation()}>
        <div className={s.header}>
          <h2>Add Integration</h2>
          <p>Choose an integration type to configure</p>
          <button className={s.closeBtn} onClick={onClose}><X size={18} /></button>
        </div>
        <div className={s.grid}>
          {visibleCatalog.map((tmpl) => (
            <button key={tmpl.type} className={s.card} onClick={() => onSelect(tmpl)}>
              <div className={s.cardIcon}>{categoryIcon(tmpl.category)}</div>
              <div className={s.cardText}>
                <h3>{tmpl.name}</h3>
                <span className={s.vendor}>{tmpl.vendor}</span>
                <p>{tmpl.description.slice(0, 120)}…</p>
              </div>
              <ChevronRight size={16} className={s.chevron} />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
