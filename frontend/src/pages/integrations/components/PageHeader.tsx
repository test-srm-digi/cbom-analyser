import { Plus } from 'lucide-react';
import s from '../IntegrationsPage.module.scss';

interface PageHeaderProps {
  onAddClick: () => void;
}

export default function PageHeader({ onAddClick }: PageHeaderProps) {
  return (
    <div className={s.header}>
      <div className={s.headerText}>
        <h1 className={s.title}>Integrations</h1>
        <p className={s.subtitle}>
          Connect data sources to build your cryptographic inventory. Each integration imports certificates, endpoints,
          keys, and software assets into the unified crypto inventory for quantum-readiness analysis.
        </p>
      </div>
      <button className={s.addBtn} onClick={onAddClick}>
        <Plus size={16} />
        Add Integration
      </button>
    </div>
  );
}
