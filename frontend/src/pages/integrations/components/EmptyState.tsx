import { Plus, ArrowRight, Server } from 'lucide-react';
import s from '../IntegrationsPage.module.scss';

interface EmptyStateProps {
  onAddClick: () => void;
}

export default function EmptyState({ onAddClick }: EmptyStateProps) {
  return (
    <div className={s.emptyState}>
      <div className={s.emptyIcon}>
        <Server size={48} />
      </div>
      <h2 className={s.emptyTitle}>Build Your Crypto Inventory</h2>
      <p className={s.emptyDesc}>
        Connect your first data source to start discovering cryptographic assets across your infrastructure.
        Each integration type provides a different view into your crypto posture.
      </p>

      <div className={s.workflowSteps}>
        <div className={s.workflowStep}>
          <div className={s.stepNumber}>1</div>
          <div className={s.stepContent}>
            <h4>Choose an Integration</h4>
            <p>Select from DigiCert managers, network scanners, CBOM imports, or repository scanners</p>
          </div>
        </div>
        <div className={s.workflowArrow}><ArrowRight size={16} /></div>
        <div className={s.workflowStep}>
          <div className={s.stepNumber}>2</div>
          <div className={s.stepContent}>
            <h4>Configure & Connect</h4>
            <p>Provide API credentials, target ranges, or repository access. Test the connection before saving.</p>
          </div>
        </div>
        <div className={s.workflowArrow}><ArrowRight size={16} /></div>
        <div className={s.workflowStep}>
          <div className={s.stepNumber}>3</div>
          <div className={s.stepContent}>
            <h4>Import & Analyze</h4>
            <p>Assets flow into the Discovery page. View certificates, endpoints, and software with quantum-safety verdicts.</p>
          </div>
        </div>
      </div>

      <button className={s.addBtnLarge} onClick={onAddClick}>
        <Plus size={18} />
        Add Your First Integration
      </button>
    </div>
  );
}
