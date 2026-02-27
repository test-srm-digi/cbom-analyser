import { Plug, ArrowRight, Database, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';
import s from './shared.module.scss';

export interface IntegrationStep {
  step: number;
  title: string;
  description: string;
}

interface Props {
  /** E.g. "Certificates", "Endpoints" */
  title: string;
  /** Integration source name, e.g. "DigiCert Trust Lifecycle Manager" */
  integrationName: string;
  /** Brief description of what data this integration provides */
  integrationDescription: string;
  /** Step-by-step guide to set up the integration */
  steps: IntegrationStep[];
  /** Callback when user clicks "Load Sample Data" */
  onLoadSample: () => void;
  /** Whether sample data is currently loading */
  loading?: boolean;
  /** Navigate to the Integrations page */
  onGoToIntegrations?: () => void;
}

export default function EmptyState({
  title,
  integrationName,
  integrationDescription,
  steps,
  onLoadSample,
  loading,
  onGoToIntegrations,
}: Props) {
  return (
    <div className={s.emptyState}>
      {/* Sample data option */}
      <div className={s.sampleCard}>
        <div className={s.sampleLeft}>
          <AlertTriangle className={s.sampleIcon} />
          <div>
            <p className={s.sampleTitle}>Want to explore first?</p>
            <p className={s.sampleDesc}>
              Load sample data to preview how {title.toLowerCase()} appear, with realistic PQC-readiness metrics and quantum-safe analysis. You can clear this at any time.
            </p>
          </div>
        </div>
        <button className={s.sampleBtn} onClick={onLoadSample} disabled={loading}>
          {loading ? 'Loading…' : 'Load Sample Data'}
        </button>
      </div>

      {/* Hero card */}
      <div className={s.emptyHero}>
        <div className={s.emptyIconWrap}>
          <Database className={s.emptyIcon} />
        </div>
        <h2 className={s.emptyTitle}>No {title} Discovered Yet</h2>
        <p className={s.emptyDesc}>
          Connect <strong>{integrationName}</strong> to automatically discover and import {title.toLowerCase()} data into Quantum Readiness Advisor.
        </p>
        <p className={s.emptyDescSub}>{integrationDescription}</p>

        {onGoToIntegrations && (
          <button className={s.goToIntegrationsBtn} onClick={onGoToIntegrations}>
            <Plug size={15} />
            Go to Integrations
            <ExternalLink size={13} />
          </button>
        )}
      </div>

      {/* Integration steps */}
      <div className={s.stepsCard}>
        <div className={s.stepsHeader}>
          <Plug className={s.stepsHeaderIcon} />
          <h3 className={s.stepsTitle}>How to Integrate — {integrationName}</h3>
        </div>

        <ol className={s.stepsList}>
          {steps.map((step) => (
            <li key={step.step} className={s.stepItem}>
              <span className={s.stepNumber}>{step.step}</span>
              <div className={s.stepContent}>
                <span className={s.stepTitle}>{step.title}</span>
                <span className={s.stepDesc}>{step.description}</span>
              </div>
              {step.step < steps.length && <ArrowRight className={s.stepArrow} />}
            </li>
          ))}
        </ol>

        <div className={s.stepsFooter}>
          <div className={s.stepsNote}>
            <CheckCircle2 className={s.stepsNoteIcon} />
            <span>Once connected, {title.toLowerCase()} will be discovered automatically on every sync cycle.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
