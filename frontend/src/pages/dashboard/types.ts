import type { CBOMDocument, QuantumReadinessScore, ComplianceSummary } from '../../types';

export type Tab = 'overview' | 'inventory' | 'libraries';

export interface DashboardPageProps {
  /* Upload / sample-data flow (props-driven) */
  cbom?: CBOMDocument | null;
  readinessScore?: QuantumReadinessScore | null;
  compliance?: ComplianceSummary | null;
  onNavigate?: (path: string) => void;
  onUpload?: () => void;
  onLoadSample?: () => void;
  onClearCbom?: () => void;
  onLoadCbomUpload?: (id: string) => void;
  /* Import flow (self-fetching) */
  cbomImportId?: string;
  onBack?: () => void;
}
