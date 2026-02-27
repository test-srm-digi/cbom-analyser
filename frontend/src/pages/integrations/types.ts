import type {
  Integration,
  IntegrationTemplate,
  IntegrationField,
  IntegrationStatus,
  ImportScope,
  SyncSchedule,
} from '../../types';

/* ── Local state types used by the integrations hook & components ── */

export interface ConfigPanelState {
  template: IntegrationTemplate;
  integration?: Integration;
}

export type TestStatus = 'idle' | 'testing' | 'success' | 'error';

export interface IntegrationsState {
  integrations: Integration[];
  showCatalog: boolean;
  configPanel: ConfigPanelState | null;
  configValues: Record<string, string>;
  configScope: ImportScope[];
  configSchedule: SyncSchedule;
  configName: string;
  testStatus: TestStatus;
}

export interface IntegrationsActions {
  openNewConfig: (template: IntegrationTemplate) => void;
  openEditConfig: (integration: Integration) => void;
  closeConfig: () => void;
  testConnection: () => void;
  saveIntegration: () => void;
  deleteIntegration: (id: string) => void;
  toggleEnabled: (id: string) => void;
  triggerSync: (id: string) => void;
  setShowCatalog: (show: boolean) => void;
  setConfigValues: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  setConfigScope: React.Dispatch<React.SetStateAction<ImportScope[]>>;
  setConfigSchedule: React.Dispatch<React.SetStateAction<SyncSchedule>>;
  setConfigName: React.Dispatch<React.SetStateAction<string>>;
}

export type { Integration, IntegrationTemplate, IntegrationField, IntegrationStatus, ImportScope, SyncSchedule };
