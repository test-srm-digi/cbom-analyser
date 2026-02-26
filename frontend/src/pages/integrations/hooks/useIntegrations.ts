import { useState, useCallback } from 'react';
import type {
  Integration,
  IntegrationTemplate,
  IntegrationStatus,
  ImportScope,
  SyncSchedule,
  ConfigPanelState,
  TestStatus,
  IntegrationsActions,
} from '../types';
import { INTEGRATION_CATALOG } from '../constants';

/**
 * Central state & actions for the Integrations page.
 * Keeps IntegrationsPage.tsx focused on layout & rendering only.
 */
export function useIntegrations() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [showCatalog, setShowCatalog] = useState(false);
  const [configPanel, setConfigPanel] = useState<ConfigPanelState | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [configScope, setConfigScope] = useState<ImportScope[]>([]);
  const [configSchedule, setConfigSchedule] = useState<SyncSchedule>('24h');
  const [configName, setConfigName] = useState('');
  const [testStatus, setTestStatus] = useState<TestStatus>('idle');

  /* ── Open config for a catalog template ────────────────── */
  const openNewConfig = useCallback((template: IntegrationTemplate) => {
    setConfigPanel({ template });
    setConfigValues({});
    setConfigScope([...template.defaultScope]);
    setConfigSchedule('24h');
    setConfigName(template.name);
    setTestStatus('idle');
    setShowCatalog(false);
  }, []);

  /* ── Open config for existing integration ──────────────── */
  const openEditConfig = useCallback((integration: Integration) => {
    const template = INTEGRATION_CATALOG.find((t) => t.type === integration.templateType);
    if (!template) return;
    setConfigPanel({ template, integration });
    setConfigValues(integration.config);
    setConfigScope(integration.importScope);
    setConfigSchedule(integration.syncSchedule);
    setConfigName(integration.name);
    setTestStatus(
      integration.status === 'connected' ? 'success' : integration.status === 'error' ? 'error' : 'idle',
    );
  }, []);

  /* ── Close config panel ─────────────────────────────────── */
  const closeConfig = useCallback(() => {
    setConfigPanel(null);
    setTestStatus('idle');
  }, []);

  /* ── Test connection ────────────────────────────────────── */
  const testConnection = useCallback(() => {
    setTestStatus('testing');
    setTimeout(() => {
      const hasRequiredFields = configPanel?.template.fields
        .filter((f) => f.required)
        .every((f) => configValues[f.key]?.trim());
      setTestStatus(hasRequiredFields ? 'success' : 'error');
    }, 2000);
  }, [configPanel, configValues]);

  /* ── Save integration ───────────────────────────────────── */
  const saveIntegration = useCallback(() => {
    if (!configPanel) return;
    const { template, integration } = configPanel;

    if (integration) {
      setIntegrations((prev) =>
        prev.map((i) =>
          i.id === integration.id
            ? {
                ...i,
                name: configName,
                config: configValues,
                importScope: configScope,
                syncSchedule: configSchedule,
                status: testStatus === 'success' ? 'connected' : i.status,
              }
            : i,
        ),
      );
    } else {
      const newIntegration: Integration = {
        id: `intg-${Date.now()}`,
        templateType: template.type,
        name: configName,
        description: template.description,
        status: testStatus === 'success' ? 'connected' : 'not_configured',
        enabled: true,
        config: configValues,
        importScope: configScope,
        syncSchedule: configSchedule,
        createdAt: new Date().toISOString(),
      };
      setIntegrations((prev) => [...prev, newIntegration]);
    }
    closeConfig();
  }, [configPanel, configName, configValues, configScope, configSchedule, testStatus, closeConfig]);

  /* ── Delete integration ─────────────────────────────────── */
  const deleteIntegration = useCallback((id: string) => {
    setIntegrations((prev) => prev.filter((i) => i.id !== id));
  }, []);

  /* ── Toggle enabled ─────────────────────────────────────── */
  const toggleEnabled = useCallback((id: string) => {
    setIntegrations((prev) =>
      prev.map((i) =>
        i.id === id
          ? {
              ...i,
              enabled: !i.enabled,
              status: i.enabled
                ? ('disabled' as IntegrationStatus)
                : i.status === 'disabled'
                  ? ('connected' as IntegrationStatus)
                  : i.status,
            }
          : i,
      ),
    );
  }, []);

  /* ── Trigger manual sync ────────────────────────────────── */
  const triggerSync = useCallback((id: string) => {
    setIntegrations((prev) =>
      prev.map((i) => (i.id === id ? { ...i, status: 'testing' as IntegrationStatus } : i)),
    );
    setTimeout(() => {
      setIntegrations((prev) =>
        prev.map((i) =>
          i.id === id
            ? {
                ...i,
                status: 'connected' as IntegrationStatus,
                lastSync: new Date().toLocaleString(),
                lastSyncItems: Math.floor(Math.random() * 80) + 20,
                lastSyncErrors: 0,
              }
            : i,
        ),
      );
    }, 3000);
  }, []);

  /* ── Computed values ────────────────────────────────────── */
  const configuredCount = integrations.filter((i) => i.status === 'connected').length;
  const totalItems = integrations.reduce((sum, i) => sum + (i.lastSyncItems || 0), 0);

  return {
    /* state */
    integrations,
    showCatalog,
    configPanel,
    configValues,
    configScope,
    configSchedule,
    configName,
    testStatus,
    configuredCount,
    totalItems,
    /* actions */
    openNewConfig,
    openEditConfig,
    closeConfig,
    testConnection,
    saveIntegration,
    deleteIntegration,
    toggleEnabled,
    triggerSync,
    setShowCatalog,
    setConfigValues,
    setConfigScope,
    setConfigSchedule,
    setConfigName,
  };
}
