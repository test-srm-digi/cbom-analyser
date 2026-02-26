import { useState, useCallback } from 'react';
import type {
  Integration,
  IntegrationTemplate,
  ImportScope,
  SyncSchedule,
  ConfigPanelState,
  TestStatus,
} from '../types';
import { INTEGRATION_CATALOG } from '../constants';
import {
  useGetIntegrationsQuery,
  useCreateIntegrationMutation,
  useUpdateIntegrationMutation,
  useDeleteIntegrationMutation,
  useToggleIntegrationMutation,
  useSyncIntegrationMutation,
} from '../../../store';

/**
 * Central state & actions for the Integrations page.
 * Uses RTK Query for server-persisted integration data (MariaDB)
 * and local state for UI-only concerns (config drawer, catalog overlay).
 */
export function useIntegrations() {
  /* ── RTK Query: server state ────────────────────────────── */
  const { data: integrations = [], isLoading, refetch } = useGetIntegrationsQuery();
  const [createIntegration] = useCreateIntegrationMutation();
  const [updateIntegration] = useUpdateIntegrationMutation();
  const [deleteIntegrationMut] = useDeleteIntegrationMutation();
  const [toggleIntegrationMut] = useToggleIntegrationMutation();
  const [syncIntegrationMut] = useSyncIntegrationMutation();

  /* ── Local UI state ─────────────────────────────────────── */
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

  /* ── Test connection (client-side validation) ───────────── */
  const testConnection = useCallback(() => {
    setTestStatus('testing');
    setTimeout(() => {
      const hasRequiredFields = configPanel?.template.fields
        .filter((f) => {
          if (!f.required) return false;
          // Skip fields hidden by visibleWhen
          if (f.visibleWhen) {
            const depValue = configValues[f.visibleWhen.field] || '';
            if (!f.visibleWhen.values.includes(depValue)) return false;
          }
          return true;
        })
        .every((f) => configValues[f.key]?.trim());
      setTestStatus(hasRequiredFields ? 'success' : 'error');
    }, 2000);
  }, [configPanel, configValues]);

  /* ── Save integration → API ─────────────────────────────── */
  const saveIntegration = useCallback(async () => {
    if (!configPanel) return;
    const { template, integration } = configPanel;

    try {
      if (integration) {
        await updateIntegration({
          id: integration.id,
          name: configName,
          config: configValues,
          importScope: configScope,
          syncSchedule: configSchedule,
          status: testStatus === 'success' ? 'connected' : undefined,
        }).unwrap();
      } else {
        await createIntegration({
          templateType: template.type,
          name: configName,
          description: template.description,
          status: testStatus === 'success' ? 'connected' : 'not_configured',
          config: configValues,
          importScope: configScope,
          syncSchedule: configSchedule,
        }).unwrap();
      }
      closeConfig();
    } catch (err) {
      console.error('Failed to save integration:', err);
    }
  }, [configPanel, configName, configValues, configScope, configSchedule, testStatus, closeConfig, createIntegration, updateIntegration]);

  /* ── Delete integration → API ───────────────────────────── */
  const deleteIntegration = useCallback(async (id: string) => {
    try {
      await deleteIntegrationMut(id).unwrap();
    } catch (err) {
      console.error('Failed to delete integration:', err);
    }
  }, [deleteIntegrationMut]);

  /* ── Toggle enabled → API ───────────────────────────────── */
  const toggleEnabled = useCallback(async (id: string) => {
    try {
      await toggleIntegrationMut(id).unwrap();
    } catch (err) {
      console.error('Failed to toggle integration:', err);
    }
  }, [toggleIntegrationMut]);

  /* ── Trigger manual sync → API ──────────────────────────── */
  const triggerSync = useCallback(async (id: string) => {
    try {
      await syncIntegrationMut(id).unwrap();
      // Refetch after sync completes server-side (simulated 3s)
      setTimeout(() => refetch(), 3500);
    } catch (err) {
      console.error('Failed to trigger sync:', err);
    }
  }, [syncIntegrationMut, refetch]);

  /* ── Computed values ────────────────────────────────────── */
  const configuredCount = integrations.filter((i) => i.status === 'connected').length;
  const totalItems = integrations.reduce((sum, i) => sum + (i.lastSyncItems || 0), 0);

  return {
    /* state */
    integrations,
    isLoading,
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
