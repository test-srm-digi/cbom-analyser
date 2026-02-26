import { useIntegrations } from './hooks/useIntegrations';
import {
  PageHeader,
  StatsRow,
  EmptyState,
  IntegrationCard,
  AddCard,
  HowItWorks,
  CatalogOverlay,
  ConfigDrawer,
} from './components';
import s from './IntegrationsPage.module.scss';

export default function IntegrationsPage() {
  const {
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
  } = useIntegrations();

  return (
    <div className={s.page}>
      {/* Header */}
      <PageHeader onAddClick={() => setShowCatalog(true)} />

      {/* Stats */}
      <StatsRow
        totalIntegrations={integrations.length}
        connectedCount={configuredCount}
        totalItems={totalItems}
      />

      {/* Empty state — workflow guide */}
      {integrations.length === 0 && !showCatalog && (
        <EmptyState onAddClick={() => setShowCatalog(true)} />
      )}

      {/* Active integrations grid */}
      {integrations.length > 0 && (
        <div className={s.section}>
          <h2 className={s.sectionTitle}>Active Integrations</h2>
          <div className={s.intgGrid}>
            {integrations.map((intg) => (
              <IntegrationCard
                key={intg.id}
                integration={intg}
                onEdit={openEditConfig}
                onDelete={deleteIntegration}
                onToggle={toggleEnabled}
                onSync={triggerSync}
              />
            ))}
            <AddCard onClick={() => setShowCatalog(true)} />
          </div>
        </div>
      )}

      {/* How It Works */}
      <HowItWorks />

      {/* Catalog overlay */}
      {showCatalog && (
        <CatalogOverlay
          onSelect={openNewConfig}
          onClose={() => setShowCatalog(false)}
        />
      )}

      {/* Config drawer */}
      {configPanel && (
        <ConfigDrawer
          panel={configPanel}
          configValues={configValues}
          configScope={configScope}
          configSchedule={configSchedule}
          configName={configName}
          testStatus={testStatus}
          onConfigValuesChange={setConfigValues}
          onConfigScopeChange={setConfigScope}
          onConfigScheduleChange={setConfigSchedule}
          onConfigNameChange={setConfigName}
          onTestConnection={testConnection}
          onSave={saveIntegration}
          onClose={closeConfig}
        />
      )}
    </div>
  );
}
