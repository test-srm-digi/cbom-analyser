import { useState } from 'react';
import { useIntegrations } from './hooks/useIntegrations';
import {
  PageHeader,
  StatsRow,
  TypeBreakdown,
  EmptyState,
  IntegrationCard,
  AddCard,
  HowItWorks,
  CatalogOverlay,
  ConfigDrawer,
} from './components';
import { INTEGRATION_CATALOG } from './constants';
import s from './IntegrationsPage.module.scss';

export default function IntegrationsPage() {
  const {
    integrations,
    showCatalog,
    syncingIds,
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

  const [selectedType, setSelectedType] = useState<string | null>(
    INTEGRATION_CATALOG.length > 0 ? INTEGRATION_CATALOG[0].type : null,
  );
  const [catalogFilter, setCatalogFilter] = useState<string | null>(null);

  const handleTypeSelect = (type: string) => {
    setSelectedType((prev) => (prev === type ? null : type));
  };

  const filteredIntegrations = selectedType
    ? integrations.filter((i) => i.templateType === selectedType)
    : integrations;

  const selectedTypeName = selectedType
    ? INTEGRATION_CATALOG.find((t) => t.type === selectedType)?.name ?? selectedType
    : null;

  return (
    <div className={s.page}>
      {/* Header */}
      <PageHeader onAddClick={() => { setCatalogFilter(null); setShowCatalog(true); }} />

      {/* Stats */}
      <StatsRow
        totalIntegrations={integrations.length}
        connectedCount={configuredCount}
        totalItems={totalItems}
      />

      {/* Type breakdown */}
      <TypeBreakdown
        integrations={integrations}
        selectedType={selectedType}
        onSelectType={handleTypeSelect}
      />

      {/* Empty state — workflow guide */}
      {integrations.length === 0 && !showCatalog && (
        <EmptyState onAddClick={() => { setCatalogFilter(null); setShowCatalog(true); }} />
      )}

      {/* Active integrations grid */}
      {integrations.length > 0 && (
        <div className={s.section}>
          <div className={s.sectionHeader}>
            <h2 className={s.sectionTitle}>
              {selectedType
                ? `Active Integrations — ${selectedTypeName}`
                : 'Active Integrations'}
            </h2>
            {selectedType && (
              <button
                className={s.clearFilterBtn}
                onClick={() => setSelectedType(null)}
              >
                Show all
              </button>
            )}
          </div>
          <div className={s.intgGrid}>
            {filteredIntegrations.map((intg) => (
              <IntegrationCard
                key={intg.id}
                integration={intg}
                syncing={syncingIds.has(intg.id)}
                onEdit={openEditConfig}
                onDelete={deleteIntegration}
                onToggle={toggleEnabled}
                onSync={triggerSync}
              />
            ))}
            {filteredIntegrations.length === 0 && selectedType && (
              <div className={s.noFilterResults}>
                No active integrations of this type.
              </div>
            )}
            <AddCard onClick={() => { setCatalogFilter(selectedType); setShowCatalog(true); }} />
          </div>
        </div>
      )}

      {/* How It Works */}
      <HowItWorks />

      {/* Catalog overlay */}
      {showCatalog && (
        <CatalogOverlay
          filterType={catalogFilter}
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
