import { useState } from 'react';
import { Download, Upload, Settings, Database, Shield } from 'lucide-react';
import type { Integration } from '../types';
import { SAMPLE_INTEGRATIONS } from '../sampleDiscoveryData';
import s from './IntegrationsPage.module.scss';

type Tab = 'datasources' | 'integrations';

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('datasources');
  const [integrations, setIntegrations] = useState<Integration[]>(SAMPLE_INTEGRATIONS);

  const toggleEnabled = (id: string) => {
    setIntegrations((prev) =>
      prev.map((i) => (i.id === id ? { ...i, enabled: !i.enabled } : i)),
    );
  };

  const statusCls = (status: Integration['status']) => {
    switch (status) {
      case 'connected':    return s.statusConnected;
      case 'disconnected': return s.statusDisconnected;
      case 'error':        return s.statusError;
    }
  };

  return (
    <div>
      {/* Header */}
      <div className={s.header}>
        <h1 className={s.title}>Integrations</h1>
        <p className={s.subtitle}>
          Connect external data sources and integrations for automated cryptographic discovery and remediation
        </p>
      </div>

      {/* Tabs */}
      <div className={s.tabs}>
        <button
          className={activeTab === 'datasources' ? s.tabActive : s.tab}
          onClick={() => setActiveTab('datasources')}
        >
          <Download className={s.tabIcon} />
          Data Sources
        </button>
        <button
          className={activeTab === 'integrations' ? s.tabActive : s.tab}
          onClick={() => setActiveTab('integrations')}
        >
          <Upload className={s.tabIcon} />
          Integrations
        </button>
      </div>

      {/* Cards grid */}
      <div className={s.grid}>
        {integrations.map((intg) => (
          <div key={intg.id} className={s.card}>
            {/* Card header: icon + name + status */}
            <div className={s.cardHeader}>
              <div className={s.cardIcon}>
                {intg.name.includes('Device') ? (
                  <Shield className={s.cardIconSvg} />
                ) : intg.name.includes('Software') ? (
                  <Database className={s.cardIconSvg} />
                ) : (
                  <svg className={s.cardIconSvg} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <circle cx="12" cy="12" r="10" />
                  </svg>
                )}
              </div>
              <div>
                <h3 className={s.cardTitle}>
                  {intg.name}
                  <span className={statusCls(intg.status)}>
                    <span className={s.statusDot} />
                    {intg.status === 'connected' ? 'Connected' : intg.status === 'error' ? 'Error' : 'Disconnected'}
                  </span>
                </h3>
              </div>
            </div>

            <p className={s.cardDescription}>{intg.description}</p>

            {/* Fields */}
            <div className={s.cardFields}>
              <div className={s.field}>
                <div className={s.fieldLabel}>Configuration URL</div>
                <div className={s.fieldValue}>{intg.configUrl}</div>
              </div>
              <div className={s.field}>
                <div className={s.fieldLabel}>Last Import</div>
                <div className={s.fieldValue}>{intg.lastImport}</div>
              </div>
            </div>

            {/* Footer */}
            <div className={s.cardFooter}>
              <div className={s.toggleWrap}>
                <button
                  className={intg.enabled ? s.toggleOn : s.toggle}
                  onClick={() => toggleEnabled(intg.id)}
                  aria-label={intg.enabled ? 'Disable integration' : 'Enable integration'}
                />
                <span className={s.toggleLabel}>Enabled</span>
              </div>
              <button className={s.configBtn}>
                <Settings className={s.configIcon} />
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
