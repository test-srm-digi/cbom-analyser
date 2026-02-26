import { useState } from 'react';
import {
  ShieldCheck,
  Wifi,
  Code2,
  Cpu,
  FileJson,
  Package,
} from 'lucide-react';
import type { DiscoveryTab } from './types';
import {
  CertificatesTab,
  EndpointsTab,
  SoftwareTab,
  DevicesTab,
  CodeAnalysisTab,
  CbomImportsTab,
} from './tabs';
import { CERTIFICATES, ENDPOINTS, SOFTWARE, DEVICES, CODE_FINDINGS, CBOM_IMPORTS } from './data';
import s from './DiscoveryPage.module.scss';

/* ═══════════════════════════════════════════════════════════════
   Tab definitions — mapped to integration sources
   ═══════════════════════════════════════════════════════════════ */

const TABS: { id: DiscoveryTab; label: string; icon: React.ReactNode; count: number; source: string }[] = [
  { id: 'certificates',  label: 'Certificates',   icon: <ShieldCheck className={s.tabIcon} />, count: CERTIFICATES.length,  source: 'DigiCert TLM' },
  { id: 'endpoints',     label: 'Endpoints',      icon: <Wifi className={s.tabIcon} />,       count: ENDPOINTS.length,     source: 'Network Scanner' },
  { id: 'software',      label: 'Software',       icon: <Package className={s.tabIcon} />,    count: SOFTWARE.length,      source: 'DigiCert STM' },
  { id: 'devices',       label: 'Devices',        icon: <Cpu className={s.tabIcon} />,        count: DEVICES.length,       source: 'DigiCert DTM' },
  { id: 'code-analysis', label: 'Code Analysis',  icon: <Code2 className={s.tabIcon} />,      count: CODE_FINDINGS.length, source: 'GitHub Scanner' },
  { id: 'cbom-imports',  label: 'CBOM Imports',   icon: <FileJson className={s.tabIcon} />,   count: CBOM_IMPORTS.length,  source: 'CycloneDX Import' },
];

/* ═══════════════════════════════════════════════════════════════
   DiscoveryPage — orchestrator
   ═══════════════════════════════════════════════════════════════ */

export default function DiscoveryPage() {
  const [activeTab, setActiveTab] = useState<DiscoveryTab>('certificates');
  const [search, setSearch] = useState('');

  const handleTabChange = (tab: DiscoveryTab) => {
    setActiveTab(tab);
    setSearch('');
  };

  return (
    <div>
      {/* Header */}
      <div className={s.header}>
        <h1 className={s.title}>Discovery</h1>
        <p className={s.subtitle}>
          Cryptographic asset inventory aggregated from all configured integrations — certificates, endpoints, software signing, devices, code analysis, and CBOM imports.
        </p>
      </div>

      {/* Tabs */}
      <div className={s.tabs}>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={activeTab === t.id ? s.tabActive : s.tab}
            onClick={() => handleTabChange(t.id)}
          >
            {t.icon}
            <span>
              {t.label}
              <span className={s.sourceTag}>{t.source}</span>
            </span>
            <span className={activeTab === t.id ? s.tabCountActive : s.tabCount}>{t.count}</span>
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'certificates'  && <CertificatesTab search={search} setSearch={setSearch} />}
      {activeTab === 'endpoints'     && <EndpointsTab    search={search} setSearch={setSearch} />}
      {activeTab === 'software'      && <SoftwareTab     search={search} setSearch={setSearch} />}
      {activeTab === 'devices'       && <DevicesTab      search={search} setSearch={setSearch} />}
      {activeTab === 'code-analysis' && <CodeAnalysisTab search={search} setSearch={setSearch} />}
      {activeTab === 'cbom-imports'  && <CbomImportsTab  search={search} setSearch={setSearch} />}
    </div>
  );
}
