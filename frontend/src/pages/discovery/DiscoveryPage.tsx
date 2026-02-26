import { useState } from 'react';
import type { DiscoveryTab } from './types';
import {
  CertificatesTab,
  EndpointsTab,
  SoftwareTab,
  DevicesTab,
  CbomImportsTab,
} from './tabs';
import s from './DiscoveryPage.module.scss';

/* ═══════════════════════════════════════════════════════════════
   Tab label map — for the page header
   ═══════════════════════════════════════════════════════════════ */

const TAB_META: Record<DiscoveryTab, { title: string; subtitle: string }> = {
  certificates:   { title: 'Certificates',  subtitle: 'TLS / PKI certificates discovered via DigiCert TLM — algorithm inventory, expiry tracking, and PQC-readiness assessment.' },
  endpoints:      { title: 'Endpoints',     subtitle: 'Network endpoints scanned for TLS configuration, cipher suites, and key-agreement protocols used in transit encryption.' },
  software:       { title: 'Software',      subtitle: 'Software releases and signing artifacts discovered via DigiCert STM — signing algorithm and PQC migration status.' },
  devices:        { title: 'Devices',       subtitle: 'IoT and managed devices discovered via DigiCert DTM — firmware crypto, certificate enrollment, and key-strength audit.' },
  'cbom-imports':  { title: 'CBOM Imports',  subtitle: 'CycloneDX CBOM files imported from CI/CD pipelines — crypto component inventory and PQC-readiness breakdown.' },
};

/* ═══════════════════════════════════════════════════════════════
   DiscoveryPage — renders the active discovery sub-page
   ═══════════════════════════════════════════════════════════════ */

interface Props {
  tab: DiscoveryTab;
  onViewCbom?: (id: string) => void;
}

export default function DiscoveryPage({ tab, onViewCbom }: Props) {
  const [search, setSearch] = useState('');
  const meta = TAB_META[tab];

  const tabContent = () => {
    switch (tab) {
      case 'certificates':   return <CertificatesTab search={search} setSearch={setSearch} />;
      case 'endpoints':      return <EndpointsTab    search={search} setSearch={setSearch} />;
      case 'software':       return <SoftwareTab     search={search} setSearch={setSearch} />;
      case 'devices':        return <DevicesTab      search={search} setSearch={setSearch} />;
      case 'cbom-imports':   return <CbomImportsTab  search={search} setSearch={setSearch} onViewCbom={onViewCbom} />;
    }
  };

  return (
    <div>
      {/* Header */}
      <div className={s.header}>
        <p className={s.breadcrumb}>Discovery</p>
        <h1 className={s.title}>{meta.title}</h1>
        <p className={s.subtitle}>{meta.subtitle}</p>
      </div>

      {/* Content */}
      {tabContent()}
    </div>
  );
}
