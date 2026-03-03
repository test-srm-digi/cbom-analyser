import { useState } from 'react';
import { useUploadXBOMMutation } from '../../../store/api';
import type { XBOMDocument, XBOMAnalytics } from '../../../types';
import type { DetailTab } from '../types';
import { fmtDate } from '../utils';
import {
  SoftwarePanel,
  CryptoAnalysisPanel,
  VulnerabilityPanel,
  CrossRefPanel,
  BomOverviewPanel,
  BomDownloadButtons,
} from '../../../components/bom-panels';
import s from '../../XBOMPage.module.scss';

interface LocalXBOMDetailViewProps {
  xbom: XBOMDocument;
  analytics: XBOMAnalytics;
  onBack: () => void;
}

export default function LocalXBOMDetailView({
  xbom,
  analytics,
  onBack,
}: LocalXBOMDetailViewProps) {
  const [uploadXBOM, { isLoading: saving }] = useUploadXBOMMutation();
  const [tab, setTab] = useState<DetailTab>('overview');
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    const fd = new FormData();
    fd.append('xbom', JSON.stringify(xbom));
    try {
      await uploadXBOM(fd).unwrap();
      setSaved(true);
    } catch {
      /* ignore */
    }
  };

  const tabDef: { key: DetailTab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'software', label: 'Software', count: xbom.components?.length },
    { key: 'crypto', label: 'Crypto Assets', count: xbom.cryptoAssets?.length },
    {
      key: 'vulnerabilities',
      label: 'Vulnerabilities',
      count: xbom.vulnerabilities?.length,
    },
    {
      key: 'cross-references',
      label: 'Cross-References',
      count: xbom.crossReferences?.length,
    },
  ];

  const componentName = xbom.metadata?.component?.name ?? 'xBOM';

  return (
    <div className={s.xbomPage}>
      <div className={s.detailHeader}>
        <div>
          <button className={s.backBtn} onClick={onBack}>
            ← Back to xBOM list
          </button>
          <h2 style={{ margin: '8px 0 4px' }}>
            {componentName}
            <span
              style={{
                fontSize: 12,
                fontWeight: 400,
                marginLeft: 10,
                padding: '2px 8px',
                borderRadius: 10,
                background: '#dbeafe',
                color: '#1d4ed8',
              }}
            >
              Uploaded
            </span>
          </h2>
          <div className={s.detailMeta}>
            <span>
              Format: {xbom.bomFormat} {xbom.specVersion}
            </span>
            <span>Generated: {fmtDate(xbom.metadata?.timestamp)}</span>
            {xbom.metadata?.repository?.url && (
              <span>Repo: {xbom.metadata.repository.url}</span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <BomDownloadButtons
            compact
            items={[
              {
                label: 'xBOM',
                filename: `${componentName}-xbom.json`,
                data: xbom,
              },
              {
                label: 'SBOM',
                filename: `${componentName}-sbom.json`,
                data: xbom.components?.length
                  ? {
                      bomFormat: 'CycloneDX',
                      specVersion: xbom.specVersion,
                      components: xbom.components,
                    }
                  : null,
              },
              {
                label: 'CBOM',
                filename: `${componentName}-cbom.json`,
                data: xbom.cryptoAssets?.length
                  ? {
                      bomFormat: 'CycloneDX',
                      specVersion: xbom.specVersion,
                      cryptoAssets: xbom.cryptoAssets,
                    }
                  : null,
              },
            ]}
          />
          <button
            className={s.iconBtn}
            style={{
              padding: '8px 16px',
              fontSize: 13,
              opacity: saved ? 0.6 : 1,
            }}
            onClick={handleSave}
            disabled={saving || saved}
          >
            {saved ? '✓ Saved' : saving ? 'Saving…' : 'Save to server'}
          </button>
        </div>
      </div>

      <div className={s.tabs}>
        {tabDef.map((t) => (
          <button
            key={t.key}
            className={`${s.tab} ${tab === t.key ? s.tabActive : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            {t.count !== undefined && (
              <span className={s.tabBadge}>{t.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content — shared panels */}
      {tab === 'overview' && (
        <BomOverviewPanel xbom={xbom} analytics={analytics} />
      )}
      {tab === 'software' && (
        <SoftwarePanel components={xbom.components ?? []} />
      )}
      {tab === 'crypto' && (
        <CryptoAnalysisPanel assets={xbom.cryptoAssets ?? []} thirdPartyLibraries={xbom.thirdPartyLibraries} />
      )}
      {tab === 'vulnerabilities' && (
        <VulnerabilityPanel
          vulns={xbom.vulnerabilities ?? []}
          summary={analytics?.vulnerabilitySummary}
        />
      )}
      {tab === 'cross-references' && (
        <CrossRefPanel
          refs={xbom.crossReferences ?? []}
          components={xbom.components}
          cryptoAssets={xbom.cryptoAssets}
        />
      )}
    </div>
  );
}
