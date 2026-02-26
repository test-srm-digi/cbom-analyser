import { useState, useCallback, useRef } from 'react';
import AppShell, { type NavPage } from './layouts/AppShell';
import DashboardPage from './pages/DashboardPage';
import InventoryPage from './pages/InventoryPage';
import VisualizePage from './pages/VisualizePage';
import ViolationsPage from './pages/ViolationsPage';
import NetworkPage from './pages/NetworkPage';
import IntegrationsPage from './pages/integrations';
import DiscoveryPage from './pages/discovery';
import CbomDetailPage from './pages/discovery/CbomDetailPage';
import type { DiscoveryTab } from './pages/discovery/types';
import PlaceholderPage from './pages/PlaceholderPage';
import {
  ShieldHalf,
  Tablet,
  FileSignature,
} from 'lucide-react';
import {
  CBOMDocument,
  QuantumReadinessScore,
  ComplianceSummary,
  UploadResponse,
} from './types';
import { SAMPLE_CBOM } from './sampleData';

export default function App() {
  const [activePage, setActivePage] = useState<NavPage>('dashboard');
  const [cbom, setCbom] = useState<CBOMDocument | null>(null);
  const [readinessScore, setReadinessScore] = useState<QuantumReadinessScore | null>(null);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedCbomId, setSelectedCbomId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /* ── Upload ──────────────────────────────────────────── */

  const handleUpload = useCallback(async (file: File) => {
    setIsLoading(true);
    try {
      const formData = new FormData();
      formData.append('cbom', file);
      const resp = await fetch('/api/upload', { method: 'POST', body: formData });
      const data: UploadResponse = await resp.json();
      if (data.success && data.cbom) {
        setCbom(data.cbom);
        setReadinessScore(data.readinessScore || null);
        setCompliance(data.compliance || null);
      } else {
        const text = await file.text();
        handleLocalParse(text);
      }
    } catch {
      try {
        const text = await file.text();
        handleLocalParse(text);
      } catch {
        // silent
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  function triggerUpload() {
    fileInputRef.current?.click();
  }

  function onFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) handleUpload(file);
  }

  /* ── Local parse ─────────────────────────────────────── */

  function handleLocalParse(jsonText: string) {
    let data = JSON.parse(jsonText);

    if (data.success !== undefined && data.cbom) {
      const wrappedScore = data.readinessScore;
      const wrappedCompliance = data.compliance;
      data = data.cbom;
      if (wrappedScore && wrappedCompliance) {
        const doc = buildDoc(data);
        setCbom(doc);
        setReadinessScore(wrappedScore);
        setCompliance(wrappedCompliance);
        return;
      }
    }

    const doc = buildDoc(data);

    if (doc.cryptoAssets.length === 0 && doc.components.length > 0) {
      for (const comp of doc.components as any[]) {
        const cp = comp.cryptoProperties || comp['crypto-properties'];
        if (cp) {
          doc.cryptoAssets.push({
            id: comp['bom-ref'] || crypto.randomUUID(),
            name: comp.name,
            type: comp.type || 'crypto-asset',
            cryptoProperties: {
              assetType: cp.assetType || cp['asset-type'] || 'algorithm',
              algorithmProperties: cp.algorithmProperties,
            },
            location: comp.evidence?.occurrences?.[0]
              ? { fileName: comp.evidence.occurrences[0].location || '', lineNumber: comp.evidence.occurrences[0].line }
              : undefined,
            quantumSafety: 'unknown' as any,
          });
        }
      }
    }

    const safe = doc.cryptoAssets.filter((a) => a.quantumSafety === 'quantum-safe').length;
    const notSafe = doc.cryptoAssets.filter((a) => a.quantumSafety === 'not-quantum-safe').length;
    const unknown = doc.cryptoAssets.filter((a) => a.quantumSafety === 'unknown').length;
    const total = doc.cryptoAssets.length;

    setCbom(doc);
    setReadinessScore({
      score: total > 0 ? Math.round(((safe + unknown * 0.5) / total) * 100) : 100,
      totalAssets: total,
      quantumSafe: safe,
      notQuantumSafe: notSafe,
      conditional: 0,
      unknown,
    });
    setCompliance({
      isCompliant: notSafe === 0,
      policy: 'NIST Post-Quantum Cryptography',
      source: 'Basic Local Compliance Service',
      totalAssets: total,
      compliantAssets: safe,
      nonCompliantAssets: notSafe,
      unknownAssets: unknown,
    });
  }

  function buildDoc(data: any): CBOMDocument {
    return {
      bomFormat: data.bomFormat || 'CycloneDX',
      specVersion: data.specVersion || '1.7',
      serialNumber: data.serialNumber,
      version: data.version || 1,
      metadata: data.metadata || { timestamp: new Date().toISOString() },
      components: data.components || [],
      cryptoAssets: data.cryptoAssets || [],
      dependencies: data.dependencies,
      thirdPartyLibraries: data.thirdPartyLibraries,
    };
  }

  /* ── Load sample data on demand ──────────────────────── */

  const loadSampleData = useCallback(() => {
    handleLocalParse(JSON.stringify(SAMPLE_CBOM));
  }, []);

  /* ── Render page ─────────────────────────────────────── */

  function renderPage() {
    switch (activePage) {
      case 'cbom-analyzer':
        // bare parent → redirect to first child
        setActivePage('dashboard');
        return null;
      case 'dashboard':
        return (
          <DashboardPage
            cbom={cbom}
            readinessScore={readinessScore}
            compliance={compliance}
            onNavigate={(p) => setActivePage(p as NavPage)}
            onUpload={triggerUpload}
            onLoadSample={loadSampleData}
          />
        );
      case 'inventory':
        return <InventoryPage cbom={cbom} readinessScore={readinessScore} onUpload={triggerUpload} onLoadSample={loadSampleData} />;
      case 'visualize':
        return <VisualizePage cbom={cbom} onUpload={triggerUpload} onLoadSample={loadSampleData} />;
            case 'network':
        return <NetworkPage />;
      // case 'violations':
      //   return <ViolationsPage cbom={cbom} onUpload={triggerUpload} onLoadSample={loadSampleData} />;
      case 'integrations':
        return <IntegrationsPage />;
      case 'discovery':
        // bare discovery → redirect to first child
        setActivePage('discovery-certificates');
        return null;
      case 'discovery-certificates':
      case 'discovery-endpoints':
      case 'discovery-software':
      case 'discovery-devices':
      case 'discovery-cbom-imports':
        return (
          <DiscoveryPage
            tab={activePage.replace('discovery-', '') as DiscoveryTab}
            onViewCbom={(id) => { setSelectedCbomId(id); setActivePage('cbom-detail'); }}
          />
        );
      case 'cbom-detail':
        return selectedCbomId ? (
          <CbomDetailPage
            cbomImportId={selectedCbomId}
            onBack={() => { setSelectedCbomId(null); setActivePage('discovery-cbom-imports'); }}
          />
        ) : null;
  

      /* ── Other product placeholders ──────────────── */
      case 'private-ca':
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Private CA"
            icon={ShieldHalf}
            description="Assess private CA certificates for quantum vulnerability, migrate issuing CAs to PQC-ready algorithms, and enforce post-quantum policies across internal PKI."
            features={['CA algorithm audit', 'PQC migration planner', 'Quantum-safe policy enforcement', 'CBOM generation for CA chains']}
          />
        );
      case 'device-trust':
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Device Trust"
            icon={Tablet}
            description="Inventory cryptographic algorithms embedded in IoT firmware, identify harvest-now-decrypt-later risks, and plan quantum-safe certificate rollouts for device fleets."
            features={['Firmware crypto scanning', 'HNDL risk assessment', 'Fleet PQC migration plan', 'Device CBOM inventory']}
          />
        );
      case 'document-trust':
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Document Trust"
            icon={FileSignature}
            description="Evaluate document-signing certificates for quantum vulnerability, migrate to ML-DSA / SLH-DSA signatures, and verify long-term document integrity against future quantum threats."
            features={['Signature algorithm audit', 'ML-DSA migration path', 'Long-term integrity check', 'Quantum-safe timestamping']}
          />
        );

      default:
        return (
          <div className="dc1-placeholder-page">
            <h2>{activePage.charAt(0).toUpperCase() + activePage.slice(1)}</h2>
            <p>This page is coming soon.</p>
          </div>
        );
    }
  }

  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,.cdx,.xml"
        style={{ display: 'none' }}
        onChange={onFileSelected}
      />
      <AppShell activePage={activePage} onNavigate={setActivePage}>
        {renderPage()}
      </AppShell>
    </>
  );
}
