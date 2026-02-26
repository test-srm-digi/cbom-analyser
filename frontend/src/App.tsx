import { useState, useCallback, useRef } from 'react';
import AppShell, { type NavPage } from './layouts/AppShell';
import DashboardPage from './pages/DashboardPage';
import InventoryPage from './pages/InventoryPage';
import VisualizePage from './pages/VisualizePage';
import ViolationsPage from './pages/ViolationsPage';
import NetworkPage from './pages/NetworkPage';
import IntegrationsPage from './pages/IntegrationsPage';
import DiscoveryPage from './pages/DiscoveryPage';
import PlaceholderPage from './pages/PlaceholderPage';
import {
  FileText,
  BarChart3,
  UserCog,
  LayoutDashboard,
  ShieldCheck,
  KeyRound,
  Award,
  PackageOpen,
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
      case 'violations':
        return <ViolationsPage cbom={cbom} onUpload={triggerUpload} onLoadSample={loadSampleData} />;
      case 'integrations':
        return <IntegrationsPage />;
      case 'discovery':
        return <DiscoveryPage />;
      case 'network':
        return <NetworkPage />;

      /* ── Trust Lifecycle placeholders ─────────────── */
      case 'reporting':
        return (
          <PlaceholderPage
            section="Trust Lifecycle"
            title="Reporting"
            icon={BarChart3}
            description="Generate compliance reports, certificate expiry summaries, and quantum-readiness audits across your entire crypto inventory."
            features={['Compliance audit reports', 'Expiry forecasting', 'Quantum-readiness posture', 'Scheduled PDF / CSV exports']}
          />
        );
      case 'account':
        return (
          <PlaceholderPage
            section="Trust Lifecycle"
            title="Account"
            icon={UserCog}
            description="Manage your organisation profile, team members, API keys, and billing for Trust Lifecycle Manager services."
            features={['Team & role management', 'API key rotation', 'Billing & usage', 'Audit log']}
          />
        );

      /* ── Software Trust placeholders ─────────────── */
      case 'stm-dashboard':
        return (
          <PlaceholderPage
            section="Software Trust"
            title="Dashboard"
            icon={LayoutDashboard}
            description="Overview of your code-signing posture, release activity, and keypair health across all Software Trust Manager projects."
            features={['Signing activity timeline', 'Key expiry alerts', 'Release pipeline status', 'Policy violations']}
          />
        );
      case 'stm-release-security':
        return (
          <PlaceholderPage
            section="Software Trust"
            title="Release Security"
            icon={ShieldCheck}
            description="Enforce signing policies on software releases. Review approval workflows, validation rules, and tamper evidence."
            features={['Approval workflows', 'Signature validation', 'Tamper-evidence logs', 'Policy enforcement']}
          />
        );
      case 'stm-keypairs':
        return (
          <PlaceholderPage
            section="Software Trust"
            title="Keypairs"
            icon={KeyRound}
            description="Manage code-signing keypairs stored in DigiCert ONE. Generate, rotate, and assign keys to release pipelines."
            features={['HSM-backed key generation', 'Key rotation schedules', 'Assignment to pipelines', 'Usage audit trail']}
          />
        );
      case 'stm-certificates':
        return (
          <PlaceholderPage
            section="Software Trust"
            title="Certificates"
            icon={Award}
            description="View and manage code-signing certificates issued through Software Trust Manager, including EV and standard OV certificates."
            features={['Certificate lifecycle', 'Auto-renewal', 'Revocation management', 'Chain validation']}
          />
        );
      case 'stm-releases':
        return (
          <PlaceholderPage
            section="Software Trust"
            title="Releases"
            icon={PackageOpen}
            description="Track signed software releases across all projects. Verify signatures, view provenance, and manage distribution."
            features={['Release inventory', 'Signature verification', 'Provenance tracking', 'Distribution channels']}
          />
        );

      /* ── Other product placeholders ──────────────── */
      case 'private-ca':
        return (
          <PlaceholderPage
            section="DigiCert ONE"
            title="Private CA"
            icon={ShieldHalf}
            description="Deploy and manage private Certificate Authorities for internal TLS, mTLS, and device identity use cases."
            features={['Private root & issuing CAs', 'Certificate templates', 'CRL & OCSP responder', 'Policy enforcement']}
          />
        );
      case 'device-trust':
        return (
          <PlaceholderPage
            section="DigiCert ONE"
            title="Device Trust"
            icon={Tablet}
            description="Secure IoT and device identities with certificate-based authentication, firmware signing, and lifecycle management."
            features={['Device identity enrollment', 'Firmware signing', 'Certificate lifecycle', 'Fleet management']}
          />
        );
      case 'document-trust':
        return (
          <PlaceholderPage
            section="DigiCert ONE"
            title="Document Trust"
            icon={FileSignature}
            description="Apply trusted digital signatures to documents and verify document authenticity with DigiCert-issued signing certificates."
            features={['eSignature workflows', 'PDF signing & sealing', 'Timestamp authority', 'Signature validation']}
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
