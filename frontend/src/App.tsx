import { useState, useCallback, useRef, useMemo, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AppShell, { type NavPage } from "./layouts/AppShell";
import DashboardPage from "./pages/DashboardPage";
import ViolationsPage from "./pages/ViolationsPage";
import NetworkPage from "./pages/NetworkPage";
import IntegrationsPage from "./pages/integrations";
import PoliciesPage from "./pages/policies";
import { TrackingPage } from "./pages/tracking";
import { TicketSettingsPage } from "./pages/tracking";
import DiscoveryPage from "./pages/discovery";
import RepoOverviewPage from "./pages/discovery/RepoOverviewPage";
import type { DiscoveryTab } from "./pages/discovery/types";
import PlaceholderPage from "./pages/PlaceholderPage";
import XBOMPage from "./pages/XBOMPage";
import { ShieldHalf, Tablet, FileSignature } from "lucide-react";
import {
  CBOMDocument,
  QuantumReadinessScore,
  ComplianceSummary,
  UploadResponse,
} from "./types";
import { SAMPLE_CBOM } from "./sampleData";
import { parseCbomJson } from "./utils/cbomParser";

/* ── NavPage ↔ URL path mapping ──────────────────────────── */

const PAGE_TO_PATH: Record<NavPage, string> = {
  tools: "/tools",
  dashboard: "/dashboard",
  inventory: "/inventory",
  visualize: "/visualize",
  violations: "/violations",
  tracking: "/tracking",
  "tracking-tickets": "/tracking/tickets",
  "tracking-settings": "/tracking/settings",
  policies: "/policies",
  integrations: "/integrations",
  discovery: "/discovery",
  "discovery-certificates": "/discovery/certificates",
  "discovery-endpoints": "/discovery/endpoints",
  "discovery-software": "/discovery/software",
  "discovery-devices": "/discovery/devices",
  "discovery-cbom-imports": "/discovery/cbom-imports",
  "cbom-detail": "/discovery/cbom-imports/detail",
  "repo-overview": "/discovery/cbom-imports/repo",
  network: "/network",
  xbom: "/xbom",
  settings: "/settings",
  "private-ca": "/private-ca",
  "device-trust": "/device-trust",
  "document-trust": "/document-trust",
};

const PATH_TO_PAGE: Record<string, NavPage> = Object.fromEntries(
  Object.entries(PAGE_TO_PATH).map(([k, v]) => [v, k as NavPage]),
) as Record<string, NavPage>;

function pathToPage(pathname: string): NavPage {
  // exact match first
  if (PATH_TO_PAGE[pathname]) return PATH_TO_PAGE[pathname];
  // cbom-detail with id suffix
  if (pathname.startsWith("/discovery/cbom-imports/detail"))
    return "cbom-detail";
  if (pathname.startsWith("/discovery/cbom-imports/repo"))
    return "repo-overview";
  // fallback
  return "dashboard";
}

export default function App() {
  const location = useLocation();
  const nav = useNavigate();
  const activePage = useMemo(
    () => pathToPage(location.pathname),
    [location.pathname],
  );

  // Redirect bare root to /dashboard
  useEffect(() => {
    if (location.pathname === "/") {
      nav("/dashboard", { replace: true });
    }
  }, [location.pathname, nav]);

  const setActivePage = useCallback(
    (page: NavPage) => nav(PAGE_TO_PATH[page]),
    [nav],
  );

  const [cbom, setCbom] = useState<CBOMDocument | null>(null);
  const [readinessScore, setReadinessScore] =
    useState<QuantumReadinessScore | null>(null);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedCbomId, setSelectedCbomId] = useState<string | null>(null);
  const [selectedRepoName, setSelectedRepoName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /* ── Upload ──────────────────────────────────────────── */

  const handleUpload = useCallback(async (file: File) => {
    setIsLoading(true);
    try {
      const formData = new FormData();
      formData.append("cbom", file);
      const resp = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
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

  /* ── Local parse (delegates to shared parser) ────────── */

  function handleLocalParse(jsonText: string) {
    const {
      doc,
      readinessScore: score,
      compliance: comp,
    } = parseCbomJson(jsonText, "Basic Local Compliance Service");
    setCbom(doc);
    setReadinessScore(score);
    setCompliance(comp);
  }

  /* ── Load sample data on demand ──────────────────────── */

  const loadSampleData = useCallback(() => {
    handleLocalParse(JSON.stringify(SAMPLE_CBOM));
  }, []);

  /* ── Render page ─────────────────────────────────────── */

  function renderPage() {
    switch (activePage) {
      case "tools":
        // bare parent → redirect to first child
        nav("/dashboard", { replace: true });
        return null;
      case "dashboard":
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
      case "network":
        return <NetworkPage />;
      case "xbom":
        return <XBOMPage />;
      // case 'violations':
      //   return <ViolationsPage cbom={cbom} onUpload={triggerUpload} onLoadSample={loadSampleData} />;
      case "tracking":
        // bare parent → redirect to first child
        nav("/tracking/tickets", { replace: true });
        return null;
      case "tracking-tickets":
        return <TrackingPage />;
      case "tracking-settings":
        return <TicketSettingsPage />;
      case "policies":
        return <PoliciesPage />;
      case "integrations":
        return <IntegrationsPage />;
      case "discovery":
        // bare discovery → redirect to first child
        nav("/discovery/certificates", { replace: true });
        return null;
      case "discovery-certificates":
      case "discovery-endpoints":
      case "discovery-software":
      case "discovery-devices":
      case "discovery-cbom-imports":
        return (
          <DiscoveryPage
            tab={activePage.replace("discovery-", "") as DiscoveryTab}
            onViewCbom={(id) => {
              setSelectedCbomId(id);
              setActivePage("cbom-detail");
            }}
            onViewRepo={(name) => {
              setSelectedRepoName(name);
              setActivePage("repo-overview");
            }}
            onGoToIntegrations={() => setActivePage("integrations")}
          />
        );
      case "cbom-detail":
        return selectedCbomId ? (
          <DashboardPage
            cbomImportId={selectedCbomId}
            onBack={() => {
              setSelectedCbomId(null);
              setActivePage("discovery-cbom-imports");
            }}
          />
        ) : null;
      case "repo-overview":
        return selectedRepoName ? (
          <RepoOverviewPage
            repoName={selectedRepoName}
            onBack={() => {
              setSelectedRepoName(null);
              setActivePage("discovery-cbom-imports");
            }}
            onViewCbom={(id) => {
              setSelectedCbomId(id);
              setActivePage("cbom-detail");
            }}
          />
        ) : null;

      /* ── Other product placeholders ──────────────── */
      case "private-ca":
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Private CA"
            icon={ShieldHalf}
            description="Assess private CA certificates for quantum vulnerability, migrate issuing CAs to PQC-ready algorithms, and enforce post-quantum policies across internal PKI."
            features={[
              "CA algorithm audit",
              "PQC migration planner",
              "Quantum-safe policy enforcement",
              "CBOM generation for CA chains",
            ]}
          />
        );
      case "device-trust":
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Device Trust"
            icon={Tablet}
            description="Inventory cryptographic algorithms embedded in IoT firmware, identify harvest-now-decrypt-later risks, and plan quantum-safe certificate rollouts for device fleets."
            features={[
              "Firmware crypto scanning",
              "HNDL risk assessment",
              "Fleet PQC migration plan",
              "Device CBOM inventory",
            ]}
          />
        );
      case "document-trust":
        return (
          <PlaceholderPage
            section="Quantum Readiness Advisor"
            title="Document Trust"
            icon={FileSignature}
            description="Evaluate document-signing certificates for quantum vulnerability, migrate to ML-DSA / SLH-DSA signatures, and verify long-term document integrity against future quantum threats."
            features={[
              "Signature algorithm audit",
              "ML-DSA migration path",
              "Long-term integrity check",
              "Quantum-safe timestamping",
            ]}
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
        style={{ display: "none" }}
        onChange={onFileSelected}
      />
      <AppShell activePage={activePage} onNavigate={setActivePage}>
        {renderPage()}
      </AppShell>
    </>
  );
}
