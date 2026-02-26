import { useState, useCallback } from 'react';
import {
  Plus,
  Settings,
  Shield,
  Database,
  GitBranch,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronRight,
  X,
  Play,
  Loader2,
  Clock,
  ExternalLink,
  Info,
  Trash2,
  Copy,
  Network,
  FileCode2,
  Server,
  ArrowRight,
} from 'lucide-react';
import type {
  Integration,
  IntegrationTemplate,
  IntegrationField,
  IntegrationStatus,
  ImportScope,
  SyncSchedule,
} from '../types';
import s from './IntegrationsPage.module.scss';

/* ═══════════════════════════════════════════════════════════════
   Integration Catalog — available types users can configure
   ═══════════════════════════════════════════════════════════════ */

const INTEGRATION_CATALOG: IntegrationTemplate[] = [
  {
    type: 'digicert-tlm',
    name: 'DigiCert Trust Lifecycle Manager',
    vendor: 'DigiCert',
    category: 'digicert',
    description:
      'Import certificates, keys, and endpoint data from DigiCert Trust Lifecycle Manager via REST API. Enables automated discovery of TLS certificates, CA hierarchies, and cryptographic posture across your managed PKI infrastructure.',
    docsUrl: 'https://docs.digicert.com/en/trust-lifecycle-manager/manage-certificates/certificate-api.html',
    capabilities: [
      'Certificate inventory import (public & private CA)',
      'Endpoint & host TLS configuration discovery',
      'Automated CA hierarchy mapping',
      'Key algorithm & strength analysis',
      'Expiration & lifecycle tracking',
    ],
    fields: [
      { key: 'apiBaseUrl', label: 'API Base URL', type: 'url', placeholder: 'https://one.digicert.com', required: true, helpText: 'Your DigiCert ONE tenant URL' },
      { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Enter your API key', required: true, helpText: 'Generate from DigiCert ONE → Admin → API Keys' },
      { key: 'divisionId', label: 'Division ID', type: 'text', placeholder: 'Optional — leave blank for all divisions', required: false, helpText: 'Restrict import to a specific division' },
      { key: 'accountId', label: 'Account ID', type: 'text', placeholder: 'Your DigiCert account ID', required: true, helpText: 'Found under Admin → Account Settings' },
    ],
  },
  {
    type: 'digicert-stm',
    name: 'DigiCert Software Trust Manager',
    vendor: 'DigiCert',
    category: 'digicert',
    description:
      'Import code signing certificates, software hashes, and SBOM-linked cryptographic assets from DigiCert Software Trust Manager. Analyze signing algorithms used across your software supply chain.',
    docsUrl: 'https://docs.digicert.com/en/software-trust-manager.html',
    capabilities: [
      'Code signing certificate inventory',
      'Signing key algorithm analysis',
      'Software release cryptographic audit',
      'SBOM crypto-asset correlation',
      'Timestamp authority tracking',
    ],
    fields: [
      { key: 'apiBaseUrl', label: 'API Base URL', type: 'url', placeholder: 'https://one.digicert.com', required: true, helpText: 'Your DigiCert ONE tenant URL' },
      { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Enter your API key', required: true, helpText: 'Generate from DigiCert ONE → Admin → API Keys' },
      { key: 'environment', label: 'Environment', type: 'select', required: true, helpText: 'Which STM environment to connect to', options: [{ value: 'production', label: 'Production' }, { value: 'staging', label: 'Staging / Test' }] },
    ],
  },
  {
    type: 'digicert-dtm',
    name: 'DigiCert Device Trust Manager',
    vendor: 'DigiCert',
    category: 'digicert',
    description:
      'Import IoT device certificates and embedded cryptographic configurations from DigiCert Device Trust Manager. Track quantum readiness of device fleets and embedded firmware crypto.',
    docsUrl: 'https://docs.digicert.com/en/iot-trust-manager.html',
    capabilities: [
      'Device certificate inventory',
      'Embedded crypto algorithm detection',
      'Device fleet quantum readiness',
      'Firmware signing verification',
      'Device identity lifecycle tracking',
    ],
    fields: [
      { key: 'apiBaseUrl', label: 'API Base URL', type: 'url', placeholder: 'https://one.digicert.com', required: true, helpText: 'Your DigiCert ONE tenant URL' },
      { key: 'apiKey', label: 'API Key', type: 'password', placeholder: 'Enter your API key', required: true, helpText: 'Generate from DigiCert ONE → Admin → API Keys' },
      { key: 'deviceGroup', label: 'Device Group', type: 'text', placeholder: 'Optional — filter by device group', required: false },
    ],
  },
  {
    type: 'network-scanner',
    name: 'Network TLS Scanner',
    vendor: 'Built-in',
    category: 'scanner',
    description:
      'Scan your network to discover TLS endpoints, cipher suites, certificate chains, and key exchange algorithms. Identify hosts using quantum-vulnerable cryptography before Q-Day.',
    docsUrl: '',
    capabilities: [
      'CIDR range & port TLS probing',
      'Certificate chain extraction',
      'Cipher suite enumeration',
      'Key exchange algorithm detection',
      'TLS version compliance check',
    ],
    fields: [
      { key: 'targets', label: 'Target CIDR Ranges', type: 'text', placeholder: '10.0.0.0/24, 192.168.1.0/24', required: true, helpText: 'Comma-separated CIDR ranges to scan' },
      { key: 'ports', label: 'Port Ranges', type: 'text', placeholder: '443, 8443, 636, 993, 995', required: true, helpText: 'Ports to probe for TLS. Common: 443, 8443, 636 (LDAPS)' },
      { key: 'concurrency', label: 'Max Concurrent Connections', type: 'select', required: true, helpText: 'Higher concurrency = faster scan but more network load', options: [{ value: '10', label: '10 (Conservative)' }, { value: '50', label: '50 (Moderate)' }, { value: '100', label: '100 (Aggressive)' }] },
      { key: 'timeout', label: 'Connection Timeout (seconds)', type: 'select', required: true, helpText: 'Timeout per TLS handshake attempt', options: [{ value: '5', label: '5s' }, { value: '10', label: '10s' }, { value: '30', label: '30s' }] },
    ],
  },
  {
    type: 'cbom-import',
    name: 'CBOM File Import',
    vendor: 'CycloneDX',
    category: 'import',
    description:
      'Upload or link CycloneDX CBOM (Cryptographic Bill of Materials) files from your CI/CD pipeline, SBOM tools, or manual audit. Supports CycloneDX 1.6+ with crypto extensions.',
    docsUrl: 'https://cyclonedx.org/capabilities/cbom/',
    capabilities: [
      'CycloneDX 1.6 / 1.7 CBOM parsing',
      'JSON & XML format support',
      'CI/CD artifact ingestion',
      'URL-based remote fetch',
      'Merge & deduplication across imports',
    ],
    fields: [
      { key: 'importMethod', label: 'Import Method', type: 'select', required: true, options: [{ value: 'upload', label: 'File Upload' }, { value: 'url', label: 'URL Fetch' }, { value: 'artifact', label: 'CI/CD Artifact (GitHub Actions)' }] },
      { key: 'url', label: 'CBOM URL', type: 'url', placeholder: 'https://example.com/cbom.json', required: false, helpText: 'Direct link to a CycloneDX CBOM JSON or XML file' },
      { key: 'githubRepo', label: 'GitHub Repository', type: 'text', placeholder: 'owner/repo', required: false, helpText: 'For artifact import — GitHub repository (e.g., acme/my-app)' },
      { key: 'githubToken', label: 'GitHub Token', type: 'password', placeholder: 'ghp_xxxxxxxxxxxx', required: false, helpText: 'Personal access token with actions:read scope' },
    ],
  },
  {
    type: 'github-scanner',
    name: 'GitHub Repository Scanner',
    vendor: 'GitHub',
    category: 'repository',
    description:
      'Scan GitHub repositories for cryptographic API usage, hardcoded keys, certificate files, and crypto library dependencies. Generates a CBOM from source code analysis.',
    docsUrl: '',
    capabilities: [
      'Source code crypto-API call detection',
      'Crypto library dependency mapping',
      'Certificate & key file discovery',
      'Algorithm parameter extraction (key sizes, modes)',
      'CBOM auto-generation from source analysis',
    ],
    fields: [
      { key: 'repoUrl', label: 'Repository URL', type: 'url', placeholder: 'https://github.com/org/repo', required: true },
      { key: 'accessToken', label: 'Access Token', type: 'password', placeholder: 'ghp_xxxxxxxxxxxx or fine-grained PAT', required: true, helpText: 'Needs contents:read scope' },
      { key: 'branch', label: 'Branch', type: 'text', placeholder: 'main', required: false, helpText: 'Defaults to the default branch' },
      { key: 'scanPaths', label: 'Paths to Scan', type: 'text', placeholder: 'src/, lib/ (blank = entire repo)', required: false },
    ],
  },
];

/* ═══════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════ */

function categoryIcon(category: string) {
  switch (category) {
    case 'digicert':   return <Shield size={20} />;
    case 'scanner':    return <Network size={20} />;
    case 'import':     return <FileCode2 size={20} />;
    case 'repository': return <GitBranch size={20} />;
    default:           return <Database size={20} />;
  }
}

function statusLabel(status: IntegrationStatus): string {
  switch (status) {
    case 'not_configured': return 'Not Configured';
    case 'configuring':    return 'Configuring';
    case 'testing':        return 'Testing Connection…';
    case 'connected':      return 'Connected';
    case 'error':          return 'Connection Error';
    case 'disabled':       return 'Disabled';
  }
}

function statusCls(status: IntegrationStatus): string {
  switch (status) {
    case 'connected': return s.statusConnected;
    case 'error':     return s.statusError;
    case 'testing':   return s.statusTesting;
    case 'disabled':  return s.statusDisabled;
    default:          return s.statusDefault;
  }
}

const SCOPE_OPTIONS: { value: ImportScope; label: string; description: string }[] = [
  { value: 'certificates', label: 'Certificates', description: 'TLS, code-signing, CA certs' },
  { value: 'endpoints',    label: 'Endpoints',    description: 'Hosts, IPs, TLS configs' },
  { value: 'software',     label: 'Software',     description: 'Crypto libraries, SBOMs' },
  { value: 'keys',         label: 'Keys',         description: 'Key pairs, signing keys' },
];

const SCHEDULE_OPTIONS: { value: SyncSchedule; label: string }[] = [
  { value: 'manual', label: 'Manual only' },
  { value: '1h',     label: 'Every hour' },
  { value: '6h',     label: 'Every 6 hours' },
  { value: '12h',    label: 'Every 12 hours' },
  { value: '24h',    label: 'Every 24 hours' },
];

/* ═══════════════════════════════════════════════════════════════
   Component
   ═══════════════════════════════════════════════════════════════ */

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [showCatalog, setShowCatalog] = useState(false);
  const [configPanel, setConfigPanel] = useState<{ template: IntegrationTemplate; integration?: Integration } | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [configScope, setConfigScope] = useState<ImportScope[]>(['certificates', 'endpoints']);
  const [configSchedule, setConfigSchedule] = useState<SyncSchedule>('24h');
  const [configName, setConfigName] = useState('');
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');

  /* ── Open config panel for a catalog template ──────────── */
  const openNewConfig = useCallback((template: IntegrationTemplate) => {
    setConfigPanel({ template });
    setConfigValues({});
    setConfigScope(['certificates', 'endpoints']);
    setConfigSchedule('24h');
    setConfigName(template.name);
    setTestStatus('idle');
    setShowCatalog(false);
  }, []);

  /* ── Open config panel for an existing integration ─────── */
  const openEditConfig = useCallback((integration: Integration) => {
    const template = INTEGRATION_CATALOG.find((t) => t.type === integration.templateType);
    if (!template) return;
    setConfigPanel({ template, integration });
    setConfigValues(integration.config);
    setConfigScope(integration.importScope);
    setConfigSchedule(integration.syncSchedule);
    setConfigName(integration.name);
    setTestStatus(integration.status === 'connected' ? 'success' : integration.status === 'error' ? 'error' : 'idle');
  }, []);

  /* ── Close config panel ─────────────────────────────────── */
  const closeConfig = useCallback(() => {
    setConfigPanel(null);
    setTestStatus('idle');
  }, []);

  /* ── Test connection ────────────────────────────────────── */
  const testConnection = useCallback(() => {
    setTestStatus('testing');
    // Simulate async connection test
    setTimeout(() => {
      const hasRequiredFields = configPanel?.template.fields
        .filter((f) => f.required)
        .every((f) => configValues[f.key]?.trim());
      setTestStatus(hasRequiredFields ? 'success' : 'error');
    }, 2000);
  }, [configPanel, configValues]);

  /* ── Save integration ───────────────────────────────────── */
  const saveIntegration = useCallback(() => {
    if (!configPanel) return;
    const { template, integration } = configPanel;

    if (integration) {
      // Update existing
      setIntegrations((prev) =>
        prev.map((i) =>
          i.id === integration.id
            ? {
                ...i,
                name: configName,
                config: configValues,
                importScope: configScope,
                syncSchedule: configSchedule,
                status: testStatus === 'success' ? 'connected' : i.status,
              }
            : i,
        ),
      );
    } else {
      // Create new
      const newIntegration: Integration = {
        id: `intg-${Date.now()}`,
        templateType: template.type,
        name: configName,
        description: template.description,
        status: testStatus === 'success' ? 'connected' : 'not_configured',
        enabled: true,
        config: configValues,
        importScope: configScope,
        syncSchedule: configSchedule,
        createdAt: new Date().toISOString(),
      };
      setIntegrations((prev) => [...prev, newIntegration]);
    }
    closeConfig();
  }, [configPanel, configName, configValues, configScope, configSchedule, testStatus, closeConfig]);

  /* ── Delete integration ─────────────────────────────────── */
  const deleteIntegration = useCallback((id: string) => {
    setIntegrations((prev) => prev.filter((i) => i.id !== id));
  }, []);

  /* ── Toggle enabled ─────────────────────────────────────── */
  const toggleEnabled = useCallback((id: string) => {
    setIntegrations((prev) =>
      prev.map((i) => (i.id === id ? { ...i, enabled: !i.enabled, status: i.enabled ? 'disabled' as IntegrationStatus : (i.status === 'disabled' ? 'connected' as IntegrationStatus : i.status) } : i)),
    );
  }, []);

  /* ── Trigger manual sync ────────────────────────────────── */
  const triggerSync = useCallback((id: string) => {
    setIntegrations((prev) =>
      prev.map((i) =>
        i.id === id
          ? { ...i, status: 'testing' as IntegrationStatus }
          : i,
      ),
    );
    // Simulate sync completion
    setTimeout(() => {
      setIntegrations((prev) =>
        prev.map((i) =>
          i.id === id
            ? {
                ...i,
                status: 'connected' as IntegrationStatus,
                lastSync: new Date().toLocaleString(),
                lastSyncItems: Math.floor(Math.random() * 80) + 20,
                lastSyncErrors: 0,
              }
            : i,
        ),
      );
    }, 3000);
  }, []);

  const configuredCount = integrations.filter((i) => i.status === 'connected').length;
  const totalItems = integrations.reduce((sum, i) => sum + (i.lastSyncItems || 0), 0);

  /* ────────────────────────────────────────────────────────── */
  /* ── RENDER ──────────────────────────────────────────────── */
  /* ────────────────────────────────────────────────────────── */

  return (
    <div className={s.page}>
      {/* ── Header ─────────────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerText}>
          <h1 className={s.title}>Integrations</h1>
          <p className={s.subtitle}>
            Connect data sources to build your cryptographic inventory. Each integration imports certificates, endpoints,
            keys, and software assets into the unified crypto inventory for quantum-readiness analysis.
          </p>
        </div>
        <button className={s.addBtn} onClick={() => setShowCatalog(true)}>
          <Plus size={16} />
          Add Integration
        </button>
      </div>

      {/* ── Stats ──────────────────────────────────────────── */}
      <div className={s.stats}>
        <div className={s.statCard}>
          <div className={s.statValue}>{integrations.length}</div>
          <div className={s.statLabel}>Configured</div>
        </div>
        <div className={s.statCard}>
          <div className={`${s.statValue} ${s.statSuccess}`}>{configuredCount}</div>
          <div className={s.statLabel}>Connected</div>
        </div>
        <div className={s.statCard}>
          <div className={s.statValue}>{totalItems}</div>
          <div className={s.statLabel}>Assets Imported</div>
        </div>
        <div className={s.statCard}>
          <div className={s.statValue}>{INTEGRATION_CATALOG.length}</div>
          <div className={s.statLabel}>Available Types</div>
        </div>
      </div>

      {/* ── Workflow Guide (when no integrations) ──────────── */}
      {integrations.length === 0 && !showCatalog && (
        <div className={s.emptyState}>
          <div className={s.emptyIcon}>
            <Server size={48} />
          </div>
          <h2 className={s.emptyTitle}>Build Your Crypto Inventory</h2>
          <p className={s.emptyDesc}>
            Connect your first data source to start discovering cryptographic assets across your infrastructure.
            Each integration type provides a different view into your crypto posture.
          </p>

          <div className={s.workflowSteps}>
            <div className={s.workflowStep}>
              <div className={s.stepNumber}>1</div>
              <div className={s.stepContent}>
                <h4>Choose an Integration</h4>
                <p>Select from DigiCert managers, network scanners, CBOM imports, or repository scanners</p>
              </div>
            </div>
            <div className={s.workflowArrow}><ArrowRight size={16} /></div>
            <div className={s.workflowStep}>
              <div className={s.stepNumber}>2</div>
              <div className={s.stepContent}>
                <h4>Configure & Connect</h4>
                <p>Provide API credentials, target ranges, or repository access. Test the connection before saving.</p>
              </div>
            </div>
            <div className={s.workflowArrow}><ArrowRight size={16} /></div>
            <div className={s.workflowStep}>
              <div className={s.stepNumber}>3</div>
              <div className={s.stepContent}>
                <h4>Import & Analyze</h4>
                <p>Assets flow into the Discovery page. View certificates, endpoints, and software with quantum-safety verdicts.</p>
              </div>
            </div>
          </div>

          <button className={s.addBtnLarge} onClick={() => setShowCatalog(true)}>
            <Plus size={18} />
            Add Your First Integration
          </button>
        </div>
      )}

      {/* ── Configured Integrations List ───────────────────── */}
      {integrations.length > 0 && (
        <div className={s.section}>
          <h2 className={s.sectionTitle}>Active Integrations</h2>
          <div className={s.intgGrid}>
            {integrations.map((intg) => {
              const template = INTEGRATION_CATALOG.find((t) => t.type === intg.templateType);
              return (
                <div key={intg.id} className={`${s.intgCard} ${!intg.enabled ? s.intgCardDisabled : ''}`}>
                  <div className={s.intgCardHeader}>
                    <div className={s.intgCardIcon}>
                      {template ? categoryIcon(template.category) : <Database size={20} />}
                    </div>
                    <div className={s.intgCardMeta}>
                      <h3 className={s.intgCardName}>{intg.name}</h3>
                      <span className={s.intgCardVendor}>{template?.vendor}</span>
                    </div>
                    <span className={statusCls(intg.status)}>
                      {intg.status === 'testing' && <Loader2 size={12} className={s.spin} />}
                      {statusLabel(intg.status)}
                    </span>
                  </div>

                  {/* Sync info */}
                  <div className={s.intgCardBody}>
                    <div className={s.intgFieldRow}>
                      <span className={s.intgFieldLabel}>Sync Schedule</span>
                      <span className={s.intgFieldValue}>
                        {SCHEDULE_OPTIONS.find((o) => o.value === intg.syncSchedule)?.label || intg.syncSchedule}
                      </span>
                    </div>
                    <div className={s.intgFieldRow}>
                      <span className={s.intgFieldLabel}>Import Scope</span>
                      <span className={s.intgFieldValue}>
                        {intg.importScope.map((sc) => sc.charAt(0).toUpperCase() + sc.slice(1)).join(', ')}
                      </span>
                    </div>
                    {intg.lastSync && (
                      <div className={s.intgFieldRow}>
                        <span className={s.intgFieldLabel}>Last Sync</span>
                        <span className={s.intgFieldValue}>
                          {intg.lastSync}
                          {intg.lastSyncItems != null && (
                            <span className={s.syncBadge}>{intg.lastSyncItems} items</span>
                          )}
                        </span>
                      </div>
                    )}
                    {intg.errorMessage && (
                      <div className={s.intgError}>
                        <AlertTriangle size={14} />
                        {intg.errorMessage}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className={s.intgCardFooter}>
                    <div className={s.intgActions}>
                      <button className={s.toggleWrap} onClick={() => toggleEnabled(intg.id)} title={intg.enabled ? 'Disable' : 'Enable'}>
                        <span className={intg.enabled ? s.toggleOn : s.toggle} />
                        <span className={s.toggleLabel}>{intg.enabled ? 'Enabled' : 'Disabled'}</span>
                      </button>
                    </div>
                    <div className={s.intgActions}>
                      <button
                        className={s.iconBtn}
                        onClick={() => triggerSync(intg.id)}
                        disabled={!intg.enabled || intg.status === 'testing'}
                        title="Sync Now"
                      >
                        <RefreshCw size={14} className={intg.status === 'testing' ? s.spin : ''} />
                      </button>
                      <button className={s.iconBtn} onClick={() => openEditConfig(intg)} title="Configure">
                        <Settings size={14} />
                      </button>
                      <button className={`${s.iconBtn} ${s.iconBtnDanger}`} onClick={() => deleteIntegration(intg.id)} title="Delete">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}

            {/* Add more card */}
            <button className={s.addCard} onClick={() => setShowCatalog(true)}>
              <Plus size={24} />
              <span>Add Integration</span>
            </button>
          </div>
        </div>
      )}

      {/* ── How It Works Section ───────────────────────────── */}
      <div className={s.section}>
        <h2 className={s.sectionTitle}>How Integrations Work</h2>
        <div className={s.howGrid}>
          <div className={s.howCard}>
            <div className={s.howIcon}><Shield size={24} /></div>
            <h4>DigiCert Managers</h4>
            <p>
              Connect to DigiCert ONE Trust Lifecycle, Software Trust, or Device Trust Manager using your
              <strong> API key</strong>. The integration pulls certificate inventories, signing keys, and device
              identities via the DigiCert REST API on your configured schedule.
            </p>
            <div className={s.howRequires}>
              <strong>Requires:</strong> DigiCert ONE account, API key with read access, Account/Division ID
            </div>
          </div>
          <div className={s.howCard}>
            <div className={s.howIcon}><Network size={24} /></div>
            <h4>Network Scanner</h4>
            <p>
              Probe <strong>CIDR ranges</strong> and port lists to discover TLS endpoints on your network.
              The scanner performs TLS handshakes, extracts certificate chains, cipher suites, and key exchange
              algorithms to assess quantum vulnerability.
            </p>
            <div className={s.howRequires}>
              <strong>Requires:</strong> Network access to target ranges, allowed ports, optional proxy config
            </div>
          </div>
          <div className={s.howCard}>
            <div className={s.howIcon}><FileCode2 size={24} /></div>
            <h4>CBOM Import</h4>
            <p>
              Upload a <strong>CycloneDX CBOM</strong> file (JSON or XML) generated by your CI/CD pipeline,
              or fetch it from a URL. Supports CycloneDX 1.6+ with cryptographic property extensions for
              algorithms, certificates, keys, and protocols.
            </p>
            <div className={s.howRequires}>
              <strong>Requires:</strong> CycloneDX CBOM file (v1.6+), or GitHub Actions artifact access
            </div>
          </div>
          <div className={s.howCard}>
            <div className={s.howIcon}><GitBranch size={24} /></div>
            <h4>Repository Scanner</h4>
            <p>
              Scan a <strong>GitHub repository</strong> for cryptographic API calls, key files, certificates,
              and crypto library dependencies. Generates a CBOM from static analysis of your source code.
            </p>
            <div className={s.howRequires}>
              <strong>Requires:</strong> Repository URL, access token with contents:read scope
            </div>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════════
          Integration Catalog Overlay
          ═══════════════════════════════════════════════════════ */}
      {showCatalog && (
        <div className={s.overlay} onClick={() => setShowCatalog(false)}>
          <div className={s.catalogPanel} onClick={(e) => e.stopPropagation()}>
            <div className={s.catalogHeader}>
              <h2>Add Integration</h2>
              <p>Choose an integration type to configure</p>
              <button className={s.closeBtn} onClick={() => setShowCatalog(false)}><X size={18} /></button>
            </div>
            <div className={s.catalogGrid}>
              {INTEGRATION_CATALOG.map((tmpl) => (
                <button key={tmpl.type} className={s.catalogCard} onClick={() => openNewConfig(tmpl)}>
                  <div className={s.catalogCardIcon}>{categoryIcon(tmpl.category)}</div>
                  <div className={s.catalogCardText}>
                    <h3>{tmpl.name}</h3>
                    <span className={s.catalogVendor}>{tmpl.vendor}</span>
                    <p>{tmpl.description.slice(0, 120)}…</p>
                  </div>
                  <ChevronRight size={16} className={s.catalogChevron} />
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════
          Configuration Slide-Out Panel
          ═══════════════════════════════════════════════════════ */}
      {configPanel && (
        <div className={s.overlay} onClick={closeConfig}>
          <div className={s.configDrawer} onClick={(e) => e.stopPropagation()}>
            {/* Drawer header */}
            <div className={s.drawerHeader}>
              <div className={s.drawerHeaderIcon}>{categoryIcon(configPanel.template.category)}</div>
              <div>
                <h2>{configPanel.integration ? 'Edit Integration' : 'New Integration'}</h2>
                <p>{configPanel.template.name}</p>
              </div>
              <button className={s.closeBtn} onClick={closeConfig}><X size={18} /></button>
            </div>

            <div className={s.drawerBody}>
              {/* ── Step 1: Name ── */}
              <div className={s.configSection}>
                <h3 className={s.configSectionTitle}>
                  <span className={s.configStepBadge}>1</span>
                  Integration Name
                </h3>
                <input
                  className={s.configInput}
                  value={configName}
                  onChange={(e) => setConfigName(e.target.value)}
                  placeholder="Give this integration a name"
                />
              </div>

              {/* ── Step 2: Connection Config ── */}
              <div className={s.configSection}>
                <h3 className={s.configSectionTitle}>
                  <span className={s.configStepBadge}>2</span>
                  Connection Settings
                </h3>
                {configPanel.template.docsUrl && (
                  <a href={configPanel.template.docsUrl} target="_blank" rel="noreferrer" className={s.docsLink}>
                    <ExternalLink size={13} />
                    View setup documentation
                  </a>
                )}

                <div className={s.configFields}>
                  {configPanel.template.fields.map((field) => (
                    <ConfigField
                      key={field.key}
                      field={field}
                      value={configValues[field.key] || ''}
                      onChange={(val) => setConfigValues((prev) => ({ ...prev, [field.key]: val }))}
                    />
                  ))}
                </div>

                {/* Test Connection */}
                <div className={s.testRow}>
                  <button
                    className={s.testBtn}
                    onClick={testConnection}
                    disabled={testStatus === 'testing'}
                  >
                    {testStatus === 'testing' ? (
                      <><Loader2 size={14} className={s.spin} /> Testing…</>
                    ) : testStatus === 'success' ? (
                      <><CheckCircle2 size={14} /> Connected</>
                    ) : testStatus === 'error' ? (
                      <><XCircle size={14} /> Failed — Retry</>
                    ) : (
                      <><Play size={14} /> Test Connection</>
                    )}
                  </button>
                  {testStatus === 'success' && <span className={s.testSuccess}>Connection successful</span>}
                  {testStatus === 'error' && <span className={s.testError}>Check credentials and try again</span>}
                </div>
              </div>

              {/* ── Step 3: Import Scope ── */}
              <div className={s.configSection}>
                <h3 className={s.configSectionTitle}>
                  <span className={s.configStepBadge}>3</span>
                  Import Scope
                </h3>
                <p className={s.configHint}>Select the types of assets to import from this source</p>
                <div className={s.scopeGrid}>
                  {SCOPE_OPTIONS.map((opt) => {
                    const active = configScope.includes(opt.value);
                    return (
                      <button
                        key={opt.value}
                        className={active ? s.scopeChipActive : s.scopeChip}
                        onClick={() =>
                          setConfigScope((prev) =>
                            active ? prev.filter((v) => v !== opt.value) : [...prev, opt.value],
                          )
                        }
                      >
                        <span className={s.scopeChipLabel}>{opt.label}</span>
                        <span className={s.scopeChipDesc}>{opt.description}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* ── Step 4: Sync Schedule ── */}
              <div className={s.configSection}>
                <h3 className={s.configSectionTitle}>
                  <span className={s.configStepBadge}>4</span>
                  Sync Schedule
                </h3>
                <p className={s.configHint}>How often should this integration pull new data?</p>
                <div className={s.scheduleRow}>
                  {SCHEDULE_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      className={configSchedule === opt.value ? s.scheduleBtnActive : s.scheduleBtn}
                      onClick={() => setConfigSchedule(opt.value)}
                    >
                      <Clock size={13} />
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* ── Capabilities ── */}
              <div className={s.configSection}>
                <h3 className={s.configSectionTitle}>
                  <Info size={16} />
                  What This Integration Provides
                </h3>
                <ul className={s.capList}>
                  {configPanel.template.capabilities.map((cap, i) => (
                    <li key={i}>
                      <CheckCircle2 size={14} className={s.capIcon} />
                      {cap}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Drawer footer */}
            <div className={s.drawerFooter}>
              <button className={s.cancelBtn} onClick={closeConfig}>Cancel</button>
              <button
                className={s.saveBtn}
                onClick={saveIntegration}
                disabled={!configName.trim()}
              >
                {configPanel.integration ? 'Save Changes' : 'Add Integration'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Config Field Sub-component
   ═══════════════════════════════════════════════════════════════ */

function ConfigField({
  field,
  value,
  onChange,
}: {
  field: IntegrationField;
  value: string;
  onChange: (val: string) => void;
}) {
  return (
    <div className={s.fieldGroup}>
      <label className={s.fieldLabel}>
        {field.label}
        {field.required && <span className={s.fieldRequired}>*</span>}
      </label>
      {field.type === 'select' ? (
        <select className={s.configSelect} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">Select…</option>
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      ) : field.type === 'textarea' ? (
        <textarea
          className={s.configTextarea}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={3}
        />
      ) : (
        <div className={s.inputWrap}>
          <input
            className={s.configInput}
            type={field.type === 'password' ? 'password' : 'text'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
          />
          {field.type === 'password' && value && (
            <button className={s.copyBtn} onClick={() => navigator.clipboard.writeText(value)} title="Copy">
              <Copy size={13} />
            </button>
          )}
        </div>
      )}
      {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
    </div>
  );
}
