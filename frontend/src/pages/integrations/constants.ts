import type { IntegrationTemplate, SyncSchedule } from './types';

/* ═══════════════════════════════════════════════════════════════
   Integration Catalog — available types users can configure
   ═══════════════════════════════════════════════════════════════ */

export const INTEGRATION_CATALOG: IntegrationTemplate[] = [
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
    scopeOptions: [
      { value: 'certificates',   label: 'Certificates',   description: 'TLS, CA, and private certificates from managed PKI' },
      { value: 'endpoints',      label: 'Endpoints',      description: 'Hosts and IPs discovered via network & cloud scans' },
      { value: 'keys',           label: 'Keys',           description: 'Key algorithms, strength, and lifecycle data' },
      { value: 'ca-hierarchies', label: 'CA Hierarchies', description: 'Intermediate & root CA chain mappings' },
    ],
    defaultScope: ['certificates', 'endpoints', 'keys', 'ca-hierarchies'],
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
    scopeOptions: [
      { value: 'signing-certificates', label: 'Signing Certificates', description: 'Code signing & timestamping certificates' },
      { value: 'keypairs',             label: 'Keypairs',             description: 'Signing key pairs and algorithm metadata' },
      { value: 'releases',             label: 'Releases',             description: 'Software release windows and signing audit trails' },
      { value: 'threats',              label: 'Threat Detection',     description: 'Vulnerability and threat scan results' },
    ],
    defaultScope: ['signing-certificates', 'keypairs', 'releases'],
  },
  {
    type: 'digicert-dtm',
    name: 'DigiCert Device Trust Manager',
    vendor: 'DigiCert',
    category: 'digicert',
    description:
      'Import IoT device certificates and embedded cryptographic configurations from DigiCert Device Trust Manager. Track quantum readiness of device fleets and embedded firmware crypto.',
    docsUrl: 'https://docs.digicert.com/en/device-trust-manager.html',
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
    scopeOptions: [
      { value: 'device-certificates', label: 'Device Certificates', description: 'IoT/OT device identity certificates' },
      { value: 'devices',             label: 'Devices',             description: 'Device records, enrollment status, and profiles' },
      { value: 'firmware',            label: 'Firmware',            description: 'Firmware versions and signing verification data' },
      { value: 'device-groups',       label: 'Device Groups',       description: 'Logical groupings and enrollment profiles' },
    ],
    defaultScope: ['device-certificates', 'devices', 'firmware'],
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
    scopeOptions: [
      { value: 'endpoints',     label: 'Endpoints',     description: 'TLS-enabled hosts, IPs, and port configurations' },
      { value: 'certificates',  label: 'Certificates',  description: 'Certificate chains extracted from TLS handshakes' },
      { value: 'cipher-suites', label: 'Cipher Suites', description: 'Supported cipher suites per endpoint' },
      { value: 'key-exchange',  label: 'Key Exchange',  description: 'KEX algorithms (ECDHE, X25519, ML-KEM, etc.)' },
    ],
    defaultScope: ['endpoints', 'certificates', 'cipher-suites', 'key-exchange'],
  },
  {
    type: 'cbom-import',
    name: 'CBOM File Import',
    vendor: 'CycloneDX',
    category: 'import',
    description:
      'Ingest CycloneDX CBOM (Cryptographic Bill of Materials) artifacts from your GitHub Actions CI/CD pipeline. Supports CycloneDX 1.6+ with crypto extensions.',
    docsUrl: 'https://cyclonedx.org/capabilities/cbom/',
    capabilities: [
      'CycloneDX 1.6 / 1.7 CBOM parsing',
      'JSON & XML format support',
      'CI/CD artifact ingestion via GitHub Actions',
      'Incremental sync — only new workflow runs',
      'Auto-generated workflow YAML for your repo',
    ],
    fields: [
      // ── GitHub Actions: Repository Connection ──
      { key: 'githubRepo', label: 'GitHub Repository', type: 'text', placeholder: 'owner/repo', required: true, helpText: 'GitHub repository (e.g., acme/my-app)' },
      { key: 'githubToken', label: 'GitHub Token', type: 'password', placeholder: 'ghp_xxxxxxxxxxxx', required: true, helpText: 'Personal access token with actions:read and actions:write scope' },

      // ── Workflow Configuration Section ──
      { key: '_wfConfigHeader', label: 'Workflow Configuration', type: 'section-header', required: false, helpText: 'Configure your GitHub Actions workflow for CBOM scanning' },

      { key: 'branches', label: 'Branches', type: 'tags', required: false, defaultValue: 'main', placeholder: 'Type a branch name and press Enter', helpText: 'Branches to run the workflow on (default: main)' },

      { key: 'triggers', label: 'Trigger Events', type: 'multi-select', required: false, helpText: 'When should the workflow run?', defaultValue: 'push,pull_request', options: [
        { value: 'push', label: 'Push to branch' },
        { value: 'pull_request', label: 'Pull Request' },
        { value: 'release', label: 'Release published' },
        { value: 'schedule', label: 'Scheduled (cron)' },
      ] },

      { key: 'cronSchedule', label: 'Cron Schedule', type: 'text', placeholder: '0 2 * * 1', required: false, helpText: 'Cron expression for scheduled runs (e.g., "0 2 * * 1" = every Monday at 2 AM UTC)', visibleWhen: { field: 'triggers', values: ['schedule'] } },

      { key: 'language', label: 'Project Language', type: 'select', required: true, helpText: 'Primary language — determines scanner tooling in the workflow', options: [
        { value: 'java', label: 'Java' },
        { value: 'python', label: 'Python' },
        { value: 'javascript', label: 'JavaScript / TypeScript' },
        { value: 'go', label: 'Go' },
        { value: 'dotnet', label: 'C# / .NET' },
        { value: 'other', label: 'Other' },
      ] },

      { key: 'artifactName', label: 'Artifact Name', type: 'text', placeholder: 'cbom-report', required: false, helpText: 'Name of the uploaded artifact (default: cbom-report)' },

      // ── Runner Configuration ──
      { key: 'selfHostedRunner', label: 'Use self-hosted runner', type: 'checkbox', required: false, defaultValue: 'false', helpText: 'Run the workflow on your own infrastructure instead of GitHub-hosted runners' },
      { key: 'runnerLabel', label: 'Runner Label', type: 'text', placeholder: 'self-hosted, linux, x64', required: false, helpText: 'Comma-separated labels for your self-hosted runner', visibleWhen: { field: 'selfHostedRunner', values: ['true'] } },

      // ── Sonar Integration ──
      { key: 'sonarEnabled', label: 'Enable SonarQube / SonarCloud integration', type: 'checkbox', required: false, defaultValue: 'false', helpText: 'Add SonarQube or SonarCloud analysis step to the workflow' },
      { key: '_sonarInfo', label: 'SonarQube Setup', type: 'info-panel', required: false, variant: 'tip', content: '**Setting up SonarQube for CBOM scanning:**\n\n1. Create a SonarQube/SonarCloud account and project\n2. Add `SONAR_TOKEN` to your repository secrets\n3. Add `SONAR_HOST_URL` secret (for SonarQube Server)\n4. The IBM Sonar Cryptography plugin detects crypto usage\n\n**Resources:**\n- [IBM Sonar Cryptography Plugin](https://github.com/IBM/sonar-cryptography)\n- [SonarCloud Setup Guide](https://docs.sonarcloud.io/getting-started/github/)\n- [SonarQube GitHub Actions](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/ci-integration/github-actions/)', visibleWhen: { field: 'sonarEnabled', values: ['true'] } },
      { key: 'sonarProjectKey', label: 'Sonar Project Key', type: 'text', placeholder: 'org_project-key', required: false, helpText: 'Your SonarQube/SonarCloud project key', visibleWhen: { field: 'sonarEnabled', values: ['true'] } },

      // ── PQC Threshold ──
      { key: 'pqcThresholdEnabled', label: 'Enforce PQC readiness threshold', type: 'checkbox', required: false, defaultValue: 'false', helpText: 'Fail the workflow if post-quantum cryptography readiness is below the threshold' },
      { key: 'pqcThreshold', label: 'Minimum PQC-safe percentage', type: 'number', required: false, defaultValue: '80', placeholder: '80', min: 0, max: 100, suffix: '%', helpText: 'Workflow will fail if the percentage of quantum-safe components is below this value', visibleWhen: { field: 'pqcThresholdEnabled', values: ['true'] } },

      // ── Advanced Settings ──
      { key: '_advancedHeader', label: 'Advanced Settings', type: 'section-header', required: false, collapsed: true, helpText: 'Additional workflow customization options' },
      { key: 'excludePaths', label: 'Excluded Paths', type: 'tags', required: false, placeholder: 'e.g. vendor/**, test/**, docs/**', helpText: 'Glob patterns of files/directories to exclude from scanning' },
      { key: 'retentionDays', label: 'Artifact Retention (days)', type: 'number', required: false, defaultValue: '90', placeholder: '90', min: 1, max: 400, suffix: 'days', helpText: 'How long to keep the CBOM artifact in GitHub' },
      { key: 'failOnError', label: 'Fail workflow on scan errors', type: 'checkbox', required: false, defaultValue: 'true', helpText: 'If the scanner encounters errors, fail the workflow run' },
      { key: 'uploadToRelease', label: 'Attach CBOM to GitHub Releases', type: 'checkbox', required: false, defaultValue: 'false', helpText: 'Automatically attach the CBOM report to GitHub releases' },

      // ── Generate Workflow Button ──
      { key: 'workflowYaml', label: 'Generate Workflow YAML', type: 'generate-btn', required: false, helpText: 'Generate a ready-to-use GitHub Actions workflow based on your configuration' },
    ],
    scopeOptions: [
      { value: 'crypto-components', label: 'Crypto Components', description: 'Algorithms, protocols, and crypto primitives from CBOM' },
      { value: 'certificates',      label: 'Certificates',      description: 'Certificates referenced in the CBOM' },
      { value: 'keys',              label: 'Keys',              description: 'Key material and parameters in the CBOM' },
      { value: 'dependencies',      label: 'Dependencies',      description: 'Crypto library dependencies and versions' },
    ],
    defaultScope: ['crypto-components', 'certificates', 'keys', 'dependencies'],
  },
];

/* ═══════════════════════════════════════════════════════════════
   Schedule options
   ═══════════════════════════════════════════════════════════════ */

export const SCHEDULE_OPTIONS: { value: SyncSchedule; label: string }[] = [
  { value: 'manual', label: 'Manual only' },
  { value: '1h',     label: 'Every hour' },
  { value: '6h',     label: 'Every 6 hours' },
  { value: '12h',    label: 'Every 12 hours' },
  { value: '24h',    label: 'Every 24 hours' },
];
