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
    scopeOptions: [
      { value: 'crypto-components', label: 'Crypto Components', description: 'Algorithms, protocols, and crypto primitives from CBOM' },
      { value: 'certificates',      label: 'Certificates',      description: 'Certificates referenced in the CBOM' },
      { value: 'keys',              label: 'Keys',              description: 'Key material and parameters in the CBOM' },
      { value: 'dependencies',      label: 'Dependencies',      description: 'Crypto library dependencies and versions' },
    ],
    defaultScope: ['crypto-components', 'certificates', 'keys', 'dependencies'],
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
    scopeOptions: [
      { value: 'crypto-api-calls', label: 'Crypto API Calls',   description: 'Detect cryptographic function calls in source code' },
      { value: 'dependencies',     label: 'Dependencies',       description: 'Crypto library imports and version tracking' },
      { value: 'key-cert-files',   label: 'Key & Cert Files',   description: 'Certificate and key files in the repository' },
      { value: 'configurations',   label: 'Configurations',     description: 'Crypto-related config files (TLS, SSH, etc.)' },
    ],
    defaultScope: ['crypto-api-calls', 'dependencies', 'key-cert-files', 'configurations'],
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
