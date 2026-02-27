/**
 * Integration Connectors — Per-type data fetchers
 *
 * Each connector knows how to pull data from its external source
 * and return normalized records ready for bulk insert into the
 * corresponding discovery table.
 *
 * ARCHITECTURE NOTE:
 * ──────────────────
 * In production, each connector would:
 *   1. Read the integration's `config` (API keys, URLs, tokens)
 *   2. Make HTTP calls to the external API (DigiCert ONE, GitHub, etc.)
 *   3. Transform the vendor-specific response into our normalized schema
 *   4. Return the records for the SyncExecutor to persist
 *
 * Currently all connectors return **simulated data** so the full
 * scheduler pipeline can be exercised end-to-end without real
 * external credentials.  Replace the body of each `fetch*()` method
 * with real HTTP calls when the external APIs are available.
 */
import { v4 as uuidv4 } from 'uuid';

/* ── Shared types ──────────────────────────────────────────── */

export interface ConnectorResult<T> {
  success: boolean;
  data: T[];
  errors: string[];
  /** Metadata about the fetch (duration, pagination, etc.) */
  meta?: Record<string, unknown>;
}

export interface ConnectorConfig {
  apiBaseUrl?: string;
  apiKey?: string;
  accountId?: string;
  organizationId?: string;
  token?: string;
  [key: string]: string | undefined;
}

/* ── Helper: random pick from array ────────────────────────── */

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pastDate(daysAgo: number): string {
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  return d.toISOString();
}

function futureDate(daysAhead: number): string {
  const d = new Date();
  d.setDate(d.getDate() + daysAhead);
  return d.toISOString();
}

/* ══════════════════════════════════════════════════════════════
 *  1. DigiCert TLM — Certificate Connector
 * ══════════════════════════════════════════════════════════════ */

export async function fetchCertificates(
  _config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const algorithms = ['RSA', 'ECDSA', 'Ed25519', 'ML-DSA'];
  const keyLengths: Record<string, string[]> = {
    RSA: ['2048', '3072', '4096'],
    ECDSA: ['P-256', 'P-384'],
    Ed25519: ['256'],
    'ML-DSA': ['ML-DSA-65', 'ML-DSA-87'],
  };
  const statuses = ['Issued', 'Expired', 'Revoked', 'Pending'] as const;
  const vendors = ['DigiCert', 'Let\'s Encrypt', 'Sectigo', 'GlobalSign'];
  const sigAlgs = ['SHA256withRSA', 'SHA384withECDSA', 'Ed25519', 'ML-DSA-65'];

  const count = randInt(5, 25);
  const data: Record<string, unknown>[] = [];

  for (let i = 0; i < count; i++) {
    const algo = pick(algorithms);
    const kl = pick(keyLengths[algo]);
    data.push({
      id: uuidv4(),
      integrationId,
      commonName: `${pick(['www', 'api', 'mail', 'cdn', 'auth', '*.internal'])}.${pick(['example.com', 'corp.net', 'secure.io', 'acme.dev'])}`,
      caVendor: pick(vendors),
      status: pick([...statuses]),
      keyAlgorithm: algo,
      keyLength: kl,
      quantumSafe: ['Ed25519', 'ML-DSA'].includes(algo),
      source: 'DigiCert TLM',
      expiryDate: pick([...statuses]) === 'Expired' ? pastDate(randInt(1, 90)) : futureDate(randInt(30, 365)),
      serialNumber: uuidv4().replace(/-/g, '').substring(0, 20).toUpperCase(),
      signatureAlgorithm: pick(sigAlgs),
    });
  }

  return { success: true, data, errors: [] };
}

/* ══════════════════════════════════════════════════════════════
 *  2. Network Scanner — Endpoint Connector
 * ══════════════════════════════════════════════════════════════ */

export async function fetchEndpoints(
  _config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const tlsVersions = ['TLS 1.2', 'TLS 1.3'];
  const cipherSuites = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
  ];
  const keyAgreements = ['ECDHE', 'X25519', 'ML-KEM-768', 'X448'];

  const count = randInt(5, 20);
  const data: Record<string, unknown>[] = [];

  for (let i = 0; i < count; i++) {
    const ka = pick(keyAgreements);
    data.push({
      id: uuidv4(),
      integrationId,
      hostname: `${pick(['web', 'api', 'db', 'cache', 'proxy', 'lb'])}-${randInt(1, 99)}.${pick(['prod', 'staging', 'dev'])}.internal`,
      ipAddress: `10.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
      port: pick([443, 8443, 636, 993, 5432]),
      tlsVersion: pick(tlsVersions),
      cipherSuite: pick(cipherSuites),
      keyAgreement: ka,
      quantumSafe: ['ML-KEM-768'].includes(ka),
      source: 'Network Scanner',
      lastScanned: new Date().toISOString(),
      certCommonName: `*.${pick(['prod', 'staging', 'dev'])}.internal`,
    });
  }

  return { success: true, data, errors: [] };
}

/* ══════════════════════════════════════════════════════════════
 *  3. DigiCert STM — Software Connector
 * ══════════════════════════════════════════════════════════════ */

export async function fetchSoftware(
  _config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const names = ['CoreService', 'AuthLib', 'PaymentSDK', 'DataPipeline', 'MobileApp', 'DesktopClient', 'FirmwareUpdater', 'CLITool'];
  const vendors = ['Acme Corp', 'Internal', 'TechPartner', 'OpenSource'];
  const sigAlgs = ['RSA-SHA256', 'ECDSA-SHA384', 'Ed25519', 'ML-DSA-65'];
  const hashAlgs = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256'];
  const libs = ['OpenSSL', 'BouncyCastle', 'libsodium', 'WolfSSL', 'NSS'];

  const count = randInt(3, 12);
  const data: Record<string, unknown>[] = [];

  for (let i = 0; i < count; i++) {
    const sigAlg = pick(sigAlgs);
    data.push({
      id: uuidv4(),
      integrationId,
      name: pick(names),
      version: `${randInt(1, 5)}.${randInt(0, 15)}.${randInt(0, 99)}`,
      vendor: pick(vendors),
      signingAlgorithm: sigAlg,
      signingKeyLength: sigAlg.includes('RSA') ? pick(['2048', '4096']) : pick(['P-256', 'Ed25519', 'ML-DSA-65']),
      hashAlgorithm: pick(hashAlgs),
      cryptoLibraries: [pick(libs), ...(Math.random() > 0.5 ? [pick(libs)] : [])],
      quantumSafe: ['Ed25519', 'ML-DSA-65'].includes(sigAlg),
      source: 'DigiCert STM',
      releaseDate: pastDate(randInt(1, 180)),
      sbomLinked: Math.random() > 0.4,
    });
  }

  return { success: true, data, errors: [] };
}

/* ══════════════════════════════════════════════════════════════
 *  4. DigiCert DTM — Device Connector
 * ══════════════════════════════════════════════════════════════ */

export async function fetchDevices(
  _config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const deviceNames = ['GW', 'Sensor', 'Controller', 'Actuator', 'Gateway', 'Edge-Node', 'Camera'];
  const deviceTypes = ['Gateway', 'Sensor', 'Controller', 'Edge Device', 'Camera', 'Actuator'];
  const manufacturers = ['Siemens', 'Honeywell', 'ABB', 'Schneider', 'Bosch', 'GE'];
  const certAlgos = ['RSA', 'ECDSA', 'Ed25519', 'ML-DSA'];
  const statuses = ['Enrolled', 'Pending', 'Revoked', 'Expired'] as const;
  const groups = ['Floor-1', 'Floor-2', 'Outdoor', 'Warehouse', 'HVAC', null];

  const count = randInt(5, 15);
  const data: Record<string, unknown>[] = [];

  for (let i = 0; i < count; i++) {
    const algo = pick(certAlgos);
    data.push({
      id: uuidv4(),
      integrationId,
      deviceName: `${pick(deviceNames)}-${randInt(100, 999)}`,
      deviceType: pick(deviceTypes),
      manufacturer: pick(manufacturers),
      firmwareVersion: `${randInt(1, 4)}.${randInt(0, 9)}.${randInt(0, 20)}`,
      certAlgorithm: algo,
      keyLength: algo === 'RSA' ? pick(['2048', '4096']) : pick(['P-256', 'Ed25519', 'ML-DSA-65']),
      quantumSafe: ['Ed25519', 'ML-DSA'].includes(algo),
      enrollmentStatus: pick([...statuses]),
      lastCheckin: pastDate(randInt(0, 14)),
      source: 'DigiCert DTM',
      deviceGroup: pick(groups),
    });
  }

  return { success: true, data, errors: [] };
}

/* ══════════════════════════════════════════════════════════════
 *  6. CBOM Import Connector
 * ══════════════════════════════════════════════════════════════ */

/** Algorithm pools used to generate realistic CBOM content */
const QS_ALGORITHMS = [
  { name: 'ML-KEM-768',        assetType: 'algorithm', primitive: 'key-encapsulation', fn: 'key-exchange' },
  { name: 'ML-DSA-65',         assetType: 'algorithm', primitive: 'signature',          fn: 'sign' },
  { name: 'SLH-DSA-SHA2-128s', assetType: 'algorithm', primitive: 'signature',          fn: 'sign' },
  { name: 'AES-256-GCM',       assetType: 'algorithm', primitive: 'block-cipher',       fn: 'encrypt' },
  { name: 'SHA-3-256',         assetType: 'algorithm', primitive: 'hash',               fn: 'hash-function' },
  { name: 'SHA-256',           assetType: 'algorithm', primitive: 'hash',               fn: 'hash-function' },
  { name: 'SHA-384',           assetType: 'algorithm', primitive: 'hash',               fn: 'hash-function' },
  { name: 'SHAKE-256',         assetType: 'algorithm', primitive: 'hash',               fn: 'digest' },
];

const NON_QS_ALGORITHMS = [
  { name: 'RSA-2048',          assetType: 'algorithm', primitive: 'pke',                fn: 'encrypt' },
  { name: 'ECDSA-P256',        assetType: 'algorithm', primitive: 'signature',          fn: 'sign' },
  { name: 'ECDH-P256',         assetType: 'algorithm', primitive: 'key-agreement',      fn: 'key-exchange' },
  { name: 'AES-128-CBC',       assetType: 'algorithm', primitive: 'block-cipher',       fn: 'encrypt' },
  { name: 'HMAC-SHA-256',      assetType: 'algorithm', primitive: 'mac',                fn: 'tag' },
  { name: 'RSA-4096',          assetType: 'algorithm', primitive: 'signature',          fn: 'sign' },
  { name: 'DES-EDE3',          assetType: 'algorithm', primitive: 'block-cipher',       fn: 'encrypt' },
  { name: 'MD5',               assetType: 'algorithm', primitive: 'hash',               fn: 'digest' },
  { name: 'SHA-1',             assetType: 'algorithm', primitive: 'hash',               fn: 'hash-function' },
  { name: 'ChaCha20-Poly1305', assetType: 'algorithm', primitive: 'ae',                fn: 'encrypt' },
];

const JAVA_FILES = [
  'AbstractIdentityProvider.java', 'KeycloakModelUtils.java', 'PkceUtils.java',
  'TokenVerifier.java', 'MutualTLSUtils.java', 'OIDCLoginProtocol.java',
  'S256CodeChallenge.java', 'LegacyHashProvider.java', 'CryptoProvider.java',
  'SSLContextFactory.java', 'JWKParser.java', 'KeyWrapper.java',
  'JWETokenProcessor.java', 'PBKDF2PasswordHashProvider.java', 'HmacUtil.java',
];

function buildCbomContent(
  appName: string,
  qsSafe: number,
  nonQsSafe: number,
  totalCrypto: number,
): Buffer {
  const cryptoAssets: Record<string, unknown>[] = [];

  // Quantum-safe assets
  for (let i = 0; i < qsSafe; i++) {
    const algo = QS_ALGORITHMS[i % QS_ALGORITHMS.length];
    cryptoAssets.push({
      id: `asset-qs-${i + 1}`,
      name: algo.name,
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: algo.assetType,
        algorithmProperties: {
          primitive: algo.primitive,
          cryptoFunctions: [algo.fn],
        },
      },
      location: { fileName: pick(JAVA_FILES), lineNumber: randInt(10, 500) },
      quantumSafety: 'quantum-safe',
      detectionSource: pick(['sonar', 'regex']),
    });
  }

  // Non-quantum-safe assets
  for (let i = 0; i < nonQsSafe; i++) {
    const algo = NON_QS_ALGORITHMS[i % NON_QS_ALGORITHMS.length];
    cryptoAssets.push({
      id: `asset-nqs-${i + 1}`,
      name: algo.name,
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: algo.assetType,
        algorithmProperties: {
          primitive: algo.primitive,
          cryptoFunctions: [algo.fn],
        },
      },
      location: { fileName: pick(JAVA_FILES), lineNumber: randInt(10, 500) },
      quantumSafety: 'not-quantum-safe',
      detectionSource: pick(['sonar', 'regex']),
    });
  }

  // Unknown assets (fill remainder)
  const unknownCount = totalCrypto - qsSafe - nonQsSafe;
  for (let i = 0; i < unknownCount; i++) {
    const pool = [...QS_ALGORITHMS, ...NON_QS_ALGORITHMS];
    const algo = pool[i % pool.length];
    cryptoAssets.push({
      id: `asset-unk-${i + 1}`,
      name: algo.name,
      type: 'crypto-asset',
      cryptoProperties: {
        assetType: algo.assetType,
        algorithmProperties: {
          primitive: algo.primitive,
          cryptoFunctions: [algo.fn],
        },
      },
      location: { fileName: pick(JAVA_FILES), lineNumber: randInt(10, 500) },
      quantumSafety: 'unknown',
      detectionSource: 'regex',
    });
  }

  const cbom = {
    bomFormat: 'CycloneDX',
    specVersion: pick(['1.6', '1.7']),
    serialNumber: `urn:uuid:${uuidv4()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        { vendor: 'QuantumGuard', name: 'CBOM Hub', version: '2.0.0' },
        { vendor: 'IBM', name: 'sonar-cryptography', version: '1.4.0' },
      ],
      component: {
        name: appName,
        type: 'application',
      },
    },
    components: [],
    cryptoAssets,
  };

  return Buffer.from(JSON.stringify(cbom), 'utf-8');
}

export async function fetchCbomImports(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  // ── Real GitHub Actions mode ──
  if (config.githubRepo && config.githubToken) {
    const { fetchCbomImportsFromGitHub } = await import('./githubCbomConnector');
    return fetchCbomImportsFromGitHub(config, integrationId);
  }

  // ── Simulated data mode (dev / demo — no GitHub credentials) ──
  const apps = ['Keycloak', 'Spring Petclinic', 'Node API Gateway', 'Python ML Service', 'Go Microservice'];
  const formats = ['CycloneDX', 'CycloneDX'];
  const versions = ['1.6', '1.7'];
  const statuses = ['Processed', 'Processing', 'Failed', 'Partial'] as const;

  const count = randInt(2, 8);
  const data: Record<string, unknown>[] = [];

  for (let i = 0; i < count; i++) {
    const total = randInt(10, 80);
    const crypto = randInt(5, total);
    const qsSafe = randInt(0, crypto);
    const nonQsSafe = crypto - qsSafe;
    const appName = pick(apps);
    data.push({
      id: uuidv4(),
      integrationId,
      fileName: `${appName.toLowerCase().replace(/ /g, '-')}-cbom-${randInt(1, 99)}.json`,
      format: pick(formats),
      specVersion: pick(versions),
      totalComponents: total,
      cryptoComponents: crypto,
      quantumSafeComponents: qsSafe,
      nonQuantumSafeComponents: nonQsSafe,
      importDate: new Date().toISOString(),
      status: pick([...statuses]),
      source: 'CBOM Import',
      applicationName: appName,
      cbomFile: buildCbomContent(appName, qsSafe, nonQsSafe, crypto),
      cbomFileType: 'application/json',
    });
  }

  return { success: true, data, errors: [] };
}

/* ── Connector registry ────────────────────────────────────── */

/**
 * Maps integration templateType → connector function.
 * Each connector returns records appropriate for its discovery table.
 */
export const CONNECTOR_REGISTRY: Record<
  string,
  {
    fetch: (config: ConnectorConfig, integrationId: string) => Promise<ConnectorResult<Record<string, unknown>>>;
    /** Sequelize model name to bulkCreate into */
    model: string;
    /** Human-readable label */
    label: string;
  }
> = {
  'digicert-tlm': { fetch: fetchCertificates, model: 'Certificate', label: 'DigiCert TLM (Certificates)' },
  'network-scanner': { fetch: fetchEndpoints, model: 'Endpoint', label: 'Network Scanner (Endpoints)' },
  'digicert-stm': { fetch: fetchSoftware, model: 'Software', label: 'DigiCert STM (Software)' },
  'digicert-dtm': { fetch: fetchDevices, model: 'Device', label: 'DigiCert DTM (Devices)' },
  'cbom-import': { fetch: fetchCbomImports, model: 'CbomImport', label: 'CBOM Import' },
};
