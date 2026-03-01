// ══════════════════════════════════════════════════════════════
//  Discovery Module — Type Definitions
//  Types for all 5 integration-sourced discovery tabs
// ══════════════════════════════════════════════════════════════

export type DiscoveryTab =
  | 'certificates'
  | 'endpoints'
  | 'software'
  | 'devices'
  | 'cbom-imports';

// ── Tab metadata ─────────────────────────────────────────────

export interface TabDefinition {
  id: DiscoveryTab;
  label: string;
  sourceIntegration: string;
  /** Lucide icon name hint — actual icon component passed in orchestrator */
}

// ── Certificates (from DigiCert Trust Lifecycle Manager) ─────

export type CertificateStatus = 'Issued' | 'Expired' | 'Revoked' | 'Pending';

export interface DiscoveryCertificate {
  id: string;
  integrationId?: string | null;
  commonName: string;
  caVendor: string;
  status: CertificateStatus;
  keyAlgorithm: string;
  keyLength: string;
  quantumSafe: boolean;
  source: string;
  expiryDate?: string;
  serialNumber?: string;
  signatureAlgorithm?: string;
}

// ── Endpoints (from Network TLS Scanner) ─────────────────────

export interface DiscoveryEndpoint {
  id: string;
  integrationId?: string | null;
  hostname: string;
  ipAddress: string;
  port: number;
  tlsVersion: string;
  cipherSuite: string;
  keyAgreement: string;
  quantumSafe: boolean;
  source: string;
  lastScanned?: string;
  certCommonName?: string;
}

// ── Software (from DigiCert Software Trust Manager) ──────────
//    STM focuses on code-signing certs, signing keys, and
//    release-level cryptographic audit. Unlike CBOM imports
//    (which ingest pre-generated crypto inventories), STM
//    discovers signing infrastructure: which keys sign your
//    releases, what algorithms protect your software supply
//    chain, and whether those signing primitives are PQC-ready.

export interface DiscoverySoftware {
  id: string;
  integrationId?: string | null;
  name: string;
  version: string;
  vendor: string;
  signingAlgorithm: string;
  signingKeyLength: string;
  hashAlgorithm: string;
  cryptoLibraries: string[];
  quantumSafe: boolean;
  source: string;
  releaseDate?: string;
  sbomLinked?: boolean;
}

// ── Devices (from DigiCert Device Trust Manager) ─────────────

export type DeviceEnrollmentStatus = 'Enrolled' | 'Pending' | 'Revoked' | 'Expired';

export interface DiscoveryDevice {
  id: string;
  integrationId?: string | null;
  deviceName: string;
  deviceType: string;
  manufacturer: string;
  firmwareVersion: string;
  certAlgorithm: string;
  keyLength: string;
  quantumSafe: boolean;
  enrollmentStatus: DeviceEnrollmentStatus;
  lastCheckin: string;
  source: string;
  deviceGroup?: string;
}


// ── CBOM Imports (from CycloneDX CBOM File Import) ───────────
//    CBOM imports ingest pre-generated CycloneDX 1.6+ crypto
//    inventories from CI/CD pipelines or SBOM tools. These
//    contain full cryptographic component manifests — unlike
//    STM which discovers the *signing* infrastructure, CBOM
//    imports carry the complete crypto BOM of an application
//    (algorithms, protocols, certificates, keys) as declared
//    by the build/analysis toolchain.

export type CbomImportStatus = 'Processed' | 'Processing' | 'Failed' | 'Partial';

export interface DiscoveryCbomImport {
  id: string;
  integrationId?: string | null;
  fileName: string;
  format: string;
  specVersion: string;
  totalComponents: number;
  cryptoComponents: number;
  quantumSafeComponents: number;
  nonQuantumSafeComponents: number;
  conditionalComponents: number;
  importDate: string;
  status: CbomImportStatus;
  source: string;
  applicationName?: string;
  /** Base64-encoded artifact file (JSON or ZIP) — only present on single-item GET */
  cbomFile?: string;
  /** MIME type of the stored file: application/json or application/zip */
  cbomFileType?: string;
  /** Base64-encoded SBOM file — only present on single-item GET */
  sbomFile?: string;
  sbomFileType?: string;
  /** Base64-encoded xBOM file — only present on single-item GET */
  xbomFile?: string;
  xbomFileType?: string;
}

// ── Stat card config ─────────────────────────────────────────

export interface StatCardConfig {
  title: string;
  value: string | number;
  sub: string;
  variant: 'default' | 'success' | 'danger';
}
