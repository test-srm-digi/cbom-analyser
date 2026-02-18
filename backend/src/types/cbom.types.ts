/**
 * CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Type Definitions
 *
 * Based on the CycloneDX ECMA standard with cryptographic extensions.
 * @see https://cyclonedx.org/
 * @see https://github.com/IBM/CBOM
 */

// ─── Enums ───────────────────────────────────────────────────────────────────

export enum QuantumSafetyStatus {
  QUANTUM_SAFE = 'quantum-safe',
  NOT_QUANTUM_SAFE = 'not-quantum-safe',
  UNKNOWN = 'unknown',
}

export enum CryptoPrimitive {
  HASH = 'hash',
  BLOCK_CIPHER = 'block-cipher',
  STREAM_CIPHER = 'stream-cipher',
  MAC = 'mac',
  SIGNATURE = 'signature',
  KEY_ENCAPSULATION = 'key-encapsulation',
  KEY_AGREEMENT = 'key-agreement',
  KEY_DERIVATION = 'key-derivation',
  KEYGEN = 'keygen',
  DIGEST = 'digest',
  PKE = 'pke',
  AE = 'ae',
  OTHER = 'other',
}

export enum CryptoFunction {
  HASH_FUNCTION = 'Hash Function',
  KEYGEN = 'Keygen',
  ENCRYPT = 'Encrypt',
  DECRYPT = 'Decrypt',
  SIGN = 'Sign',
  VERIFY = 'Verify',
  KEY_EXCHANGE = 'Key Exchange',
  DIGEST = 'Digest',
  TAG = 'Tag',
  OTHER = 'Other',
}

export enum AssetType {
  ALGORITHM = 'algorithm',
  PROTOCOL = 'protocol',
  CERTIFICATE = 'certificate',
  RELATED_MATERIAL = 'related-crypto-material',
}

export enum ComplianceStatus {
  COMPLIANT = 'compliant',
  NOT_COMPLIANT = 'not-compliant',
  UNKNOWN = 'unknown',
}

// ─── Core Interfaces ─────────────────────────────────────────────────────────

export interface CryptoLocation {
  fileName: string;
  lineNumber?: number;
  className?: string;
  methodName?: string;
}

export interface AlgorithmProperties {
  primitive: CryptoPrimitive;
  parameterSetIdentifier?: string;
  curve?: string;
  executionEnvironment?: string;
  implementationPlatform?: string;
  certificationLevel?: string[];
  mode?: string;
  padding?: string;
  cryptoFunctions?: CryptoFunction[];
}

export interface ProtocolProperties {
  type: string;
  version: string;
  cipherSuites?: CipherSuite[];
}

export interface CipherSuite {
  name: string;
  algorithms?: string[];
  identifiers?: string[];
}

export interface CertificateProperties {
  subjectName?: string;
  issuerName?: string;
  notValidBefore?: string;
  notValidAfter?: string;
  signatureAlgorithm?: string;
  subjectPublicKeyAlgorithm?: string;
  certificateFormat?: string;
  certificateExtension?: string;
}

export interface RelatedCryptoMaterialProperties {
  type: string;
  id?: string;
  state?: string;
  size?: number;
  algorithmRef?: string;
  securedBy?: {
    mechanism: string;
    algorithmRef?: string;
  };
}

export interface CryptoProperties {
  assetType: AssetType;
  algorithmProperties?: AlgorithmProperties;
  protocolProperties?: ProtocolProperties;
  certificateProperties?: CertificateProperties;
  relatedCryptoMaterialProperties?: RelatedCryptoMaterialProperties;
  oid?: string;
}

// ─── Crypto Asset ────────────────────────────────────────────────────────────

export interface CryptoAsset {
  id: string;
  name: string;
  type: string;
  version?: string;
  description?: string;
  cryptoProperties: CryptoProperties;
  location?: CryptoLocation;
  quantumSafety: QuantumSafetyStatus;
  keyLength?: number;
  recommendedPQC?: string;
  complianceStatus?: ComplianceStatus;
  provider?: string;
}

// ─── CBOM Component ──────────────────────────────────────────────────────────

export interface CBOMComponent {
  name: string;
  version?: string;
  type: string;
  group?: string;
  description?: string;
  purl?: string;
}

// ─── Dependency Mapping ──────────────────────────────────────────────────────

export interface CryptoDependency {
  ref: string;
  dependsOn: string[];
}

// ─── CBOM Metadata ───────────────────────────────────────────────────────────

export interface CBOMMetadata {
  timestamp: string;
  tools?: CBOMTool[];
  component?: CBOMComponent;
  authors?: CBOMAuthor[];
}

export interface CBOMTool {
  vendor: string;
  name: string;
  version: string;
}

export interface CBOMAuthor {
  name: string;
  email?: string;
}

// ─── Full CBOM Document ──────────────────────────────────────────────────────

export interface CBOMDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.6';
  serialNumber?: string;
  version: number;
  metadata: CBOMMetadata;
  components: CBOMComponent[];
  cryptoAssets: CryptoAsset[];
  dependencies?: CryptoDependency[];
}

// ─── Dashboard Aggregated Types ──────────────────────────────────────────────

export interface QuantumReadinessScore {
  score: number; // 0-100
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  unknown: number;
}

export interface PrimitiveDistribution {
  primitive: string;
  count: number;
  percentage: number;
}

export interface ComplianceSummary {
  isCompliant: boolean;
  policy: string;
  source: string;
  totalAssets: number;
  compliantAssets: number;
  nonCompliantAssets: number;
  unknownAssets: number;
}

export interface NetworkScanResult {
  name: string;
  type: 'network-service';
  protocol: string;
  cipherSuite: string;
  version: string;
  isQuantumSafe: boolean;
  lastScanned: string;
  host: string;
  port: number;
}

// ─── API Request/Response Types ──────────────────────────────────────────────

export interface UploadResponse {
  success: boolean;
  message: string;
  cbom?: CBOMDocument;
  readinessScore?: QuantumReadinessScore;
  compliance?: ComplianceSummary;
}

export interface NetworkScanRequest {
  url: string;
  port?: number;
}

export interface NetworkScanResponse {
  success: boolean;
  result?: NetworkScanResult;
  cbomAsset?: CryptoAsset;
  error?: string;
}

export interface ScanCodeRequest {
  repoPath: string;
  language?: 'java' | 'python';
  /** Glob patterns to exclude from scanning (e.g., test directories, spec files) */
  excludePatterns?: string[];
}

/** Default patterns to exclude test files */
export const DEFAULT_EXCLUDE_PATTERNS = [
  '**/test/**',
  '**/tests/**',
  '**/__tests__/**',
  '**/*.test.ts',
  '**/*.test.js',
  '**/*.test.tsx',
  '**/*.test.jsx',
  '**/*.spec.ts',
  '**/*.spec.js',
  '**/*.spec.tsx',
  '**/*.spec.jsx',
  '**/Test.java',
  '**/*Test.java',
  '**/*Tests.java',
  '**/test_*.py',
  '**/*_test.py',
];

export interface ScanCodeResponse {
  success: boolean;
  cbom?: CBOMDocument;
  error?: string;
}
