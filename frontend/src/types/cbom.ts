/**
 * Frontend CBOM Types (mirrors backend CycloneDX 1.7 types)
 */

export enum QuantumSafetyStatus {
  QUANTUM_SAFE = 'quantum-safe',
  NOT_QUANTUM_SAFE = 'not-quantum-safe',
  CONDITIONAL = 'conditional',
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

export enum ComplianceStatus {
  COMPLIANT = 'compliant',
  NOT_COMPLIANT = 'not-compliant',
  UNKNOWN = 'unknown',
}

/**
 * CycloneDX 1.7 Asset Types — full taxonomy
 */
export enum AssetType {
  ALGORITHM = 'algorithm',
  PROTOCOL = 'protocol',
  CERTIFICATE = 'certificate',
  RELATED_MATERIAL = 'related-crypto-material',
  PRIVATE_KEY = 'private-key',
  PUBLIC_KEY = 'public-key',
  SECRET_KEY = 'secret-key',
}

/**
 * CycloneDX 1.7 Related Crypto Material sub-types
 */
export enum RelatedCryptoMaterialType {
  PUBLIC_KEY = 'public-key',
  PRIVATE_KEY = 'private-key',
  SECRET_KEY = 'secret-key',
  KEY = 'key',
  SALT = 'salt',
  CREDENTIAL = 'credential',
  PASSWORD = 'password',
  CIPHERTEXT = 'ciphertext',
  DIGEST = 'digest',
  SHARED_SECRET = 'shared-secret',
  TOKEN = 'token',
  SIGNATURE = 'signature',
  SEED = 'seed',
  INITIALIZATION_VECTOR = 'initialization-vector',
  TAG = 'tag',
  ADDITIONAL_DATA = 'additional-data',
  NONCE = 'nonce',
  OTHER = 'other',
}

/**
 * PQC Readiness Verdict — definitive assessment
 */
export enum PQCReadinessVerdict {
  PQC_READY = 'pqc-ready',
  NOT_PQC_READY = 'not-pqc-ready',
  REVIEW_NEEDED = 'review-needed',
}

export interface PQCVerdictDetail {
  verdict: PQCReadinessVerdict;
  confidence: number;
  reasons: string[];
  parameters?: Record<string, string | number | boolean>;
  recommendation?: string;
}

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
  mode?: string;
  padding?: string;
  cryptoFunctions?: CryptoFunction[];
}

export interface ProtocolProperties {
  type: string;
  version: string;
  cipherSuites?: { name: string; algorithms?: string[] }[];
}

export interface CryptoProperties {
  assetType: string;
  algorithmProperties?: AlgorithmProperties;
  protocolProperties?: ProtocolProperties;
  oid?: string;
}

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
  suggestedFix?: string;
  complianceStatus?: ComplianceStatus;
  provider?: string;
  /** Definitive PQC readiness verdict */
  pqcVerdict?: PQCVerdictDetail;
  /** Detection source */
  detectionSource?: 'sonar' | 'regex' | 'dependency' | 'network';
}

export interface CBOMComponent {
  name: string;
  version?: string;
  type: string;
  group?: string;
}

export interface CBOMRepository {
  url: string;
  branch?: string;
}

export interface CBOMMetadata {
  timestamp: string;
  tools?: { vendor: string; name: string; version: string }[];
  component?: CBOMComponent;
  repository?: CBOMRepository;
}

export interface CryptoDependency {
  ref: string;
  dependsOn: string[];
  provides?: string[];
}

export interface ThirdPartyCryptoLibrary {
  name: string;
  groupId?: string;
  artifactId?: string;
  version?: string;
  packageManager: 'maven' | 'gradle' | 'npm' | 'pip' | 'go';
  cryptoAlgorithms: string[];
  quantumSafety: QuantumSafetyStatus;
  isDirectDependency: boolean;
  depth: number;
  dependencyPath?: string[];
  manifestFile: string;
}

export interface CBOMDocument {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  version: number;
  metadata: CBOMMetadata;
  components: CBOMComponent[];
  cryptoAssets: CryptoAsset[];
  dependencies?: CryptoDependency[];
  thirdPartyLibraries?: ThirdPartyCryptoLibrary[];
}

export interface QuantumReadinessScore {
  score: number;
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  conditional: number;
  unknown: number;
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

export interface UploadResponse {
  success: boolean;
  message: string;
  cbom?: CBOMDocument;
  readinessScore?: QuantumReadinessScore;
  compliance?: ComplianceSummary;
}

export interface NetworkScanResult {
  name: string;
  type: string;
  protocol: string;
  cipherSuite: string;
  version: string;
  isQuantumSafe: boolean;
  lastScanned: string;
  host: string;
  port: number;
}

// ─── Chart data types ────────────────────────────────────────────────────────

export interface DonutChartData {
  name: string;
  value: number;
  color: string;
}

export interface BubbleData {
  name: string;
  value: number;
  x: number;
  y: number;
  z: number;
}

export interface PrimitiveDistribution {
  primitive: string;
  count: number;
  percentage: number;
}
