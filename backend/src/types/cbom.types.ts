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
 * CycloneDX 1.6 Related Crypto Material sub-types
 * @see CycloneDX 1.6 CBOM specification
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
 * PQC Readiness Verdict — definitive assessment beyond just quantum safety status.
 * Used for assets like PBKDF2 where the verdict depends on actual parameters.
 */
export enum PQCReadinessVerdict {
  PQC_READY = 'pqc-ready',
  NOT_PQC_READY = 'not-pqc-ready',
  REVIEW_NEEDED = 'review-needed',
}

/**
 * Detailed analysis of why an asset received a particular PQC verdict.
 */
export interface PQCVerdictDetail {
  verdict: PQCReadinessVerdict;
  confidence: number;       // 0-100
  reasons: string[];        // Human-readable list of rationale items
  parameters?: Record<string, string | number | boolean>; // Extracted config (iterations, keyLength, etc.)
  recommendation?: string;  // Actionable next step
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
  type: RelatedCryptoMaterialType;
  id?: string;
  state?: string;
  size?: number;
  algorithmRef?: string;
  securedBy?: {
    mechanism: string;
    algorithmRef?: string;
  };
  format?: string;
  value?: string;                     // Only for non-sensitive material (e.g., salt, IV, nonce)
  creationDate?: string;
  activationDate?: string;
  expirationDate?: string;
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
  /** Definitive PQC readiness verdict based on actual parameter analysis */
  pqcVerdict?: PQCVerdictDetail;
  /** Source of detection: sonar, regex, dependency, network */
  detectionSource?: 'sonar' | 'regex' | 'dependency' | 'network';
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

/**
 * CycloneDX 1.6 dependency relationships.
 * - dependsOn: this component depends on the listed refs
 * - provides: this component provides/exposes the listed refs
 */
export interface CryptoDependency {
  ref: string;
  dependsOn: string[];
  provides?: string[];
}

// ─── Third-Party Crypto Library ──────────────────────────────────────────────

export interface ThirdPartyCryptoLibrary {
  name: string;
  groupId?: string;        // e.g. org.bouncycastle
  artifactId?: string;     // e.g. bcprov-jdk18on
  version?: string;
  packageManager: 'maven' | 'gradle' | 'npm' | 'pip' | 'go';
  cryptoAlgorithms: string[];     // Algorithms this library is known to provide
  quantumSafety: QuantumSafetyStatus;
  isDirectDependency: boolean;    // true = direct, false = transitive
  depth: number;                  // 0 = direct dep, 1 = transitive dep of direct, etc.
  dependencyPath?: string[];      // e.g. ['my-app', 'spring-security', 'bcprov']
  manifestFile: string;           // e.g. 'pom.xml', 'build.gradle'
  lineNumber?: number;            // Line in manifest where the dependency is declared
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
  /** Third-party libraries detected from dependency manifests (pom.xml, package.json, etc.) */
  thirdPartyLibraries?: ThirdPartyCryptoLibrary[];
}

// ─── Dashboard Aggregated Types ──────────────────────────────────────────────

export interface QuantumReadinessScore {
  score: number; // 0-100
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  conditional: number;
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
