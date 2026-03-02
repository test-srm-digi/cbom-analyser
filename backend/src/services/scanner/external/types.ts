/**
 * Types for external tool integrations.
 */

// ─── Tool Availability ──────────────────────────────────────────────────────

export interface ToolAvailability {
  codeql: boolean;
  cbomkitTheia: boolean;
  keytool: boolean;
  openssl: boolean;
}

// ─── SARIF Types (shared by CodeQL) ─────────────────────────────────────────

export interface SARIFResult {
  ruleId: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn?: number };
    };
  }>;
}

export interface SARIFRun {
  results: SARIFResult[];
}

export interface SARIFReport {
  runs: SARIFRun[];
}

// ─── cbomkit-theia Types ────────────────────────────────────────────────────

export interface CbomkitComponent {
  type: string;
  name: string;
  'crypto-properties'?: {
    assetType: string;
    algorithmProperties?: {
      algorithm?: string;
      primitive?: string;
      parameterSetIdentifier?: string;
    };
    certificateProperties?: {
      signatureAlgorithm?: string;
      subjectPublicKeyAlgorithm?: string;
      certificateFormat?: string;
      subjectName?: string;
      issuerName?: string;
    };
    oid?: string;
  };
  evidence?: {
    occurrences: Array<{
      location: string;
      line?: number;
    }>;
  };
}

export interface CbomkitOutput {
  components?: CbomkitComponent[];
}


