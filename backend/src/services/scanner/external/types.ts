/**
 * Types for external tool integrations.
 */

// ─── Tool Availability ──────────────────────────────────────────────────────

export interface ToolAvailability {
  cbomkitTheia: boolean;
  keytool: boolean;
  openssl: boolean;
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


