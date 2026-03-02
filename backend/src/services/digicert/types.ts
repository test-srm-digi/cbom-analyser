/**
 * DigiCert TLM Connector — Type Definitions
 */

/* ── Endpoint candidate for auto-detection ─────────────────── */

export interface CertEndpointCandidate {
  path: string;
  method: 'GET' | 'POST';
}

/* ── DigiCert API response types ──────────────────────────── */

export interface DigiCertCertificate {
  id?: string;
  serial_number?: string;
  common_name?: string;
  status?: string;                // ISSUED, EXPIRED, REVOKED, PENDING, etc.
  valid_till?: string;           // ISO date
  valid_from?: string;
  signature_algorithm?: string;   // e.g. "sha256WithRSAEncryption"
  key_type?: string;             // e.g. "RSA", "EC"
  key_size?: number;             // e.g. 2048
  key_curve?: string;            // e.g. "P-256"
  issuer?: string;
  thumbprint?: string;
  subject?: string;
  /* The actual shape varies between CertCentral and MPKI; we handle both */
  [key: string]: unknown;
}

export interface DigiCertListResponse {
  /* MPKI returns array directly or { items: [] } */
  items?: DigiCertCertificate[];
  total?: number;
  offset?: number;
  limit?: number;
  [key: string]: unknown;
}

export interface DigiCertUserResponse {
  id?: string;
  email?: string;
  [key: string]: unknown;
}

export interface DetectedEndpoint {
  path: string;
  method: 'GET' | 'POST';
  response: DigiCertListResponse | DigiCertCertificate[];
}
