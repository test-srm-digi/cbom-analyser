/**
 * DigiCert TLM Connector — Type Definitions
 */

/* ── Endpoint candidate for auto-detection ─────────────────── */

export interface CertEndpointCandidate {
  path: string;
  method: 'GET' | 'POST';
  /** When true, account must be passed as a query param (ui-api routes) */
  accountInQuery?: boolean;
  /** Additional query params to include (e.g. status, unique_certificate_view) */
  extraParams?: Record<string, string>;
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
  /** When true, account must be passed as a query param instead of header */
  accountInQuery?: boolean;
  /** Additional query params to include on every page request */
  extraParams?: Record<string, string>;
}

/* ── DigiCert Endpoint (inventory) types ──────────────────── */

export interface DigiCertEndpoint {
  id?: string;
  common_name?: string;
  hostname?: string;
  ip?: string;
  ip_address?: string;
  port?: number;
  tls_version?: string;
  protocol_version?: string;
  cipher_suite?: string;
  tls_cipher_suite?: string;
  key_algorithm?: string;
  certificate_key_algorithm?: string;
  certificate_common_name?: string;
  last_scan_date?: string;
  last_checked?: string;
  status?: string;
  [key: string]: unknown;
}

export interface DigiCertEndpointListResponse {
  items?: DigiCertEndpoint[];
  total?: number;
  offset?: number;
  limit?: number;
  [key: string]: unknown;
}
