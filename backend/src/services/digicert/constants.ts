/**
 * DigiCert TLM Connector — Constants
 */
import type { CertEndpointCandidate } from './types';

export const PAGE_SIZE = 100;
export const MAX_PAGES = 50;          // safety cap → max 5 000 certs per sync
export const REQUEST_TIMEOUT = 30_000; // 30 s

/**
 * Well-known DigiCert ONE API paths for certificate listing,
 * tried in order when no explicit `apiPath` is configured.
 * On-prem clusters may only have a subset of micro-services deployed.
 *
 * Entries marked `method: 'POST'` use a JSON request body for
 * pagination (`{ offset, limit }`) — this is the primary listing
 * mechanism exposed by DigiCert ONE micro-services.
 */
export const CERTIFICATE_API_PATHS: CertEndpointCandidate[] = [
  // POST search endpoints (preferred — most DigiCert ONE deployments)
  { path: 'mpki/api/v1/certificate/search',        method: 'POST' },
  { path: 'em/api/v1/certificate/search',           method: 'POST' },
  { path: 'tlm/api/v1/certificate/search',          method: 'POST' },
  // GET collection endpoints (classic / CertCentral)
  { path: 'mpki/api/v1/certificate',                method: 'GET'  },
  { path: 'em/api/v1/certificate',                  method: 'GET'  },
  { path: 'tlm/api/v1/certificate',                 method: 'GET'  },
  { path: 'certcentral/api/v1/certificate',          method: 'GET'  },
  // CertCentral v2
  { path: 'services/v2/order/certificate',           method: 'GET'  },
];

/** Account API endpoint used for connection / auth testing */
export const ACCOUNT_API_PATH = 'account/api/v1/user';

/** Algorithms considered quantum-safe in certificate context */
export const QUANTUM_SAFE_ALGORITHMS = new Set([
  'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON', 'SPHINCS+',
  'XMSS', 'LMS', 'Ed448', 'Ed25519',
  'ml-dsa', 'ml-kem', 'slh-dsa', 'falcon', 'sphincs+',
  'xmss', 'lms', 'ed448', 'ed25519',
]);
