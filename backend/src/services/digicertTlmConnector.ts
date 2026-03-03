/**
 * DigiCert TLM Connector — thin re-export shim.
 *
 * Implementation has moved to the `digicert/` module for cleaner separation.
 * This file preserves backward compatibility for all existing importers.
 */
export {
  fetchCertificatesFromDigiCert,
  fetchEndpointsFromDigiCert,
  testDigiCertConnection,
  digicertRequest,
  isQuantumSafe,
  normaliseAlgorithm,
  normaliseStatus,
  extractCaVendor,
  detectCertificateApiPath,
} from './digicert';

export {
  PAGE_SIZE,
  MAX_PAGES,
  REQUEST_TIMEOUT,
  CERTIFICATE_API_PATHS,
  ENDPOINT_API_PATHS,
  ACCOUNT_API_PATH,
  QUANTUM_SAFE_ALGORITHMS,
} from './digicert';

export type {
  CertEndpointCandidate,
  DigiCertCertificate,
  DigiCertListResponse,
  DigiCertUserResponse,
  DetectedEndpoint,
  DigiCertEndpoint,
  DigiCertEndpointListResponse,
} from './digicert';
