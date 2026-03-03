/**
 * DigiCert TLM Connector — Utility Functions
 *
 * Algorithm classification, status normalisation, CA vendor extraction,
 * and API path auto-detection.
 */
import { CERTIFICATE_API_PATHS, QUANTUM_SAFE_ALGORITHMS } from './constants';
import { digicertRequest } from './httpClient';
import type { DigiCertCertificate, DigiCertListResponse, DetectedEndpoint } from './types';

/**
 * Safely coerce a DigiCert API value to a string.
 * The ui-api/v2 endpoints may return fields as objects (e.g. { value: "..." })
 * instead of plain strings. This helper handles both shapes.
 */
export function str(val: unknown): string {
  if (val == null) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (typeof val === 'object') {
    // { value: "..." } or { name: "..." } or { id: "..." }
    const obj = val as Record<string, unknown>;
    if (typeof obj.value === 'string') return obj.value;
    if (typeof obj.name === 'string') return obj.name;
    if (typeof obj.id === 'string') return obj.id;
    // Last resort: JSON or toString
    try { return JSON.stringify(val); } catch { return String(val); }
  }
  return String(val);
}

/* ── Algorithm classification ─────────────────────────────── */

export function isQuantumSafe(algo: string | undefined): boolean {
  if (!algo) return false;
  const upper = algo.toUpperCase();
  return [...QUANTUM_SAFE_ALGORITHMS].some((qs) => upper.includes(qs.toUpperCase()));
}

/** Normalise the key algorithm string */
export function normaliseAlgorithm(cert: DigiCertCertificate): { keyAlgorithm: string; keyLength: string } {
  const keyType = str(cert.key_type).toUpperCase();
  if (keyType === 'EC' || keyType === 'ECDSA') {
    return {
      keyAlgorithm: 'ECDSA',
      keyLength: str(cert.key_curve) || `P-${cert.key_size || 256}`,
    };
  }
  if (keyType === 'RSA' || keyType.includes('RSA')) {
    return { keyAlgorithm: 'RSA', keyLength: String(cert.key_size || cert.key_length || 2048) };
  }
  if (keyType.includes('ED25519')) {
    return { keyAlgorithm: 'Ed25519', keyLength: '256' };
  }
  if (keyType.includes('ED448')) {
    return { keyAlgorithm: 'Ed448', keyLength: '448' };
  }
  if (keyType.includes('ML-DSA') || keyType.includes('DILITHIUM')) {
    return { keyAlgorithm: 'ML-DSA', keyLength: str(cert.key_curve) || 'ML-DSA-65' };
  }
  // Fallback
  return { keyAlgorithm: str(cert.key_type) || 'Unknown', keyLength: String(cert.key_size || cert.key_length || 'Unknown') };
}

/** Map DigiCert status string to our enum */
export function normaliseStatus(raw: string | undefined): 'Issued' | 'Expired' | 'Revoked' | 'Pending' {
  if (!raw) return 'Pending';
  const s = str(raw).toUpperCase();
  if (s === 'ISSUED' || s === 'ACTIVE' || s === 'VALID') return 'Issued';
  if (s === 'EXPIRED') return 'Expired';
  if (s === 'REVOKED' || s === 'SUSPENDED') return 'Revoked';
  return 'Pending';
}

/** Best-effort extraction of CA vendor from issuer DN */
export function extractCaVendor(cert: DigiCertCertificate): string {
  // Prefer the direct ca_vendor field if present
  const directVendor = str(cert.ca_vendor);
  if (directVendor && directVendor !== 'Self signed') return directVendor;
  if (directVendor === 'Self signed') return 'Self-signed';
  const issuer = str(cert.issuer);
  if (issuer.includes('DigiCert')) return 'DigiCert';
  if (issuer.includes("Let's Encrypt") || issuer.includes('ISRG')) return "Let's Encrypt";
  if (issuer.includes('Sectigo') || issuer.includes('Comodo')) return 'Sectigo';
  if (issuer.includes('GlobalSign')) return 'GlobalSign';
  if (issuer.includes('Entrust')) return 'Entrust';
  if (issuer.includes('GoDaddy')) return 'GoDaddy';
  return 'DigiCert'; // default since it's coming from TLM
}

/* ── API path auto-detection ──────────────────────────────── */

/**
 * Probe multiple well-known DigiCert ONE certificate endpoints
 * and return the first that responds with valid JSON (not 503 or HTML).
 * Tries both POST /search and GET collection endpoints.
 */
export async function detectCertificateApiPath(
  baseUrl: string,
  apiKey: string,
  accountId: string | undefined,
  rejectUnauthorized: boolean,
): Promise<DetectedEndpoint | null> {
  for (const candidate of CERTIFICATE_API_PATHS) {
    try {
      let url: URL;
      let resp: DigiCertListResponse | DigiCertCertificate[];
      // For ui-api routes, pass accountId as a query param instead of header
      const headerAccountId = candidate.accountInQuery ? undefined : accountId;

      if (candidate.method === 'POST') {
        url = new URL(`${baseUrl}/${candidate.path}`);
        if (candidate.accountInQuery && accountId) {
          url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
        }
        const body = JSON.stringify({ offset: 0, limit: 1 });
        console.log(`[DigiCert TLM] Probing POST ${candidate.path}`);
        resp = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, headerAccountId, rejectUnauthorized, 'POST', body,
        );
      } else {
        url = new URL(`${baseUrl}/${candidate.path}`);
        url.searchParams.set('offset', '0');
        url.searchParams.set('limit', '1');
        if (candidate.accountInQuery && accountId) {
          url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
        }
        // Add extra params (e.g. status=issued for ui-api/v2)
        if (candidate.extraParams) {
          for (const [k, v] of Object.entries(candidate.extraParams)) {
            url.searchParams.set(k, v);
          }
        }
        console.log(`[DigiCert TLM] Probing GET  ${candidate.path}`);
        resp = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, headerAccountId, rejectUnauthorized,
        );
      }

      console.log(`[DigiCert TLM] ✓ Endpoint "${candidate.path}" (${candidate.method}) responded with valid JSON`);
      return {
        path: candidate.path,
        method: candidate.method,
        response: resp,
        accountInQuery: candidate.accountInQuery,
        extraParams: candidate.extraParams,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[DigiCert TLM] ✗ Endpoint "${candidate.path}" (${candidate.method}) failed: ${msg.slice(0, 120)}`);
      // Try next candidate
    }
  }
  return null;
}
