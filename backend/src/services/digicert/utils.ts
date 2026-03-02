/**
 * DigiCert TLM Connector — Utility Functions
 *
 * Algorithm classification, status normalisation, CA vendor extraction,
 * and API path auto-detection.
 */
import { CERTIFICATE_API_PATHS, QUANTUM_SAFE_ALGORITHMS } from './constants';
import { digicertRequest } from './httpClient';
import type { DigiCertCertificate, DigiCertListResponse, DetectedEndpoint } from './types';

/* ── Algorithm classification ─────────────────────────────── */

export function isQuantumSafe(algo: string | undefined): boolean {
  if (!algo) return false;
  const upper = algo.toUpperCase();
  return [...QUANTUM_SAFE_ALGORITHMS].some((qs) => upper.includes(qs.toUpperCase()));
}

/** Normalise the key algorithm string */
export function normaliseAlgorithm(cert: DigiCertCertificate): { keyAlgorithm: string; keyLength: string } {
  const keyType = (cert.key_type || '').toUpperCase();
  if (keyType === 'EC' || keyType === 'ECDSA') {
    return {
      keyAlgorithm: 'ECDSA',
      keyLength: cert.key_curve || `P-${cert.key_size || 256}`,
    };
  }
  if (keyType === 'RSA' || keyType.includes('RSA')) {
    return { keyAlgorithm: 'RSA', keyLength: String(cert.key_size || 2048) };
  }
  if (keyType.includes('ED25519')) {
    return { keyAlgorithm: 'Ed25519', keyLength: '256' };
  }
  if (keyType.includes('ED448')) {
    return { keyAlgorithm: 'Ed448', keyLength: '448' };
  }
  if (keyType.includes('ML-DSA') || keyType.includes('DILITHIUM')) {
    return { keyAlgorithm: 'ML-DSA', keyLength: cert.key_curve || 'ML-DSA-65' };
  }
  // Fallback
  return { keyAlgorithm: cert.key_type || 'Unknown', keyLength: String(cert.key_size || 'Unknown') };
}

/** Map DigiCert status string to our enum */
export function normaliseStatus(raw: string | undefined): 'Issued' | 'Expired' | 'Revoked' | 'Pending' {
  if (!raw) return 'Pending';
  const s = raw.toUpperCase();
  if (s === 'ISSUED' || s === 'ACTIVE' || s === 'VALID') return 'Issued';
  if (s === 'EXPIRED') return 'Expired';
  if (s === 'REVOKED' || s === 'SUSPENDED') return 'Revoked';
  return 'Pending';
}

/** Best-effort extraction of CA vendor from issuer DN */
export function extractCaVendor(cert: DigiCertCertificate): string {
  const issuer = (cert.issuer || '') as string;
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

      if (candidate.method === 'POST') {
        url = new URL(`${baseUrl}/${candidate.path}`);
        const body = JSON.stringify({ offset: 0, limit: 1 });
        console.log(`[DigiCert TLM] Probing POST ${candidate.path}`);
        resp = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, accountId, rejectUnauthorized, 'POST', body,
        );
      } else {
        url = new URL(`${baseUrl}/${candidate.path}`);
        url.searchParams.set('offset', '0');
        url.searchParams.set('limit', '1');
        console.log(`[DigiCert TLM] Probing GET  ${candidate.path}`);
        resp = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, accountId, rejectUnauthorized,
        );
      }

      console.log(`[DigiCert TLM] ✓ Endpoint "${candidate.path}" (${candidate.method}) responded with valid JSON`);
      return { path: candidate.path, method: candidate.method, response: resp };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[DigiCert TLM] ✗ Endpoint "${candidate.path}" (${candidate.method}) failed: ${msg.slice(0, 120)}`);
      // Try next candidate
    }
  }
  return null;
}
