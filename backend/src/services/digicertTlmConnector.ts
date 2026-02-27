/**
 * DigiCert Trust Lifecycle Manager — Real API Connector
 *
 * Fetches certificate data from the DigiCert ONE REST API and maps
 * it to the normalised Certificate model used by CBOM Analyser.
 *
 * API Reference:
 *   • List certificates: GET {baseUrl}/{apiPath}  (default: mpki/api/v1/certificate)
 *   • Auth header:       x-api-key: <apiKey>
 *   • Pagination:        offset / limit query params
 *
 * The connector tries multiple well-known DigiCert ONE API paths
 * in fallback order if the primary path fails (e.g. MPKI micro-
 * service not deployed on an on-prem cluster).
 *
 * Required ConnectorConfig keys:
 *   apiBaseUrl        – e.g. "https://one.digicert.com"
 *   apiKey            – DigiCert ONE API key
 *   accountId         – DigiCert account ID (optional filter)
 *   divisionId        – restrict to a specific division (optional)
 *   allowInsecureTls  – "true" to accept self-signed / internal CA certs
 *   apiPath           – override the certificate list endpoint path
 *                       (e.g. "mpki/api/v1/certificate")
 */
import https from 'https';
import http from 'http';
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from './connectors';

/* ── Constants ─────────────────────────────────────────────── */

const PAGE_SIZE = 100;
const MAX_PAGES = 50;          // safety cap → max 5 000 certs per sync
const REQUEST_TIMEOUT = 30_000; // 30 s

/**
 * Well-known DigiCert ONE API paths for certificate listing,
 * tried in order when no explicit `apiPath` is configured.
 * On-prem clusters may only have a subset of micro-services deployed.
 */
const CERTIFICATE_API_PATHS = [
  'mpki/api/v1/certificate',          // Standard MPKI (cloud & most on-prem)
  'em/api/v1/certificate',            // Enterprise Manager / TLM
  'tlm/api/v1/certificate',           // Trust Lifecycle Manager (newer)
  'certcentral/api/v1/certificate',   // CertCentral
];

/** Account API endpoint used for connection / auth testing */
const ACCOUNT_API_PATH = 'account/api/v1/user';

/* ── Helpers ───────────────────────────────────────────────── */

/**
 * HTTP(S) request using Node's built-in modules.
 * Unlike native `fetch()`, this supports `rejectUnauthorized: false`
 * for internal / self-signed TLS endpoints, and surfaces detailed
 * error messages (ENOTFOUND, ECONNREFUSED, CERT_HAS_EXPIRED, etc.).
 */
function digicertRequest<T>(
  url: string,
  apiKey: string,
  accountId?: string,
  rejectUnauthorized = true,
  method: 'GET' | 'POST' = 'GET',
  body?: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';

    const headers: Record<string, string> = {
      'x-api-key': apiKey,
      Accept: 'application/json',
      ...(accountId ? { 'x-dc-account-id': accountId } : {}),
    };
    if (body) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body).toString();
    }

    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: REQUEST_TIMEOUT,
      headers,
      ...(isHttps ? { rejectUnauthorized } : {}),
    };

    const mod = isHttps ? https : http;

    const req = mod.request(options, (res) => {
      let respBody = '';
      res.on('data', (chunk: Buffer) => { respBody += chunk.toString(); });
      res.on('end', () => {
        const status = res.statusCode || 0;
        if (status >= 200 && status < 300) {
          try {
            resolve(JSON.parse(respBody) as T);
          } catch {
            // Some endpoints return HTML (SPA fallback) instead of JSON
            if (respBody.includes('<!doctype') || respBody.includes('<html')) {
              reject(new Error(`ENDPOINT_NOT_API: ${parsed.pathname} returned HTML instead of JSON — this API path is not available on this deployment`));
            } else {
              reject(new Error(`DigiCert API returned invalid JSON (HTTP ${status}): ${respBody.slice(0, 200)}`));
            }
          }
        } else if (status === 503) {
          reject(new Error(`SERVICE_UNAVAILABLE: The micro-service at ${parsed.pathname} is not running or not deployed on this DigiCert ONE instance (HTTP 503). Contact your DigiCert ONE administrator to verify the service is enabled.`));
        } else if (status === 404) {
          reject(new Error(`ENDPOINT_NOT_FOUND: ${parsed.pathname} returned HTTP 404 — this API path does not exist on this deployment`));
        } else {
          reject(new Error(`DigiCert API HTTP ${status}: ${respBody.slice(0, 300)}`));
        }
      });
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      // Provide actionable error messages
      if (err.code === 'ENOTFOUND') {
        reject(new Error(`DNS lookup failed for "${parsed.hostname}" — verify the API Base URL is correct and the host is reachable`));
      } else if (err.code === 'ECONNREFUSED') {
        reject(new Error(`Connection refused by ${parsed.hostname}:${options.port} — is the DigiCert ONE service running?`));
      } else if (err.code === 'ECONNRESET') {
        reject(new Error(`Connection reset by ${parsed.hostname} — possible firewall or proxy issue`));
      } else if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN' || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' || (err.message && err.message.includes('self-signed'))) {
        reject(new Error(`TLS certificate verification failed for ${parsed.hostname} — if using an internal CA or self-signed cert, enable "Allow Insecure TLS" in the integration config`));
      } else if (err.code === 'CERT_HAS_EXPIRED') {
        reject(new Error(`TLS certificate for ${parsed.hostname} has expired`));
      } else {
        reject(new Error(`Network error connecting to ${parsed.hostname}: ${err.message} (${err.code || 'unknown'})`));
      }
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request to ${parsed.hostname} timed out after ${REQUEST_TIMEOUT / 1000}s`));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

/* ── API path auto-detection ──────────────────────────────── */

/**
 * Probe multiple well-known DigiCert ONE certificate endpoints
 * and return the first that responds with valid JSON (not 503 or HTML).
 */
async function detectCertificateApiPath(
  baseUrl: string,
  apiKey: string,
  accountId: string | undefined,
  rejectUnauthorized: boolean,
): Promise<{ path: string; response: DigiCertListResponse | DigiCertCertificate[] } | null> {
  for (const p of CERTIFICATE_API_PATHS) {
    try {
      const url = new URL(`${baseUrl}/${p}`);
      url.searchParams.set('offset', '0');
      url.searchParams.set('limit', '1');

      console.log(`[DigiCert TLM] Probing endpoint: ${p}`);
      const resp = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
        url.toString(), apiKey, accountId, rejectUnauthorized,
      );
      console.log(`[DigiCert TLM] ✓ Endpoint "${p}" responded with valid JSON`);
      return { path: p, response: resp };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[DigiCert TLM] ✗ Endpoint "${p}" failed: ${msg.slice(0, 120)}`);
      // Try next path
    }
  }
  return null;
}

/* ── Response typings (subset of DigiCert ONE v1 schema) ──── */

interface DigiCertCertificate {
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

interface DigiCertListResponse {
  /* MPKI returns array directly or { items: [] } */
  items?: DigiCertCertificate[];
  total?: number;
  offset?: number;
  limit?: number;
  [key: string]: unknown;
}

/* ── Algorithm classification ─────────────────────────────── */

const QUANTUM_SAFE_ALGORITHMS = new Set([
  'ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON', 'SPHINCS+',
  'XMSS', 'LMS', 'Ed448', 'Ed25519',
  'ml-dsa', 'ml-kem', 'slh-dsa', 'falcon', 'sphincs+',
  'xmss', 'lms', 'ed448', 'ed25519',
]);

function isQuantumSafe(algo: string | undefined): boolean {
  if (!algo) return false;
  const upper = algo.toUpperCase();
  return [...QUANTUM_SAFE_ALGORITHMS].some((qs) => upper.includes(qs.toUpperCase()));
}

/** Normalise the key algorithm string */
function normaliseAlgorithm(cert: DigiCertCertificate): { keyAlgorithm: string; keyLength: string } {
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
function normaliseStatus(raw: string | undefined): 'Issued' | 'Expired' | 'Revoked' | 'Pending' {
  if (!raw) return 'Pending';
  const s = raw.toUpperCase();
  if (s === 'ISSUED' || s === 'ACTIVE' || s === 'VALID') return 'Issued';
  if (s === 'EXPIRED') return 'Expired';
  if (s === 'REVOKED' || s === 'SUSPENDED') return 'Revoked';
  return 'Pending';
}

/** Best-effort extraction of CA vendor from issuer DN */
function extractCaVendor(cert: DigiCertCertificate): string {
  const issuer = (cert.issuer || '') as string;
  if (issuer.includes('DigiCert')) return 'DigiCert';
  if (issuer.includes("Let's Encrypt") || issuer.includes('ISRG')) return "Let's Encrypt";
  if (issuer.includes('Sectigo') || issuer.includes('Comodo')) return 'Sectigo';
  if (issuer.includes('GlobalSign')) return 'GlobalSign';
  if (issuer.includes('Entrust')) return 'Entrust';
  if (issuer.includes('GoDaddy')) return 'GoDaddy';
  return 'DigiCert'; // default since it's coming from TLM
}

/* ── Main fetch ────────────────────────────────────────────── */

export async function fetchCertificatesFromDigiCert(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const baseUrl = (config.apiBaseUrl || '').replace(/\/+$/, '');
  const apiKey = config.apiKey || '';
  const accountId = config.accountId;
  const divisionId = config.divisionId;
  const rejectUnauthorized = config.allowInsecureTls !== 'true';
  const explicitApiPath = config.apiPath?.replace(/^\/+|\/+$/g, ''); // user override

  if (!baseUrl || !apiKey) {
    return {
      success: false,
      data: [],
      errors: ['Missing apiBaseUrl or apiKey in integration config'],
    };
  }

  const allCerts: Record<string, unknown>[] = [];
  const errors: string[] = [];
  let offset = 0;
  let totalFetched = 0;
  let hasMore = true;

  console.log(`[DigiCert TLM] Starting certificate fetch from ${baseUrl} (TLS verify: ${rejectUnauthorized})`);

  /* ── Resolve the certificate API path ────────────────────── */
  let certApiPath: string;
  if (explicitApiPath) {
    certApiPath = explicitApiPath;
    console.log(`[DigiCert TLM] Using explicit apiPath: ${certApiPath}`);
  } else {
    // Auto-detect working endpoint
    console.log(`[DigiCert TLM] No explicit apiPath configured — auto-detecting…`);
    const detected = await detectCertificateApiPath(baseUrl, apiKey, accountId, rejectUnauthorized);
    if (detected) {
      certApiPath = detected.path;
      console.log(`[DigiCert TLM] Auto-detected working path: ${certApiPath}`);
    } else {
      // None of the probed paths worked — collect detailed diagnostics
      const triedPaths = CERTIFICATE_API_PATHS.map((p) => `  • /${p}`).join('\n');
      const errMsg =
        `No working certificate API endpoint found on ${baseUrl}. ` +
        `Tried the following paths:\n${triedPaths}\n` +
        `The certificate micro-service (MPKI) may not be deployed or running on this DigiCert ONE instance. ` +
        `Please verify the MPKI service status with your DigiCert ONE administrator, or set a custom "API Path" in the integration config.`;
      console.error(`[DigiCert TLM] ${errMsg}`);
      return { success: false, data: [], errors: [errMsg] };
    }
  }

  try {
    while (hasMore && offset / PAGE_SIZE < MAX_PAGES) {
      // Build URL with pagination params
      const url = new URL(`${baseUrl}/${certApiPath}`);
      url.searchParams.set('offset', String(offset));
      url.searchParams.set('limit', String(PAGE_SIZE));
      if (divisionId) {
        url.searchParams.set('division_id', divisionId);
      }

      console.log(`[DigiCert TLM] Fetching page offset=${offset} limit=${PAGE_SIZE}`);

      const response = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
        url.toString(),
        apiKey,
        accountId,
        rejectUnauthorized,
      );

      // DigiCert API may return an array directly or { items: [...] }
      let certs: DigiCertCertificate[];
      let total: number | undefined;

      if (Array.isArray(response)) {
        certs = response;
        total = undefined; // no pagination metadata
      } else {
        certs = response.items || [];
        total = response.total;
      }

      if (certs.length === 0) {
        hasMore = false;
        break;
      }

      // Map each DigiCert cert to our Certificate model schema
      for (const cert of certs) {
        const { keyAlgorithm, keyLength } = normaliseAlgorithm(cert);
        const sigAlg = cert.signature_algorithm || null;
        const qSafe = isQuantumSafe(keyAlgorithm) || isQuantumSafe(sigAlg || '');

        allCerts.push({
          id: uuidv4(),
          integrationId,
          commonName: cert.common_name || cert.subject || 'Unknown',
          caVendor: extractCaVendor(cert),
          status: normaliseStatus(cert.status),
          keyAlgorithm,
          keyLength,
          quantumSafe: qSafe,
          source: 'DigiCert TLM',
          expiryDate: cert.valid_till || null,
          serialNumber: cert.serial_number || null,
          signatureAlgorithm: sigAlg,
        });
      }

      totalFetched += certs.length;
      offset += PAGE_SIZE;

      // Stop if we've fetched all
      if (total !== undefined && totalFetched >= total) {
        hasMore = false;
      }
      // If page returned fewer than PAGE_SIZE, no more pages
      if (certs.length < PAGE_SIZE) {
        hasMore = false;
      }
    }

    console.log(`[DigiCert TLM] Fetched ${allCerts.length} certificates total`);

    return {
      success: true,
      data: allCerts,
      errors,
      meta: {
        totalFetched: allCerts.length,
        source: 'DigiCert ONE API',
        baseUrl,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[DigiCert TLM] Fetch error: ${message}`);
    return {
      success: false,
      data: allCerts, // return any certs fetched before the error
      errors: [message],
    };
  }
}

/* ── Test connection ───────────────────────────────────────── */

interface DigiCertUserResponse {
  id?: string;
  email?: string;
  [key: string]: unknown;
}

/**
 * Tests the DigiCert ONE API connection by:
 *   1. Verifying auth via the Account API  (/account/api/v1/user)
 *   2. Probing for a working certificate endpoint
 *
 * Returns success if at least auth works.
 */
export async function testDigiCertConnection(
  config: ConnectorConfig,
): Promise<{ success: boolean; message: string }> {
  const baseUrl = (config.apiBaseUrl || '').replace(/\/+$/, '');
  const apiKey = config.apiKey || '';
  const accountId = config.accountId;
  const rejectUnauthorized = config.allowInsecureTls !== 'true';

  if (!baseUrl || !apiKey) {
    return { success: false, message: 'Missing API Base URL or API Key' };
  }

  /* Step 1: Verify auth via Account API */
  let userEmail = '';
  try {
    const accountUrl = `${baseUrl}/${ACCOUNT_API_PATH}`;
    console.log(`[DigiCert TLM] Testing auth via ${accountUrl}`);
    const user = await digicertRequest<DigiCertUserResponse>(
      accountUrl, apiKey, accountId, rejectUnauthorized,
    );
    userEmail = user?.email || '';
    console.log(`[DigiCert TLM] Auth OK — user: ${userEmail}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      message: `Authentication failed: ${message}`,
    };
  }

  /* Step 2: Probe certificate endpoints */
  const explicitApiPath = config.apiPath?.replace(/^\/+|\/+$/g, '');
  let certEndpointStatus = '';

  if (explicitApiPath) {
    // Test explicit path
    try {
      const url = new URL(`${baseUrl}/${explicitApiPath}`);
      url.searchParams.set('offset', '0');
      url.searchParams.set('limit', '1');
      await digicertRequest<unknown>(url.toString(), apiKey, accountId, rejectUnauthorized);
      certEndpointStatus = `Certificate endpoint (${explicitApiPath}) is reachable.`;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      certEndpointStatus = `⚠ Certificate endpoint (${explicitApiPath}) returned an error: ${msg.slice(0, 100)}. Sync may fail.`;
    }
  } else {
    const detected = await detectCertificateApiPath(baseUrl, apiKey, accountId, rejectUnauthorized);
    if (detected) {
      certEndpointStatus = `Certificate endpoint auto-detected: /${detected.path}`;
    } else {
      certEndpointStatus = `⚠ No certificate API endpoint found. The MPKI service may not be running on this instance. Sync will fail until the service is available, or you can set a custom API Path.`;
    }
  }

  const msg = [
    `Connected to DigiCert ONE`,
    userEmail ? `(${userEmail})` : '',
    `— ${certEndpointStatus}`,
  ].filter(Boolean).join(' ');

  return { success: true, message: msg };
}
