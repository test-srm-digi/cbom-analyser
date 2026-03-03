/**
 * DigiCert Device Trust Manager (DTM) Connector
 *
 * Fetches IoT/OT devices from DigiCert ONE's Device Trust Manager API.
 *
 * API docs: https://docs.digicert.com/en/device-trust-manager.html
 *
 * Auth: supports **both** API key (`x-api-key`) and Bearer / access
 *       token (`Authorization: Bearer …`).  The staging environment
 *       typically uses Bearer tokens from the browser session, while
 *       production uses long-lived API keys.
 *
 * Endpoints used:
 *   GET /devicetrustmanager/api/v4/device?limit=N&offset=O&account_id=X
 *   GET /devicetrustmanager/certificate-issuance-service/api/v2/certificate?limit=N&offset=O
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { digicertRequest } from './httpClient';

/* ── Constants ─────────────────────────────────────────────── */

const DTM_PAGE_SIZE = 100;
const DTM_MAX_PAGES = 50; // safety cap → max 5 000 devices
const DTM_DEVICE_PATH = 'devicetrustmanager/api/v4/device';
const DTM_CERT_PATH   = 'devicetrustmanager/certificate-issuance-service/api/v2/certificate';

/* ── DTM API response types ────────────────────────────────── */

export interface DtmDeviceGroup {
  id: string;
  name: string;
}

export interface DtmDevice {
  id?: string;
  name?: string;
  status?: string;               // REGISTERED, PROVISIONED, DEREGISTERED, etc.
  operational_status?: string;   // ENABLED, DISABLED
  device_group?: DtmDeviceGroup;
  connected?: boolean;
  created_on?: string;           // ISO date
  updated_on?: string;           // ISO date
  mqtt_endpoints?: unknown[];
  [key: string]: unknown;
}

export type DtmDeviceListResponse = DtmDevice[];

/** A single certificate record returned by the DTM v2 certificates endpoint */
export interface DtmDeviceCertificate {
  id?: string;
  serial_number?: string;
  common_name?: string;
  subject?: string;
  issuer?: string;
  issuer_common_name?: string;
  status?: string;              // ISSUED, REVOKED, EXPIRED, etc.
  key_type?: string;            // "RSA_2048", "EC_prime256v1", etc. (combined algo+size)
  key_algorithm?: string;
  key_size?: number;
  key_length?: number;
  signature_algorithm?: string; // "sha256WithRSA", etc.
  signature_hash_algorithm?: string;
  not_before?: string;
  not_after?: string;
  valid_from?: string;          // v2 API uses valid_from
  valid_to?: string;            // v2 API uses valid_to
  valid_till?: string;
  thumbprint?: string;
  thumbprint_sha256?: string;
  created?: string;             // v2 uses "created" not "created_on"
  created_on?: string;
  updated_on?: string;
  device_id?: string;
  device?: {                    // v2 nests device info
    id?: string;
    name?: string;
  };
  device_group?: {
    id?: string;
    name?: string;
  };
  certificate_format?: string;
  enrollment_method?: string;
  certificate_type?: string;
  [key: string]: unknown;
}

/* ── Auth helpers ──────────────────────────────────────────── */

/**
 * Resolve auth fields from connector config.
 * Supports API key (`x-api-key`) OR access/Bearer token.
 */
function resolveAuth(config: ConnectorConfig) {
  const baseUrl = (config.apiBaseUrl || '').replace(/\/+$/, '');
  const apiKey = config.apiKey || '';
  const accessToken = config.accessToken || '';
  const accountId = config.accountId || '';
  const rejectUnauthorized = config.allowInsecureTls !== 'true';

  return { baseUrl, apiKey, accessToken, accountId, rejectUnauthorized };
}

/** Make a DTM API request using whichever auth method is configured */
function dtmRequest<T>(
  url: string,
  auth: ReturnType<typeof resolveAuth>,
): Promise<T> {
  return digicertRequest<T>(
    url,
    auth.apiKey,
    auth.accountId || undefined,
    auth.rejectUnauthorized,
    'GET',
    undefined,
    auth.accessToken || undefined,
  );
}

/**
 * Extract an array of items from a DTM API response.
 *
 * The DTM API returns different shapes depending on auth method and
 * API version:
 *   - Bearer token → bare array: [{…}, {…}]
 *   - API key      → paginated object: {total, records:[{…}], next, …}
 *   - Some paths   → {items:[{…}]}, {data:[{…}]}, {certificates:[{…}]}, etc.
 *
 * As a last resort, we look for _any_ top-level property whose value
 * is an array of objects.
 */
function extractRecords<T>(raw: unknown, label = 'extractRecords'): { items: T[]; hasNext: boolean } {
  if (Array.isArray(raw)) {
    console.log(`[DigiCert DTM] ${label}: response is a bare array (${raw.length} items)`);
    return { items: raw as T[], hasNext: false };
  }
  const obj = raw as Record<string, unknown> | null;
  if (!obj || typeof obj !== 'object') {
    console.warn(`[DigiCert DTM] ${label}: response is null or not an object`);
    return { items: [], hasNext: false };
  }

  // Log top-level keys for diagnostics
  const topKeys = Object.keys(obj);
  console.log(`[DigiCert DTM] ${label}: response keys = [${topKeys.join(', ')}]`);

  // Known array property names in order of priority
  const knownArrayKeys = ['records', 'items', 'data', 'certificates', 'results', 'content', 'certs', 'list'];
  for (const key of knownArrayKeys) {
    if (Array.isArray(obj[key])) {
      const hasNext = 'next' in obj ? !!obj.next : false;
      console.log(`[DigiCert DTM] ${label}: found '${key}' array (${(obj[key] as unknown[]).length} items, hasNext=${hasNext})`);
      return { items: obj[key] as T[], hasNext };
    }
  }

  // Fallback: find the first top-level property that is a non-empty array of objects
  for (const key of topKeys) {
    const val = obj[key];
    if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object' && val[0] !== null) {
      console.log(`[DigiCert DTM] ${label}: fallback — using '${key}' array (${val.length} items)`);
      return { items: val as T[], hasNext: false };
    }
  }

  // Maybe the object itself IS the single record (e.g. when device has one cert).
  // Check if it looks like a cert (has common cert fields)
  const certishKeys = ['serial_number', 'serialNumber', 'common_name', 'commonName', 'key_type', 'keyType', 'key_algorithm', 'keyAlgorithm', 'thumbprint', 'fingerprint'];
  if (certishKeys.some(k => k in obj)) {
    console.log(`[DigiCert DTM] ${label}: response appears to be a single record object — wrapping in array`);
    return { items: [obj as T], hasNext: false };
  }

  console.warn(`[DigiCert DTM] ${label}: could not locate array in response. Keys: [${topKeys.join(', ')}]`);
  return { items: [], hasNext: false };
}

/* ── Status mapping ────────────────────────────────────────── */

/**
 * Map DTM API status values to our DeviceAttributes.enrollmentStatus.
 * DTM uses: REGISTERED, PROVISIONED, DEREGISTERED, SUSPENDED, ...
 */
function mapEnrollmentStatus(dtmStatus?: string): 'Enrolled' | 'Pending' | 'Revoked' | 'Expired' {
  if (!dtmStatus) return 'Pending';
  const upper = dtmStatus.toUpperCase();
  switch (upper) {
    case 'REGISTERED':
    case 'PROVISIONED':
      return 'Enrolled';
    case 'DEREGISTERED':
    case 'REVOKED':
    case 'SUSPENDED':
      return 'Revoked';
    case 'EXPIRED':
      return 'Expired';
    default:
      return 'Pending';
  }
}

/* ── PQC helpers ───────────────────────────────────────────── */

function isQuantumSafeAlgorithm(algo?: string): boolean {
  if (!algo) return false;
  const upper = algo.toUpperCase();
  const pqcPatterns = ['ML-DSA', 'ML-KEM', 'SLH-DSA', 'FALCON', 'DILITHIUM', 'KYBER', 'SPHINCS'];
  return pqcPatterns.some(p => upper.includes(p));
}

/**
 * Parse the algorithm from a DTM certificate.
 *
 * The v2 API returns `key_type` as a combined string like:
 *   "RSA_2048", "RSA_4096", "EC_prime256v1", "EC_secp384r1", etc.
 *
 * We extract the algorithm part (before the underscore / size).
 */
function normalizeCertAlgorithm(cert: DtmDeviceCertificate): string {
  const raw = cert as Record<string, unknown>;

  // 1. Try key_type first (v2 format: "RSA_2048", "EC_prime256v1")
  const keyType = cert.key_type || raw['keyType'] as string | undefined;
  if (keyType && typeof keyType === 'string') {
    return parseAlgorithmFromKeyType(keyType);
  }

  // 2. Fallback to other fields
  const candidates: (string | undefined)[] = [
    cert.key_algorithm,
    raw['keyAlgorithm'] as string | undefined,
    raw['algorithm'] as string | undefined,
    raw['public_key_algorithm'] as string | undefined,
    raw['publicKeyAlgorithm'] as string | undefined,
    cert.signature_algorithm,
    cert.signature_hash_algorithm,
    raw['signatureAlgorithm'] as string | undefined,
  ];

  const result = candidates.find(c => typeof c === 'string' && c.trim().length > 0);
  if (!result) {
    console.warn(`[DigiCert DTM] normalizeCertAlgorithm: no algorithm field found. Cert keys: [${Object.keys(raw).join(', ')}]`);
  }
  return result || 'Unknown';
}

/**
 * Parse algorithm name from key_type strings like "RSA_2048", "EC_prime256v1".
 */
function parseAlgorithmFromKeyType(keyType: string): string {
  const upper = keyType.toUpperCase();

  // RSA_2048, RSA_4096, RSA_3072, etc.
  if (upper.startsWith('RSA')) return 'RSA';

  // EC_prime256v1, EC_secp384r1, EC_secp521r1, etc.
  if (upper.startsWith('EC')) {
    // Try to give a more descriptive name
    if (upper.includes('PRIME256') || upper.includes('P256') || upper.includes('SECP256')) return 'ECDSA P-256';
    if (upper.includes('P384') || upper.includes('SECP384')) return 'ECDSA P-384';
    if (upper.includes('P521') || upper.includes('SECP521')) return 'ECDSA P-521';
    return 'ECDSA';
  }

  // PQC algorithms
  if (upper.includes('ML-DSA') || upper.includes('DILITHIUM')) return keyType;
  if (upper.includes('ML-KEM') || upper.includes('KYBER')) return keyType;
  if (upper.includes('SLH-DSA') || upper.includes('SPHINCS')) return keyType;
  if (upper.includes('FALCON')) return keyType;

  // EdDSA
  if (upper.includes('ED25519')) return 'Ed25519';
  if (upper.includes('ED448')) return 'Ed448';

  // Fallback — return as-is (strip trailing size if obvious pattern)
  const parts = keyType.split('_');
  if (parts.length >= 2 && /^\d+$/.test(parts[parts.length - 1])) {
    return parts.slice(0, -1).join('_');
  }
  return keyType;
}

/**
 * Parse the key length from a DTM certificate.
 *
 * The v2 API returns `key_type` as a combined string like:
 *   "RSA_2048" → 2048,  "EC_prime256v1" → P-256
 */
function normalizeCertKeyLength(cert: DtmDeviceCertificate): string {
  const raw = cert as Record<string, unknown>;

  // 1. Try to parse from key_type first (v2 format)
  const keyType = cert.key_type || raw['keyType'] as string | undefined;
  if (keyType && typeof keyType === 'string') {
    const parsed = parseKeyLengthFromKeyType(keyType);
    if (parsed) return parsed;
  }

  // 2. Check explicit size fields
  const sizeCandidates: (number | string | undefined)[] = [
    cert.key_size,
    cert.key_length,
    raw['keySize'] as number | undefined,
    raw['keyLength'] as number | undefined,
    raw['key_bits'] as number | undefined,
    raw['bits'] as number | undefined,
    raw['strength'] as number | undefined,
    raw['public_key_length'] as number | undefined,
  ];

  const sizeVal = sizeCandidates.find(s => s !== undefined && s !== null && s !== '' && s !== 0);
  if (sizeVal) return String(sizeVal);

  console.warn(`[DigiCert DTM] normalizeCertKeyLength: no key length found. key_type=${keyType}, Cert keys: [${Object.keys(raw).join(', ')}]`);
  return 'Unknown';
}

/**
 * Parse key length from key_type strings like "RSA_2048", "EC_prime256v1".
 */
function parseKeyLengthFromKeyType(keyType: string): string | null {
  const upper = keyType.toUpperCase();

  // RSA_2048, RSA_4096, RSA_3072 → extract the number
  if (upper.startsWith('RSA')) {
    const m = keyType.match(/(\d{3,5})/);
    if (m) return m[1];
  }

  // EC curves → map to friendly name
  if (upper.includes('PRIME256') || upper.includes('P256') || upper.includes('SECP256')) return 'P-256';
  if (upper.includes('P384') || upper.includes('SECP384')) return 'P-384';
  if (upper.includes('P521') || upper.includes('SECP521')) return 'P-521';

  // EdDSA
  if (upper.includes('ED25519') || upper.includes('CURVE25519') || upper.includes('25519')) return '256';
  if (upper.includes('ED448') || upper.includes('448')) return '448';

  // Generic: try to extract any number from the string
  const m = keyType.match(/(\d{3,5})/);
  if (m) return m[1];

  return null;
}

/* ── Fetch ALL certificates (bulk) ─────────────────────────── */

/**
 * Fetch ALL certificates from the DTM certificate-issuance-service v2 API.
 *
 * This endpoint returns certs across all devices with `device.id` embedded,
 * so we can build a Map<deviceId, cert> in one paginated sweep — much more
 * efficient than calling per-device.
 *
 * Endpoint: GET /devicetrustmanager/certificate-issuance-service/api/v2/certificate
 * Response: { records: [...], total, next, limit, offset }
 */
async function fetchAllCertsFromDtm(
  auth: ReturnType<typeof resolveAuth>,
): Promise<Map<string, DtmDeviceCertificate>> {
  const certMap = new Map<string, DtmDeviceCertificate>();
  let offset = 0;
  let hasMore = true;
  let pageCount = 0;
  const CERT_PAGE_SIZE = 100;

  console.log(`[DigiCert DTM] Fetching all certificates from ${auth.baseUrl}/${DTM_CERT_PATH}`);

  while (hasMore && pageCount < DTM_MAX_PAGES) {
    try {
      const url = `${auth.baseUrl}/${DTM_CERT_PATH}?limit=${CERT_PAGE_SIZE}&offset=${offset}`;
      const raw = await dtmRequest<unknown>(url, auth);

      // Log shape on first page for diagnostics
      if (pageCount === 0) {
        const rawType = Array.isArray(raw) ? 'array' : typeof raw;
        console.log(`[DigiCert DTM] Cert list response: type=${rawType}` +
          (rawType === 'object' && raw ? `, keys=[${Object.keys(raw as object).join(', ')}]` : ''));
      }

      const { items: certs, hasNext } = extractRecords<DtmDeviceCertificate>(raw, `allCerts(page=${pageCount + 1})`);

      if (certs.length === 0) {
        hasMore = false;
        break;
      }

      // Log first cert's keys on first page for debugging field names
      if (pageCount === 0 && certs.length > 0) {
        console.log(`[DigiCert DTM] Sample cert keys: [${Object.keys(certs[0] as object).join(', ')}]`);
        console.log(`[DigiCert DTM] Sample cert key_type=${certs[0].key_type}, signature_algorithm=${certs[0].signature_algorithm}`);
      }

      // Index by device ID — keep the most relevant cert per device (prefer ISSUED/ACTIVE)
      for (const cert of certs) {
        const deviceId = cert.device?.id || cert.device_id || (cert as Record<string, unknown>)['deviceId'] as string || '';
        if (!deviceId) continue;

        const existing = certMap.get(deviceId);
        if (!existing) {
          certMap.set(deviceId, cert);
        } else {
          // Prefer ISSUED/ACTIVE over other statuses
          const newStatus = (cert.status || '').toUpperCase();
          const oldStatus = (existing.status || '').toUpperCase();
          if ((newStatus === 'ISSUED' || newStatus === 'ACTIVE') && oldStatus !== 'ISSUED' && oldStatus !== 'ACTIVE') {
            certMap.set(deviceId, cert);
          }
        }
      }

      pageCount++;
      offset += CERT_PAGE_SIZE;
      if (!hasNext && certs.length < CERT_PAGE_SIZE) {
        hasMore = false;
      }

      console.log(`[DigiCert DTM] Cert page ${pageCount}: ${certs.length} certs (mapped ${certMap.size} devices so far)`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[DigiCert DTM] Failed to fetch cert page at offset ${offset}: ${errMsg}`);
      if (err instanceof Error && err.stack) {
        console.error(`[DigiCert DTM] Stack: ${err.stack}`);
      }
      hasMore = false;
    }
  }

  console.log(`[DigiCert DTM] Cert fetch complete: ${certMap.size} devices have certificates (${pageCount} pages)`);
  return certMap;
}

/* ── Main fetcher ──────────────────────────────────────────── */

export async function fetchDevicesFromDtm(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const auth = resolveAuth(config);

  if (!auth.baseUrl || (!auth.apiKey && !auth.accessToken)) {
    return {
      success: false,
      data: [],
      errors: ['Missing API Base URL or credentials (API Key or Access Token) for DTM connector'],
    };
  }

  if (!auth.accountId) {
    return {
      success: false,
      data: [],
      errors: ['Missing Account ID — required for the DTM API'],
    };
  }

  const allDevices: Record<string, unknown>[] = [];
  const errors: string[] = [];
  let offset = 0;
  let hasMore = true;
  let pageCount = 0;

  const authMethod = auth.accessToken ? 'Bearer token' : 'API key';
  console.log(`[DigiCert DTM] Fetching devices from ${auth.baseUrl}/${DTM_DEVICE_PATH} (auth: ${authMethod})`);

  /* ── Step 1: Fetch all devices (paginated) ───────────────── */
  const rawDevices: DtmDevice[] = [];

  while (hasMore && pageCount < DTM_MAX_PAGES) {
    try {
      const url = `${auth.baseUrl}/${DTM_DEVICE_PATH}?limit=${DTM_PAGE_SIZE}&offset=${offset}&account_id=${auth.accountId}`;
      const raw = await dtmRequest<unknown>(url, auth);
      const { items: devices, hasNext } = extractRecords<DtmDevice>(raw, `devices(page=${pageCount + 1})`);

      if (devices.length === 0) {
        hasMore = false;
        break;
      }

      rawDevices.push(...devices);
      pageCount++;
      offset += DTM_PAGE_SIZE;
      // Stop if the API signals no more pages OR we got fewer than requested
      if (!hasNext && devices.length < DTM_PAGE_SIZE) {
        hasMore = false;
      }

      console.log(`[DigiCert DTM] Page ${pageCount}: fetched ${devices.length} devices (total so far: ${rawDevices.length})`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`DTM API error at offset ${offset}: ${msg}`);
      hasMore = false;
    }
  }

  /* ── Step 2: Fetch ALL certificates in one sweep ─────────── */
  console.log(`[DigiCert DTM] Fetching certificate data for enrichment…`);
  const certMap = await fetchAllCertsFromDtm(auth);

  // Log enrichment stats
  const devicesWithCerts = rawDevices.filter(d => d.id && certMap.has(d.id)).length;
  console.log(`[DigiCert DTM] ${devicesWithCerts}/${rawDevices.length} devices have matching certificates`);

  /* ── Step 3: Map devices to our model ────────────────────── */
  for (const dev of rawDevices) {
    const cert = (dev.id ? certMap.get(dev.id) : undefined) || null;
    if (cert && dev.id) {
      const algo = normalizeCertAlgorithm(cert);
      const keyLen = normalizeCertKeyLength(cert);
      console.log(`[DigiCert DTM] Device ${dev.id.slice(0, 8)} → algo=${algo}, keyLen=${keyLen}, key_type=${cert.key_type}`);
    }
    allDevices.push(mapDtmDevice(dev, integrationId, cert));
  }

  console.log(`[DigiCert DTM] Fetch complete: ${allDevices.length} devices in ${pageCount} pages, ${errors.length} errors`);

  return {
    success: errors.length === 0 || allDevices.length > 0,
    data: allDevices,
    errors,
  };
}

/* ── Map a single DTM device to our Device model ──────────── */

function mapDtmDevice(
  dev: DtmDevice,
  integrationId: string,
  cert: DtmDeviceCertificate | null,
): Record<string, unknown> {
  const certAlgo = cert ? normalizeCertAlgorithm(cert) : 'Unknown';
  const keyLen   = cert ? normalizeCertKeyLength(cert)  : 'Unknown';

  return {
    id: dev.id || uuidv4(),
    integrationId,
    deviceName: dev.name || 'Unknown Device',
    deviceType: 'IoT Device',
    manufacturer: 'DigiCert DTM',
    firmwareVersion: 'N/A',
    certAlgorithm: certAlgo,
    keyLength: keyLen,
    quantumSafe: isQuantumSafeAlgorithm(certAlgo),
    enrollmentStatus: mapEnrollmentStatus(dev.status),
    lastCheckin: dev.updated_on || dev.created_on || new Date().toISOString(),
    source: 'DigiCert DTM',
    deviceGroup: dev.device_group?.name || null,
    operationalStatus: dev.operational_status || 'Unknown',
    connected: dev.connected ?? false,
  };
}

/* ── Fetch device certificates as standalone Certificate model records ── */

export async function fetchDeviceCertificatesFromDtm(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const auth = resolveAuth(config);

  if (!auth.baseUrl || (!auth.apiKey && !auth.accessToken) || !auth.accountId) {
    return { success: false, data: [], errors: ['Missing credentials for DTM certificate fetch'] };
  }

  const errors: string[] = [];
  const allCerts: Record<string, unknown>[] = [];

  /* First get all device IDs */
  let offset = 0;
  let hasMore = true;
  const deviceIds: string[] = [];

  while (hasMore) {
    try {
      const url = `${auth.baseUrl}/${DTM_DEVICE_PATH}?limit=${DTM_PAGE_SIZE}&offset=${offset}&account_id=${auth.accountId}`;
      const raw = await dtmRequest<unknown>(url, auth);
      const { items: devices, hasNext: morePages } = extractRecords<DtmDevice>(raw, 'certFetch-deviceList');
      if (devices.length === 0) { hasMore = false; break; }
      for (const d of devices) { if (d.id) deviceIds.push(d.id); }
      offset += DTM_PAGE_SIZE;
      if (!morePages && devices.length < DTM_PAGE_SIZE) hasMore = false;
    } catch (err) {
      errors.push(`Failed to list devices: ${(err as Error).message}`);
      hasMore = false;
    }
  }

  console.log(`[DigiCert DTM] Fetching all certificates via v2 API…`);

  /* Fetch all certs in one paginated sweep */
  let certOffset = 0;
  let certHasMore = true;
  const CERT_PAGE = 100;

  while (certHasMore) {
    try {
      const url = `${auth.baseUrl}/${DTM_CERT_PATH}?limit=${CERT_PAGE}&offset=${certOffset}`;
      const raw = await dtmRequest<unknown>(url, auth);
      const { items: certs, hasNext } = extractRecords<DtmDeviceCertificate>(raw, `certStandalone(offset=${certOffset})`);
      if (certs.length === 0) { certHasMore = false; break; }

      for (const c of certs) {
        const devId = c.device?.id || c.device_id || '';
        if (devId && (deviceIds.length === 0 || deviceIds.includes(devId))) {
          allCerts.push(mapDtmCertificate(c, integrationId, devId));
        }
      }

      certOffset += CERT_PAGE;
      if (!hasNext && certs.length < CERT_PAGE) certHasMore = false;
    } catch (err) {
      errors.push(`Failed to fetch certs at offset ${certOffset}: ${(err as Error).message}`);
      certHasMore = false;
    }
  }

  console.log(`[DigiCert DTM] Fetched ${allCerts.length} certificate(s) across ${deviceIds.length} devices`);
  return { success: errors.length === 0 || allCerts.length > 0, data: allCerts, errors };
}

/** Map a DTM certificate to our Certificate model */
function mapDtmCertificate(
  cert: DtmDeviceCertificate,
  integrationId: string,
  deviceId: string,
): Record<string, unknown> {
  const raw = cert as Record<string, unknown>;
  const algo = normalizeCertAlgorithm(cert);
  const keyLen = normalizeCertKeyLength(cert);

  // Handle v2 API field names: valid_from, valid_to (and fallbacks)
  const notAfter  = cert.valid_to || cert.not_after || cert.valid_till
    || raw['validTo'] as string | undefined
    || raw['notAfter'] as string | undefined
    || raw['expiry_date'] as string | undefined
    || raw['expires'] as string | undefined;
  const notBefore = cert.valid_from || cert.not_before
    || raw['validFrom'] as string | undefined
    || raw['notBefore'] as string | undefined
    || raw['issued_date'] as string | undefined;

  // Determine status from multiple possible fields
  const statusStr = (cert.status || raw['statusName'] || raw['state'] || '') as string;
  let status: string = 'Issued';
  if (statusStr) {
    const s = statusStr.toUpperCase();
    if (s === 'REVOKED') status = 'Revoked';
    else if (s === 'EXPIRED') status = 'Expired';
    else if (s === 'ACTIVE' || s === 'ISSUED' || s === 'VALID') status = 'Issued';
    else if (s === 'PENDING') status = 'Pending';
  }
  // Auto-detect expired from date
  if (notAfter && new Date(notAfter) < new Date()) status = 'Expired';

  const sigAlgo = cert.signature_algorithm || cert.signature_hash_algorithm
    || raw['signatureAlgorithm'] as string | undefined
    || raw['signatureHashAlgorithm'] as string | undefined
    || raw['sig_algorithm'] as string | undefined
    || 'Unknown';

  const commonName = cert.common_name || cert.subject
    || raw['commonName'] as string | undefined
    || raw['cn'] as string | undefined
    || `Device ${deviceId.slice(0, 8)}`;

  const serialNumber = cert.serial_number || cert.thumbprint_sha256 || cert.thumbprint
    || raw['serialNumber'] as string | undefined
    || raw['thumbprint_sha256'] as string | undefined
    || raw['fingerprint'] as string | undefined
    || uuidv4().replace(/-/g, '').substring(0, 20);

  const issuer = cert.issuer_common_name || cert.issuer
    || raw['issuer_common_name'] as string | undefined
    || raw['issuerCommonName'] as string | undefined
    || raw['issuerName'] as string | undefined
    || raw['issuer_name'] as string | undefined
    || 'DigiCert';

  return {
    id: cert.id || raw['certId'] || raw['certificate_id'] || uuidv4(),
    integrationId,
    commonName,
    serialNumber,
    keyAlgorithm: algo,
    keyLength: keyLen,
    signatureAlgorithm: sigAlgo,
    caVendor: issuer,
    status,
    quantumSafe: isQuantumSafeAlgorithm(algo),
    source: 'DigiCert DTM',
    expiryDate: notAfter || null,
    issuedDate: notBefore || null,
  };
}

/* ── Test connection ───────────────────────────────────────── */

export async function testDtmConnection(
  config: ConnectorConfig,
): Promise<{ success: boolean; message: string }> {
  const auth = resolveAuth(config);

  if (!auth.baseUrl || (!auth.apiKey && !auth.accessToken)) {
    return { success: false, message: 'Missing API Base URL or credentials (API Key or Access Token)' };
  }

  if (!auth.accountId) {
    return { success: false, message: 'Missing Account ID — required for the DTM API' };
  }

  const authMethod = auth.accessToken ? 'Bearer token' : 'API key';
  console.log(`[DigiCert DTM] Testing connection (auth: ${authMethod})…`);

  /* Step 1: Probe DTM device endpoint directly */
  try {
    const url = `${auth.baseUrl}/${DTM_DEVICE_PATH}?limit=1&offset=0&account_id=${auth.accountId}`;
    const raw = await dtmRequest<unknown>(url, auth);
    const { items } = extractRecords<DtmDevice>(raw);
    // For count, prefer the `total` field from paginated response, otherwise use array length
    const count = (raw && typeof raw === 'object' && !Array.isArray(raw) && 'total' in (raw as any))
      ? (raw as any).total
      : items.length;
    return {
      success: true,
      message: `Connected to DigiCert Device Trust Manager (${authMethod})${count > 0 ? ` — ${count} device(s) found` : ''}`,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    /* Step 2: If DTM probe failed, try generic auth endpoint as fallback */
    try {
      const accountUrl = `${auth.baseUrl}/account/api/v1/user`;
      await dtmRequest<{ email?: string }>(accountUrl, auth);
      return {
        success: true,
        message: `Authenticated OK, but DTM device endpoint returned an error: ${message.slice(0, 120)}`,
      };
    } catch {
      return { success: false, message: `Connection failed: ${message}` };
    }
  }
}
