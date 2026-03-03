/**
 * DigiCert TLM — Endpoint Fetch Connector
 *
 * Fetches automatable endpoints from the DigiCert ONE inventory API.
 * API:  GET /mpki/api/v1/inventory/endpoint/automatable
 *       (browser uses /mpki/ui-api/… but the service API uses /mpki/api/…)
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { PAGE_SIZE, MAX_PAGES, ENDPOINT_API_PATHS } from './constants';
import type { EndpointApiCandidate } from './constants';
import { digicertRequest } from './httpClient';
import { isQuantumSafe } from './utils';
import type { DigiCertEndpoint, DigiCertEndpointListResponse } from './types';

export async function fetchEndpointsFromDigiCert(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const baseUrl = (config.apiBaseUrl || '').replace(/\/+$/, '');
  const apiKey = config.apiKey || '';
  const accountId = config.accountId;
  const rejectUnauthorized = config.allowInsecureTls !== 'true';

  if (!baseUrl || !apiKey) {
    return {
      success: false,
      data: [],
      errors: ['Missing apiBaseUrl or apiKey in integration config'],
    };
  }

  const allEndpoints: Record<string, unknown>[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  let offset = 0;
  let totalFetched = 0;
  let hasMore = true;

  console.log(`[DigiCert TLM] Starting endpoint fetch from ${baseUrl}`);

  /* ── Find a working endpoint API path ────────────────────── */
  let endpointApiPath: string | null = null;
  let useAccountInQuery = false;
  const explicitEndpointPath = (config as Record<string, string>).endpointApiPath?.replace(/^\/+|\/+$/g, '');

  if (explicitEndpointPath) {
    endpointApiPath = explicitEndpointPath;
    useAccountInQuery = explicitEndpointPath.includes('ui-api');
    console.log(`[DigiCert TLM] Using explicit endpointApiPath: ${endpointApiPath}`);
  } else {
    for (const candidate of ENDPOINT_API_PATHS) {
      try {
        const url = new URL(`${baseUrl}/${candidate.path}`);
        url.searchParams.set('offset', '0');
        url.searchParams.set('limit', '1');
        if (candidate.accountInQuery && accountId) {
          url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
        }
        const headerAcct = candidate.accountInQuery ? undefined : accountId;
        console.log(`[DigiCert TLM] Probing endpoint path: GET ${candidate.path}`);
        await digicertRequest<unknown>(url.toString(), apiKey, headerAcct, rejectUnauthorized);
        endpointApiPath = candidate.path;
        useAccountInQuery = !!candidate.accountInQuery;
        console.log(`[DigiCert TLM] Endpoint API found: ${candidate.path}${useAccountInQuery ? ' [account-in-query]' : ''}`);
        break;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`${candidate.path} - ${msg}`);
        console.log(`[DigiCert TLM] Endpoint probe failed: ${candidate.path} — ${msg}`);
      }
    }
  }

  if (!endpointApiPath) {
    const msg = `No working endpoint API found on ${baseUrl}. This is non-fatal — certificate import will still proceed.`;
    console.warn(`[DigiCert TLM] ${msg}`);
    return { success: true, data: [], errors: [], meta: { warnings: [msg] } };
  }

  /* ── Paginated fetch ─────────────────────────────────────── */
  const headerAccountId = useAccountInQuery ? undefined : accountId;

  try {
    while (hasMore && offset / PAGE_SIZE < MAX_PAGES) {
      const url = new URL(`${baseUrl}/${endpointApiPath}`);
      url.searchParams.set('offset', String(offset));
      url.searchParams.set('limit', String(PAGE_SIZE));
      if (useAccountInQuery && accountId) {
        url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
      }

      console.log(`[DigiCert TLM] Fetching endpoints offset=${offset} limit=${PAGE_SIZE}`);
      const response = await digicertRequest<DigiCertEndpointListResponse | DigiCertEndpoint[]>(
        url.toString(), apiKey, headerAccountId, rejectUnauthorized,
      );

      let endpoints: DigiCertEndpoint[];
      let total: number | undefined;

      if (Array.isArray(response)) {
        endpoints = response;
        total = undefined;
      } else {
        endpoints = response.items || [];
        total = response.total;
      }

      if (endpoints.length === 0) {
        hasMore = false;
        break;
      }

      for (const ep of endpoints) {
        const keyAlgo = ep.key_algorithm || ep.certificate_key_algorithm || '';
        const cipherSuite = ep.cipher_suite || ep.tls_cipher_suite || '';
        const tlsVersion = ep.tls_version || ep.protocol_version || (ep as Record<string, unknown>).protocols as string || '';
        const keyAgreement = extractKeyAgreement(cipherSuite, tlsVersion);
        const qSafe = isQuantumSafe(keyAlgo) || isQuantumSafe(keyAgreement);

        /* ── Extract new inventory fields ──────────────────── */
        const raw = ep as Record<string, unknown>;
        const securityRating  = stringOrNull(raw.security_rating);
        const automationStatus = stringOrNull(raw.automation_status);
        const caVendor        = stringOrNull(raw.ca_vendor);
        const validTo         = stringOrNull(raw.valid_to);
        const osName          = stringOrNull(raw.os_name);
        const sensorName      = stringOrNull(raw.sensor_name);
        const domainName      = stringOrNull(raw.domain_name);

        const mapped = {
          id: uuidv4(),
          integrationId,
          hostname: (ep.common_name || ep.hostname || ep.ip || 'Unknown').slice(0, 255),
          ipAddress: (ep.ip || ep.ip_address || '0.0.0.0').slice(0, 255),
          port: ep.port || 443,
          tlsVersion: (tlsVersion || 'Unknown').slice(0, 20),
          cipherSuite: (cipherSuite || 'Unknown').slice(0, 255),
          keyAgreement: (keyAgreement || 'Unknown').slice(0, 50),
          quantumSafe: qSafe,
          source: 'DigiCert TLM',
          lastScanned: ep.last_scan_date || ep.last_checked || new Date().toISOString(),
          certCommonName: (ep.common_name || ep.certificate_common_name || null)?.slice(0, 255) || null,
          securityRating: securityRating?.slice(0, 50) || null,
          automationStatus: automationStatus?.slice(0, 50) || null,
          caVendor: caVendor?.slice(0, 100) || null,
          expiryDate: validTo?.slice(0, 100) || null,
          osName: osName?.slice(0, 255) || null,
          sensorName: sensorName?.slice(0, 255) || null,
          domainName: domainName?.slice(0, 255) || null,
        };

        // Debug: log first 3 endpoint mappings
        if (allEndpoints.length < 3) {
          console.log(`[DigiCert TLM] Endpoint #${allEndpoints.length + 1} mapping:`, JSON.stringify({
            raw: { common_name: ep.common_name, ip: ep.ip, port: ep.port, security_rating: raw.security_rating, automation_status: raw.automation_status, ca_vendor: raw.ca_vendor, valid_to: raw.valid_to, os_name: raw.os_name, sensor_name: raw.sensor_name },
            mapped: { hostname: mapped.hostname, ipAddress: mapped.ipAddress, securityRating: mapped.securityRating, automationStatus: mapped.automationStatus, caVendor: mapped.caVendor, expiryDate: mapped.expiryDate, osName: mapped.osName },
          }, null, 2));
        }

        allEndpoints.push(mapped);
      }

      totalFetched += endpoints.length;
      offset += PAGE_SIZE;

      if (total !== undefined && totalFetched >= total) hasMore = false;
      if (endpoints.length < PAGE_SIZE) hasMore = false;
    }

    console.log(`[DigiCert TLM] Fetched ${allEndpoints.length} endpoints total`);

    return {
      success: true,
      data: allEndpoints,
      errors,
      meta: {
        totalFetched: allEndpoints.length,
        source: 'DigiCert ONE API',
        baseUrl,
        warnings,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[DigiCert TLM] Endpoint fetch error: ${message}`);
    return {
      success: true, // non-fatal — certificates may still have succeeded
      data: allEndpoints,
      errors: [message],
      meta: { warnings: [...warnings, message] },
    };
  }
}

/* ── Helpers ─────────────────────────────────────────────────── */

/** Safely coerce a raw API value to string or null */
function stringOrNull(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === 'string') return v || null;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return null;
}

/** Best-effort extraction of key agreement from cipher suite string */
function extractKeyAgreement(cipherSuite: string, tlsVersion: string): string {
  const upper = (cipherSuite || '').toUpperCase();
  if (upper.includes('ML-KEM') || upper.includes('MLKEM')) return 'ML-KEM';
  if (upper.includes('X25519')) return 'X25519';
  if (upper.includes('X448')) return 'X448';
  if (upper.includes('ECDHE')) return 'ECDHE';
  if (upper.includes('DHE')) return 'DHE';
  // TLS 1.3 defaults to ECDHE
  if (tlsVersion.includes('1.3')) return 'ECDHE';
  return 'RSA';
}
