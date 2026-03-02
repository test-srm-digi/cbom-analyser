/**
 * DigiCert TLM — Certificate Fetch Connector
 *
 * Main function to fetch certificates from DigiCert ONE API.
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { PAGE_SIZE, MAX_PAGES, CERTIFICATE_API_PATHS } from './constants';
import { digicertRequest } from './httpClient';
import { isQuantumSafe, normaliseAlgorithm, normaliseStatus, extractCaVendor, detectCertificateApiPath } from './utils';
import type { DigiCertCertificate, DigiCertListResponse } from './types';

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
  let certApiMethod: 'GET' | 'POST' = 'GET';
  if (explicitApiPath) {
    certApiPath = explicitApiPath;
    // If explicit path ends with /search, use POST
    certApiMethod = explicitApiPath.endsWith('/search') ? 'POST' : 'GET';
    console.log(`[DigiCert TLM] Using explicit apiPath: ${certApiPath} (${certApiMethod})`);
  } else {
    // Auto-detect working endpoint
    console.log(`[DigiCert TLM] No explicit apiPath configured — auto-detecting…`);
    const detected = await detectCertificateApiPath(baseUrl, apiKey, accountId, rejectUnauthorized);
    if (detected) {
      certApiPath = detected.path;
      certApiMethod = detected.method;
      console.log(`[DigiCert TLM] Auto-detected working path: ${certApiPath} (${certApiMethod})`);
    } else {
      // None of the probed paths worked — collect detailed diagnostics
      const triedPaths = CERTIFICATE_API_PATHS.map((c) => `  • ${c.method} /${c.path}`).join('\n');
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
      let response: DigiCertListResponse | DigiCertCertificate[];

      if (certApiMethod === 'POST') {
        // POST search: pagination in JSON body
        const body: Record<string, unknown> = { offset, limit: PAGE_SIZE };
        if (divisionId) body.division_id = divisionId;
        console.log(`[DigiCert TLM] POST search page offset=${offset} limit=${PAGE_SIZE}`);
        response = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, accountId, rejectUnauthorized, 'POST', JSON.stringify(body),
        );
      } else {
        // GET: pagination in query string
        url.searchParams.set('offset', String(offset));
        url.searchParams.set('limit', String(PAGE_SIZE));
        if (divisionId) url.searchParams.set('division_id', divisionId);
        console.log(`[DigiCert TLM] GET page offset=${offset} limit=${PAGE_SIZE}`);
        response = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, accountId, rejectUnauthorized,
        );
      }

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
