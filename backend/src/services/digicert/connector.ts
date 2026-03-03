/**
 * DigiCert TLM — Certificate Fetch Connector
 *
 * Main function to fetch certificates from DigiCert ONE API.
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { PAGE_SIZE, MAX_PAGES, CERTIFICATE_API_PATHS } from './constants';
import { digicertRequest } from './httpClient';
import { isQuantumSafe, normaliseAlgorithm, normaliseStatus, extractCaVendor, detectCertificateApiPath, str } from './utils';
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
  let useAccountInQuery = false;
  let certExtraParams: Record<string, string> | undefined;

  if (explicitApiPath) {
    certApiPath = explicitApiPath;
    // If explicit path ends with /search, use POST
    certApiMethod = explicitApiPath.endsWith('/search') ? 'POST' : 'GET';
    // ui-api paths need account as query param
    useAccountInQuery = explicitApiPath.includes('ui-api');
    console.log(`[DigiCert TLM] Using explicit apiPath: ${certApiPath} (${certApiMethod})`);
  } else {
    // Auto-detect working endpoint
    console.log(`[DigiCert TLM] No explicit apiPath configured — auto-detecting…`);
    const detected = await detectCertificateApiPath(baseUrl, apiKey, accountId, rejectUnauthorized);
    if (detected) {
      certApiPath = detected.path;
      certApiMethod = detected.method;
      useAccountInQuery = !!detected.accountInQuery;
      certExtraParams = detected.extraParams;
      console.log(`[DigiCert TLM] Auto-detected working path: ${certApiPath} (${certApiMethod})${useAccountInQuery ? ' [account-in-query]' : ''}`);
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

  // For ui-api routes, pass accountId as query param; for standard API, use header
  const headerAccountId = useAccountInQuery ? undefined : accountId;

  try {
    while (hasMore && offset / PAGE_SIZE < MAX_PAGES) {
      // Build URL with pagination params
      const url = new URL(`${baseUrl}/${certApiPath}`);
      let response: DigiCertListResponse | DigiCertCertificate[];

      // Add account query param for ui-api routes
      if (useAccountInQuery && accountId) {
        url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
      }
      // Add extra query params (e.g. status=issued, unique_certificate_view=true)
      if (certExtraParams) {
        for (const [k, v] of Object.entries(certExtraParams)) {
          url.searchParams.set(k, v);
        }
      }

      if (certApiMethod === 'POST') {
        // POST search: pagination in JSON body
        const body: Record<string, unknown> = { offset, limit: PAGE_SIZE };
        if (divisionId) body.division_id = divisionId;
        console.log(`[DigiCert TLM] POST search page offset=${offset} limit=${PAGE_SIZE}`);
        response = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, headerAccountId, rejectUnauthorized, 'POST', JSON.stringify(body),
        );
      } else {
        // GET: pagination in query string
        url.searchParams.set('offset', String(offset));
        url.searchParams.set('limit', String(PAGE_SIZE));
        if (divisionId) url.searchParams.set('division_id', divisionId);
        console.log(`[DigiCert TLM] GET page offset=${offset} limit=${PAGE_SIZE}`);
        response = await digicertRequest<DigiCertListResponse | DigiCertCertificate[]>(
          url.toString(), apiKey, headerAccountId, rejectUnauthorized,
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
        const sigAlg = str(cert.signature_algorithm) || str(cert.signing_algorithm) || null;
        const qSafe = isQuantumSafe(keyAlgorithm) || isQuantumSafe(sigAlg || '');

        // Extract commonName with smart fallbacks for certs missing the field
        const subjectObj = (typeof cert.subject === 'object' && cert.subject) ? cert.subject as Record<string, unknown> : null;
        const commonName = (
          str(cert.common_name)
          || (subjectObj ? str(subjectObj.common_name) : '')
          || str(cert.organization_unit)
          || str(cert.organization_name)
          || 'Unknown'
        ).slice(0, 255);

        const mapped = {
          id: uuidv4(),
          integrationId,
          commonName,
          caVendor: extractCaVendor(cert).slice(0, 100),
          status: normaliseStatus(str(cert.status) || undefined),
          keyAlgorithm: (keyAlgorithm || 'Unknown').slice(0, 50),
          keyLength: (keyLength || 'Unknown').slice(0, 50),
          quantumSafe: qSafe,
          source: 'DigiCert TLM',
          expiryDate: str(cert.valid_till) || str(cert.valid_to) || null,
          serialNumber: str(cert.serial_number).slice(0, 100) || null,
          signatureAlgorithm: sigAlg?.slice(0, 100) || null,
        };

        // Debug: log first 3 cert mappings so we can verify field extraction
        if (allCerts.length < 3) {
          console.log(`[DigiCert TLM] Cert #${allCerts.length + 1} mapping:`, JSON.stringify({
            raw: { common_name: cert.common_name, key_type: cert.key_type, key_size: cert.key_size, key_length: (cert as any).key_length, signing_algorithm: (cert as any).signing_algorithm, signature_algorithm: cert.signature_algorithm, valid_to: (cert as any).valid_to, valid_till: cert.valid_till, ca_vendor: (cert as any).ca_vendor, status: cert.status },
            mapped: { commonName: mapped.commonName, keyAlgorithm: mapped.keyAlgorithm, keyLength: mapped.keyLength, signatureAlgorithm: mapped.signatureAlgorithm, caVendor: mapped.caVendor, expiryDate: mapped.expiryDate, quantumSafe: mapped.quantumSafe, status: mapped.status },
          }, null, 2));
        }

        allCerts.push(mapped);
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
