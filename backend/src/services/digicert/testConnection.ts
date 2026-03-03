/**
 * DigiCert TLM — Connection Test
 *
 * Tests the DigiCert ONE API connection by:
 *   1. Verifying auth via the Account API  (/account/api/v1/user)
 *   2. Probing for a working certificate endpoint
 *
 * Returns success if at least auth works.
 */
import type { ConnectorConfig } from '../connectors';
import { ACCOUNT_API_PATH } from './constants';
import { digicertRequest } from './httpClient';
import { detectCertificateApiPath } from './utils';
import type { DigiCertUserResponse } from './types';

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
    const isUiApi = explicitApiPath.includes('ui-api');
    const headerAcct = isUiApi ? undefined : accountId;
    try {
      const url = new URL(`${baseUrl}/${explicitApiPath}`);
      const isSearchPath = explicitApiPath.endsWith('/search');
      if (isUiApi && accountId) {
        url.searchParams.set('account', JSON.stringify({ id: accountId, name: accountId }));
      }
      if (isSearchPath) {
        await digicertRequest<unknown>(url.toString(), apiKey, headerAcct, rejectUnauthorized, 'POST', JSON.stringify({ offset: 0, limit: 1 }));
      } else {
        url.searchParams.set('offset', '0');
        url.searchParams.set('limit', '1');
        await digicertRequest<unknown>(url.toString(), apiKey, headerAcct, rejectUnauthorized);
      }
      certEndpointStatus = `Certificate endpoint (${explicitApiPath}) is reachable.`;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      certEndpointStatus = `⚠ Certificate endpoint (${explicitApiPath}) returned an error: ${msg.slice(0, 100)}. Sync may fail.`;
    }
  } else {
    const detected = await detectCertificateApiPath(baseUrl, apiKey, accountId, rejectUnauthorized);
    if (detected) {
      certEndpointStatus = `Certificate endpoint auto-detected: ${detected.method} /${detected.path}`;
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
