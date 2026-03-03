/**
 * DigiCert Device Trust Manager (DTM) Connector
 *
 * Fetches IoT/OT devices from DigiCert ONE's Device Trust Manager API.
 *
 * API docs: https://docs.digicert.com/en/device-trust-manager.html
 *
 * Endpoint: GET /devicetrustmanager/api/v4/device?limit=N&offset=O&account_id=X
 *
 * Each device record includes:
 *   - name, id, status (REGISTERED / PROVISIONED / etc.)
 *   - device_group { id, name }
 *   - operational_status (ENABLED / DISABLED)
 *   - connected (boolean)
 *   - created_on / updated_on
 *   - mqtt_endpoints []
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { digicertRequest } from './httpClient';

/* ── Constants ─────────────────────────────────────────────── */

const DTM_PAGE_SIZE = 100;
const DTM_MAX_PAGES = 50; // safety cap → max 5 000 devices
const DTM_API_PATH = 'devicetrustmanager/api/v4/device';

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

/* ── Main fetcher ──────────────────────────────────────────── */

export async function fetchDevicesFromDtm(
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
      errors: ['Missing API Base URL or API Key for DTM connector'],
    };
  }

  if (!accountId) {
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

  console.log(`[DigiCert DTM] Fetching devices from ${baseUrl}/${DTM_API_PATH}`);

  while (hasMore && pageCount < DTM_MAX_PAGES) {
    try {
      const url = `${baseUrl}/${DTM_API_PATH}?limit=${DTM_PAGE_SIZE}&offset=${offset}&account_id=${accountId}`;
      const raw = await digicertRequest<DtmDeviceListResponse | { items?: DtmDevice[]; total?: number }>(
        url,
        apiKey,
        accountId,
        rejectUnauthorized,
      );

      // The DTM API returns either a bare array or { items: [...], total: N }
      let devices: DtmDevice[];
      if (Array.isArray(raw)) {
        devices = raw;
      } else if (raw && Array.isArray((raw as any).items)) {
        devices = (raw as any).items;
      } else {
        devices = [];
      }

      if (devices.length === 0) {
        hasMore = false;
        break;
      }

      for (const dev of devices) {
        allDevices.push(mapDtmDevice(dev, integrationId));
      }

      pageCount++;
      offset += DTM_PAGE_SIZE;
      if (devices.length < DTM_PAGE_SIZE) {
        hasMore = false;
      }

      console.log(`[DigiCert DTM] Page ${pageCount}: fetched ${devices.length} devices (total so far: ${allDevices.length})`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`DTM API error at offset ${offset}: ${msg}`);
      hasMore = false;
    }
  }

  console.log(`[DigiCert DTM] Fetch complete: ${allDevices.length} devices in ${pageCount} pages, ${errors.length} errors`);

  return {
    success: errors.length === 0 || allDevices.length > 0,
    data: allDevices,
    errors,
  };
}

/* ── Map a single DTM device to our Device model ──────────── */

function mapDtmDevice(dev: DtmDevice, integrationId: string): Record<string, unknown> {
  return {
    id: dev.id || uuidv4(),
    integrationId,
    deviceName: dev.name || 'Unknown Device',
    deviceType: 'IoT Device',                               // DTM doesn't provide type; default
    manufacturer: 'Unknown',                                 // Not available from list endpoint
    firmwareVersion: 'N/A',                                  // Not available from list endpoint
    certAlgorithm: 'Unknown',                                // Would need per-device cert fetch
    keyLength: 'Unknown',                                    // Would need per-device cert fetch
    quantumSafe: false,                                      // Default; unknown without cert info
    enrollmentStatus: mapEnrollmentStatus(dev.status),
    lastCheckin: dev.updated_on || dev.created_on || new Date().toISOString(),
    source: 'DigiCert DTM',
    deviceGroup: dev.device_group?.name || null,
    operationalStatus: dev.operational_status || 'Unknown',
    connected: dev.connected ?? false,
  };
}

/* ── Test connection ───────────────────────────────────────── */

export async function testDtmConnection(
  config: ConnectorConfig,
): Promise<{ success: boolean; message: string }> {
  const baseUrl = (config.apiBaseUrl || '').replace(/\/+$/, '');
  const apiKey = config.apiKey || '';
  const accountId = config.accountId;
  const rejectUnauthorized = config.allowInsecureTls !== 'true';

  if (!baseUrl || !apiKey) {
    return { success: false, message: 'Missing API Base URL or API Key' };
  }

  if (!accountId) {
    return { success: false, message: 'Missing Account ID — required for the DTM API' };
  }

  /* Step 1: Verify auth via Account API */
  try {
    const accountUrl = `${baseUrl}/account/api/v1/user`;
    console.log(`[DigiCert DTM] Testing auth via ${accountUrl}`);
    const user = await digicertRequest<{ email?: string }>(
      accountUrl, apiKey, accountId, rejectUnauthorized,
    );
    console.log(`[DigiCert DTM] Auth OK — user: ${user?.email || 'unknown'}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Authentication failed: ${message}` };
  }

  /* Step 2: Probe DTM device endpoint */
  try {
    const url = `${baseUrl}/${DTM_API_PATH}?limit=1&offset=0&account_id=${accountId}`;
    const raw = await digicertRequest<DtmDeviceListResponse | { total?: number }>(
      url, apiKey, accountId, rejectUnauthorized,
    );

    const count = Array.isArray(raw) ? raw.length : (raw as any)?.total ?? 0;
    return {
      success: true,
      message: `Connected to DigiCert Device Trust Manager — device endpoint reachable${count > 0 ? ` (${count} device(s) found)` : ''}`,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      success: true,          // Auth worked; DTM endpoint may be unreachable
      message: `Authenticated, but DTM device endpoint returned an error: ${message.slice(0, 120)}`,
    };
  }
}
