/**
 * ServiceNow Service — Creates incidents via the ServiceNow REST API (Table API)
 *
 * Uses Basic Auth (username + password/token):
 *   https://docs.servicenow.com/bundle/paris-application-development/page/integrate/inbound-rest/concept/c_RESTAPI.html
 */

/* ── Types ─────────────────────────────────────────────────── */

export interface ServiceNowConnectorConfig {
  username: string;
  password: string;            // or OAuth token
  defaultCategory?: string;
  defaultSubcategory?: string;
  defaultAssignmentGroup?: string;
  defaultImpact?: string;      // "1" | "2" | "3"
  defaultUrgency?: string;     // "1" | "2" | "3"
  defaultAssignee?: string;    // sys_id or username
}

export interface ServiceNowCreateIncidentPayload {
  short_description: string;
  description: string;
  category?: string;
  subcategory?: string;
  impact?: string;
  urgency?: string;
  assignment_group?: string;
  assigned_to?: string;
  caller_id?: string;
}

export interface ServiceNowIncidentResult {
  success: boolean;
  number?: string;             // e.g. "INC0012345"
  sys_id?: string;
  url?: string;                // browsable URL
  error?: string;
}

/* ── Priority / Impact map ─────────────────────────────────── */
const IMPACT_MAP: Record<string, string> = {
  'Critical': '1',
  'High':     '2',
  'Medium':   '3',
  'Low':      '3',
  '1 - Critical': '1',
  '2 - High': '2',
  '3 - Medium': '3',
  '4 - Low': '3',
};

/* ── Create incident ──────────────────────────────────────── */

export async function createServiceNowIncident(
  baseUrl: string,
  config: ServiceNowConnectorConfig,
  payload: ServiceNowCreateIncidentPayload,
): Promise<ServiceNowIncidentResult> {
  const url = `${baseUrl.replace(/\/+$/, '')}/api/now/table/incident`;
  const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');

  const body: Record<string, unknown> = {
    short_description: payload.short_description,
    description: payload.description,
    category: payload.category ?? config.defaultCategory ?? 'Security',
    subcategory: payload.subcategory ?? config.defaultSubcategory ?? 'Cryptography',
    impact: IMPACT_MAP[payload.impact ?? ''] ?? config.defaultImpact ?? '2',
    urgency: IMPACT_MAP[payload.urgency ?? ''] ?? config.defaultUrgency ?? '2',
    ...(payload.assignment_group ? { assignment_group: payload.assignment_group } : config.defaultAssignmentGroup ? { assignment_group: config.defaultAssignmentGroup } : {}),
    ...(payload.assigned_to ? { assigned_to: payload.assigned_to } : config.defaultAssignee ? { assigned_to: config.defaultAssignee } : {}),
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const json = await response.json() as { result?: Record<string, unknown>; error?: Record<string, unknown> };

    if (!response.ok) {
      console.error('ServiceNow API error:', response.status, json);
      return {
        success: false,
        error: `ServiceNow API ${response.status}: ${json.error?.message ?? JSON.stringify(json)}`,
      };
    }

    const result = json.result ?? {};
    const number = result.number as string;
    const sys_id = result.sys_id as string;
    const browsableUrl = `${baseUrl.replace(/\/+$/, '')}/nav_to.do?uri=incident.do?sys_id=${sys_id}`;

    return {
      success: true,
      number,
      sys_id,
      url: browsableUrl,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('ServiceNow API call failed:', message);
    return { success: false, error: message };
  }
}

/* ── Test connection ──────────────────────────────────────── */

export async function testServiceNowConnection(
  baseUrl: string,
  config: ServiceNowConnectorConfig,
): Promise<{ ok: boolean; user?: string; error?: string }> {
  const url = `${baseUrl.replace(/\/+$/, '')}/api/now/table/sys_user?sysparm_query=user_name=${encodeURIComponent(config.username)}&sysparm_limit=1&sysparm_fields=user_name,name`;
  const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }

    const json = await res.json() as { result?: Array<{ name?: string; user_name?: string }> };
    const user = json.result?.[0]?.name ?? json.result?.[0]?.user_name ?? config.username;
    return { ok: true, user };
  } catch (err: unknown) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/* ── Fetch assignment groups ──────────────────────────────── */

export interface ServiceNowGroup {
  sys_id: string;
  name: string;
}

export async function fetchServiceNowGroups(
  baseUrl: string,
  config: ServiceNowConnectorConfig,
): Promise<ServiceNowGroup[]> {
  const url = `${baseUrl.replace(/\/+$/, '')}/api/now/table/sys_user_group?sysparm_limit=50&sysparm_fields=sys_id,name&sysparm_query=active=true`;
  const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) return [];
    const json = await res.json() as { result?: ServiceNowGroup[] };
    return json.result ?? [];
  } catch {
    return [];
  }
}
