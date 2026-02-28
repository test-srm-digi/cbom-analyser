/**
 * JIRA Service — Creates issues via the Atlassian JIRA REST API v3
 *
 * Uses Basic Auth (email + API token) as per:
 *   https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/
 */

/* ── Types ─────────────────────────────────────────────────── */

export interface JiraConnectorConfig {
  email: string;
  apiToken: string;
  projectKey: string;
  defaultIssueType?: string;   // "Bug" | "Story" | "Task"
  defaultAssignee?: string;    // Atlassian account ID or email
  defaultBoard?: string;       // board ID
  defaultLabels?: string[];    // default labels applied
  defaultPriority?: string;    // "Critical" | "High" | "Medium" | "Low"
}

export interface JiraCreateIssuePayload {
  projectKey: string;
  issueType: string;
  summary: string;
  description: string;
  priority?: string;           // "Highest" | "High" | "Medium" | "Low" | "Lowest"
  labels?: string[];
  assigneeId?: string;         // Atlassian account ID
}

export interface JiraIssueResult {
  success: boolean;
  key?: string;                // e.g. "CRYPTO-1234"
  id?: string;
  self?: string;
  url?: string;                // browsable URL
  error?: string;
}

/* ── Priority map ──────────────────────────────────────────── */
const PRIORITY_MAP: Record<string, string> = {
  Critical: 'Highest',
  High: 'High',
  Medium: 'Medium',
  Low: 'Low',
};

/* ── Create issue ──────────────────────────────────────────── */

export async function createJiraIssue(
  baseUrl: string,
  config: JiraConnectorConfig,
  payload: JiraCreateIssuePayload,
): Promise<JiraIssueResult> {
  const url = `${baseUrl.replace(/\/+$/, '')}/rest/api/3/issue`;

  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');

  // Build ADF (Atlassian Document Format) body
  const body: Record<string, unknown> = {
    fields: {
      project: { key: payload.projectKey },
      issuetype: { name: payload.issueType },
      summary: payload.summary,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [{ type: 'text', text: payload.description }],
          },
        ],
      },
      ...(payload.priority ? { priority: { name: PRIORITY_MAP[payload.priority] ?? payload.priority } } : {}),
      ...(payload.labels?.length ? { labels: payload.labels } : {}),
      ...(payload.assigneeId ? { assignee: { accountId: payload.assigneeId } } : {}),
    },
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

    const json = await response.json() as Record<string, unknown>;

    if (!response.ok) {
      const errors = (json as Record<string, unknown>).errors ?? json;
      console.error('JIRA API error:', response.status, errors);
      return {
        success: false,
        error: `JIRA API ${response.status}: ${JSON.stringify(errors)}`,
      };
    }

    const key = json.key as string;
    const browsableUrl = `${baseUrl.replace(/\/+$/, '')}/browse/${key}`;

    return {
      success: true,
      key,
      id: json.id as string,
      self: json.self as string,
      url: browsableUrl,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('JIRA API call failed:', message);
    return { success: false, error: message };
  }
}

/* ── Search assignable users (for autocomplete) ───────────── */

export interface JiraUser {
  accountId: string;
  displayName: string;
  emailAddress?: string;
  avatarUrls?: Record<string, string>;
}

export async function searchJiraUsers(
  baseUrl: string,
  config: JiraConnectorConfig,
  query: string,
): Promise<JiraUser[]> {
  const url = `${baseUrl.replace(/\/+$/, '')}/rest/api/3/user/search?query=${encodeURIComponent(query)}&maxResults=10`;
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) return [];
    return (await res.json()) as JiraUser[];
  } catch {
    return [];
  }
}

/* ── Fetch projects (user's accessible & recent projects) ── */

export interface JiraProject {
  id: string;
  key: string;
  name: string;
  isMember?: boolean;      // true = user recently accessed / is lead
}

/**
 * Fetches projects the authenticated user has permission to browse.
 * Merges with the "recent" projects list so the user's own / recently-used
 * projects are prioritised and flagged with `isMember: true`.
 */
export async function fetchJiraProjects(
  baseUrl: string,
  config: JiraConnectorConfig,
): Promise<JiraProject[]> {
  const base = baseUrl.replace(/\/+$/, '');
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');
  const headers = { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' };

  // 1.  Fetch only projects that have BROWSE_PROJECTS + are live (not archived)
  //     JIRA Cloud's /project/search honours the caller's permissions automatically.
  let allProjects: JiraProject[] = [];
  try {
    let startAt = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const url = `${base}/rest/api/3/project/search?action=browse&status=live&maxResults=50&startAt=${startAt}`;
      const res = await fetch(url, { headers });
      if (!res.ok) break;
      const json = await res.json() as { values?: JiraProject[]; isLast?: boolean };
      const values = json.values ?? [];
      allProjects.push(...values.map((p) => ({ id: p.id, key: p.key, name: p.name })));
      if (json.isLast || values.length === 0) break;
      startAt += values.length;
    }
  } catch { /* return whatever collected */ }

  // 2.  Fetch recently-accessed projects (max 20) to mark them as "member"
  const recentKeys = new Set<string>();
  try {
    const res = await fetch(`${base}/rest/api/3/project/recent?maxResults=20`, { headers });
    if (res.ok) {
      const recent = (await res.json()) as Array<{ key: string }>;
      for (const r of recent) recentKeys.add(r.key);
    }
  } catch { /* non-critical */ }

  // 3.  Also get "myself" to grab accountId for lead check
  let myAccountId: string | null = null;
  try {
    const res = await fetch(`${base}/rest/api/3/myself`, { headers });
    if (res.ok) {
      const me = (await res.json()) as { accountId?: string };
      myAccountId = me.accountId ?? null;
    }
  } catch { /* non-critical */ }

  // 4.  Cross-reference: if a project key is in "recent" list → isMember = true
  //     Sort so member projects come first.
  for (const p of allProjects) {
    if (recentKeys.has(p.key)) p.isMember = true;
  }

  // 5.  If we have a lead match available, try enriching via /project/{key}
  //     (skip this extra call for large lists – only when < 30 projects)
  if (myAccountId && allProjects.length <= 30) {
    // We already know the lead from the search payload if we use expand=lead,
    // but the search endpoint doesn't reliably return it. Instead, since we
    // already have recent projects, those are a good proxy for "member".
  }

  // Stable sort: member projects first, then alphabetical by key
  allProjects.sort((a, b) => {
    if (a.isMember && !b.isMember) return -1;
    if (!a.isMember && b.isMember) return 1;
    return a.key.localeCompare(b.key);
  });

  return allProjects;
}

/* ── Test connection ──────────────────────────────────────── */

export async function testJiraConnection(
  baseUrl: string,
  config: JiraConnectorConfig,
): Promise<{ ok: boolean; user?: string; error?: string }> {
  const url = `${baseUrl.replace(/\/+$/, '')}/rest/api/3/myself`;
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');

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

    const json = await res.json() as { displayName?: string };
    return { ok: true, user: json.displayName ?? 'Unknown' };
  } catch (err: unknown) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/* ── Fetch boards (JIRA Agile REST API) ───────────────────── */

export interface JiraBoard {
  id: number;
  name: string;
  type: string;           // "scrum" | "kanban" | "simple"
  projectKey?: string;    // project key if associated
}

/**
 * Fetches boards. When `projectKey` is supplied, only boards for that
 * project are returned (much smaller result set).
 */
export async function fetchJiraBoards(
  baseUrl: string,
  config: JiraConnectorConfig,
  projectKey?: string,
): Promise<JiraBoard[]> {
  const base = baseUrl.replace(/\/+$/, '');
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');
  const boards: JiraBoard[] = [];
  let startAt = 0;

  try {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      let url = `${base}/rest/agile/1.0/board?startAt=${startAt}&maxResults=50`;
      if (projectKey) url += `&projectKeyOrId=${encodeURIComponent(projectKey)}`;
      const res = await fetch(url, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json',
        },
      });

      if (!res.ok) break;

      const json = await res.json() as {
        values?: Array<{
          id: number;
          name: string;
          type: string;
          location?: { projectKey?: string };
        }>;
        isLast?: boolean;
      };

      const values = json.values ?? [];
      for (const b of values) {
        boards.push({
          id: b.id,
          name: b.name,
          type: b.type,
          projectKey: b.location?.projectKey,
        });
      }

      if (json.isLast || values.length === 0) break;
      startAt += values.length;
    }
  } catch {
    // return whatever we collected
  }

  return boards;
}

/* ── Fetch issue types for a specific project ─────────────── */

export interface JiraIssueType {
  id: string;
  name: string;
  subtask: boolean;
  description?: string;
  iconUrl?: string;
}

export async function fetchProjectIssueTypes(
  baseUrl: string,
  config: JiraConnectorConfig,
  projectKey: string,
): Promise<JiraIssueType[]> {
  const url = `${baseUrl.replace(/\/+$/, '')}/rest/api/3/project/${encodeURIComponent(projectKey)}`;
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) return [];
    const json = await res.json() as { issueTypes?: JiraIssueType[] };
    return (json.issueTypes ?? []).filter((t) => !t.subtask);
  } catch {
    return [];
  }
}

/* ── Fetch assignable users for a project ─────────────────── */

export async function fetchAssignableUsers(
  baseUrl: string,
  config: JiraConnectorConfig,
  projectKey: string,
): Promise<JiraUser[]> {
  const base = baseUrl.replace(/\/+$/, '');
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');
  const headers = { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' };

  try {
    // 1. Fetch all assignable users with pagination
    const allUsers: JiraUser[] = [];
    let startAt = 0;
    const pageSize = 200;
    let hasMore = true;

    while (hasMore) {
      const url = `${base}/rest/api/3/user/assignable/search?project=${encodeURIComponent(projectKey)}&startAt=${startAt}&maxResults=${pageSize}`;
      const res = await fetch(url, { headers });
      if (!res.ok) break;
      const page = (await res.json()) as JiraUser[];
      allUsers.push(...page);
      hasMore = page.length === pageSize;
      startAt += pageSize;
    }

    // 2. Fetch the currently authenticated user to ensure they're always present
    try {
      const myselfRes = await fetch(`${base}/rest/api/3/myself`, { headers });
      if (myselfRes.ok) {
        const me = (await myselfRes.json()) as JiraUser;
        if (me.accountId && !allUsers.some((u) => u.accountId === me.accountId)) {
          allUsers.unshift(me);
        }
      }
    } catch { /* ignore – best effort */ }

    // 3. Also search by the authenticated user's email to catch partial results
    try {
      const emailQuery = config.email.split('@')[0]; // username portion
      const searchUrl = `${base}/rest/api/3/user/search?query=${encodeURIComponent(emailQuery)}&maxResults=10`;
      const searchRes = await fetch(searchUrl, { headers });
      if (searchRes.ok) {
        const found = (await searchRes.json()) as JiraUser[];
        for (const u of found) {
          if (u.accountId && !allUsers.some((eu) => eu.accountId === u.accountId)) {
            allUsers.push(u);
          }
        }
      }
    } catch { /* ignore */ }

    return allUsers;
  } catch {
    return [];
  }
}
