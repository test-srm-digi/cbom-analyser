/**
 * GitHub Service — Creates issues via the GitHub REST API v3
 *
 * Uses Personal Access Token (PAT) for authentication:
 *   https://docs.github.com/en/rest/issues/issues#create-an-issue
 */

/* ── Types ─────────────────────────────────────────────────── */

export interface GitHubConnectorConfig {
  token: string;               // Personal Access Token (PAT)
  owner: string;               // GitHub user or org  (e.g. "my-org")
  repo: string;                // Default repository  (e.g. "crypto-inventory")
  defaultLabels?: string[];    // Default labels applied to every issue
  defaultAssignee?: string;    // GitHub username auto-assigned
}

export interface GitHubCreateIssuePayload {
  owner: string;
  repo: string;
  title: string;
  body: string;
  labels?: string[];
  assignees?: string[];
}

export interface GitHubIssueResult {
  success: boolean;
  number?: number;             // e.g. 42
  url?: string;                // html_url — browsable
  error?: string;
}

/* ── Create issue ──────────────────────────────────────────── */

export async function createGitHubIssue(
  config: GitHubConnectorConfig,
  payload: GitHubCreateIssuePayload,
): Promise<GitHubIssueResult> {
  const url = `https://api.github.com/repos/${payload.owner}/${payload.repo}/issues`;

  const body = {
    title: payload.title,
    body: payload.body,
    labels: payload.labels ?? [],
    assignees: payload.assignees ?? [],
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify(body),
    });

    const json = await response.json() as Record<string, unknown>;

    if (!response.ok) {
      console.error('GitHub API error:', response.status, json);
      return {
        success: false,
        error: `GitHub API ${response.status}: ${(json as Record<string, unknown>).message ?? JSON.stringify(json)}`,
      };
    }

    return {
      success: true,
      number: json.number as number,
      url: json.html_url as string,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('GitHub API call failed:', message);
    return { success: false, error: message };
  }
}

/* ── List repositories (for config validation) ────────────── */

export interface GitHubRepo {
  id: number;
  full_name: string;
  name: string;
  private: boolean;
  owner?: { login: string };
}

export async function fetchGitHubRepos(
  config: GitHubConnectorConfig,
): Promise<GitHubRepo[]> {
  const url = `https://api.github.com/user/repos?per_page=50&sort=updated&affiliation=owner,collaborator,organization_member`;

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!res.ok) return [];
    return (await res.json()) as GitHubRepo[];
  } catch {
    return [];
  }
}

/* ── List organizations the authenticated user belongs to ─── */

export interface GitHubOrg {
  id: number;
  login: string;
  description?: string;
  avatar_url?: string;
}

export async function fetchGitHubOrgs(
  token: string,
): Promise<GitHubOrg[]> {
  try {
    // Fetch orgs the user belongs to
    const res = await fetch('https://api.github.com/user/orgs?per_page=100', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (!res.ok) return [];
    const orgs = (await res.json()) as GitHubOrg[];

    // Also get the authenticated user so they appear as an option
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (userRes.ok) {
      const user = (await userRes.json()) as { login: string; id: number; avatar_url?: string };
      // Prepend the user's own account as the first option
      orgs.unshift({ id: user.id, login: user.login, description: 'Personal account', avatar_url: user.avatar_url });
    }

    return orgs;
  } catch {
    return [];
  }
}

/* ── List repos for a specific owner/org ──────────────────── */

export async function fetchGitHubReposByOwner(
  token: string,
  owner: string,
): Promise<GitHubRepo[]> {
  const allRepos: GitHubRepo[] = [];
  let page = 1;
  const perPage = 100;

  try {
    // First, try as an org
    while (true) {
      const res = await fetch(
        `https://api.github.com/orgs/${encodeURIComponent(owner)}/repos?per_page=${perPage}&page=${page}&sort=updated`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        },
      );
      if (res.status === 404) break; // Not an org, try as user
      if (!res.ok) break;
      const batch = (await res.json()) as GitHubRepo[];
      allRepos.push(...batch);
      if (batch.length < perPage) break;
      page++;
      if (page > 10) break; // safety cap
    }

    // If org returned 404 (not an org), try user repos
    if (allRepos.length === 0) {
      page = 1;
      while (true) {
        const res = await fetch(
          `https://api.github.com/users/${encodeURIComponent(owner)}/repos?per_page=${perPage}&page=${page}&sort=updated`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Accept': 'application/vnd.github+json',
              'X-GitHub-Api-Version': '2022-11-28',
            },
          },
        );
        if (!res.ok) break;
        const batch = (await res.json()) as GitHubRepo[];
        allRepos.push(...batch);
        if (batch.length < perPage) break;
        page++;
        if (page > 10) break;
      }
    }

    return allRepos;
  } catch {
    return [];
  }
}

/* ── List collaborators (assignees) for a repo ─────────────── */

export interface GitHubCollaborator {
  id: number;
  login: string;
  avatar_url?: string;
  type: string;           // 'User', 'Bot', etc.
}

export async function fetchGitHubCollaborators(
  token: string,
  owner: string,
  repo: string,
): Promise<GitHubCollaborator[]> {
  const all: GitHubCollaborator[] = [];
  let page = 1;
  const perPage = 100;

  try {
    while (true) {
      const res = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/collaborators?per_page=${perPage}&page=${page}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        },
      );
      if (!res.ok) break;
      const batch = (await res.json()) as GitHubCollaborator[];
      all.push(...batch);
      if (batch.length < perPage) break;
      page++;
      if (page > 10) break;
    }
    return all;
  } catch {
    return [];
  }
}

/* ── Test connection ──────────────────────────────────────── */

export async function testGitHubConnection(
  token: string,
): Promise<{ ok: boolean; user?: string; error?: string }> {
  const url = 'https://api.github.com/user';

  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }

    const json = await res.json() as { login?: string };
    return { ok: true, user: json.login ?? 'Unknown' };
  } catch (err: unknown) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
