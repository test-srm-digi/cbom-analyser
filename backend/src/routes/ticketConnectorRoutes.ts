/**
 * TicketConnector Routes — CRUD for ticket integration connectors
 *
 * GET    /api/ticket-connectors            → list all
 * GET    /api/ticket-connectors/:id        → get one
 * POST   /api/ticket-connectors            → create / upsert
 * PUT    /api/ticket-connectors/:id        → update
 * PATCH  /api/ticket-connectors/:id/toggle → toggle enabled
 * DELETE /api/ticket-connectors/:id        → delete
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { TicketConnector } from '../models';
import { testJiraConnection, fetchJiraProjects, searchJiraUsers, fetchJiraBoards, fetchProjectIssueTypes, fetchAssignableUsers } from '../services/jiraService';
import type { JiraConnectorConfig } from '../services/jiraService';
import { testGitHubConnection, fetchGitHubRepos, fetchGitHubOrgs, fetchGitHubReposByOwner, fetchGitHubCollaborators } from '../services/githubService';
import type { GitHubConnectorConfig } from '../services/githubService';
import { testServiceNowConnection } from '../services/serviceNowService';
import type { ServiceNowConnectorConfig } from '../services/serviceNowService';

const router = Router();

function parseRow(row: InstanceType<typeof TicketConnector>) {
  const plain = row.toJSON() as unknown as Record<string, unknown>;
  try { plain.config = typeof plain.config === 'string' ? JSON.parse(plain.config as string) : plain.config; } catch { plain.config = {}; }
  return plain;
}

/* ── GET /api/ticket-connectors ───────────────────────────── */
router.get('/ticket-connectors', async (_req: Request, res: Response) => {
  try {
    const rows = await TicketConnector.findAll({ order: [['type', 'ASC']] });
    res.json({ success: true, data: rows.map(parseRow) });
  } catch (error) {
    console.error('Error fetching ticket connectors:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch connectors' });
  }
});

/* ── GET /api/ticket-connectors/:id ───────────────────────── */
router.get('/ticket-connectors/:id', async (req: Request, res: Response) => {
  try {
    const row = await TicketConnector.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Connector not found' });
    res.json({ success: true, data: parseRow(row) });
  } catch (error) {
    console.error('Error fetching connector:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch connector' });
  }
});

/* ── POST /api/ticket-connectors ──────────────────────────── */
router.post('/ticket-connectors', async (req: Request, res: Response) => {
  try {
    const body = { ...req.body };
    if (body.config && typeof body.config === 'object') {
      body.config = JSON.stringify(body.config);
    }
    const row = await TicketConnector.create({ id: uuidv4(), ...body });
    res.status(201).json({ success: true, data: parseRow(row) });
  } catch (error) {
    console.error('Error creating connector:', error);
    res.status(500).json({ success: false, message: 'Failed to create connector' });
  }
});

/* ── PUT /api/ticket-connectors/:id ───────────────────────── */
router.put('/ticket-connectors/:id', async (req: Request, res: Response) => {
  try {
    const row = await TicketConnector.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Connector not found' });
    const body = { ...req.body };
    if (body.config && typeof body.config === 'object') {
      body.config = JSON.stringify(body.config);
    }
    await row.update(body);
    res.json({ success: true, data: parseRow(row) });
  } catch (error) {
    console.error('Error updating connector:', error);
    res.status(500).json({ success: false, message: 'Failed to update connector' });
  }
});

/* ── PATCH /api/ticket-connectors/:id/toggle ──────────────── */
router.patch('/ticket-connectors/:id/toggle', async (req: Request, res: Response) => {
  try {
    const row = await TicketConnector.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Connector not found' });
    await row.update({ enabled: !row.enabled });
    res.json({ success: true, data: parseRow(row) });
  } catch (error) {
    console.error('Error toggling connector:', error);
    res.status(500).json({ success: false, message: 'Failed to toggle connector' });
  }
});

/* ── DELETE /api/ticket-connectors/:id ────────────────────── */
router.delete('/ticket-connectors/:id', async (req: Request, res: Response) => {
  try {
    const row = await TicketConnector.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Connector not found' });
    await row.destroy();
    res.json({ success: true, message: 'Connector deleted' });
  } catch (error) {
    console.error('Error deleting connector:', error);
    res.status(500).json({ success: false, message: 'Failed to delete connector' });
  }
});

/* ── POST /api/ticket-connectors/jira/test ────────────────── */
router.post('/ticket-connectors/jira/test', async (req: Request, res: Response) => {
  try {
    const { baseUrl, email, apiToken } = req.body;
    if (!baseUrl || !email || !apiToken) {
      return res.status(400).json({ success: false, message: 'baseUrl, email, and apiToken are required' });
    }
    const result = await testJiraConnection(baseUrl, { email, apiToken, projectKey: '' });
    res.json({ success: result.ok, user: result.user, error: result.error });
  } catch (error) {
    console.error('Error testing JIRA connection:', error);
    res.status(500).json({ success: false, message: 'Failed to test connection' });
  }
});

/* ── GET /api/ticket-connectors/jira/projects ─────────────── */
router.get('/ticket-connectors/jira/projects', async (_req: Request, res: Response) => {
  try {
    const connector = await TicketConnector.findOne({ where: { type: 'JIRA' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: JiraConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as JiraConnectorConfig; }

    if (!cfg.email || !cfg.apiToken) return res.json({ success: true, data: [] });

    const projects = await fetchJiraProjects(connector.baseUrl, cfg);
    res.json({ success: true, data: projects });
  } catch (error) {
    console.error('Error fetching JIRA projects:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch projects' });
  }
});

/* ── GET /api/ticket-connectors/jira/users?q=... ──────────── */
router.get('/ticket-connectors/jira/users', async (req: Request, res: Response) => {
  try {
    const q = (req.query.q as string) ?? '';
    const connector = await TicketConnector.findOne({ where: { type: 'JIRA' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: JiraConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as JiraConnectorConfig; }

    if (!cfg.email || !cfg.apiToken) return res.json({ success: true, data: [] });

    const users = await searchJiraUsers(connector.baseUrl, cfg, q);
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error searching JIRA users:', error);
    res.status(500).json({ success: false, message: 'Failed to search users' });
  }
});

/* ── GET /api/ticket-connectors/jira/boards?project=KEY ──── */
router.get('/ticket-connectors/jira/boards', async (req: Request, res: Response) => {
  try {
    const projectKey = (req.query.project as string) || undefined;
    const connector = await TicketConnector.findOne({ where: { type: 'JIRA' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: JiraConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as JiraConnectorConfig; }

    if (!cfg.email || !cfg.apiToken) return res.json({ success: true, data: [] });

    const boards = await fetchJiraBoards(connector.baseUrl, cfg, projectKey);
    res.json({ success: true, data: boards });
  } catch (error) {
    console.error('Error fetching JIRA boards:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch boards' });
  }
});

/* ── GET /api/ticket-connectors/jira/issue-types?project=KEY ─ */
router.get('/ticket-connectors/jira/issue-types', async (req: Request, res: Response) => {
  try {
    const projectKey = (req.query.project as string) ?? '';
    if (!projectKey) return res.status(400).json({ success: false, message: 'project query param required' });

    const connector = await TicketConnector.findOne({ where: { type: 'JIRA' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: JiraConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as JiraConnectorConfig; }

    if (!cfg.email || !cfg.apiToken) return res.json({ success: true, data: [] });

    const types = await fetchProjectIssueTypes(connector.baseUrl, cfg, projectKey);
    res.json({ success: true, data: types });
  } catch (error) {
    console.error('Error fetching JIRA issue types:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch issue types' });
  }
});

/* ── GET /api/ticket-connectors/jira/assignable?project=KEY ── */
router.get('/ticket-connectors/jira/assignable', async (req: Request, res: Response) => {
  try {
    const projectKey = (req.query.project as string) ?? '';
    if (!projectKey) return res.status(400).json({ success: false, message: 'project query param required' });

    const connector = await TicketConnector.findOne({ where: { type: 'JIRA' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: JiraConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as JiraConnectorConfig; }

    if (!cfg.email || !cfg.apiToken) return res.json({ success: true, data: [] });

    const users = await fetchAssignableUsers(connector.baseUrl, cfg, projectKey);
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error fetching assignable users:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch assignable users' });
  }
});

/* ── POST /api/ticket-connectors/github/test ──────────────── */
router.post('/ticket-connectors/github/test', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, message: 'token is required' });
    }
    const result = await testGitHubConnection(token);
    res.json({ success: result.ok, user: result.user, error: result.error });
  } catch (error) {
    console.error('Error testing GitHub connection:', error);
    res.status(500).json({ success: false, message: 'Failed to test connection' });
  }
});

/* ── GET /api/ticket-connectors/github/repos ──────────────── */
router.get('/ticket-connectors/github/repos', async (_req: Request, res: Response) => {
  try {
    const connector = await TicketConnector.findOne({ where: { type: 'GitHub' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: GitHubConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as GitHubConnectorConfig; }

    if (!cfg.token) return res.json({ success: true, data: [] });

    const repos = await fetchGitHubRepos(cfg);
    res.json({ success: true, data: repos });
  } catch (error) {
    console.error('Error fetching GitHub repos:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch repos' });
  }
});

/* ── GET /api/ticket-connectors/github/orgs ───────────────── */
router.get('/ticket-connectors/github/orgs', async (_req: Request, res: Response) => {
  try {
    const connector = await TicketConnector.findOne({ where: { type: 'GitHub' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: GitHubConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as GitHubConnectorConfig; }

    if (!cfg.token) return res.json({ success: true, data: [] });

    const orgs = await fetchGitHubOrgs(cfg.token);
    res.json({ success: true, data: orgs });
  } catch (error) {
    console.error('Error fetching GitHub orgs:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch organizations' });
  }
});

/* ── GET /api/ticket-connectors/github/repos-by-owner?owner=X */
router.get('/ticket-connectors/github/repos-by-owner', async (req: Request, res: Response) => {
  try {
    const owner = (req.query.owner as string) ?? '';
    if (!owner) return res.status(400).json({ success: false, message: 'owner query param required' });

    const connector = await TicketConnector.findOne({ where: { type: 'GitHub' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: GitHubConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as GitHubConnectorConfig; }

    if (!cfg.token) return res.json({ success: true, data: [] });

    const repos = await fetchGitHubReposByOwner(cfg.token, owner);
    res.json({ success: true, data: repos });
  } catch (error) {
    console.error('Error fetching GitHub repos by owner:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch repos' });
  }
});

/* ── GET /api/ticket-connectors/github/collaborators?owner=X&repo=Y */
router.get('/ticket-connectors/github/collaborators', async (req: Request, res: Response) => {
  try {
    const owner = (req.query.owner as string) ?? '';
    const repo = (req.query.repo as string) ?? '';
    if (!owner || !repo) return res.status(400).json({ success: false, message: 'owner and repo query params required' });

    const connector = await TicketConnector.findOne({ where: { type: 'GitHub' } });
    if (!connector) return res.json({ success: true, data: [] });

    let cfg: GitHubConnectorConfig;
    try { cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config; }
    catch { cfg = {} as GitHubConnectorConfig; }

    if (!cfg.token) return res.json({ success: true, data: [] });

    const collaborators = await fetchGitHubCollaborators(cfg.token, owner, repo);
    res.json({ success: true, data: collaborators });
  } catch (error) {
    console.error('Error fetching GitHub collaborators:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch collaborators' });
  }
});

/* ── POST /api/ticket-connectors/servicenow/test ──────────── */
router.post('/ticket-connectors/servicenow/test', async (req: Request, res: Response) => {
  try {
    const { baseUrl, username, password } = req.body;
    if (!baseUrl || !username || !password) {
      return res.status(400).json({ success: false, message: 'baseUrl, username, and password are required' });
    }
    const result = await testServiceNowConnection(baseUrl, { username, password } as ServiceNowConnectorConfig);
    res.json({ success: result.ok, user: result.user, error: result.error });
  } catch (error) {
    console.error('Error testing ServiceNow connection:', error);
    res.status(500).json({ success: false, message: 'Failed to test connection' });
  }
});

export default router;
