/**
 * Ticket Routes — CRUD for remediation tickets
 *
 * GET    /api/tickets            → list all
 * GET    /api/tickets/:id        → get one
 * POST   /api/tickets            → create one
 * PUT    /api/tickets/:id        → update
 * DELETE /api/tickets/:id        → delete one
 * DELETE /api/tickets/all        → delete all
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Ticket, TicketConnector } from '../models';
import { createJiraIssue } from '../services/jiraService';
import type { JiraConnectorConfig } from '../services/jiraService';
import { createGitHubIssue } from '../services/githubService';
import type { GitHubConnectorConfig } from '../services/githubService';
import { createServiceNowIncident } from '../services/serviceNowService';
import type { ServiceNowConnectorConfig } from '../services/serviceNowService';

const router = Router();

/** Parse JSON-serialised columns back to objects */
function parseTicketRow(row: InstanceType<typeof Ticket>) {
  const plain = row.toJSON() as unknown as Record<string, unknown>;
  try { plain.labels = typeof plain.labels === 'string' ? JSON.parse(plain.labels as string) : plain.labels; } catch { plain.labels = []; }
  try { plain.platformDetails = typeof plain.platformDetails === 'string' ? JSON.parse(plain.platformDetails as string) : plain.platformDetails; } catch { plain.platformDetails = {}; }
  return plain;
}

/* ── GET /api/tickets ─────────────────────────────────────── */
router.get('/tickets', async (_req: Request, res: Response) => {
  try {
    const rows = await Ticket.findAll({ order: [['created_at', 'DESC']] });
    const parsed = rows.map(parseTicketRow);
    res.json({ success: true, data: parsed });
  } catch (error) {
    console.error('Error fetching tickets:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch tickets' });
  }
});

/* ── GET /api/tickets/:id ─────────────────────────────────── */
router.get('/tickets/:id', async (req: Request, res: Response) => {
  try {
    const row = await Ticket.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Ticket not found' });
    res.json({ success: true, data: parseTicketRow(row) });
  } catch (error) {
    console.error('Error fetching ticket:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch ticket' });
  }
});

/* ── POST /api/tickets ────────────────────────────────────── */
router.post('/tickets', async (req: Request, res: Response) => {
  try {
    const body = { ...req.body };

    // ── If JIRA — try to create a real JIRA issue ───────────
    if (body.type === 'JIRA') {
      const connector = await TicketConnector.findOne({ where: { type: 'JIRA', enabled: true } });
      if (connector) {
        let cfg: JiraConnectorConfig;
        try {
          cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config;
        } catch { cfg = {} as JiraConnectorConfig; }

        // Use connector defaults if not provided in payload
        const projectKey = body.project?.split(' - ')[0]?.replace(/^.*?([A-Z][A-Z0-9]+).*$/, '$1') || cfg.projectKey || 'CRYPTO';
        const issueType = body.issueType || cfg.defaultIssueType || 'Bug';
        const assigneeId = body.assignee || cfg.defaultAssignee || undefined;
        const labels = Array.isArray(body.labels) ? body.labels : cfg.defaultLabels || [];

        if (cfg.email && cfg.apiToken && projectKey) {
          const result = await createJiraIssue(connector.baseUrl, cfg, {
            projectKey,
            issueType,
            summary: body.title,
            description: body.description || '',
            priority: body.priority,
            labels,
            assigneeId,
          });

          if (result.success && result.key) {
            body.ticketId = result.key;
            body.externalUrl = result.url;
            body.status = 'To Do';
          } else {
            // Store locally even if JIRA fails — record the error
            console.warn('JIRA issue creation failed:', result.error);
            body.platformDetails = JSON.stringify({ jiraError: result.error });
          }
        }
      }
    }

    // ── If GitHub — try to create a real GitHub issue ─────
    if (body.type === 'GitHub') {
      const connector = await TicketConnector.findOne({ where: { type: 'GitHub', enabled: true } });
      if (connector) {
        let cfg: GitHubConnectorConfig;
        try {
          cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config;
        } catch { cfg = {} as GitHubConnectorConfig; }

        const owner = body.owner || cfg.owner || '';
        const repo = body.repository?.split('/').pop() || cfg.repo || '';
        const assignees = body.assignee ? [body.assignee] : cfg.defaultAssignee ? [cfg.defaultAssignee] : [];
        const ghLabels = Array.isArray(body.labels) ? body.labels : cfg.defaultLabels || [];

        if (cfg.token && owner && repo) {
          const result = await createGitHubIssue(cfg, {
            owner,
            repo,
            title: body.title,
            body: body.description || '',
            labels: ghLabels,
            assignees,
          });

          if (result.success && result.number) {
            body.ticketId = `#${result.number}`;
            body.externalUrl = result.url;
            body.status = 'Open';
          } else {
            console.warn('GitHub issue creation failed:', result.error);
            body.platformDetails = JSON.stringify({ githubError: result.error });
          }
        }
      }
    }

    // ── If ServiceNow — try to create a real incident ────
    if (body.type === 'ServiceNow') {
      const connector = await TicketConnector.findOne({ where: { type: 'ServiceNow', enabled: true } });
      if (connector) {
        let cfg: ServiceNowConnectorConfig;
        try {
          cfg = typeof connector.config === 'string' ? JSON.parse(connector.config) : connector.config;
        } catch { cfg = {} as ServiceNowConnectorConfig; }

        if (cfg.username && cfg.password) {
          const result = await createServiceNowIncident(connector.baseUrl, cfg, {
            short_description: body.title,
            description: body.description || '',
            category: body.category ?? cfg.defaultCategory ?? 'Security',
            subcategory: body.subcategory ?? cfg.defaultSubcategory ?? 'Cryptography',
            impact: body.impact ?? cfg.defaultImpact ?? '2',
            urgency: body.priority ?? cfg.defaultUrgency ?? '2',
            assignment_group: body.assignmentGroup ?? cfg.defaultAssignmentGroup,
            assigned_to: body.assignee ?? cfg.defaultAssignee,
          });

          if (result.success && result.number) {
            body.ticketId = result.number;
            body.externalUrl = result.url;
            body.status = 'New';
          } else {
            console.warn('ServiceNow incident creation failed:', result.error);
            body.platformDetails = JSON.stringify({ serviceNowError: result.error });
          }
        }
      }
    }

    // Generate a ticket ID if not set (platform API may have set it above)
    if (!body.ticketId) {
      const prefix = body.type === 'JIRA' ? 'CRYPTO' : body.type === 'GitHub' ? '#' : 'INC';
      const num = Math.floor(1000 + Math.random() * 9000);
      body.ticketId = body.type === 'GitHub' ? `#${num}` : `${prefix}-${num}`;
    }

    // Ensure arrays / objects are stored as JSON
    if (Array.isArray(body.labels)) body.labels = JSON.stringify(body.labels);
    if (body.platformDetails && typeof body.platformDetails === 'object') {
      body.platformDetails = JSON.stringify(body.platformDetails);
    }

    const row = await Ticket.create({ id: uuidv4(), ...body });
    res.status(201).json({ success: true, data: parseTicketRow(row) });
  } catch (error) {
    console.error('Error creating ticket:', error);
    res.status(500).json({ success: false, message: 'Failed to create ticket' });
  }
});

/* ── PUT /api/tickets/:id ─────────────────────────────────── */
router.put('/tickets/:id', async (req: Request, res: Response) => {
  try {
    const row = await Ticket.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Ticket not found' });
    const body = { ...req.body };
    if (Array.isArray(body.labels)) body.labels = JSON.stringify(body.labels);
    if (body.platformDetails && typeof body.platformDetails === 'object') {
      body.platformDetails = JSON.stringify(body.platformDetails);
    }
    await row.update(body);
    res.json({ success: true, data: parseTicketRow(row) });
  } catch (error) {
    console.error('Error updating ticket:', error);
    res.status(500).json({ success: false, message: 'Failed to update ticket' });
  }
});

/* ── DELETE /api/tickets/all ──────────────────────────────── */
router.delete('/tickets/all', async (_req: Request, res: Response) => {
  try {
    const count = await Ticket.destroy({ where: {}, truncate: true });
    res.json({ success: true, message: `Deleted ${count} tickets` });
  } catch (error) {
    console.error('Error deleting all tickets:', error);
    res.status(500).json({ success: false, message: 'Failed to delete all tickets' });
  }
});

/* ── DELETE /api/tickets/:id ──────────────────────────────── */
router.delete('/tickets/:id', async (req: Request, res: Response) => {
  try {
    const row = await Ticket.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Ticket not found' });
    await row.destroy();
    res.json({ success: true, message: 'Ticket deleted' });
  } catch (error) {
    console.error('Error deleting ticket:', error);
    res.status(500).json({ success: false, message: 'Failed to delete ticket' });
  }
});

export default router;
