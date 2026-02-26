/**
 * Integration Routes — CRUD + actions for integrations
 *
 * GET    /api/integrations            → list all
 * GET    /api/integrations/:id        → get one
 * POST   /api/integrations            → create
 * PUT    /api/integrations/:id        → update
 * DELETE /api/integrations/:id        → delete
 * PATCH  /api/integrations/:id/toggle → toggle enabled
 * POST   /api/integrations/:id/sync   → trigger sync
 * POST   /api/integrations/:id/test   → test connection
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Integration } from '../models';

const router = Router();

/* ── GET /api/integrations — List all ─────────────────────── */
router.get('/integrations', async (_req: Request, res: Response) => {
  try {
    const integrations = await Integration.findAll({
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: integrations });
  } catch (error) {
    console.error('Error fetching integrations:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch integrations' });
  }
});

/* ── GET /api/integrations/:id — Get one ──────────────────── */
router.get('/integrations/:id', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }
    res.json({ success: true, data: integration });
  } catch (error) {
    console.error('Error fetching integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch integration' });
  }
});

/* ── POST /api/integrations — Create ──────────────────────── */
router.post('/integrations', async (req: Request, res: Response) => {
  try {
    const {
      templateType,
      name,
      description,
      config,
      importScope,
      syncSchedule,
      status,
    } = req.body;

    if (!templateType || !name) {
      return res.status(400).json({
        success: false,
        message: 'templateType and name are required',
      });
    }

    const integration = await Integration.create({
      id: uuidv4(),
      templateType,
      name,
      description: description || '',
      status: status || 'not_configured',
      enabled: true,
      config: config || {},
      importScope: importScope || [],
      syncSchedule: syncSchedule || '24h',
    });

    res.status(201).json({ success: true, data: integration });
  } catch (error) {
    console.error('Error creating integration:', error);
    res.status(500).json({ success: false, message: 'Failed to create integration' });
  }
});

/* ── PUT /api/integrations/:id — Update ───────────────────── */
router.put('/integrations/:id', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }

    const {
      name,
      description,
      config,
      importScope,
      syncSchedule,
      status,
      enabled,
    } = req.body;

    await integration.update({
      ...(name !== undefined && { name }),
      ...(description !== undefined && { description }),
      ...(config !== undefined && { config }),
      ...(importScope !== undefined && { importScope }),
      ...(syncSchedule !== undefined && { syncSchedule }),
      ...(status !== undefined && { status }),
      ...(enabled !== undefined && { enabled }),
    });

    res.json({ success: true, data: integration });
  } catch (error) {
    console.error('Error updating integration:', error);
    res.status(500).json({ success: false, message: 'Failed to update integration' });
  }
});

/* ── DELETE /api/integrations/:id — Delete ────────────────── */
router.delete('/integrations/:id', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }

    await integration.destroy();
    res.json({ success: true, message: 'Integration deleted' });
  } catch (error) {
    console.error('Error deleting integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete integration' });
  }
});

/* ── PATCH /api/integrations/:id/toggle — Toggle enabled ──── */
router.patch('/integrations/:id/toggle', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }

    const newEnabled = !integration.enabled;
    await integration.update({
      enabled: newEnabled,
      status: newEnabled
        ? (integration.status === 'disabled' ? 'connected' : integration.status)
        : 'disabled',
    });

    res.json({ success: true, data: integration });
  } catch (error) {
    console.error('Error toggling integration:', error);
    res.status(500).json({ success: false, message: 'Failed to toggle integration' });
  }
});

/* ── POST /api/integrations/:id/sync — Trigger sync ───────── */
router.post('/integrations/:id/sync', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }

    // Mark as syncing
    await integration.update({ status: 'testing' });

    // Simulate sync (replace with real connector logic later)
    setTimeout(async () => {
      try {
        await integration.update({
          status: 'connected',
          lastSync: new Date().toLocaleString(),
          lastSyncItems: Math.floor(Math.random() * 80) + 20,
          lastSyncErrors: 0,
        });
      } catch (err) {
        console.error('Error completing sync:', err);
      }
    }, 3000);

    res.json({ success: true, message: 'Sync started', data: integration });
  } catch (error) {
    console.error('Error triggering sync:', error);
    res.status(500).json({ success: false, message: 'Failed to trigger sync' });
  }
});

/* ── POST /api/integrations/:id/test — Test connection ────── */
router.post('/integrations/:id/test', async (req: Request, res: Response) => {
  try {
    const integration = await Integration.findByPk(req.params.id);
    if (!integration) {
      return res.status(404).json({ success: false, message: 'Integration not found' });
    }

    // Simulate connection test (replace with real logic later)
    const configKeys = Object.keys(integration.config || {});
    const hasValues = configKeys.length > 0 && configKeys.every((k) => integration.config[k]?.trim());

    if (hasValues) {
      await integration.update({ status: 'connected', errorMessage: null });
      res.json({ success: true, data: { status: 'success', message: 'Connection successful' } });
    } else {
      await integration.update({ status: 'error', errorMessage: 'Missing required configuration fields' });
      res.json({ success: false, data: { status: 'error', message: 'Check credentials and try again' } });
    }
  } catch (error) {
    console.error('Error testing connection:', error);
    res.status(500).json({ success: false, message: 'Failed to test connection' });
  }
});

export default router;
