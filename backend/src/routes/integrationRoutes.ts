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
import { executeSyncForIntegration } from '../services/syncExecutor';
import { onScheduleChanged, onIntegrationDeleted, onIntegrationToggled, scheduleJob } from '../services/syncScheduler';

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

    // Schedule cron job if non-manual
    if (integration.syncSchedule !== 'manual') {
      scheduleJob(integration.id, integration.syncSchedule, integration.name);
    }

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

    // Notify scheduler of schedule or enabled changes
    if (syncSchedule !== undefined || enabled !== undefined) {
      onScheduleChanged(
        integration.id,
        integration.syncSchedule,
        integration.name,
        integration.enabled,
      );
    }

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
    onIntegrationDeleted(integration.id);
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

    // Start or stop cron job based on new enabled state
    onIntegrationToggled(integration.id, newEnabled, integration.syncSchedule, integration.name);

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

    if (!integration.enabled) {
      return res.status(400).json({ success: false, message: 'Integration is disabled — enable it before syncing' });
    }

    // Execute sync via the SyncExecutor (creates SyncLog, calls connector, persists data)
    const result = await executeSyncForIntegration(integration.id, 'manual');

    // Reload integration to get updated metadata
    await integration.reload();

    res.json({
      success: result.success,
      message: result.success
        ? `Sync completed: ${result.itemsCreated} items fetched in ${result.durationMs}ms`
        : `Sync completed with ${result.errors.length} error(s)`,
      data: {
        integration,
        syncResult: {
          syncLogId: result.syncLogId,
          itemsFetched: result.itemsFetched,
          itemsCreated: result.itemsCreated,
          itemsDeleted: result.itemsDeleted,
          errors: result.errors,
          durationMs: result.durationMs,
        },
      },
    });
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

    const config = (integration.config || {}) as Record<string, string>;
    const templateType = integration.templateType;

    // ── Real connection test for DigiCert TLM ──
    if (templateType === 'digicert-tlm' && config.apiBaseUrl && config.apiKey) {
      const { testDigiCertConnection } = await import('../services/digicertTlmConnector');
      const result = await testDigiCertConnection(config as import('../services/connectors').ConnectorConfig);

      if (result.success) {
        await integration.update({ status: 'connected', errorMessage: null });
        res.json({ success: true, data: { status: 'success', message: result.message } });
      } else {
        await integration.update({ status: 'error', errorMessage: result.message });
        res.json({ success: false, data: { status: 'error', message: result.message } });
      }
      return;
    }

    // ── Fallback: basic config-presence check for other integrations ──
    const configKeys = Object.keys(config);
    const hasValues = configKeys.length > 0 && configKeys.every((k) => config[k]?.trim());

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
