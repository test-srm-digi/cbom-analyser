/**
 * SyncLog Routes — Read-only access to sync history
 *
 * GET  /api/sync-logs                          → list all (newest first, limit 100)
 * GET  /api/sync-logs/integration/:integId     → list for a specific integration
 * GET  /api/sync-logs/:id                      → get a single log entry
 * DELETE /api/sync-logs/integration/:integId   → delete logs for an integration
 */
import { Router, Request, Response } from 'express';
import { SyncLog } from '../models';

const router = Router();

/* ── GET /api/sync-logs — List all ────────────────────────── */
router.get('/sync-logs', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const logs = await SyncLog.findAll({
      order: [['started_at', 'DESC']],
      limit,
    });
    res.json({ success: true, data: logs });
  } catch (error) {
    console.error('Error fetching sync logs:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch sync logs' });
  }
});

/* ── GET /api/sync-logs/integration/:integId — By integration  */
router.get('/sync-logs/integration/:integId', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const logs = await SyncLog.findAll({
      where: { integrationId: req.params.integId },
      order: [['started_at', 'DESC']],
      limit,
    });
    res.json({ success: true, data: logs });
  } catch (error) {
    console.error('Error fetching sync logs:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch sync logs' });
  }
});

/* ── GET /api/sync-logs/:id — Get one ─────────────────────── */
router.get('/sync-logs/:id', async (req: Request, res: Response) => {
  try {
    const log = await SyncLog.findByPk(req.params.id);
    if (!log) {
      return res.status(404).json({ success: false, message: 'Sync log not found' });
    }
    res.json({ success: true, data: log });
  } catch (error) {
    console.error('Error fetching sync log:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch sync log' });
  }
});

/* ── DELETE /api/sync-logs/integration/:integId — Clear logs ─ */
router.delete('/sync-logs/integration/:integId', async (req: Request, res: Response) => {
  try {
    const deleted = await SyncLog.destroy({
      where: { integrationId: req.params.integId },
    });
    res.json({ success: true, message: `Deleted ${deleted} sync logs` });
  } catch (error) {
    console.error('Error deleting sync logs:', error);
    res.status(500).json({ success: false, message: 'Failed to delete sync logs' });
  }
});

export default router;
