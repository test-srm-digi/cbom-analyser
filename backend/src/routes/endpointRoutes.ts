/**
 * Endpoint Routes — CRUD for discovered TLS endpoints
 *
 * GET    /api/endpoints                        → list all
 * GET    /api/endpoints/integration/:integId   → list by integration
 * GET    /api/endpoints/:id                    → get one
 * POST   /api/endpoints                        → create one
 * POST   /api/endpoints/bulk                   → bulk create
 * PUT    /api/endpoints/:id                    → update
 * DELETE /api/endpoints/:id                    → delete
 * DELETE /api/endpoints/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Endpoint } from '../models';

const router = Router();

/* ── GET /api/endpoints ───────────────────────────────────── */
router.get('/endpoints', async (_req: Request, res: Response) => {
  try {
    const rows = await Endpoint.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching endpoints:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch endpoints' });
  }
});

/* ── GET /api/endpoints/integration/:integId ──────────────── */
router.get('/endpoints/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await Endpoint.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching endpoints by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch endpoints' });
  }
});

/* ── GET /api/endpoints/:id ───────────────────────────────── */
router.get('/endpoints/:id', async (req: Request, res: Response) => {
  try {
    const row = await Endpoint.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Endpoint not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching endpoint:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch endpoint' });
  }
});

/* ── POST /api/endpoints ──────────────────────────────────── */
router.post('/endpoints', async (req: Request, res: Response) => {
  try {
    const row = await Endpoint.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating endpoint:', error);
    res.status(500).json({ success: false, message: 'Failed to create endpoint' });
  }
});

/* ── POST /api/endpoints/bulk ─────────────────────────────── */
router.post('/endpoints/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await Endpoint.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} endpoints` });
  } catch (error) {
    console.error('Error bulk creating endpoints:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create endpoints' });
  }
});

/* ── PUT /api/endpoints/:id ───────────────────────────────── */
router.put('/endpoints/:id', async (req: Request, res: Response) => {
  try {
    const row = await Endpoint.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Endpoint not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating endpoint:', error);
    res.status(500).json({ success: false, message: 'Failed to update endpoint' });
  }
});

/* ── DELETE /api/endpoints/all ─────────────────────────────── */
router.delete('/endpoints/all', async (_req: Request, res: Response) => {
  try {
    const count = await Endpoint.destroy({ where: {}, truncate: true });
    res.json({ success: true, message: `Deleted ${count} endpoints` });
  } catch (error) {
    console.error('Error deleting all endpoints:', error);
    res.status(500).json({ success: false, message: 'Failed to delete all endpoints' });
  }
});

/* ── DELETE /api/endpoints/:id ────────────────────────────── */
router.delete('/endpoints/:id', async (req: Request, res: Response) => {
  try {
    const row = await Endpoint.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Endpoint not found' });
    await row.destroy();
    res.json({ success: true, message: 'Endpoint deleted' });
  } catch (error) {
    console.error('Error deleting endpoint:', error);
    res.status(500).json({ success: false, message: 'Failed to delete endpoint' });
  }
});

/* ── DELETE /api/endpoints/integration/:integId ───────────── */
router.delete('/endpoints/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await Endpoint.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} endpoints` });
  } catch (error) {
    console.error('Error deleting endpoints by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete endpoints' });
  }
});

export default router;
