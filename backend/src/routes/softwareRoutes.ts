/**
 * Software Routes — CRUD for discovered software signing data
 *
 * GET    /api/software                        → list all
 * GET    /api/software/integration/:integId   → list by integration
 * GET    /api/software/:id                    → get one
 * POST   /api/software                        → create one
 * POST   /api/software/bulk                   → bulk create
 * PUT    /api/software/:id                    → update
 * DELETE /api/software/:id                    → delete
 * DELETE /api/software/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Software } from '../models';

const router = Router();

/* ── GET /api/software ────────────────────────────────────── */
router.get('/software', async (_req: Request, res: Response) => {
  try {
    const rows = await Software.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching software:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch software' });
  }
});

/* ── GET /api/software/integration/:integId ───────────────── */
router.get('/software/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await Software.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching software by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch software' });
  }
});

/* ── GET /api/software/:id ────────────────────────────────── */
router.get('/software/:id', async (req: Request, res: Response) => {
  try {
    const row = await Software.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Software not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching software:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch software' });
  }
});

/* ── POST /api/software ───────────────────────────────────── */
router.post('/software', async (req: Request, res: Response) => {
  try {
    const row = await Software.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating software:', error);
    res.status(500).json({ success: false, message: 'Failed to create software' });
  }
});

/* ── POST /api/software/bulk ──────────────────────────────── */
router.post('/software/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await Software.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} software records` });
  } catch (error) {
    console.error('Error bulk creating software:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create software' });
  }
});

/* ── PUT /api/software/:id ────────────────────────────────── */
router.put('/software/:id', async (req: Request, res: Response) => {
  try {
    const row = await Software.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Software not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating software:', error);
    res.status(500).json({ success: false, message: 'Failed to update software' });
  }
});

/* ── DELETE /api/software/all ──────────────────────────────── */
router.delete('/software/all', async (_req: Request, res: Response) => {
  try {
    const count = await Software.destroy({ where: {}, truncate: true });
    res.json({ success: true, message: `Deleted ${count} software records` });
  } catch (error) {
    console.error('Error deleting all software:', error);
    res.status(500).json({ success: false, message: 'Failed to delete all software' });
  }
});

/* ── DELETE /api/software/:id ─────────────────────────────── */
router.delete('/software/:id', async (req: Request, res: Response) => {
  try {
    const row = await Software.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Software not found' });
    await row.destroy();
    res.json({ success: true, message: 'Software deleted' });
  } catch (error) {
    console.error('Error deleting software:', error);
    res.status(500).json({ success: false, message: 'Failed to delete software' });
  }
});

/* ── DELETE /api/software/integration/:integId ────────────── */
router.delete('/software/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await Software.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} software records` });
  } catch (error) {
    console.error('Error deleting software by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete software' });
  }
});

export default router;
