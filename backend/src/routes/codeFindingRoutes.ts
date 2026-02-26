/**
 * CodeFinding Routes — CRUD for discovered crypto code findings
 *
 * GET    /api/code-findings                        → list all
 * GET    /api/code-findings/integration/:integId   → list by integration
 * GET    /api/code-findings/:id                    → get one
 * POST   /api/code-findings                        → create one
 * POST   /api/code-findings/bulk                   → bulk create
 * PUT    /api/code-findings/:id                    → update
 * DELETE /api/code-findings/:id                    → delete
 * DELETE /api/code-findings/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { CodeFinding } from '../models';

const router = Router();

/* ── GET /api/code-findings ───────────────────────────────── */
router.get('/code-findings', async (_req: Request, res: Response) => {
  try {
    const rows = await CodeFinding.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching code findings:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch code findings' });
  }
});

/* ── GET /api/code-findings/integration/:integId ──────────── */
router.get('/code-findings/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await CodeFinding.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching code findings by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch code findings' });
  }
});

/* ── GET /api/code-findings/:id ───────────────────────────── */
router.get('/code-findings/:id', async (req: Request, res: Response) => {
  try {
    const row = await CodeFinding.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Code finding not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching code finding:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch code finding' });
  }
});

/* ── POST /api/code-findings ──────────────────────────────── */
router.post('/code-findings', async (req: Request, res: Response) => {
  try {
    const row = await CodeFinding.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating code finding:', error);
    res.status(500).json({ success: false, message: 'Failed to create code finding' });
  }
});

/* ── POST /api/code-findings/bulk ─────────────────────────── */
router.post('/code-findings/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await CodeFinding.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} code findings` });
  } catch (error) {
    console.error('Error bulk creating code findings:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create code findings' });
  }
});

/* ── PUT /api/code-findings/:id ───────────────────────────── */
router.put('/code-findings/:id', async (req: Request, res: Response) => {
  try {
    const row = await CodeFinding.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Code finding not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating code finding:', error);
    res.status(500).json({ success: false, message: 'Failed to update code finding' });
  }
});

/* ── DELETE /api/code-findings/:id ────────────────────────── */
router.delete('/code-findings/:id', async (req: Request, res: Response) => {
  try {
    const row = await CodeFinding.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Code finding not found' });
    await row.destroy();
    res.json({ success: true, message: 'Code finding deleted' });
  } catch (error) {
    console.error('Error deleting code finding:', error);
    res.status(500).json({ success: false, message: 'Failed to delete code finding' });
  }
});

/* ── DELETE /api/code-findings/integration/:integId ───────── */
router.delete('/code-findings/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await CodeFinding.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} code findings` });
  } catch (error) {
    console.error('Error deleting code findings by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete code findings' });
  }
});

export default router;
