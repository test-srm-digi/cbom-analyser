/**
 * Certificate Routes — CRUD for discovered certificates
 *
 * GET    /api/certificates                        → list all
 * GET    /api/certificates/integration/:integId   → list by integration
 * GET    /api/certificates/:id                    → get one
 * POST   /api/certificates                        → create one
 * POST   /api/certificates/bulk                   → bulk create
 * PUT    /api/certificates/:id                    → update
 * DELETE /api/certificates/:id                    → delete
 * DELETE /api/certificates/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Certificate } from '../models';

const router = Router();

/* ── GET /api/certificates ────────────────────────────────── */
router.get('/certificates', async (_req: Request, res: Response) => {
  try {
    const rows = await Certificate.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching certificates:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch certificates' });
  }
});

/* ── GET /api/certificates/integration/:integId ───────────── */
router.get('/certificates/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await Certificate.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching certificates by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch certificates' });
  }
});

/* ── GET /api/certificates/:id ────────────────────────────── */
router.get('/certificates/:id', async (req: Request, res: Response) => {
  try {
    const row = await Certificate.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Certificate not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching certificate:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch certificate' });
  }
});

/* ── POST /api/certificates ───────────────────────────────── */
router.post('/certificates', async (req: Request, res: Response) => {
  try {
    const row = await Certificate.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating certificate:', error);
    res.status(500).json({ success: false, message: 'Failed to create certificate' });
  }
});

/* ── POST /api/certificates/bulk ──────────────────────────── */
router.post('/certificates/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await Certificate.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} certificates` });
  } catch (error) {
    console.error('Error bulk creating certificates:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create certificates' });
  }
});

/* ── PUT /api/certificates/:id ────────────────────────────── */
router.put('/certificates/:id', async (req: Request, res: Response) => {
  try {
    const row = await Certificate.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Certificate not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating certificate:', error);
    res.status(500).json({ success: false, message: 'Failed to update certificate' });
  }
});

/* ── DELETE /api/certificates/all ──────────────────────────── */
router.delete('/certificates/all', async (_req: Request, res: Response) => {
  try {
    const count = await Certificate.destroy({ where: {}, truncate: true });
    res.json({ success: true, message: `Deleted ${count} certificates` });
  } catch (error) {
    console.error('Error deleting all certificates:', error);
    res.status(500).json({ success: false, message: 'Failed to delete all certificates' });
  }
});

/* ── DELETE /api/certificates/:id ─────────────────────────── */
router.delete('/certificates/:id', async (req: Request, res: Response) => {
  try {
    const row = await Certificate.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Certificate not found' });
    await row.destroy();
    res.json({ success: true, message: 'Certificate deleted' });
  } catch (error) {
    console.error('Error deleting certificate:', error);
    res.status(500).json({ success: false, message: 'Failed to delete certificate' });
  }
});

/* ── DELETE /api/certificates/integration/:integId ────────── */
router.delete('/certificates/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await Certificate.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} certificates` });
  } catch (error) {
    console.error('Error deleting certificates by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete certificates' });
  }
});

export default router;
