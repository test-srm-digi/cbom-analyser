/**
 * CBOM Import Routes — CRUD for CycloneDX CBOM file imports
 *
 * GET    /api/cbom-imports                        → list all
 * GET    /api/cbom-imports/integration/:integId   → list by integration
 * GET    /api/cbom-imports/:id                    → get one
 * POST   /api/cbom-imports                        → create one
 * POST   /api/cbom-imports/bulk                   → bulk create
 * PUT    /api/cbom-imports/:id                    → update
 * DELETE /api/cbom-imports/:id                    → delete
 * DELETE /api/cbom-imports/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { CbomImport } from '../models';

const router = Router();

/* ── GET /api/cbom-imports ────────────────────────────────── */
router.get('/cbom-imports', async (_req: Request, res: Response) => {
  try {
    const rows = await CbomImport.findAll({ order: [['created_at', 'DESC']], attributes: { exclude: ['cbomFile'] } });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching CBOM imports:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch CBOM imports' });
  }
});

/* ── GET /api/cbom-imports/integration/:integId ───────────── */
router.get('/cbom-imports/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await CbomImport.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
      attributes: { exclude: ['cbomFile'] },
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching CBOM imports by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch CBOM imports' });
  }
});

/* ── GET /api/cbom-imports/:id ────────────────────────────── */
router.get('/cbom-imports/:id', async (req: Request, res: Response) => {
  try {
    const row = await CbomImport.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'CBOM import not found' });

    // Serialize BLOB as base64 for JSON transport
    const plain = row.toJSON() as unknown as Record<string, unknown>;
    if (row.cbomFile) {
      plain.cbomFile = (row.cbomFile as Buffer).toString('base64');
    }

    res.json({ success: true, data: plain });
  } catch (error) {
    console.error('Error fetching CBOM import:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch CBOM import' });
  }
});

/* ── POST /api/cbom-imports ───────────────────────────────── */
router.post('/cbom-imports', async (req: Request, res: Response) => {
  try {
    const row = await CbomImport.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating CBOM import:', error);
    res.status(500).json({ success: false, message: 'Failed to create CBOM import' });
  }
});

/* ── POST /api/cbom-imports/bulk ──────────────────────────── */
router.post('/cbom-imports/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await CbomImport.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} CBOM imports` });
  } catch (error) {
    console.error('Error bulk creating CBOM imports:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create CBOM imports' });
  }
});

/* ── PUT /api/cbom-imports/:id ────────────────────────────── */
router.put('/cbom-imports/:id', async (req: Request, res: Response) => {
  try {
    const row = await CbomImport.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'CBOM import not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating CBOM import:', error);
    res.status(500).json({ success: false, message: 'Failed to update CBOM import' });
  }
});

/* ── DELETE /api/cbom-imports/:id ─────────────────────────── */
router.delete('/cbom-imports/:id', async (req: Request, res: Response) => {
  try {
    const row = await CbomImport.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'CBOM import not found' });
    await row.destroy();
    res.json({ success: true, message: 'CBOM import deleted' });
  } catch (error) {
    console.error('Error deleting CBOM import:', error);
    res.status(500).json({ success: false, message: 'Failed to delete CBOM import' });
  }
});

/* ── DELETE /api/cbom-imports/integration/:integId ────────── */
router.delete('/cbom-imports/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await CbomImport.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} CBOM imports` });
  } catch (error) {
    console.error('Error deleting CBOM imports by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete CBOM imports' });
  }
});

export default router;
