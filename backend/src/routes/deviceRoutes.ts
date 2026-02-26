/**
 * Device Routes — CRUD for discovered IoT/industrial devices
 *
 * GET    /api/devices                        → list all
 * GET    /api/devices/integration/:integId   → list by integration
 * GET    /api/devices/:id                    → get one
 * POST   /api/devices                        → create one
 * POST   /api/devices/bulk                   → bulk create
 * PUT    /api/devices/:id                    → update
 * DELETE /api/devices/:id                    → delete
 * DELETE /api/devices/integration/:integId   → delete all for integration
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { Device } from '../models';

const router = Router();

/* ── GET /api/devices ─────────────────────────────────────── */
router.get('/devices', async (_req: Request, res: Response) => {
  try {
    const rows = await Device.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching devices:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch devices' });
  }
});

/* ── GET /api/devices/integration/:integId ────────────────── */
router.get('/devices/integration/:integId', async (req: Request, res: Response) => {
  try {
    const rows = await Device.findAll({
      where: { integrationId: req.params.integId },
      order: [['created_at', 'DESC']],
    });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching devices by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch devices' });
  }
});

/* ── GET /api/devices/:id ─────────────────────────────────── */
router.get('/devices/:id', async (req: Request, res: Response) => {
  try {
    const row = await Device.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Device not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching device:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch device' });
  }
});

/* ── POST /api/devices ────────────────────────────────────── */
router.post('/devices', async (req: Request, res: Response) => {
  try {
    const row = await Device.create({ id: uuidv4(), ...req.body });
    res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error('Error creating device:', error);
    res.status(500).json({ success: false, message: 'Failed to create device' });
  }
});

/* ── POST /api/devices/bulk ───────────────────────────────── */
router.post('/devices/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
    }));
    const rows = await Device.bulkCreate(items);
    res.status(201).json({ success: true, data: rows, message: `Created ${rows.length} devices` });
  } catch (error) {
    console.error('Error bulk creating devices:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create devices' });
  }
});

/* ── PUT /api/devices/:id ─────────────────────────────────── */
router.put('/devices/:id', async (req: Request, res: Response) => {
  try {
    const row = await Device.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Device not found' });
    await row.update(req.body);
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error updating device:', error);
    res.status(500).json({ success: false, message: 'Failed to update device' });
  }
});

/* ── DELETE /api/devices/:id ──────────────────────────────── */
router.delete('/devices/:id', async (req: Request, res: Response) => {
  try {
    const row = await Device.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Device not found' });
    await row.destroy();
    res.json({ success: true, message: 'Device deleted' });
  } catch (error) {
    console.error('Error deleting device:', error);
    res.status(500).json({ success: false, message: 'Failed to delete device' });
  }
});

/* ── DELETE /api/devices/integration/:integId ─────────────── */
router.delete('/devices/integration/:integId', async (req: Request, res: Response) => {
  try {
    const count = await Device.destroy({ where: { integrationId: req.params.integId } });
    res.json({ success: true, message: `Deleted ${count} devices` });
  } catch (error) {
    console.error('Error deleting devices by integration:', error);
    res.status(500).json({ success: false, message: 'Failed to delete devices' });
  }
});

export default router;
