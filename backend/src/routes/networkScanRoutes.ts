/**
 * Network Scan History Routes — CRUD for persisted TLS scan results
 *
 * These routes are for the *persisted* scan history, separate from
 * the live scan endpoints in networkRoutes.ts.
 *
 * GET    /api/network-scans              → list all scans
 * GET    /api/network-scans/:id          → get one scan
 * DELETE /api/network-scans/:id          → delete one
 * DELETE /api/network-scans/all          → delete all
 */
import { Router, Request, Response } from 'express';
import NetworkScan from '../models/NetworkScan';

const router = Router();

/* ── GET /api/network-scans ───────────────────────────────── */
router.get('/network-scans', async (req: Request, res: Response) => {
  try {
    const rows = await NetworkScan.findAll({ where: { ...(req.userId && { userId: req.userId }) }, order: [['scanned_at', 'DESC']] });
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching network scans:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch network scans' });
  }
});

/* ── GET /api/network-scans/:id ───────────────────────────── */
router.get('/network-scans/:id', async (req: Request, res: Response) => {
  try {
    const row = await NetworkScan.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Scan not found' });
    res.json({ success: true, data: row });
  } catch (error) {
    console.error('Error fetching network scan:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch network scan' });
  }
});

/* ── DELETE /api/network-scans/all ────────────────────────── */
router.delete('/network-scans/all', async (req: Request, res: Response) => {
  try {
    const count = await NetworkScan.destroy({ where: { ...(req.userId && { userId: req.userId }) } });
    res.json({ success: true, message: `Deleted ${count} network scans` });
  } catch (error) {
    console.error('Error deleting all network scans:', error);
    res.status(500).json({ success: false, message: 'Failed to delete network scans' });
  }
});

/* ── DELETE /api/network-scans/:id ────────────────────────── */
router.delete('/network-scans/:id', async (req: Request, res: Response) => {
  try {
    const row = await NetworkScan.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Scan not found' });
    await row.destroy();
    res.json({ success: true, message: 'Scan deleted' });
  } catch (error) {
    console.error('Error deleting network scan:', error);
    res.status(500).json({ success: false, message: 'Failed to delete network scan' });
  }
});

export default router;
