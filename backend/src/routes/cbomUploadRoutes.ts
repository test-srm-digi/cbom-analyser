/**
 * CBOM Upload (dashboard) routes
 * Persists CBOMs uploaded via the CBOM Analyzer page to the DB.
 */
import { Router, Request, Response } from 'express';
import CbomUpload from '../models/CbomUpload';

const router = Router();

/* ── GET /api/cbom-uploads ── list all uploads (most-recent first) */
router.get('/cbom-uploads', async (_req: Request, res: Response) => {
  try {
    const rows = await CbomUpload.findAll({
      order: [['created_at', 'DESC']],
      attributes: { exclude: ['cbomFile'] }, // skip large blob for listing
    });
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: (err as Error).message });
  }
});

/* ── GET /api/cbom-uploads/:id ── single upload with the full CBOM blob */
router.get('/cbom-uploads/:id', async (req: Request, res: Response) => {
  try {
    const row = await CbomUpload.findByPk(req.params.id);
    if (!row) {
      res.status(404).json({ success: false, message: 'Upload not found' });
      return;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const plain: any = row.toJSON();
    // Convert Buffer → base64 string for the frontend
    if (plain.cbomFile && Buffer.isBuffer(plain.cbomFile)) {
      plain.cbomFile = (plain.cbomFile as Buffer).toString('base64');
    }
    res.json({ success: true, data: plain });
  } catch (err) {
    res.status(500).json({ success: false, message: (err as Error).message });
  }
});

/* ── DELETE /api/cbom-uploads/:id */
router.delete('/cbom-uploads/:id', async (req: Request, res: Response) => {
  try {
    const deleted = await CbomUpload.destroy({ where: { id: req.params.id } });
    if (!deleted) {
      res.status(404).json({ success: false, message: 'Upload not found' });
      return;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: (err as Error).message });
  }
});

export default router;
