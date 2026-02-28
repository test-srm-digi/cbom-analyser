/**
 * CryptoPolicy Routes — CRUD for cryptographic policies
 *
 * GET    /api/policies            → list all
 * GET    /api/policies/:id        → get one
 * POST   /api/policies            → create one
 * POST   /api/policies/bulk       → bulk create (presets / seed)
 * PUT    /api/policies/:id        → update
 * DELETE /api/policies/:id        → delete one
 * DELETE /api/policies/all        → delete all
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { CryptoPolicy } from '../models';

const router = Router();

/* ── GET /api/policies ────────────────────────────────────── */
router.get('/policies', async (_req: Request, res: Response) => {
  try {
    const rows = await CryptoPolicy.findAll({ order: [['created_at', 'DESC']] });
    // Parse the JSON‑serialised rules back into objects
    const parsed = rows.map((r) => {
      const plain = r.toJSON() as unknown as Record<string, unknown>;
      try {
        plain.rules = typeof plain.rules === 'string' ? JSON.parse(plain.rules as string) : plain.rules;
      } catch {
        plain.rules = [];
      }
      return plain;
    });
    res.json({ success: true, data: parsed });
  } catch (error) {
    console.error('Error fetching policies:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch policies' });
  }
});

/* ── GET /api/policies/:id ────────────────────────────────── */
router.get('/policies/:id', async (req: Request, res: Response) => {
  try {
    const row = await CryptoPolicy.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Policy not found' });
    const plain = row.toJSON() as unknown as Record<string, unknown>;
    try {
      plain.rules = typeof plain.rules === 'string' ? JSON.parse(plain.rules as string) : plain.rules;
    } catch {
      plain.rules = [];
    }
    res.json({ success: true, data: plain });
  } catch (error) {
    console.error('Error fetching policy:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch policy' });
  }
});

/* ── POST /api/policies ───────────────────────────────────── */
router.post('/policies', async (req: Request, res: Response) => {
  try {
    const body = { ...req.body };
    // Ensure rules is stored as JSON string
    if (Array.isArray(body.rules)) {
      body.rules = JSON.stringify(body.rules);
    }
    const row = await CryptoPolicy.create({ id: uuidv4(), ...body });
    const plain = row.toJSON() as unknown as Record<string, unknown>;
    try {
      plain.rules = typeof plain.rules === 'string' ? JSON.parse(plain.rules as string) : plain.rules;
    } catch {
      plain.rules = [];
    }
    res.status(201).json({ success: true, data: plain });
  } catch (error) {
    console.error('Error creating policy:', error);
    res.status(500).json({ success: false, message: 'Failed to create policy' });
  }
});

/* ── POST /api/policies/bulk ──────────────────────────────── */
router.post('/policies/bulk', async (req: Request, res: Response) => {
  try {
    const items = (req.body.items || []).map((item: Record<string, unknown>) => ({
      id: uuidv4(),
      ...item,
      rules: Array.isArray(item.rules) ? JSON.stringify(item.rules) : item.rules || '[]',
    }));
    const rows = await CryptoPolicy.bulkCreate(items);
    const parsed = rows.map((r) => {
      const plain = r.toJSON() as unknown as Record<string, unknown>;
      try {
        plain.rules = typeof plain.rules === 'string' ? JSON.parse(plain.rules as string) : plain.rules;
      } catch {
        plain.rules = [];
      }
      return plain;
    });
    res.status(201).json({ success: true, data: parsed, message: `Created ${rows.length} policies` });
  } catch (error) {
    console.error('Error bulk creating policies:', error);
    res.status(500).json({ success: false, message: 'Failed to bulk create policies' });
  }
});

/* ── PUT /api/policies/:id ────────────────────────────────── */
router.put('/policies/:id', async (req: Request, res: Response) => {
  try {
    const row = await CryptoPolicy.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Policy not found' });
    const body = { ...req.body };
    if (Array.isArray(body.rules)) {
      body.rules = JSON.stringify(body.rules);
    }
    await row.update(body);
    const plain = row.toJSON() as unknown as Record<string, unknown>;
    try {
      plain.rules = typeof plain.rules === 'string' ? JSON.parse(plain.rules as string) : plain.rules;
    } catch {
      plain.rules = [];
    }
    res.json({ success: true, data: plain });
  } catch (error) {
    console.error('Error updating policy:', error);
    res.status(500).json({ success: false, message: 'Failed to update policy' });
  }
});

/* ── DELETE /api/policies/all ─────────────────────────────── */
router.delete('/policies/all', async (_req: Request, res: Response) => {
  try {
    const count = await CryptoPolicy.destroy({ where: {}, truncate: true });
    res.json({ success: true, message: `Deleted ${count} policies` });
  } catch (error) {
    console.error('Error deleting all policies:', error);
    res.status(500).json({ success: false, message: 'Failed to delete all policies' });
  }
});

/* ── DELETE /api/policies/:id ─────────────────────────────── */
router.delete('/policies/:id', async (req: Request, res: Response) => {
  try {
    const row = await CryptoPolicy.findByPk(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: 'Policy not found' });
    await row.destroy();
    res.json({ success: true, message: 'Policy deleted' });
  } catch (error) {
    console.error('Error deleting policy:', error);
    res.status(500).json({ success: false, message: 'Failed to delete policy' });
  }
});

export default router;
