/**
 * User Routes — list & create users (no auth, username only)
 *
 * GET    /api/users       → list all users
 * POST   /api/users       → create a user
 * GET    /api/users/:id   → get one user
 */
import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/User';

const router = Router();

/* ── GET /api/users ───────────────────────────────────────── */
router.get('/users', async (_req: Request, res: Response) => {
  try {
    const users = await User.findAll({ order: [['created_at', 'ASC']] });
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

/* ── POST /api/users ──────────────────────────────────────── */
router.post('/users', async (req: Request, res: Response) => {
  try {
    const { username } = req.body;
    if (!username || typeof username !== 'string' || username.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'username is required' });
    }

    // Check for duplicate
    const existing = await User.findOne({ where: { username: username.trim() } });
    if (existing) {
      return res.json({ success: true, data: existing, message: 'User already exists' });
    }

    const user = await User.create({ id: uuidv4(), username: username.trim() });
    res.status(201).json({ success: true, data: user });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, message: 'Failed to create user' });
  }
});

/* ── GET /api/users/:id ───────────────────────────────────── */
router.get('/users/:id', async (req: Request, res: Response) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, data: user });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user' });
  }
});

export default router;
