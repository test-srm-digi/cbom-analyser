/**
 * Scheduler Routes — Inspect and control the sync scheduler
 *
 * GET  /api/scheduler/status    → scheduler status + all active jobs
 * POST /api/scheduler/stop      → stop all jobs (graceful shutdown)
 * POST /api/scheduler/restart   → restart: re-read DB and reschedule all
 */
import { Router, Request, Response } from 'express';
import { getSchedulerStatus, stopAllJobs, initScheduler } from '../services/syncScheduler';

const router = Router();

/* ── GET /api/scheduler/status — Show active jobs ─────────── */
router.get('/scheduler/status', (_req: Request, res: Response) => {
  try {
    const status = getSchedulerStatus();
    res.json({
      success: true,
      data: {
        ...status,
        uptime: process.uptime(),
        serverTime: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('Error fetching scheduler status:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch scheduler status' });
  }
});

/* ── POST /api/scheduler/stop — Stop all jobs ─────────────── */
router.post('/scheduler/stop', (_req: Request, res: Response) => {
  try {
    stopAllJobs();
    res.json({ success: true, message: 'All scheduler jobs stopped' });
  } catch (error) {
    console.error('Error stopping scheduler:', error);
    res.status(500).json({ success: false, message: 'Failed to stop scheduler' });
  }
});

/* ── POST /api/scheduler/restart — Re-initialize scheduler ── */
router.post('/scheduler/restart', async (_req: Request, res: Response) => {
  try {
    stopAllJobs();
    await initScheduler();
    const status = getSchedulerStatus();
    res.json({
      success: true,
      message: `Scheduler restarted — ${status.totalJobs} active job(s)`,
      data: status,
    });
  } catch (error) {
    console.error('Error restarting scheduler:', error);
    res.status(500).json({ success: false, message: 'Failed to restart scheduler' });
  }
});

export default router;
