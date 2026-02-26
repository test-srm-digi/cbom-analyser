/**
 * QuantumGuard CBOM Hub – Backend Entry Point
 */
import * as dotenv from 'dotenv';
import * as path from 'path';

// Load .env from project root (one level up from backend/)
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

import express from 'express';
import cors from 'cors';
import {
  cbomRoutes,
  networkRoutes,
  scanRoutes,
  integrationRoutes,
  certificateRoutes,
  endpointRoutes,
  softwareRoutes,
  deviceRoutes,
  codeFindingRoutes,
  cbomImportRoutes,
  syncLogRoutes,
  schedulerRoutes,
} from './routes';
import { initDatabase } from './config/database';
import { initScheduler, stopAllJobs } from './services/syncScheduler';

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api', cbomRoutes);
app.use('/api', networkRoutes);
app.use('/api', scanRoutes);
app.use('/api', integrationRoutes);
app.use('/api', certificateRoutes);
app.use('/api', endpointRoutes);
app.use('/api', softwareRoutes);
app.use('/api', deviceRoutes);
app.use('/api', codeFindingRoutes);
app.use('/api', cbomImportRoutes);
app.use('/api', syncLogRoutes);
app.use('/api', schedulerRoutes);

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'QuantumGuard CBOM Hub',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.listen(PORT, async () => {
  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║   QuantumGuard CBOM Hub – Backend             ║
  ║   Running on http://localhost:${PORT}            ║
  ╚═══════════════════════════════════════════════╝
  `);

  // Initialize database
  await initDatabase();

  // Initialize sync scheduler (reads DB for active schedules)
  await initScheduler();
});

// Graceful shutdown — stop cron jobs before exit
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received — stopping scheduler…');
  stopAllJobs();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[Server] SIGINT received — stopping scheduler…');
  stopAllJobs();
  process.exit(0);
});

export default app;
