/**
 * SyncScheduler — In-process cron scheduler for integration data sync
 *
 * Uses `node-cron` to manage per-integration cron jobs.  When the
 * server starts, it reads all enabled integrations with a non-manual
 * schedule and creates a cron job for each.  When integrations are
 * created / updated / deleted, the scheduler is notified to add,
 * reschedule, or remove the corresponding cron entry.
 *
 * Schedule mapping:
 *   manual → no cron job
 *   1h     → "0 * * * *"            (every hour at :00)
 *   6h     → "0 0,6,12,18 * * *"    (every 6 hours)
 *   12h    → "0 0,12 * * *"         (every 12 hours)
 *   24h    → "0 2 * * *"            (daily at 02:00)
 *
 * All times are in the server's local timezone. In production, you'd
 * typically set TZ=UTC in your environment to avoid DST surprises.
 */
import * as cron from 'node-cron';
import { Integration } from '../models';
import { executeSyncForIntegration } from './syncExecutor';

/* ── Schedule → cron expression mapping ────────────────────── */

const SCHEDULE_CRON: Record<string, string> = {
  '1h': '0 * * * *',         // top of every hour
  '6h': '0 */6 * * *',       // every 6 hours (00:00, 06:00, 12:00, 18:00)
  '12h': '0 */12 * * *',     // every 12 hours (00:00, 12:00)
  '24h': '0 2 * * *',        // once daily at 02:00
};

/* ── Active job registry ───────────────────────────────────── */

interface ScheduledJob {
  task: cron.ScheduledTask;
  cronExpression: string;
  schedule: string;
  integrationName: string;
  integrationId: string;
  createdAt: Date;
  lastRunAt: Date | null;
  runCount: number;
}

const activeJobs = new Map<string, ScheduledJob>();

/* ══════════════════════════════════════════════════════════════
 *  Public API
 * ══════════════════════════════════════════════════════════════ */

/**
 * Initialize the scheduler — load all enabled integrations from the
 * database and start cron jobs for those with non-manual schedules.
 * Call once at server startup (after database init).
 */
export async function initScheduler(): Promise<void> {
  console.log('  ⏰ Initializing sync scheduler…');

  try {
    const integrations = await Integration.findAll({
      where: { enabled: true },
    });

    let scheduled = 0;
    for (const integration of integrations) {
      if (integration.syncSchedule !== 'manual') {
        scheduleJob(integration.id, integration.syncSchedule, integration.name);
        scheduled++;
      }
    }

    console.log(`  ✓ Sync scheduler ready — ${scheduled} active job(s) from ${integrations.length} integration(s)`);
  } catch (err) {
    const msg = (err as Error).message || String(err);
    if (msg.includes('ECONNREFUSED') || msg.includes('ConnectionRefused')) {
      console.log('  ⏰ Sync scheduler skipped — database not available');
    } else {
      console.error('  ✗ Sync scheduler initialization failed:', msg);
    }
  }
}

/**
 * Schedule (or reschedule) a cron job for an integration.
 * If a job already exists for this integrationId, it is stopped
 * and replaced.
 */
export function scheduleJob(
  integrationId: string,
  schedule: string,
  integrationName: string,
): void {
  // Remove existing job if any
  removeJob(integrationId);

  // No cron for manual schedule
  if (schedule === 'manual' || !SCHEDULE_CRON[schedule]) {
    return;
  }

  const cronExpression = SCHEDULE_CRON[schedule];
  const jobEntry: ScheduledJob = {
    task: null as unknown as cron.ScheduledTask,
    cronExpression,
    schedule,
    integrationName,
    integrationId,
    createdAt: new Date(),
    lastRunAt: null,
    runCount: 0,
  };

  const task = cron.schedule(cronExpression, async () => {
    jobEntry.lastRunAt = new Date();
    jobEntry.runCount++;

    console.log(
      `[Scheduler] Triggering sync for "${integrationName}" (${schedule}) — run #${jobEntry.runCount}`,
    );

    try {
      const result = await executeSyncForIntegration(integrationId, 'scheduled');
      console.log(
        `[Scheduler] Sync completed for "${integrationName}" — ` +
        `${result.itemsCreated} items, ${result.errors.length} errors, ${result.durationMs}ms`,
      );
    } catch (err) {
      console.error(`[Scheduler] Sync failed for "${integrationName}":`, (err as Error).message);
    }
  }, {
    scheduled: true,
    timezone: process.env.TZ || undefined,
  } as any);

  jobEntry.task = task;
  activeJobs.set(integrationId, jobEntry);

  console.log(
    `  📅 Scheduled "${integrationName}" → ${schedule} (cron: ${cronExpression})`,
  );
}

/**
 * Remove a scheduled job for an integration.
 */
export function removeJob(integrationId: string): void {
  const existing = activeJobs.get(integrationId);
  if (existing) {
    existing.task.stop();
    activeJobs.delete(integrationId);
  }
}

/**
 * Handle integration schedule change — reschedule or remove.
 */
export function onScheduleChanged(
  integrationId: string,
  newSchedule: string,
  integrationName: string,
  enabled: boolean,
): void {
  if (!enabled || newSchedule === 'manual') {
    removeJob(integrationId);
  } else {
    scheduleJob(integrationId, newSchedule, integrationName);
  }
}

/**
 * Handle integration deletion — remove its cron job.
 */
export function onIntegrationDeleted(integrationId: string): void {
  removeJob(integrationId);
}

/**
 * Handle integration toggle — start or stop its cron job.
 */
export function onIntegrationToggled(
  integrationId: string,
  enabled: boolean,
  syncSchedule: string,
  integrationName: string,
): void {
  if (enabled && syncSchedule !== 'manual') {
    scheduleJob(integrationId, syncSchedule, integrationName);
  } else {
    removeJob(integrationId);
  }
}

/**
 * Shut down all cron jobs gracefully.
 * Call on server shutdown / SIGTERM.
 */
export function stopAllJobs(): void {
  for (const [id, job] of activeJobs) {
    job.task.stop();
    console.log(`[Scheduler] Stopped job for integration ${id}`);
  }
  activeJobs.clear();
}

/**
 * Get the status of all active scheduler jobs.
 * Used by the scheduler status API endpoint.
 */
export function getSchedulerStatus(): {
  totalJobs: number;
  jobs: Array<{
    integrationId: string;
    integrationName: string;
    schedule: string;
    cronExpression: string;
    createdAt: string;
    lastRunAt: string | null;
    runCount: number;
  }>;
} {
  const jobs = Array.from(activeJobs.values()).map((j) => ({
    integrationId: j.integrationId,
    integrationName: j.integrationName,
    schedule: j.schedule,
    cronExpression: j.cronExpression,
    createdAt: j.createdAt.toISOString(),
    lastRunAt: j.lastRunAt ? j.lastRunAt.toISOString() : null,
    runCount: j.runCount,
  }));

  return { totalJobs: jobs.length, jobs };
}
