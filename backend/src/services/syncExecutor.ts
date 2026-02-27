/**
 * SyncExecutor — Executes a single sync operation for an integration
 *
 * Lifecycle:
 *   1. Create a SyncLog record (status = 'running')
 *   2. Look up the connector for the integration's templateType
 *   3. Call the connector's fetch() with the integration's config
 *   4. Delete previous data for this integration (full refresh)
 *   5. Bulk-insert the new data
 *   6. Update the integration's lastSync / lastSyncItems / nextSync
 *   7. Finalize the SyncLog (status, duration, counts)
 *
 * Designed to be called by:
 *   - SyncScheduler (scheduled runs)
 *   - integrationRoutes POST /sync (manual trigger)
 */
import { v4 as uuidv4 } from 'uuid';
import { Integration, SyncLog, Certificate, Endpoint, Software, Device, CbomImport } from '../models';
import { CONNECTOR_REGISTRY, ConnectorConfig } from './connectors';

/* ── Model lookup map ──────────────────────────────────────── */

const MODEL_MAP: Record<string, typeof Certificate | typeof Endpoint | typeof Software | typeof Device | typeof CbomImport> = {
  Certificate,
  Endpoint,
  Software,
  Device,
  CbomImport,
};

/* ── Schedule → ms mapping (for nextSync calculation) ──────── */

const SCHEDULE_MS: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
};

/* ── Main executor function ────────────────────────────────── */

export interface SyncResult {
  success: boolean;
  syncLogId: string;
  itemsFetched: number;
  itemsCreated: number;
  itemsDeleted: number;
  errors: string[];
  durationMs: number;
}

export async function executeSyncForIntegration(
  integrationId: string,
  trigger: 'scheduled' | 'manual',
): Promise<SyncResult> {
  const startTime = Date.now();
  const syncLogId = uuidv4();
  const errors: string[] = [];

  /* ── Step 1: Create SyncLog record ───────────────────────── */
  let syncLog: SyncLog;
  try {
    syncLog = await SyncLog.create({
      id: syncLogId,
      integrationId,
      trigger,
      status: 'running',
      startedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error(`[SyncExecutor] Failed to create SyncLog for integration ${integrationId}:`, err);
    return {
      success: false,
      syncLogId,
      itemsFetched: 0,
      itemsCreated: 0,
      itemsDeleted: 0,
      errors: [`Failed to create sync log: ${(err as Error).message}`],
      durationMs: Date.now() - startTime,
    };
  }

  /* ── Step 2: Load & validate integration ─────────────────── */
  let integration: Integration | null;
  try {
    integration = await Integration.findByPk(integrationId);
    if (!integration) {
      throw new Error(`Integration ${integrationId} not found`);
    }
    if (!integration.enabled) {
      throw new Error(`Integration ${integrationId} is disabled`);
    }
  } catch (err) {
    errors.push((err as Error).message);
    await finalizeSyncLog(syncLog, 'failed', startTime, 0, 0, 0, errors);
    return { success: false, syncLogId, itemsFetched: 0, itemsCreated: 0, itemsDeleted: 0, errors, durationMs: Date.now() - startTime };
  }

  /* ── Step 3: Look up connector ───────────────────────────── */
  const connector = CONNECTOR_REGISTRY[integration.templateType];
  if (!connector) {
    errors.push(`No connector registered for templateType "${integration.templateType}"`);
    await finalizeSyncLog(syncLog, 'failed', startTime, 0, 0, 0, errors);
    await integration.update({ status: 'error', errorMessage: errors[0] });
    return { success: false, syncLogId, itemsFetched: 0, itemsCreated: 0, itemsDeleted: 0, errors, durationMs: Date.now() - startTime };
  }

  /* ── Step 4: Fetch data from external source ─────────────── */
  let fetchedRecords: Record<string, unknown>[] = [];
  let fetchMeta: Record<string, unknown> = {};
  try {
    // Mark as syncing
    await integration.update({ status: 'testing' });

    const config = (integration.config || {}) as ConnectorConfig;
    // Pass lastSync and integrationCreatedAt into config so connectors can do incremental fetches
    // integrationCreatedAt ensures we never pull CBOMs from before the connection was created
    const configWithSync = {
      ...config,
      lastSync: integration.lastSync || undefined,
      integrationCreatedAt: integration.createdAt?.toISOString(),
    };
    const result = await connector.fetch(configWithSync, integrationId);

    if (!result.success) {
      errors.push(...result.errors);
      throw new Error(result.errors.join('; ') || 'Connector returned failure');
    }

    fetchedRecords = result.data;
    fetchMeta = (result as any).meta || {};
    if (result.errors.length > 0) {
      errors.push(...result.errors);
    }
  } catch (err) {
    errors.push(`Fetch failed: ${(err as Error).message}`);
    await finalizeSyncLog(syncLog, 'failed', startTime, 0, 0, 0, errors);
    await integration.update({ status: 'error', errorMessage: errors.join('; ') });
    return { success: false, syncLogId, itemsFetched: fetchedRecords.length, itemsCreated: 0, itemsDeleted: 0, errors, durationMs: Date.now() - startTime };
  }

  /* ── Step 5: Persist data (full refresh or incremental) ──── */
  const TargetModel = MODEL_MAP[connector.model];
  let deletedCount = 0;
  let createdCount = 0;

  // Incremental mode: connector signals via meta.incremental = true
  // (used by GitHub Actions CBOM connector — only appends new records)
  const isIncremental = !!fetchMeta.incremental;

  if (TargetModel) {
    try {
      if (!isIncremental) {
        // Full refresh: delete old → insert new
        deletedCount = await (TargetModel as any).destroy({
          where: { integrationId },
        });
      }

      if (fetchedRecords.length > 0) {
        const created = await (TargetModel as any).bulkCreate(
          fetchedRecords,
          { validate: true },
        );
        createdCount = created.length;
      }
    } catch (err) {
      errors.push(`Persistence failed: ${(err as Error).message}`);
    }
  } else {
    errors.push(`Model "${connector.model}" not found in MODEL_MAP`);
  }

  /* ── Step 6: Update integration metadata ─────────────────── */
  const now = new Date();
  const nextSyncDate = SCHEDULE_MS[integration.syncSchedule]
    ? new Date(now.getTime() + SCHEDULE_MS[integration.syncSchedule]).toISOString()
    : null;

  try {
    await integration.update({
      status: errors.length > 0 ? 'error' : 'connected',
      lastSync: now.toISOString(),
      lastSyncItems: createdCount,
      lastSyncErrors: errors.length,
      nextSync: nextSyncDate,
      errorMessage: errors.length > 0 ? errors.join('; ') : null,
    });
  } catch (err) {
    errors.push(`Failed to update integration metadata: ${(err as Error).message}`);
  }

  /* ── Step 7: Finalize SyncLog ────────────────────────────── */
  const finalStatus = errors.length === 0 ? 'success' : (createdCount > 0 ? 'partial' : 'failed');
  await finalizeSyncLog(syncLog, finalStatus, startTime, fetchedRecords.length, createdCount, deletedCount, errors);

  const durationMs = Date.now() - startTime;
  console.log(
    `[SyncExecutor] Integration "${integration.name}" (${connector.label}) — ${finalStatus}: ` +
    `${createdCount} created, ${deletedCount} deleted, ${errors.length} errors (${durationMs}ms)`,
  );

  return {
    success: errors.length === 0,
    syncLogId,
    itemsFetched: fetchedRecords.length,
    itemsCreated: createdCount,
    itemsDeleted: deletedCount,
    errors,
    durationMs,
  };
}

/* ── Helper: finalize a SyncLog record ─────────────────────── */

async function finalizeSyncLog(
  syncLog: SyncLog,
  status: 'success' | 'partial' | 'failed',
  startTime: number,
  itemsFetched: number,
  itemsCreated: number,
  itemsDeleted: number,
  errors: string[],
): Promise<void> {
  try {
    await syncLog.update({
      status,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      itemsFetched,
      itemsCreated,
      itemsDeleted,
      errors: errors.length,
      errorDetails: errors.length > 0 ? errors : null,
    });
  } catch (err) {
    console.error('[SyncExecutor] Failed to finalize SyncLog:', err);
  }
}
