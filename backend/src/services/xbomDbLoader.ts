/**
 * xBOM DB Loader — Loads xBOM files from CbomImport records into
 * the in-memory xbomStore so they appear in the xBOM API endpoints.
 *
 * Called:
 *   1. On server startup (to restore previously synced xBOMs)
 *   2. After each sync that creates new CBOM import records
 */
import { Op } from 'sequelize';
import { CbomImport } from '../models';
import { xbomStore } from '../routes/xbomRoutes';
import type { XBOMDocument } from '../types/xbom.types';

/**
 * Load all CbomImport records that have an xbomFile into the in-memory
 * xBOM store. Skips entries already present in the store.
 */
export async function loadXBOMsFromImports(): Promise<number> {
  let loaded = 0;

  try {
    // Find all imports that have stored xBOM files
    const imports = await CbomImport.findAll({
      where: {
        xbomFile: { [Op.ne]: null },
      },
      attributes: ['id', 'xbomFile', 'applicationName', 'importDate'],
    });

    for (const row of imports) {
      if (!row.xbomFile) continue;

      try {
        const rawText = (row.xbomFile as Buffer).toString('utf-8');
        const raw = JSON.parse(rawText);

        // Must be CycloneDX
        if (raw.bomFormat !== 'CycloneDX') continue;

        // Build a stable key from the serialNumber or the import ID
        const storeKey = raw.serialNumber || `cbom-import:${row.id}`;

        // Skip if already in store
        if (xbomStore.has(storeKey)) continue;

        // Normalise into XBOMDocument shape
        const xbom: XBOMDocument = {
          bomFormat: 'CycloneDX',
          specVersion: raw.specVersion ?? '1.6',
          serialNumber: storeKey,
          version: raw.version ?? 1,
          metadata: raw.metadata ?? {
            timestamp: row.importDate || new Date().toISOString(),
            tools: [],
          },
          components: raw.components ?? [],
          cryptoAssets: raw.cryptoAssets ?? [],
          dependencies: raw.dependencies ?? [],
          vulnerabilities: raw.vulnerabilities ?? [],
          crossReferences: raw.crossReferences ?? [],
          thirdPartyLibraries: raw.thirdPartyLibraries,
        };

        xbomStore.set(storeKey, xbom);
        loaded++;
      } catch (e) {
        console.warn(`[xbomDbLoader] Failed to parse xBOM from import ${row.id}:`, e);
      }
    }

    if (loaded > 0) {
      console.log(`[xbomDbLoader] Loaded ${loaded} xBOM(s) from DB (total in store: ${xbomStore.size})`);
    }
  } catch (e) {
    const msg = (e as Error).message || String(e);
    // In CI / GitHub Actions the DB is not available — keep log quiet
    if (msg.includes('ECONNREFUSED') || msg.includes('ConnectionRefused')) {
      console.log('[xbomDbLoader] Skipped — database not available (expected in CI/Action mode)');
    } else {
      console.error('[xbomDbLoader] Failed to query CbomImport table:', msg);
    }
  }

  return loaded;
}
