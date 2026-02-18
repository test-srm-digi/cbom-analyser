/**
 * Network Scanner Routes
 */
import { Router, Request, Response } from 'express';
import {
  scanNetworkCrypto,
  networkResultToCBOMAsset,
  scanMultipleHosts,
  enrichAssetWithPQCData,
  calculateReadinessScore,
  checkNISTPQCCompliance,
  mergeCBOMs,
} from '../services';
import { cbomStore } from './cbomRoutes';
import { NetworkScanRequest, NetworkScanResponse } from '../types';

const router = Router();

/**
 * POST /api/scan-network
 * Scan a single host for TLS/cryptographic properties.
 */
router.post('/scan-network', async (req: Request, res: Response) => {
  try {
    const { url, port }: NetworkScanRequest = req.body;

    if (!url) {
      res.status(400).json({ success: false, error: 'URL is required' });
      return;
    }

    // Strip protocol and path from URL
    const host = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:.*$/, '');

    const result = await scanNetworkCrypto(host, port || 443);
    const cbomAsset = networkResultToCBOMAsset(result);
    const enrichedAsset = enrichAssetWithPQCData(cbomAsset);

    const response: NetworkScanResponse = {
      success: true,
      result,
      cbomAsset: enrichedAsset,
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: (error as Error).message,
    });
  }
});

/**
 * POST /api/scan-network/batch
 * Scan multiple hosts at once.
 */
router.post('/scan-network/batch', async (req: Request, res: Response) => {
  try {
    const { hosts } = req.body as { hosts: { host: string; port?: number }[] };

    if (!hosts || !Array.isArray(hosts) || hosts.length === 0) {
      res.status(400).json({ success: false, error: 'Hosts array is required' });
      return;
    }

    const { results, errors } = await scanMultipleHosts(hosts);

    const cbomAssets = results.map((r) => {
      const asset = networkResultToCBOMAsset(r);
      return enrichAssetWithPQCData(asset);
    });

    res.json({
      success: true,
      results,
      cbomAssets,
      errors,
      summary: {
        scanned: results.length,
        failed: errors.length,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: (error as Error).message,
    });
  }
});

/**
 * POST /api/scan-network/merge/:cbomId
 * Scan a host and merge the result into an existing CBOM.
 */
router.post('/scan-network/merge/:cbomId', async (req: Request, res: Response) => {
  try {
    const { url, port }: NetworkScanRequest = req.body;
    const cbomId = req.params.cbomId;

    const existingCBOM = cbomStore.get(cbomId);
    if (!existingCBOM) {
      res.status(404).json({ success: false, error: 'CBOM not found' });
      return;
    }

    if (!url) {
      res.status(400).json({ success: false, error: 'URL is required' });
      return;
    }

    const host = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:.*$/, '');
    const result = await scanNetworkCrypto(host, port || 443);
    const cbomAsset = enrichAssetWithPQCData(networkResultToCBOMAsset(result));

    // Merge into existing CBOM
    const mergedCBOM = mergeCBOMs(existingCBOM, cbomAsset);
    cbomStore.set(cbomId, mergedCBOM);

    const readinessScore = calculateReadinessScore(mergedCBOM.cryptoAssets);
    const compliance = checkNISTPQCCompliance(mergedCBOM.cryptoAssets);

    res.json({
      success: true,
      message: `Network scan merged. Total assets: ${mergedCBOM.cryptoAssets.length}`,
      cbom: mergedCBOM,
      readinessScore,
      compliance,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: (error as Error).message,
    });
  }
});

export default router;
