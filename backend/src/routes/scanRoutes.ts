/**
 * Code Scanner Routes
 */
import { Router, Request, Response } from 'express';
import {
  runSonarCryptoScan,
  runRegexCryptoScan,
  calculateReadinessScore,
  checkNISTPQCCompliance,
} from '../services';
import { cbomStore } from './cbomRoutes';
import { ScanCodeRequest } from '../types';

const router = Router();

/**
 * POST /api/scan-code
 * Trigger a code scan using sonar-cryptography (or fallback regex).
 */
router.post('/scan-code', async (req: Request, res: Response) => {
  try {
    const { repoPath }: ScanCodeRequest = req.body;

    if (!repoPath) {
      res.status(400).json({ success: false, error: 'repoPath is required' });
      return;
    }

    const cbom = await runSonarCryptoScan(repoPath);

    // Store result
    const storeKey = cbom.serialNumber || `scan-${Date.now()}`;
    cbomStore.set(storeKey, cbom);

    const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
    const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

    res.json({
      success: true,
      message: `Scan complete. Found ${cbom.cryptoAssets.length} cryptographic assets.`,
      cbomId: storeKey,
      cbom,
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

/**
 * POST /api/scan-code/regex
 * Run only the regex-based scanner (faster, no sonar dependency).
 */
router.post('/scan-code/regex', async (req: Request, res: Response) => {
  try {
    const { repoPath }: ScanCodeRequest = req.body;

    if (!repoPath) {
      res.status(400).json({ success: false, error: 'repoPath is required' });
      return;
    }

    const cbom = await runRegexCryptoScan(repoPath);

    const storeKey = cbom.serialNumber || `regex-scan-${Date.now()}`;
    cbomStore.set(storeKey, cbom);

    const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
    const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

    res.json({
      success: true,
      message: `Regex scan complete. Found ${cbom.cryptoAssets.length} cryptographic assets.`,
      cbomId: storeKey,
      cbom,
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
