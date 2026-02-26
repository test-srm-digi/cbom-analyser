/**
 * Code Scanner Routes
 */
import { Router, Request, Response } from 'express';
import {
  runSonarCryptoScan,
  runRegexCryptoScan,
  runFullScan,
  calculateReadinessScore,
  checkNISTPQCCompliance,
} from '../services';
import { cbomStore } from './cbomRoutes';
import { ScanCodeRequest } from '../types';
import { CBOMRepository } from '../types/cbom.types';

const router = Router();

/** Try to extract git remote URL and current branch from a local repo path. */
async function detectGitInfo(repoPath: string): Promise<CBOMRepository | undefined> {
  try {
    const { execSync } = await import('child_process');
    const url = execSync('git config --get remote.origin.url', { cwd: repoPath, encoding: 'utf-8' }).trim();
    const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: repoPath, encoding: 'utf-8' }).trim();
    if (url) {
      // Normalise SSH URLs to HTTPS for display
      const httpsUrl = url.replace(/^git@([^:]+):/, 'https://$1/').replace(/\.git$/, '');
      return { url: httpsUrl, branch: branch || undefined };
    }
  } catch { /* not a git repo or git not available */ }
  return undefined;
}

/** Build a CBOMRepository from explicit params or fall back to git detection. */
async function resolveRepository(
  repoPath: string,
  repoUrl?: string,
  branch?: string,
): Promise<CBOMRepository | undefined> {
  if (repoUrl) return { url: repoUrl, branch };
  return detectGitInfo(repoPath);
}

/**
 * POST /api/scan-code
 * Trigger a code scan using sonar-cryptography (or fallback regex).
 */
router.post('/scan-code', async (req: Request, res: Response) => {
  try {
    const { repoPath, excludePatterns, repoUrl, branch }: ScanCodeRequest = req.body;

    if (!repoPath) {
      res.status(400).json({ success: false, error: 'repoPath is required' });
      return;
    }

    const repository = await resolveRepository(repoPath, repoUrl, branch);
    const cbom = await runSonarCryptoScan(repoPath, excludePatterns, repository);

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
    const { repoPath, excludePatterns, repoUrl, branch }: ScanCodeRequest = req.body;

    if (!repoPath) {
      res.status(400).json({ success: false, error: 'repoPath is required' });
      return;
    }

    const repository = await resolveRepository(repoPath, repoUrl, branch);
    const cbom = await runRegexCryptoScan(repoPath, excludePatterns, repository);

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

/**
 * POST /api/scan-code/full
 * Full pipeline: code scan + dependency scan + network scan + PQC parameter analysis.
 */
router.post('/scan-code/full', async (req: Request, res: Response) => {
  try {
    const { repoPath, networkHosts, excludePatterns, repoUrl, branch }: ScanCodeRequest & { networkHosts?: string[] } = req.body;

    if (!repoPath) {
      res.status(400).json({ success: false, error: 'repoPath is required' });
      return;
    }

    const repository = await resolveRepository(repoPath, repoUrl, branch);
    const cbom = await runFullScan(repoPath, networkHosts, repository);

    const storeKey = cbom.serialNumber || `full-scan-${Date.now()}`;
    cbomStore.set(storeKey, cbom);

    const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
    const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

    res.json({
      success: true,
      message: `Full scan complete. Found ${cbom.cryptoAssets.length} cryptographic assets` +
        (cbom.thirdPartyLibraries ? ` and ${cbom.thirdPartyLibraries.length} third-party crypto libraries` : '') + '.',
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
 * POST /api/ai-suggest
 * Get AI-powered suggested fix for a cryptographic asset via Bedrock.
 */
router.post('/ai-summary', async (req: Request, res: Response) => {
  try {
    const { getProjectInsight } = await import('../services/bedrockService');
    const insight = await getProjectInsight(req.body);
    res.json({ success: true, ...insight });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

router.post('/ai-suggest', async (req: Request, res: Response) => {
  try {
    const {
      algorithmName, primitive, keyLength, fileName, lineNumber,
      quantumSafety, recommendedPQC,
      assetType, detectionSource, description, mode, curve, pqcVerdict,
    } = req.body;

    if (!algorithmName) {
      res.status(400).json({ success: false, error: 'algorithmName is required' });
      return;
    }

    const { getAISuggestion } = await import('../services/bedrockService');
    const suggestion = await getAISuggestion({
      algorithmName,
      primitive,
      keyLength,
      fileName,
      lineNumber,
      quantumSafety,
      recommendedPQC,
      assetType,
      detectionSource,
      description,
      mode,
      curve,
      pqcVerdict,
    });

    res.json({ success: true, ...suggestion });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

export default router;
