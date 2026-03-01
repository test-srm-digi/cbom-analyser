/**
 * xBOM REST API Routes
 *
 * Provides endpoints to:
 *  - Generate a unified xBOM (SBOM + CBOM) by running Trivy + CBOM scanner
 *  - Merge pre-existing SBOM and CBOM JSON documents
 *  - Retrieve stored xBOMs
 *  - Download xBOM as a CycloneDX JSON file
 */

import { Router, Request, Response } from 'express';
import multer from 'multer';
import crypto from 'crypto';
import {
  XBOMDocument,
  XBOMResponse,
  XBOMGenerateRequest,
} from '../types/xbom.types';
import { CBOMDocument } from '../types/cbom.types';
import { SBOMDocument } from '../types/sbom.types';
import { mergeToXBOM, computeXBOMAnalytics } from '../services/xbomMergeService';
import { runTrivyScan, isTrivyInstalled, getTrivyVersion, parseSBOMFile } from '../services/trivyScanner';
import { runFullScan, calculateReadinessScore, checkNISTPQCCompliance, parseCBOMFile } from '../services';
import { CBOMRepository } from '../types/cbom.types';

const router = Router();

// File upload for merge endpoint
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB
});

// In-memory xBOM store
const xbomStore: Map<string, XBOMDocument> = new Map();

// ─── Health / status ─────────────────────────────────────────────────────────

/**
 * GET /api/xbom/status
 * Check Trivy availability and xBOM service readiness.
 */
router.get('/xbom/status', async (_req: Request, res: Response) => {
  const trivyInstalled = await isTrivyInstalled();
  const trivyVersion = trivyInstalled ? await getTrivyVersion() : null;

  res.json({
    success: true,
    trivyInstalled,
    trivyVersion,
    storedXBOMs: xbomStore.size,
    capabilities: {
      sbomGeneration: trivyInstalled,
      cbomGeneration: true,
      xbomMerge: true,
    },
  });
});

// ─── Generate xBOM (full scan) ───────────────────────────────────────────────

/**
 * POST /api/xbom/generate
 * Generate a unified xBOM by running both Trivy (SBOM) and CBOM Analyser (CBOM)
 * on the given repository path, then merging the results.
 */
router.post('/xbom/generate', async (req: Request, res: Response) => {
  try {
    const {
      repoPath,
      mode = 'full',
      excludePatterns,
      repoUrl,
      branch,
      specVersion,
      sbomJson,
      cbomJson,
    }: XBOMGenerateRequest = req.body;

    if (!repoPath && !sbomJson && !cbomJson) {
      res.status(400).json({ success: false, error: 'repoPath is required (or provide sbomJson/cbomJson)' });
      return;
    }

    let sbom: SBOMDocument | null = null;
    let cbom: CBOMDocument | null = null;

    const repository: CBOMRepository | undefined = repoUrl ? { url: repoUrl, branch } : undefined;

    // ── Generate or parse SBOM ──
    if (mode !== 'cbom-only') {
      if (sbomJson) {
        // Pre-supplied SBOM
        sbom = parseSBOMFile(sbomJson);
        console.log(`[xBOM] Using pre-supplied SBOM: ${sbom.components?.length ?? 0} components`);
      } else if (repoPath) {
        // Run Trivy scan
        const trivyOk = await isTrivyInstalled();
        if (trivyOk) {
          console.log(`[xBOM] Running Trivy on ${repoPath}...`);
          sbom = await runTrivyScan({ target: repoPath, scanType: 'fs' });
        } else {
          console.warn('[xBOM] Trivy not installed — skipping SBOM generation');
        }
      }
    }

    // ── Generate or parse CBOM ──
    if (mode !== 'sbom-only') {
      if (cbomJson) {
        // Pre-supplied CBOM
        cbom = parseCBOMFile(cbomJson);
        console.log(`[xBOM] Using pre-supplied CBOM: ${cbom.cryptoAssets.length} crypto assets`);
      } else if (repoPath) {
        // Run CBOM scanner
        console.log(`[xBOM] Running CBOM scanner on ${repoPath}...`);
        cbom = await runFullScan(repoPath, undefined, repository);
      }
    }

    // ── Merge ──
    const xbom = mergeToXBOM(sbom, cbom, { repoUrl, branch, specVersion });
    const analytics = computeXBOMAnalytics(xbom);

    // Store
    const storeKey = xbom.serialNumber;
    xbomStore.set(storeKey, xbom);

    const response: XBOMResponse = {
      success: true,
      message:
        `xBOM generated: ${xbom.components.length} software components, ` +
        `${xbom.cryptoAssets.length} crypto assets, ` +
        `${xbom.vulnerabilities.length} vulnerabilities, ` +
        `${xbom.crossReferences.length} cross-references.`,
      xbom,
      analytics,
    };

    res.json(response);
  } catch (error) {
    console.error('[xBOM] Generation failed:', error);
    res.status(500).json({
      success: false,
      error: (error as Error).message,
    });
  }
});

// ─── Merge existing SBOM + CBOM files ────────────────────────────────────────

/**
 * POST /api/xbom/merge
 * Merge pre-existing SBOM and CBOM JSON documents into an xBOM.
 * Accepts either JSON bodies or file uploads.
 */
router.post('/xbom/merge', upload.fields([
  { name: 'sbom', maxCount: 1 },
  { name: 'cbom', maxCount: 1 },
]), async (req: Request, res: Response) => {
  try {
    let sbom: SBOMDocument | null = null;
    let cbom: CBOMDocument | null = null;

    // Check for uploaded files
    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;

    if (files?.sbom?.[0]) {
      sbom = JSON.parse(files.sbom[0].buffer.toString('utf-8'));
    } else if (req.body.sbom) {
      sbom = typeof req.body.sbom === 'string' ? JSON.parse(req.body.sbom) : req.body.sbom;
    }

    if (files?.cbom?.[0]) {
      const cbomRaw = JSON.parse(files.cbom[0].buffer.toString('utf-8'));
      cbom = parseCBOMFile(JSON.stringify(cbomRaw));
    } else if (req.body.cbom) {
      cbom = typeof req.body.cbom === 'string' ? parseCBOMFile(req.body.cbom) : parseCBOMFile(JSON.stringify(req.body.cbom));
    }

    if (!sbom && !cbom) {
      res.status(400).json({
        success: false,
        error: 'Provide at least one of: sbom (file or JSON body), cbom (file or JSON body)',
      });
      return;
    }

    const xbom = mergeToXBOM(sbom, cbom, {
      repoUrl: req.body.repoUrl,
      branch: req.body.branch,
      specVersion: req.body.specVersion,
    });
    const analytics = computeXBOMAnalytics(xbom);

    // Store
    xbomStore.set(xbom.serialNumber, xbom);

    res.json({
      success: true,
      message:
        `xBOM merged: ${xbom.components.length} software components, ` +
        `${xbom.cryptoAssets.length} crypto assets, ` +
        `${xbom.vulnerabilities.length} vulnerabilities.`,
      xbom,
      analytics,
    });
  } catch (error) {
    console.error('[xBOM] Merge failed:', error);
    res.status(500).json({
      success: false,
      error: (error as Error).message,
    });
  }
});

// ─── List stored xBOMs ──────────────────────────────────────────────────────

/**
 * GET /api/xbom/list
 * List all stored xBOMs with summary metadata.
 */
router.get('/xbom/list', (_req: Request, res: Response) => {
  const list = Array.from(xbomStore.entries()).map(([key, xbom]) => ({
    id: key,
    component: xbom.metadata.component?.name || 'Unknown',
    timestamp: xbom.metadata.timestamp,
    softwareComponents: xbom.components.length,
    cryptoAssets: xbom.cryptoAssets.length,
    vulnerabilities: xbom.vulnerabilities.length,
    crossReferences: xbom.crossReferences.length,
    repository: xbom.metadata?.repository,
  }));

  res.json({ success: true, xboms: list });
});

// ─── Get a specific xBOM ─────────────────────────────────────────────────────

/**
 * GET /api/xbom/:id
 * Retrieve a specific stored xBOM with full analytics.
 */
router.get('/xbom/:id', (req: Request, res: Response) => {
  const xbom = xbomStore.get(req.params.id);
  if (!xbom) {
    res.status(404).json({ success: false, error: 'xBOM not found' });
    return;
  }

  const analytics = computeXBOMAnalytics(xbom);
  res.json({ success: true, xbom, analytics });
});

// ─── Upload an existing xBOM ──────────────────────────────────────────────────

/**
 * POST /api/xbom/upload
 * Upload a pre-existing xBOM JSON file (e.g. a CI artifact) to store and view.
 */
router.post('/xbom/upload', upload.single('file'), async (req: Request, res: Response) => {
  try {
    let raw: any;

    if (req.file) {
      raw = JSON.parse(req.file.buffer.toString('utf-8'));
    } else if (req.body.xbom) {
      raw = typeof req.body.xbom === 'string' ? JSON.parse(req.body.xbom) : req.body.xbom;
    } else {
      res.status(400).json({ success: false, error: 'Provide an xBOM file or JSON body (key: xbom)' });
      return;
    }

    // Basic validation — must look like a CycloneDX document
    if (raw.bomFormat !== 'CycloneDX') {
      res.status(400).json({ success: false, error: 'Invalid xBOM: bomFormat must be CycloneDX' });
      return;
    }

    // Normalise into XBOMDocument shape
    const xbom: XBOMDocument = {
      bomFormat: 'CycloneDX',
      specVersion: raw.specVersion ?? '1.6',
      serialNumber: raw.serialNumber ?? `urn:uuid:${crypto.randomUUID()}`,
      version: raw.version ?? 1,
      metadata: raw.metadata ?? { timestamp: new Date().toISOString(), tools: [] },
      components: raw.components ?? [],
      cryptoAssets: raw.cryptoAssets ?? [],
      dependencies: raw.dependencies ?? [],
      vulnerabilities: raw.vulnerabilities ?? [],
      crossReferences: raw.crossReferences ?? [],
      thirdPartyLibraries: raw.thirdPartyLibraries,
    };

    // Store it
    xbomStore.set(xbom.serialNumber, xbom);

    const analytics = computeXBOMAnalytics(xbom);

    res.json({
      success: true,
      message:
        `xBOM uploaded: ${xbom.components.length} software components, ` +
        `${xbom.cryptoAssets.length} crypto assets, ` +
        `${xbom.vulnerabilities.length} vulnerabilities, ` +
        `${xbom.crossReferences.length} cross-references.`,
      xbom,
      analytics,
    });
  } catch (error) {
    console.error('[xBOM] Upload failed:', error);
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});

// ─── Download xBOM as file ───────────────────────────────────────────────────

/**
 * GET /api/xbom/:id/download
 * Download a stored xBOM as a CycloneDX JSON file.
 */
router.get('/xbom/:id/download', (req: Request, res: Response) => {
  const xbom = xbomStore.get(req.params.id);
  if (!xbom) {
    res.status(404).json({ success: false, error: 'xBOM not found' });
    return;
  }

  const filename = `xbom-${xbom.metadata.component?.name || 'report'}-${Date.now()}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json(xbom);
});

// ─── Delete ──────────────────────────────────────────────────────────────────

/**
 * DELETE /api/xbom/:id
 * Delete a stored xBOM.
 */
router.delete('/xbom/:id', (req: Request, res: Response) => {
  const deleted = xbomStore.delete(req.params.id);
  res.json({
    success: true,
    message: deleted ? 'xBOM deleted' : 'xBOM not found (already deleted)',
  });
});

export { xbomStore };
export default router;
