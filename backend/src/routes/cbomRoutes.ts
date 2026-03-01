/**
 * CBOM Upload & Management Routes
 */
import { Router, Request, Response } from 'express';
import multer from 'multer';
import {
  parseCBOMFile,
  calculateReadinessScore,
  checkNISTPQCCompliance,
  filterInformationalAssets,
} from '../services';
import { UploadResponse, CBOMDocument } from '../types';
import CbomUpload from '../models/CbomUpload';

const router = Router();

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON files are accepted'));
    }
  },
});

// In-memory store for uploaded CBOMs (use a DB in production)
const cbomStore: Map<string, CBOMDocument> = new Map();

/**
 * POST /api/upload
 * Upload a CycloneDX CBOM JSON file (1.6 / 1.7).
 */
router.post('/upload', upload.single('cbom'), (req: Request, res: Response) => {
  try {
    if (!req.file) {
      res.status(400).json({ success: false, message: 'No file uploaded' });
      return;
    }

    const jsonContent = req.file.buffer.toString('utf-8');
    const cbom = parseCBOMFile(jsonContent);

    // Store the CBOM in memory
    const storeKey = cbom.serialNumber || `cbom-${Date.now()}`;
    cbomStore.set(storeKey, cbom);

    // Calculate analytics
    const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
    const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

    // Persist to DB (fire-and-forget, don't block response)
    const assets = cbom.cryptoAssets ?? [];
    // Use actionable assets (exclude informational) for stats
    const actionableAssets = filterInformationalAssets(assets);
    CbomUpload.create({
      fileName: req.file.originalname || 'unknown.json',
      componentName: cbom.metadata?.component?.name ?? null,
      format: cbom.bomFormat ?? 'CycloneDX',
      specVersion: cbom.specVersion ?? '1.7',
      totalAssets: assets.length,
      quantumSafe: actionableAssets.filter((a: { quantumSafety?: string }) => a.quantumSafety === 'quantum-safe').length,
      notQuantumSafe: actionableAssets.filter((a: { quantumSafety?: string }) => a.quantumSafety === 'not-quantum-safe').length,
      conditional: actionableAssets.filter((a: { quantumSafety?: string }) => a.quantumSafety === 'conditional').length,
      unknown: actionableAssets.filter((a: { quantumSafety?: string }) => a.quantumSafety === 'unknown').length,
      uploadDate: new Date().toISOString(),
      cbomFile: req.file.buffer,
      cbomFileType: 'application/json',
    }).catch((err) => console.error('Failed to persist CBOM upload:', err));

    const response: UploadResponse = {
      success: true,
      message: `CBOM parsed successfully. Found ${cbom.cryptoAssets.length} cryptographic assets.`,
      cbom,
      readinessScore,
      compliance,
    };

    res.json(response);
  } catch (error) {
    res.status(400).json({
      success: false,
      message: `Failed to parse CBOM: ${(error as Error).message}`,
    });
  }
});

/**
 * POST /api/upload/raw
 * Upload raw CBOM JSON in request body (no file upload).
 */
router.post('/upload/raw', (req: Request, res: Response) => {
  try {
    const cbom = parseCBOMFile(JSON.stringify(req.body));

    const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
    const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

    const response: UploadResponse = {
      success: true,
      message: `CBOM parsed successfully. Found ${cbom.cryptoAssets.length} cryptographic assets.`,
      cbom,
      readinessScore,
      compliance,
    };

    res.json(response);
  } catch (error) {
    res.status(400).json({
      success: false,
      message: `Failed to parse CBOM: ${(error as Error).message}`,
    });
  }
});

/**
 * GET /api/cbom/list
 * List all stored CBOMs.
 */
router.get('/cbom/list', (_req: Request, res: Response) => {
  const list = Array.from(cbomStore.entries()).map(([key, cbom]) => ({
    id: key,
    component: cbom.metadata.component?.name || 'Unknown',
    assetCount: cbom.cryptoAssets.length,
    timestamp: cbom.metadata.timestamp,
  }));
  res.json({ success: true, cboms: list });
});

/**
 * GET /api/cbom/:id
 * Get a specific stored CBOM.
 */
router.get('/cbom/:id', (req: Request, res: Response) => {
  const cbom = cbomStore.get(req.params.id);
  if (!cbom) {
    res.status(404).json({ success: false, message: 'CBOM not found' });
    return;
  }

  const readinessScore = calculateReadinessScore(cbom.cryptoAssets);
  const compliance = checkNISTPQCCompliance(cbom.cryptoAssets);

  res.json({ success: true, cbom, readinessScore, compliance });
});

export { cbomStore };
export default router;
