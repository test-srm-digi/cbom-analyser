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
  classifyAlgorithm,
} from '../services';
import { cbomStore } from './cbomRoutes';
import { NetworkScanRequest, NetworkScanResponse } from '../types';

const router = Router();

/**
 * Break a TLS cipher suite name into its constituent algorithms and classify
 * each for quantum safety.
 */
function buildCipherBreakdown(cipherSuite: string, protocol: string) {
  const upper = cipherSuite.toUpperCase();
  const components: { name: string; role: string; quantumSafe: boolean; notes: string }[] = [];

  // ── Key exchange ──
  if (/ECDHE/i.test(upper)) {
    const p = classifyAlgorithm('ECDHE');
    components.push({ name: 'ECDHE', role: 'Key Exchange', quantumSafe: p.quantumSafety === 'quantum-safe', notes: p.notes || 'Elliptic-curve Diffie-Hellman (ephemeral). Vulnerable to Shor\'s algorithm.' });
  } else if (/DHE/i.test(upper)) {
    const p = classifyAlgorithm('DHE');
    components.push({ name: 'DHE', role: 'Key Exchange', quantumSafe: false, notes: p.notes || 'Diffie-Hellman (ephemeral). Vulnerable to Shor\'s algorithm.' });
  } else if (/RSA/i.test(upper) && !/RSA.*(SHA|SIGN)/i.test(upper)) {
    const p = classifyAlgorithm('RSA');
    components.push({ name: 'RSA', role: 'Key Exchange', quantumSafe: false, notes: p.notes || 'RSA key transport. Vulnerable to Shor\'s algorithm.' });
  }
  // TLS 1.3 suites don't encode key exchange in the suite name; key exchange is negotiated separately
  if (protocol === 'TLSv1.3' && components.every(c => c.role !== 'Key Exchange')) {
    components.push({ name: 'X25519 / ECDHE (negotiated)', role: 'Key Exchange', quantumSafe: false, notes: 'TLS 1.3 negotiates key exchange separately (typically X25519 or ECDHE P-256). Vulnerable to quantum computers without ML-KEM hybrid.' });
  }

  // ── Authentication ──
  if (/ECDSA/i.test(upper)) {
    components.push({ name: 'ECDSA', role: 'Authentication', quantumSafe: false, notes: 'Elliptic Curve Digital Signature Algorithm. Vulnerable to Shor\'s algorithm.' });
  } else if (/RSA/i.test(upper)) {
    components.push({ name: 'RSA', role: 'Authentication', quantumSafe: false, notes: 'RSA signature authentication. Vulnerable to Shor\'s algorithm.' });
  }

  // ── Encryption (AEAD / block cipher) ──
  if (/AES.?256.?GCM/i.test(upper)) {
    components.push({ name: 'AES-256-GCM', role: 'Encryption', quantumSafe: true, notes: 'AES-256 in GCM mode. Quantum-safe symmetric cipher (Grover halves effective key to 128-bit, still secure).' });
  } else if (/AES.?128.?GCM/i.test(upper)) {
    components.push({ name: 'AES-128-GCM', role: 'Encryption', quantumSafe: true, notes: 'AES-128 in GCM mode. Considered quantum-safe with sufficient margin per NIST guidance.' });
  } else if (/AES.?256.?CBC/i.test(upper)) {
    components.push({ name: 'AES-256-CBC', role: 'Encryption', quantumSafe: true, notes: 'AES-256 in CBC mode. Quantum-safe symmetric cipher but CBC has known padding oracle risks.' });
  } else if (/AES.?128.?CBC/i.test(upper)) {
    components.push({ name: 'AES-128-CBC', role: 'Encryption', quantumSafe: true, notes: 'AES-128 in CBC mode. Quantum-safe but CBC is legacy.' });
  } else if (/CHACHA20.?POLY1305/i.test(upper)) {
    components.push({ name: 'ChaCha20-Poly1305', role: 'Encryption', quantumSafe: true, notes: 'ChaCha20 stream cipher with Poly1305 MAC. Quantum-safe symmetric AEAD.' });
  }

  // ── Hash (PRF / MAC) ──
  if (/SHA384/i.test(upper)) {
    components.push({ name: 'SHA-384', role: 'Hash / PRF', quantumSafe: true, notes: 'SHA-384 for TLS PRF and record MAC. Quantum-safe hash function.' });
  } else if (/SHA256/i.test(upper)) {
    components.push({ name: 'SHA-256', role: 'Hash / PRF', quantumSafe: true, notes: 'SHA-256 for TLS PRF and record MAC. Quantum-safe hash function.' });
  }

  const allSafe = components.length > 0 && components.every(c => c.quantumSafe);
  const anyNotSafe = components.some(c => !c.quantumSafe);

  return { components, allSafe, anyNotSafe };
}

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
    const breakdown = buildCipherBreakdown(result.cipherSuite, result.protocol);

    const response = {
      success: true,
      result,
      cbomAsset: enrichedAsset,
      cipherBreakdown: breakdown,
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
