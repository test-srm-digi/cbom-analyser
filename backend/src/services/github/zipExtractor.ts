/**
 * ZIP Extraction & CBOM Analysis Utilities
 */

/**
 * Extract a JSON file from a ZIP buffer.
 * GitHub Actions artifacts are always served as ZIP archives.
 *
 * Uses the Central Directory (at end of ZIP) for reliable size info,
 * since GitHub's artifacts use data descriptors (flag bit 3) which
 * set local-header sizes to 0.
 */
export async function extractJsonFromZip(zipBuffer: Buffer): Promise<string | null> {
  const { inflateRawSync } = await import('zlib');

  // ── Locate End-of-Central-Directory record ──
  // Signature: 0x06054b50, appears in the last 65557 bytes
  let eocdOffset = -1;
  const searchStart = Math.max(0, zipBuffer.length - 65557);
  for (let i = zipBuffer.length - 22; i >= searchStart; i--) {
    if (zipBuffer.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    // Fallback: no EOCD found — shouldn't happen for valid ZIPs
    return null;
  }

  const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);  // offset of central directory
  const cdEntries = zipBuffer.readUInt16LE(eocdOffset + 10);  // total entries

  // ── Walk Central Directory entries ──
  let pos = cdOffset;
  for (let i = 0; i < cdEntries && pos < zipBuffer.length - 4; i++) {
    if (zipBuffer.readUInt32LE(pos) !== 0x02014b50) break; // central dir signature

    const method = zipBuffer.readUInt16LE(pos + 10);
    const compSize = zipBuffer.readUInt32LE(pos + 20);
    const nameLen = zipBuffer.readUInt16LE(pos + 28);
    const extraLen = zipBuffer.readUInt16LE(pos + 30);
    const commentLen = zipBuffer.readUInt16LE(pos + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(pos + 42);
    const fileName = zipBuffer.toString('utf-8', pos + 46, pos + 46 + nameLen);

    // Move to next central directory entry
    pos += 46 + nameLen + extraLen + commentLen;

    if (!fileName.endsWith('.json') && !fileName.endsWith('.xml')) continue;

    // ── Read from local file header to get data offset ──
    const localNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;

    const rawData = zipBuffer.subarray(dataStart, dataStart + compSize);

    if (method === 0) {
      // Stored (no compression)
      return rawData.toString('utf-8');
    } else if (method === 8) {
      // Deflated
      const inflated = inflateRawSync(rawData);
      return inflated.toString('utf-8');
    }
  }

  return null;
}

/**
 * Parse a CBOM JSON string and extract summary metrics.
 */
export function analyzeCbom(cbomJson: string, fileName: string): {
  totalComponents: number;
  cryptoComponents: number;
  quantumSafeComponents: number;
  nonQuantumSafeComponents: number;
  conditionalComponents: number;
  format: string;
  specVersion: string;
  applicationName: string;
} {
  try {
    const cbom = JSON.parse(cbomJson);
    const specVersion = cbom.specVersion || '1.6';
    const format = cbom.bomFormat === 'CycloneDX' ? 'CycloneDX' : 'Unknown';
    const applicationName = cbom.metadata?.component?.name || fileName.replace(/-cbom.*$/, '');

    const components = cbom.components || [];
    const cryptoAssets = cbom.cryptoAssets || cbom.components?.filter(
      (c: Record<string, unknown>) => c.type === 'crypto-asset' || (c as any).cryptoProperties,
    ) || [];

    const totalComponents = components.length + (cbom.cryptoAssets?.length || 0);
    const cryptoComponents = cryptoAssets.length;

    let quantumSafe = 0;
    let nonQuantumSafe = 0;
    let conditional = 0;
    for (const asset of cryptoAssets) {
      const safety = asset.quantumSafety || asset.cryptoProperties?.quantumSafety;
      if (safety === 'quantum-safe') {
        quantumSafe++;
      } else if (safety === 'conditional') {
        conditional++;
      } else {
        nonQuantumSafe++; // not-quantum-safe, unknown, and any other value
      }
    }

    return {
      totalComponents,
      cryptoComponents,
      quantumSafeComponents: quantumSafe,
      nonQuantumSafeComponents: nonQuantumSafe,
      conditionalComponents: conditional,
      format,
      specVersion,
      applicationName,
    };
  } catch {
    return {
      totalComponents: 0,
      cryptoComponents: 0,
      quantumSafeComponents: 0,
      nonQuantumSafeComponents: 0,
      conditionalComponents: 0,
      format: 'Unknown',
      specVersion: '1.6',
      applicationName: fileName,
    };
  }
}
