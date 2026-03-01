/**
 * Certificate File Scanner
 *
 * Scans repository for certificate files (.pem, .crt, .cer, .der, .p7b)
 * and parses them using Node.js crypto to extract:
 *   - Signature algorithm (e.g., sha256WithRSAEncryption)
 *   - Public key algorithm & size (e.g., RSA-2048, EC-P256)
 *   - Subject, issuer, validity dates
 *
 * This directly resolves X.509 "conditional" assets that static regex cannot
 * classify because the certificate format is not the algorithm.
 *
 * @see docs/advanced-resolution-techniques.md — Phase 1A
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import type { CryptoAsset } from '../../types';
import {
  AssetType,
  QuantumSafetyStatus,
} from '../../types';
import { enrichAssetWithPQCData } from '../pqcRiskEngine';
import { SKIP_FILE_PATTERNS } from './scannerTypes';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ParsedCertificate {
  filePath: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  isCA: boolean;
  isSelfSigned: boolean;
}

// ─── Certificate File Extensions ────────────────────────────────────────────

const CERT_EXTENSIONS = ['.pem', '.crt', '.cer', '.der', '.p7b', '.p7c'];
const KEYSTORE_EXTENSIONS = ['.jks', '.p12', '.pfx', '.keystore', '.bks'];

// ─── Signature Algorithm Mapping ────────────────────────────────────────────

/**
 * Map OID / X.509 signature algorithm names to human-readable crypto names.
 */
const SIG_ALG_MAP: Record<string, string> = {
  // RSA
  'sha1withrsa': 'SHA1withRSA',
  'sha1withrsaencryption': 'SHA1withRSA',
  'sha256withrsa': 'SHA256withRSA',
  'sha256withrsaencryption': 'SHA256withRSA',
  'sha384withrsa': 'SHA384withRSA',
  'sha384withrsaencryption': 'SHA384withRSA',
  'sha512withrsa': 'SHA512withRSA',
  'sha512withrsaencryption': 'SHA512withRSA',
  'md5withrsa': 'MD5withRSA',
  'md5withrsaencryption': 'MD5withRSA',
  'rsassapss': 'RSA-PSS',

  // ECDSA
  'ecdsawithsha256': 'ECDSA-SHA256',
  'ecdsawithsha384': 'ECDSA-SHA384',
  'ecdsawithsha512': 'ECDSA-SHA512',
  'ecdsawithsha1': 'ECDSA-SHA1',

  // EdDSA
  'ed25519': 'Ed25519',
  'ed448': 'Ed448',

  // PQC (ML-DSA / SLH-DSA / XMSS)
  'ml-dsa-44': 'ML-DSA-44',
  'ml-dsa-65': 'ML-DSA-65',
  'ml-dsa-87': 'ML-DSA-87',
  'slh-dsa-sha2-128s': 'SLH-DSA-SHA2-128s',
  'slh-dsa-sha2-128f': 'SLH-DSA-SHA2-128f',
  'slh-dsa-sha2-192s': 'SLH-DSA-SHA2-192s',
  'slh-dsa-sha2-192f': 'SLH-DSA-SHA2-192f',
  'slh-dsa-sha2-256s': 'SLH-DSA-SHA2-256s',
  'slh-dsa-sha2-256f': 'SLH-DSA-SHA2-256f',
  'xmss': 'XMSS',
  'xmssmt': 'XMSS-MT',

  // DSA
  'sha1withdsa': 'DSA-SHA1',
  'sha256withdsa': 'DSA-SHA256',
};

/**
 * Normalise a raw X.509 signature algorithm string to a recognisable name.
 */
function normaliseSignatureAlgorithm(raw: string): string {
  const key = raw.toLowerCase().replace(/[^a-z0-9-]/g, '');
  return SIG_ALG_MAP[key] || raw;
}

/**
 * Extract public key type string from asymmetricKeyType.
 */
function publicKeyTypeName(keyType: string | undefined, keySize: number | undefined): string {
  if (!keyType) return 'Unknown';
  const upper = keyType.toUpperCase();
  if (upper === 'RSA') return keySize ? `RSA-${keySize}` : 'RSA';
  if (upper === 'EC') return keySize ? `EC-${keySize}` : 'EC';
  if (upper === 'ED25519') return 'Ed25519';
  if (upper === 'ED448') return 'Ed448';
  if (upper === 'X25519') return 'X25519';
  if (upper === 'X448') return 'X448';
  if (upper === 'DSA') return keySize ? `DSA-${keySize}` : 'DSA';
  return upper;
}

// ─── File Discovery ─────────────────────────────────────────────────────────

/**
 * Recursively discover certificate files in a directory.
 */
export function discoverCertificateFiles(repoPath: string): string[] {
  const results: string[] = [];

  function walk(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Skip build / vendor / node_modules dirs
      if (entry.isDirectory()) {
        if (SKIP_FILE_PATTERNS.some(p => p.test(entry.name + '/'))) continue;
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name).toLowerCase();
      if (CERT_EXTENSIONS.includes(ext) || KEYSTORE_EXTENSIONS.includes(ext)) {
        results.push(fullPath);
      }
    }
  }

  walk(repoPath);
  return results;
}

// ─── PEM Parsing ────────────────────────────────────────────────────────────

/**
 * Extract all PEM blocks from a file that may contain multiple certificates.
 */
function extractPEMBlocks(content: string): string[] {
  const blocks: string[] = [];
  const pemRe = /-----BEGIN\s+(?:CERTIFICATE|X509\s+CERTIFICATE)-----[\s\S]*?-----END\s+(?:CERTIFICATE|X509\s+CERTIFICATE)-----/g;
  let m: RegExpExecArray | null;
  while ((m = pemRe.exec(content)) !== null) {
    blocks.push(m[0]);
  }
  return blocks;
}

/**
 * Extract private key PEM blocks — we record these as related crypto material.
 */
function extractPrivateKeyBlocks(content: string): string[] {
  const blocks: string[] = [];
  const keyRe = /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----/g;
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(content)) !== null) {
    blocks.push(m[0]);
  }
  return blocks;
}

/**
 * Extract public key PEM blocks.
 */
function extractPublicKeyBlocks(content: string): string[] {
  const blocks: string[] = [];
  const keyRe = /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PUBLIC\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+)?PUBLIC\s+KEY-----/g;
  let m: RegExpExecArray | null;
  while ((m = keyRe.exec(content)) !== null) {
    blocks.push(m[0]);
  }
  return blocks;
}

// ─── Certificate Parsing ────────────────────────────────────────────────────

/**
 * Parse a single X.509 certificate from PEM or DER content.
 * Uses Node.js 15+ crypto.X509Certificate API.
 */
function parseCertificate(content: Buffer, filePath: string): ParsedCertificate | null {
  try {
    const cert = new crypto.X509Certificate(content);

    // Extract public key details
    const pubKey = crypto.createPublicKey(cert.publicKey);
    const keyType = (pubKey as any).asymmetricKeyType as string | undefined;
    const keyDetail = (pubKey as any).asymmetricKeySize as number | undefined;

    // Determine key size more reliably
    let keySize = keyDetail;
    if (!keySize) {
      // Try from key export (jwk format gives 'n' length for RSA)
      try {
        const jwk = pubKey.export({ format: 'jwk' });
        if (jwk.n) {
          // Base64url length × 6 / 8 = byte count → × 8 = bit count
          keySize = Math.ceil((jwk.n.length * 6) / 8) * 8;
        } else if (jwk.x && keyType === 'ec') {
          keySize = Math.ceil((jwk.x.length * 6) / 8) * 8;
        }
      } catch { /* ignore */ }
    }

    const sigAlg = normaliseSignatureAlgorithm(
      // Node.js X509Certificate doesn't have a direct sigAlgName property.
      // We extract from the fingerprint or infoAccess, but the most reliable
      // way is to parse the text representation.
      extractSignatureAlgorithmFromText(cert)
    );

    return {
      filePath,
      signatureAlgorithm: sigAlg,
      publicKeyAlgorithm: publicKeyTypeName(keyType, keySize),
      publicKeySize: keySize,
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
      isCA: cert.ca,
      isSelfSigned: cert.subject === cert.issuer,
    };
  } catch {
    return null;
  }
}

/**
 * Extract signature algorithm from the X.509 certificate text representation.
 * Node.js X509Certificate.toString() includes "Signature Algorithm: ..." line.
 */
function extractSignatureAlgorithmFromText(cert: crypto.X509Certificate): string {
  try {
    const text = cert.toString();
    // Look for "Signature Algorithm: sha256WithRSAEncryption"
    const match = text.match(/Signature Algorithm:\s*(\S+)/i);
    if (match) return match[1];
  } catch { /* ignore */ }

  // Fallback: try extracting from fingerprint algorithm
  try {
    // certfingerprint256 is sha256 — doesn't tell us the sig alg
    // Use a regex on the raw string representation
    const raw = (cert as any).sigAlgName ?? (cert as any).signatureAlgorithm;
    if (raw) return raw;
  } catch { /* ignore */ }

  return 'Unknown';
}

// ─── Main Scanner ───────────────────────────────────────────────────────────

/**
 * Scan a repository for certificate files and parse them into CryptoAsset entries.
 *
 * Each certificate becomes a CryptoAsset with:
 *   - type: 'certificate'
 *   - name: the signature algorithm (e.g., "SHA256withRSA")
 *   - certificateProperties: filled with parsed data
 *   - quantumSafety: determined by pqcRiskEngine based on the sig+key algorithms
 *   - detectionSource: 'certificate'
 *
 * Private/public key files also generate related-crypto-material assets.
 */
export async function scanCertificateFiles(
  repoPath: string,
  excludePatterns?: string[],
): Promise<CryptoAsset[]> {
  const assets: CryptoAsset[] = [];
  const certFiles = discoverCertificateFiles(repoPath);

  console.log(`Certificate scanner: found ${certFiles.length} certificate/key files`);

  for (const filePath of certFiles) {
    const relPath = path.relative(repoPath, filePath);

    // Skip excluded paths
    if (excludePatterns && excludePatterns.length > 0) {
      const { shouldExcludeFile } = await import('./scannerUtils');
      if (shouldExcludeFile(relPath, excludePatterns)) continue;
    }

    const ext = path.extname(filePath).toLowerCase();

    // Skip keystore files (JKS/P12/PFX) — need password, handled by keystore scanner
    if (KEYSTORE_EXTENSIONS.includes(ext)) {
      assets.push(createKeystoreAsset(filePath, relPath, ext));
      continue;
    }

    try {
      const rawContent = fs.readFileSync(filePath);
      const textContent = rawContent.toString('utf-8');

      // ── Parse certificate PEM blocks ──
      const pemBlocks = extractPEMBlocks(textContent);
      if (pemBlocks.length > 0) {
        for (let i = 0; i < pemBlocks.length; i++) {
          const parsed = parseCertificate(Buffer.from(pemBlocks[i]), relPath);
          if (parsed) {
            assets.push(createCertificateAsset(parsed, relPath, i));
          }
        }
      } else if (ext === '.der' || ext === '.cer') {
        // Try parsing as DER (binary) certificate
        const parsed = parseCertificate(rawContent, relPath);
        if (parsed) {
          assets.push(createCertificateAsset(parsed, relPath, 0));
        }
      } else if (ext === '.pem' || ext === '.crt') {
        // PEM file that didn't match certificate blocks — might be a key file
        // or a certificate in non-standard format. Try raw parse.
        const parsed = parseCertificate(rawContent, relPath);
        if (parsed) {
          assets.push(createCertificateAsset(parsed, relPath, 0));
        }
      }

      // ── Parse private key blocks ──
      const privKeyBlocks = extractPrivateKeyBlocks(textContent);
      for (const block of privKeyBlocks) {
        const keyAsset = parsePrivateKey(block, relPath);
        if (keyAsset) assets.push(keyAsset);
      }

      // ── Parse public key blocks ──
      const pubKeyBlocks = extractPublicKeyBlocks(textContent);
      for (const block of pubKeyBlocks) {
        const keyAsset = parsePublicKey(block, relPath);
        if (keyAsset) assets.push(keyAsset);
      }
    } catch (err) {
      console.warn(`Certificate scanner: failed to parse ${relPath}: ${(err as Error).message}`);
    }
  }

  console.log(`Certificate scanner: extracted ${assets.length} crypto assets from certificate files`);
  return assets;
}

// ─── Asset Builders ─────────────────────────────────────────────────────────

/**
 * Create a CryptoAsset from a parsed certificate.
 */
function createCertificateAsset(
  cert: ParsedCertificate,
  relPath: string,
  index: number,
): CryptoAsset {
  const sigAlg = cert.signatureAlgorithm;
  const pubKeyAlg = cert.publicKeyAlgorithm;

  // Build a descriptive name: prefer the signature algorithm
  const name = sigAlg !== 'Unknown' ? sigAlg : `X.509 (${pubKeyAlg})`;

  const asset: CryptoAsset = {
    id: uuidv4(),
    name,
    type: AssetType.CERTIFICATE,
    description: buildCertDescription(cert),
    cryptoProperties: {
      assetType: AssetType.CERTIFICATE,
      certificateProperties: {
        subjectName: cert.subject,
        issuerName: cert.issuer,
        notValidBefore: cert.validFrom,
        notValidAfter: cert.validTo,
        signatureAlgorithm: sigAlg,
        subjectPublicKeyAlgorithm: pubKeyAlg,
        certificateFormat: 'X.509',
      },
    },
    location: {
      fileName: relPath,
      lineNumber: index + 1,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,  // Will be enriched
    detectionSource: 'certificate',
  };

  // Enrich with PQC classification based on signature & key algorithms
  return enrichAssetWithPQCData(asset);
}

/**
 * Build human-readable description for a certificate.
 */
function buildCertDescription(cert: ParsedCertificate): string {
  const parts: string[] = [];

  parts.push(`X.509 certificate from file: ${cert.filePath}.`);
  parts.push(`Signature: ${cert.signatureAlgorithm}.`);
  parts.push(`Public Key: ${cert.publicKeyAlgorithm}${cert.publicKeySize ? ` (${cert.publicKeySize}-bit)` : ''}.`);

  if (cert.isCA) parts.push('This is a CA certificate.');
  if (cert.isSelfSigned) parts.push('Self-signed.');

  const validTo = new Date(cert.validTo);
  if (validTo < new Date()) {
    parts.push('⚠️ Certificate has EXPIRED.');
  } else {
    const daysLeft = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysLeft < 90) parts.push(`⚠️ Expires in ${daysLeft} days.`);
  }

  return parts.join(' ');
}

/**
 * Create a placeholder asset for keystore files that need a password to inspect.
 */
function createKeystoreAsset(filePath: string, relPath: string, ext: string): CryptoAsset {
  const formatMap: Record<string, string> = {
    '.jks': 'Java KeyStore (JKS)',
    '.p12': 'PKCS#12',
    '.pfx': 'PKCS#12 (PFX)',
    '.keystore': 'Java KeyStore',
    '.bks': 'BouncyCastle KeyStore (BKS)',
  };

  const asset: CryptoAsset = {
    id: uuidv4(),
    name: `Keystore (${formatMap[ext] || ext})`,
    type: AssetType.CERTIFICATE,
    description: `Keystore file detected: ${relPath}. Format: ${formatMap[ext] || ext}. ` +
      `Cannot inspect contents without password. Use 'keytool -list -v -keystore ${relPath}' to inspect manually.`,
    cryptoProperties: {
      assetType: AssetType.CERTIFICATE,
      certificateProperties: {
        certificateFormat: formatMap[ext] || ext,
      },
    },
    location: {
      fileName: relPath,
      lineNumber: 1,
    },
    quantumSafety: QuantumSafetyStatus.UNKNOWN,
    detectionSource: 'certificate',
  };

  return asset;
}

/**
 * Parse a private key PEM block and create a crypto asset.
 */
function parsePrivateKey(pemBlock: string, relPath: string): CryptoAsset | null {
  try {
    const key = crypto.createPrivateKey(pemBlock);
    const keyType = (key as any).asymmetricKeyType as string | undefined;
    let keySize: number | undefined;

    try {
      const jwk = key.export({ format: 'jwk' });
      if (jwk.n) {
        keySize = Math.ceil((jwk.n.length * 6) / 8) * 8;
      } else if (jwk.x && keyType === 'ec') {
        keySize = Math.ceil((jwk.x.length * 6) / 8) * 8;
      } else if (jwk.d) {
        keySize = Math.ceil((jwk.d.length * 6) / 8) * 8;
      }
    } catch { /* ignore */ }

    const name = publicKeyTypeName(keyType, keySize);

    const asset: CryptoAsset = {
      id: uuidv4(),
      name: `Private Key (${name})`,
      type: AssetType.RELATED_MATERIAL,
      description: `Private key file detected: ${relPath}. Algorithm: ${name}. ` +
        `⚠️ Private key stored in repository — review security practices.`,
      cryptoProperties: {
        assetType: AssetType.RELATED_MATERIAL,
        relatedCryptoMaterialProperties: {
          type: 'private-key' as any,
          size: keySize,
          format: 'PEM',
        },
      },
      location: { fileName: relPath, lineNumber: 1 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      keyLength: keySize,
      detectionSource: 'certificate',
    };

    return enrichAssetWithPQCData(asset);
  } catch {
    return null;
  }
}

/**
 * Parse a public key PEM block and create a crypto asset.
 */
function parsePublicKey(pemBlock: string, relPath: string): CryptoAsset | null {
  try {
    const key = crypto.createPublicKey(pemBlock);
    const keyType = (key as any).asymmetricKeyType as string | undefined;
    let keySize: number | undefined;

    try {
      const jwk = key.export({ format: 'jwk' });
      if (jwk.n) {
        keySize = Math.ceil((jwk.n.length * 6) / 8) * 8;
      } else if (jwk.x && keyType === 'ec') {
        keySize = Math.ceil((jwk.x.length * 6) / 8) * 8;
      }
    } catch { /* ignore */ }

    const name = publicKeyTypeName(keyType, keySize);

    const asset: CryptoAsset = {
      id: uuidv4(),
      name: `Public Key (${name})`,
      type: AssetType.RELATED_MATERIAL,
      description: `Public key file detected: ${relPath}. Algorithm: ${name}.`,
      cryptoProperties: {
        assetType: AssetType.RELATED_MATERIAL,
        relatedCryptoMaterialProperties: {
          type: 'public-key' as any,
          size: keySize,
          format: 'PEM',
        },
      },
      location: { fileName: relPath, lineNumber: 1 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      keyLength: keySize,
      detectionSource: 'certificate',
    };

    return enrichAssetWithPQCData(asset);
  } catch {
    return null;
  }
}

// ─── Keystore Scanner (Phase 2B) ────────────────────────────────────────────

/**
 * Attempt to inspect keystore files using `keytool` or `openssl` subprocesses.
 * Falls back gracefully if tools are not available.
 */
export async function scanKeystoreFiles(
  repoPath: string,
  passwords: Record<string, string> = {},
): Promise<CryptoAsset[]> {
  const assets: CryptoAsset[] = [];
  const keystoreFiles = discoverCertificateFiles(repoPath)
    .filter(f => KEYSTORE_EXTENSIONS.includes(path.extname(f).toLowerCase()));

  const { execSync } = await import('child_process');

  for (const ksPath of keystoreFiles) {
    const relPath = path.relative(repoPath, ksPath);
    const ext = path.extname(ksPath).toLowerCase();
    const password = passwords[relPath] || passwords[path.basename(ksPath)] || 'changeit';

    try {
      if (ext === '.jks' || ext === '.keystore' || ext === '.bks') {
        // Try keytool
        const output = execSync(
          `keytool -list -v -keystore "${ksPath}" -storepass "${password}" 2>/dev/null`,
          { timeout: 10000, encoding: 'utf-8' },
        );
        assets.push(...parseKeytoolOutput(output, relPath));
      } else if (ext === '.p12' || ext === '.pfx') {
        // Try openssl
        const output = execSync(
          `openssl pkcs12 -in "${ksPath}" -nokeys -passin pass:"${password}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null`,
          { timeout: 10000, encoding: 'utf-8' },
        );
        assets.push(...parseOpensslOutput(output, relPath));
      }
    } catch {
      // keytool/openssl not available or wrong password — skip silently
      console.warn(`Keystore scanner: could not inspect ${relPath} (wrong password or missing tool)`);
    }
  }

  return assets;
}

/**
 * Parse `keytool -list -v` output to extract certificate signature algorithms.
 */
function parseKeytoolOutput(output: string, relPath: string): CryptoAsset[] {
  const assets: CryptoAsset[] = [];
  const sigAlgMatches = output.matchAll(/Signature algorithm name:\s*(\S+)/gi);

  for (const match of sigAlgMatches) {
    const sigAlg = normaliseSignatureAlgorithm(match[1]);
    const asset: CryptoAsset = {
      id: uuidv4(),
      name: sigAlg,
      type: AssetType.CERTIFICATE,
      description: `Certificate in keystore ${relPath}: signature algorithm ${sigAlg} (extracted via keytool).`,
      cryptoProperties: {
        assetType: AssetType.CERTIFICATE,
        certificateProperties: {
          signatureAlgorithm: sigAlg,
          certificateFormat: 'JKS',
        },
      },
      location: { fileName: relPath, lineNumber: 1 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      detectionSource: 'certificate',
    };
    assets.push(enrichAssetWithPQCData(asset));
  }

  return assets;
}

/**
 * Parse `openssl x509 -text` output to extract certificate details.
 */
function parseOpensslOutput(output: string, relPath: string): CryptoAsset[] {
  const assets: CryptoAsset[] = [];
  const sigMatch = output.match(/Signature Algorithm:\s*(\S+)/i);
  const keyMatch = output.match(/Public Key Algorithm:\s*(\S+)/i);
  const keySizeMatch = output.match(/(?:RSA|DSA) Public-Key:\s*\((\d+)\s*bit\)/i) ||
                       output.match(/Public-Key:\s*\((\d+)\s*bit\)/i);

  if (sigMatch || keyMatch) {
    const sigAlg = sigMatch ? normaliseSignatureAlgorithm(sigMatch[1]) : 'Unknown';
    const keyAlg = keyMatch ? keyMatch[1] : 'Unknown';
    const keySize = keySizeMatch ? parseInt(keySizeMatch[1], 10) : undefined;

    const asset: CryptoAsset = {
      id: uuidv4(),
      name: sigAlg !== 'Unknown' ? sigAlg : keyAlg,
      type: AssetType.CERTIFICATE,
      description: `Certificate in PKCS#12 keystore ${relPath}: signature ${sigAlg}, key ${keyAlg}${keySize ? ` (${keySize}-bit)` : ''} (extracted via openssl).`,
      cryptoProperties: {
        assetType: AssetType.CERTIFICATE,
        certificateProperties: {
          signatureAlgorithm: sigAlg,
          subjectPublicKeyAlgorithm: keyAlg,
          certificateFormat: 'PKCS#12',
        },
      },
      location: { fileName: relPath, lineNumber: 1 },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      keyLength: keySize,
      detectionSource: 'certificate',
    };
    assets.push(enrichAssetWithPQCData(asset));
  }

  return assets;
}
