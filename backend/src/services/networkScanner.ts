/**
 * Network TLS Scanner
 *
 * Scans live endpoints for cryptographic properties (TLS version, cipher suites)
 * and maps findings into CycloneDX 1.7 CBOM format.
 */
import * as https from 'https';
import * as tls from 'tls';
import { v4 as uuidv4 } from 'uuid';
import {
  NetworkScanResult,
  CryptoAsset,
  AssetType,
  CryptoPrimitive,
  QuantumSafetyStatus,
} from '../types';
import { classifyAlgorithm } from './pqcRiskEngine';

/**
 * Scans a live endpoint for TLS/cryptographic properties.
 */
export async function scanNetworkCrypto(
  host: string,
  port: number = 443
): Promise<NetworkScanResult> {
  return new Promise((resolve, reject) => {
    const options: https.RequestOptions = {
      host,
      port,
      method: 'GET',
      path: '/',
      rejectUnauthorized: false, // Allow self-signed for scanning
      servername: host, // SNI
      timeout: 10000,
    };

    const req = https.request(options, (res) => {
      const socket = res.socket as tls.TLSSocket;

      if (!socket.getCipher || !socket.getProtocol) {
        reject(new Error('Not a TLS connection'));
        return;
      }

      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const cert = socket.getPeerCertificate();

      // Heuristic: TLS 1.3 with CHACHA20 or AES-256-GCM is best, but none are truly PQC yet
      const isPQC = false; // No standard TLS is PQC as of 2025

      const result: NetworkScanResult = {
        name: `TLS Connection to ${host}:${port}`,
        type: 'network-service',
        protocol: protocol || 'unknown',
        cipherSuite: cipher?.name || 'unknown',
        version: cipher?.version || 'unknown',
        isQuantumSafe: isPQC,
        lastScanned: new Date().toISOString(),
        host,
        port,
      };

      resolve(result);
      req.destroy(); // Clean up
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Connection to ${host}:${port} timed out`));
    });

    req.on('error', (e) => {
      reject(new Error(`Scanner Error for ${host}:${port}: ${e.message}`));
    });

    req.end();
  });
}

/**
 * Convert a network scan result into a CycloneDX 1.7 CBOM CryptoAsset.
 */
export function networkResultToCBOMAsset(scanResult: NetworkScanResult): CryptoAsset {
  const protocolProfile = classifyAlgorithm(scanResult.protocol);

  return {
    id: uuidv4(),
    name: scanResult.cipherSuite,
    type: 'network',
    description: `${scanResult.protocol} cipher suite detected on ${scanResult.host}:${scanResult.port}`,
    cryptoProperties: {
      assetType: AssetType.PROTOCOL,
      protocolProperties: {
        type: 'tls',
        version: scanResult.protocol,
        cipherSuites: [
          {
            name: scanResult.cipherSuite,
            algorithms: extractAlgorithmsFromCipher(scanResult.cipherSuite),
          },
        ],
      },
      oid: '1.2.840.113549.1.1.11',
    },
    location: {
      fileName: `${scanResult.host}:${scanResult.port}`,
    },
    quantumSafety: scanResult.isQuantumSafe
      ? QuantumSafetyStatus.QUANTUM_SAFE
      : QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    provider: 'QuantumGuard Network Scanner',
  };
}

/**
 * Extract individual algorithm names from a cipher suite string.
 * e.g., "TLS_AES_256_GCM_SHA384" -> ["AES-256", "GCM", "SHA-384"]
 */
function extractAlgorithmsFromCipher(cipherSuite: string): string[] {
  const algorithms: string[] = [];
  const upper = cipherSuite.toUpperCase();

  const patterns: [RegExp, string][] = [
    [/AES.?256/i, 'AES-256'],
    [/AES.?128/i, 'AES-128'],
    [/CHACHA20/i, 'CHACHA20'],
    [/SHA384|SHA.?384/i, 'SHA-384'],
    [/SHA256|SHA.?256/i, 'SHA-256'],
    [/RSA/i, 'RSA'],
    [/ECDHE/i, 'ECDHE'],
    [/ECDSA/i, 'ECDSA'],
    [/GCM/i, 'GCM'],
    [/CBC/i, 'CBC'],
    [/POLY1305/i, 'POLY1305'],
  ];

  for (const [pattern, name] of patterns) {
    if (pattern.test(upper)) {
      algorithms.push(name);
    }
  }

  return algorithms.length > 0 ? algorithms : [cipherSuite];
}

/**
 * Scan multiple hosts and aggregate results.
 */
export async function scanMultipleHosts(
  hosts: { host: string; port?: number }[]
): Promise<{ results: NetworkScanResult[]; errors: string[] }> {
  const results: NetworkScanResult[] = [];
  const errors: string[] = [];

  await Promise.allSettled(
    hosts.map(async ({ host, port }) => {
      try {
        const result = await scanNetworkCrypto(host, port);
        results.push(result);
      } catch (err) {
        errors.push(`${host}:${port || 443} - ${(err as Error).message}`);
      }
    })
  );

  return { results, errors };
}
