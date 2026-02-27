/**
 * Network TLS Connector — Real TLS endpoint scanner
 *
 * Scans user-configured targets (hostnames, IPs, CIDR ranges) on
 * specified ports, performs a real TLS handshake, and returns
 * normalised Endpoint records for the SyncExecutor to persist.
 *
 * Required ConnectorConfig keys:
 *   targets     – comma-separated hosts, IPs, or CIDR ranges
 *                  e.g. "google.com, 10.0.0.1, 192.168.1.0/24"
 *   ports       – comma-separated ports to probe
 *                  e.g. "443, 8443, 636"
 *
 * Optional:
 *   concurrency – max parallel connections (default 10)
 *   timeout     – per-connection timeout in seconds (default 10)
 */
import * as tls from 'tls';
import * as net from 'net';
import * as dns from 'dns';
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from './connectors';

/* ── Constants ─────────────────────────────────────────────── */

const DEFAULT_CONCURRENCY = 10;
const DEFAULT_TIMEOUT_SEC = 10;

/* ── Types ─────────────────────────────────────────────────── */

interface TlsProbeResult {
  hostname: string;
  ipAddress: string;
  port: number;
  tlsVersion: string;
  cipherSuite: string;
  keyAgreement: string;
  quantumSafe: boolean;
  certCommonName: string | null;
  lastScanned: string;
}

/* ── Helpers ───────────────────────────────────────────────── */

/**
 * Expand CIDR notation into individual IP addresses.
 * Supports /24 – /32 (max 256 IPs per range to avoid accidental floods).
 */
function expandCIDR(cidr: string): string[] {
  const match = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!match) return [cidr]; // not CIDR — return as-is (hostname or plain IP)

  const baseIp = match[1];
  const prefix = parseInt(match[2], 10);

  if (prefix < 24 || prefix > 32) {
    // Only support /24 to /32 to prevent huge expansions
    return [baseIp];
  }

  const parts = baseIp.split('.').map(Number);
  const baseNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const hostBits = 32 - prefix;
  const count = 1 << hostBits; // e.g. /24 → 256

  const ips: string[] = [];
  for (let i = 1; i < count - 1; i++) { // skip network & broadcast
    const ip = baseNum + i;
    ips.push(`${(ip >>> 24) & 0xff}.${(ip >>> 16) & 0xff}.${(ip >>> 8) & 0xff}.${ip & 0xff}`);
  }
  return ips;
}

/**
 * Parse target list from config into individual host entries.
 */
function parseTargets(raw: string): string[] {
  return raw
    .split(/[,\n]+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .flatMap((t) => expandCIDR(t));
}

/**
 * Parse port list from config.
 */
function parsePorts(raw: string): number[] {
  return raw
    .split(/[,\s]+/)
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => !isNaN(p) && p > 0 && p <= 65535);
}

/**
 * Resolve hostname → IP address using DNS.
 * Returns the input unchanged if it's already an IP.
 */
async function resolveHost(host: string): Promise<string> {
  if (net.isIP(host)) return host;
  return new Promise((resolve) => {
    dns.lookup(host, { family: 4 }, (err, address) => {
      resolve(err ? host : address);
    });
  });
}

/**
 * Extract key-exchange algorithm from the cipher suite name.
 * TLS 1.3 cipher names don't include KEX (it's always in the handshake extensions),
 * so we check the protocol version too.
 */
function extractKeyExchange(cipherName: string, tlsVersion: string): string {
  const upper = cipherName.toUpperCase();

  if (upper.includes('ECDHE') || upper.includes('ECDH'))  return 'ECDHE';
  if (upper.includes('DHE') || upper.includes('EDH'))     return 'DHE';
  if (upper.startsWith('TLS_'))  {
    // TLS 1.3 ciphers (TLS_AES_256_GCM_SHA384 etc.) use X25519 / ECDHE by default
    return tlsVersion === 'TLSv1.3' ? 'X25519' : 'ECDHE';
  }
  if (upper.includes('RSA'))    return 'RSA';
  return 'Unknown';
}

/**
 * Determine quantum safety from the key-exchange algorithm.
 * Only ML-KEM (Kyber) based exchanges are PQC-safe.
 */
function isQuantumSafeKex(kex: string): boolean {
  const upper = kex.toUpperCase();
  return upper.includes('ML-KEM') || upper.includes('KYBER') || upper.includes('X25519MLKEM768');
}

/* ── TLS probe ─────────────────────────────────────────────── */

/**
 * Perform a real TLS handshake against host:port and extract crypto details.
 */
function probeTls(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<TlsProbeResult> {
  return new Promise(async (resolve, reject) => {
    const ipAddress = await resolveHost(host);

    const socket = tls.connect(
      {
        host: ipAddress,
        port,
        servername: net.isIP(host) ? undefined : host, // SNI only for hostnames
        rejectUnauthorized: false, // accept self-signed for scanning
        timeout: timeoutMs,
      },
      () => {
        try {
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const cert = socket.getPeerCertificate();

          const cipherName = cipher?.name || 'unknown';
          const tlsVersion = protocol || 'unknown';
          const kex = extractKeyExchange(cipherName, tlsVersion);

          const result: TlsProbeResult = {
            hostname: host,
            ipAddress,
            port,
            tlsVersion,
            cipherSuite: cipherName,
            keyAgreement: kex,
            quantumSafe: isQuantumSafeKex(kex),
            certCommonName: cert?.subject?.CN || null,
            lastScanned: new Date().toISOString(),
          };

          socket.destroy();
          resolve(result);
        } catch (err) {
          socket.destroy();
          reject(new Error(`TLS probe error for ${host}:${port}: ${(err as Error).message}`));
        }
      },
    );

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Timeout connecting to ${host}:${port}`));
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(new Error(`TLS error for ${host}:${port}: ${err.message}`));
    });
  });
}

/* ── Parallel scanner with concurrency limit ───────────────── */

async function scanWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number,
): Promise<{ results: T[]; errors: string[] }> {
  const results: T[] = [];
  const errors: string[] = [];
  let index = 0;

  async function worker() {
    while (index < tasks.length) {
      const i = index++;
      try {
        results.push(await tasks[i]());
      } catch (err) {
        errors.push((err as Error).message);
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, () => worker());
  await Promise.all(workers);
  return { results, errors };
}

/* ── Main connector function ───────────────────────────────── */

export async function fetchEndpointsFromNetwork(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const targetsRaw = config.targets || '';
  const portsRaw = config.ports || '443';
  const concurrency = parseInt(config.concurrency || String(DEFAULT_CONCURRENCY), 10);
  const timeoutSec = parseInt(config.timeout || String(DEFAULT_TIMEOUT_SEC), 10);
  const timeoutMs = timeoutSec * 1000;

  if (!targetsRaw.trim()) {
    return {
      success: false,
      data: [],
      errors: ['Missing "targets" in integration config — specify hostnames, IPs, or CIDR ranges'],
    };
  }

  const hosts = parseTargets(targetsRaw);
  const ports = parsePorts(portsRaw);

  if (hosts.length === 0) {
    return { success: false, data: [], errors: ['No valid hosts parsed from targets'] };
  }
  if (ports.length === 0) {
    return { success: false, data: [], errors: ['No valid ports parsed from config'] };
  }

  console.log(
    `[Network TLS] Starting scan: ${hosts.length} host(s) × ${ports.length} port(s) = ${hosts.length * ports.length} probe(s), concurrency=${concurrency}, timeout=${timeoutSec}s`,
  );

  // Build probe tasks (host × port matrix)
  const tasks = hosts.flatMap((host) =>
    ports.map((port) => () => probeTls(host, port, timeoutMs)),
  );

  const { results, errors } = await scanWithConcurrency(tasks, concurrency);

  // Map probe results → Endpoint model records
  const data: Record<string, unknown>[] = results.map((r) => ({
    id: uuidv4(),
    integrationId,
    hostname: r.hostname,
    ipAddress: r.ipAddress,
    port: r.port,
    tlsVersion: r.tlsVersion,
    cipherSuite: r.cipherSuite,
    keyAgreement: r.keyAgreement,
    quantumSafe: r.quantumSafe,
    source: 'Network Scanner',
    lastScanned: r.lastScanned,
    certCommonName: r.certCommonName,
  }));

  // Separate probe-level failures (timeouts, connection refused) from real errors.
  // Probe failures are expected when scanning ports that aren't TLS-enabled.
  const probeWarnings = errors.filter(
    (e) => /timeout|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH/i.test(e),
  );
  const realErrors = errors.filter(
    (e) => !/timeout|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH/i.test(e),
  );

  // If ALL probes failed (0 endpoints discovered), surface a summary error
  // so the integration doesn't silently show "connected, 0 items".
  if (data.length === 0 && probeWarnings.length > 0 && realErrors.length === 0) {
    const uniqueReasons = [...new Set(probeWarnings.map((w) => {
      if (/timeout/i.test(w)) return 'timeout';
      if (/ECONNREFUSED/i.test(w)) return 'connection refused';
      if (/ECONNRESET/i.test(w)) return 'connection reset';
      if (/EHOSTUNREACH/i.test(w)) return 'host unreachable';
      return 'network error';
    }))];
    realErrors.push(
      `No TLS endpoints discovered. All ${probeWarnings.length} probe(s) failed (${uniqueReasons.join(', ')}). ` +
      `Verify that the target hosts are reachable and have TLS services running on the specified ports.`,
    );
  }

  console.log(
    `[Network TLS] Scan complete: ${data.length} endpoint(s) discovered, ${probeWarnings.length} probe warning(s), ${realErrors.length} error(s)`,
  );

  return {
    success: data.length > 0 || realErrors.length === 0,
    data,
    errors: realErrors,
    meta: {
      hostsScanned: hosts.length,
      portsScanned: ports.length,
      totalProbes: tasks.length,
      successfulProbes: data.length,
      failedProbes: errors.length,
      warnings: probeWarnings,
    },
  };
}
