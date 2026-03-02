/**
 * DigiCert HTTP Client
 *
 * HTTP(S) request using Node's built-in modules.
 * Unlike native `fetch()`, this supports `rejectUnauthorized: false`
 * for internal / self-signed TLS endpoints, and surfaces detailed
 * error messages (ENOTFOUND, ECONNREFUSED, CERT_HAS_EXPIRED, etc.).
 */
import https from 'https';
import http from 'http';
import { REQUEST_TIMEOUT } from './constants';

export function digicertRequest<T>(
  url: string,
  apiKey: string,
  accountId?: string,
  rejectUnauthorized = true,
  method: 'GET' | 'POST' = 'GET',
  body?: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';

    const headers: Record<string, string> = {
      'x-api-key': apiKey,
      Accept: 'application/json',
      ...(accountId ? { 'x-dc-account-id': accountId } : {}),
    };
    if (body) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body).toString();
    }

    const options: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      timeout: REQUEST_TIMEOUT,
      headers,
      ...(isHttps ? { rejectUnauthorized } : {}),
    };

    const mod = isHttps ? https : http;

    const req = mod.request(options, (res) => {
      let respBody = '';
      res.on('data', (chunk: Buffer) => { respBody += chunk.toString(); });
      res.on('end', () => {
        const status = res.statusCode || 0;
        if (status >= 200 && status < 300) {
          try {
            resolve(JSON.parse(respBody) as T);
          } catch {
            // Some endpoints return HTML (SPA fallback) instead of JSON
            if (respBody.includes('<!doctype') || respBody.includes('<html')) {
              reject(new Error(`ENDPOINT_NOT_API: ${parsed.pathname} returned HTML instead of JSON — this API path is not available on this deployment`));
            } else {
              reject(new Error(`DigiCert API returned invalid JSON (HTTP ${status}): ${respBody.slice(0, 200)}`));
            }
          }
        } else if (status === 503) {
          reject(new Error(`SERVICE_UNAVAILABLE: The micro-service at ${parsed.pathname} is not running or not deployed on this DigiCert ONE instance (HTTP 503). Contact your DigiCert ONE administrator to verify the service is enabled.`));
        } else if (status === 404) {
          reject(new Error(`ENDPOINT_NOT_FOUND: ${parsed.pathname} returned HTTP 404 — this API path does not exist on this deployment`));
        } else {
          reject(new Error(`DigiCert API HTTP ${status}: ${respBody.slice(0, 300)}`));
        }
      });
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      // Provide actionable error messages
      if (err.code === 'ENOTFOUND') {
        reject(new Error(`DNS lookup failed for "${parsed.hostname}" — verify the API Base URL is correct and the host is reachable`));
      } else if (err.code === 'ECONNREFUSED') {
        reject(new Error(`Connection refused by ${parsed.hostname}:${options.port} — is the DigiCert ONE service running?`));
      } else if (err.code === 'ECONNRESET') {
        reject(new Error(`Connection reset by ${parsed.hostname} — possible firewall or proxy issue`));
      } else if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN' || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' || (err.message && err.message.includes('self-signed'))) {
        reject(new Error(`TLS certificate verification failed for ${parsed.hostname} — if using an internal CA or self-signed cert, enable "Allow Insecure TLS" in the integration config`));
      } else if (err.code === 'CERT_HAS_EXPIRED') {
        reject(new Error(`TLS certificate for ${parsed.hostname} has expired`));
      } else {
        reject(new Error(`Network error connecting to ${parsed.hostname}: ${err.message} (${err.code || 'unknown'})`));
      }
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request to ${parsed.hostname} timed out after ${REQUEST_TIMEOUT / 1000}s`));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}
