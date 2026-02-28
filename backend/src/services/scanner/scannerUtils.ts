/**
 * Scanner Utilities
 *
 * Shared helper functions for the regex-based crypto scanner.
 */
import type { CryptoAsset } from '../../types';

// ─── False-Positive Exclusion ───────────────────────────────────────────────

/**
 * Non-cryptographic class / function names that upstream scanners (e.g.
 * sonar-cryptography) sometimes misclassify as crypto hash functions.
 *
 * These are checked against:
 *   - the asset `name` field  (case-insensitive exact match)
 *   - the `additionalContext` or `evidence` fields  (substring match)
 *   - the occurrence `location` path  (for import-only hits)
 */
const FALSE_POSITIVE_NAMES: Set<string> = new Set([
  // ── Java Collections (contain "Hash" but are data structures) ──
  'hashmap',
  'hashset',
  'hashtable',
  'concurrenthashmap',
  'linkedhashmap',
  'linkedhashset',
  'identityhashmap',
  'weakhashmap',
  'enummap',        // sometimes confused with enum hash
  'hashcode',
  'objects.hash',
  'objects.hashcode',
  'system.identityhashcode',

  // ── .NET / C# collections ──
  'dictionary',
  'hashtable',      // System.Collections.Hashtable
  'hashset',        // System.Collections.Generic.HashSet

  // ── Python built-ins ──
  'hash',           // built-in hash() function — not crypto
  'dict',

  // ── Go maps ──
  'map',

  // ── General non-crypto terms ──
  'hashcode',
  'gethashcode',
  'hash_code',
]);

/**
 * Fully-qualified class / package prefixes that are never cryptographic.
 * Matched as prefixes against the `additionalContext` or evidence fields.
 */
const FALSE_POSITIVE_PREFIXES: string[] = [
  'java.util.hashmap',
  'java.util.hashset',
  'java.util.hashtable',
  'java.util.linkedhashmap',
  'java.util.linkedhashset',
  'java.util.identityhashmap',
  'java.util.weakhashmap',
  'java.util.concurrent.concurrenthashmap',
  'java.util.objects#hash',
  'java.lang.object#hashcode',
  'java.lang.system#identityhashcode',
  'system.collections.generic.hashset',
  'system.collections.generic.dictionary',
  'system.collections.hashtable',
];

/**
 * Return `true` when a crypto asset is actually a non-cryptographic
 * false positive (e.g. `java.util.HashMap` detected as a hash function).
 */
export function isFalsePositiveCryptoAsset(asset: CryptoAsset): boolean {
  const name = (asset.name ?? '').toLowerCase().trim();

  // 1. Exact name match
  if (FALSE_POSITIVE_NAMES.has(name)) return true;

  // 2. Name looks like a data-structure hash (e.g. "HashMap<String,Object>")
  if (/^(concurrent|linked|identity|weak|enum)?(hash)(map|set|table|code)\b/i.test(name)) return true;

  // 3. Check evidence / additionalContext for known non-crypto qualified names
  const context = (asset as any)?.evidence?.occurrences
    ?.map((o: any) => (o.additionalContext ?? '').toLowerCase())
    .join(' ') ?? '';
  const descLower = (asset.description ?? '').toLowerCase();
  const combined = `${context} ${descLower}`;

  for (const prefix of FALSE_POSITIVE_PREFIXES) {
    if (combined.includes(prefix)) return true;
  }

  return false;
}

/**
 * Filter an array of crypto assets, removing known false positives.
 */
export function filterFalsePositives(assets: CryptoAsset[]): CryptoAsset[] {
  return assets.filter(a => !isFalsePositiveCryptoAsset(a));
}

// ─── Glob Pattern Matching ──────────────────────────────────────────────────

/**
 * Convert a glob pattern to a regex.
 * Supports: ** (any path), * (any chars in segment), ? (single char)
 */
export function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/\\/g, '/')
    .replace(/[.+^${}()|[\]]/g, '\\$&')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');
  return new RegExp(`^${escaped}$|/${escaped}$|^${escaped}/|/${escaped}/`);
}

/**
 * Check if a file path matches any of the exclude patterns.
 */
export function shouldExcludeFile(filePath: string, excludePatterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  return excludePatterns.some(pattern => {
    const regex = globToRegex(pattern);
    return regex.test(normalizedPath);
  });
}

// ─── Algorithm Name Normalisation ───────────────────────────────────────────

/**
 * Normalise an extracted algorithm name:
 *  - "AES/CBC/PKCS5Padding" → "AES"
 *  - "HmacSHA256" → "HMAC-SHA256"
 *  - "SHA256withRSA" → "SHA256withRSA" (leave composite signatures as-is)
 *  - "PBKDF2WithHmacSHA256" → "PBKDF2"
 *  - "aes-256-gcm" → "AES" (OpenSSL cipher names)
 *  - "sha256" → "SHA-256"
 */
export function normaliseAlgorithmName(raw: string): string {
  let name = raw.trim();

  // Cipher transforms: "AES/CBC/PKCS5Padding" → "AES"
  if (name.includes('/') && !name.startsWith('crypto/')) {
    name = name.split('/')[0];
  }

  // HmacSHA256 → HMAC-SHA256
  const hmacMatch = name.match(/^Hmac(.+)$/i);
  if (hmacMatch) {
    const inner = hmacMatch[1].replace(/^sha/i, 'SHA-').replace(/^md/i, 'MD');
    return `HMAC-${inner}`;
  }

  // PBKDF2WithHmacSHA256 → PBKDF2
  if (/^PBKDF2/i.test(name)) {
    return 'PBKDF2';
  }

  // SHA256 → SHA-256 (insert dash if missing)
  const shaMatch = name.match(/^SHA(\d{3,4})$/i);
  if (shaMatch) {
    return `SHA-${shaMatch[1]}`;
  }

  // OpenSSL cipher string: "aes-256-gcm" → "AES"
  const opensslCipherMatch = name.match(/^(aes|des|rc4|rc2|chacha20|blowfish|camellia|aria|sm4)[-_]/i);
  if (opensslCipherMatch) {
    return opensslCipherMatch[1].toUpperCase();
  }

  // Go crypto package path: "crypto/aes" → "AES"
  const goCryptoMatch = name.match(/^crypto\/(\w+)$/);
  if (goCryptoMatch) {
    const pkg = goCryptoMatch[1];
    const goMapping: Record<string, string> = {
      aes: 'AES', des: 'DES', rsa: 'RSA', ecdsa: 'ECDSA',
      ed25519: 'Ed25519', sha256: 'SHA-256', sha512: 'SHA-512',
      sha1: 'SHA-1', md5: 'MD5', hmac: 'HMAC', tls: 'TLS',
      x509: 'X.509', rand: 'CSPRNG', elliptic: 'ECC', rc4: 'RC4',
      dsa: 'DSA', cipher: 'Cipher',
    };
    return goMapping[pkg] || pkg.toUpperCase();
  }

  return name;
}

// ─── Variable Resolution ────────────────────────────────────────────────────

/**
 * Resolve a variable name to its string-literal value by scanning surrounding
 * lines for common assignment patterns across Java, TS/JS, Python, Go, C#, C++, PHP.
 *
 * Returns the resolved algorithm name or null if not found.
 */
export function resolveVariableToAlgorithm(varName: string, lines: string[], matchLine: number): string | null {
  const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Build regex: look for `varName = "something"` or `varName = 'something'`
  const assignmentRe = new RegExp(
    `(?:^|\\s)${escapedVar}\\s*[:=]\\s*["']([^"']+)["']`,
  );

  // Scan ±50 lines from the match
  const start = Math.max(0, matchLine - 50);
  const end = Math.min(lines.length, matchLine + 50);
  for (let i = start; i < end; i++) {
    const m = lines[i].match(assignmentRe);
    if (m) return m[1];
  }

  // Also try to resolve from method parameter → call site
  const methodCallRe = /function|def |private |public |protected |static |func /;
  for (let i = Math.max(0, matchLine - 5); i <= Math.min(lines.length - 1, matchLine + 5); i++) {
    const line = lines[i];
    if (methodCallRe.test(line) && line.includes(varName)) {
      const funcNameMatch = line.match(/(?:def\s+|function\s+|func\s+|(?:public|private|protected|static)\s+\S+\s+)(\w+)\s*\(/);
      if (funcNameMatch) {
        const funcName = funcNameMatch[1];
        for (const fileLine of lines) {
          const callMatch = fileLine.match(new RegExp(`${funcName}\\s*\\([^)]*["']([A-Za-z0-9_/.-]+)["']`));
          if (callMatch) return callMatch[1];
        }
      }
    }
  }

  return null;
}
