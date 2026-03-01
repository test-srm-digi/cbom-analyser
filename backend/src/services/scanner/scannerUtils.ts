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
 * Enhanced with backward variable resolution (Phase 1B) — searches backward
 * from the API call site to find where the variable was assigned, including:
 *   - Direct assignment: `const algo = "SHA-256";`
 *   - Class field: `private static final String ALGO = "AES/GCM/NoPadding";`
 *   - Dictionary/map: `algorithms["default"] = "RSA"` or `config.algorithm = "AES"`
 *   - Enum/constant: `ALGORITHM = "HMAC-SHA256"`
 *   - Method parameter → call site resolution
 *   - Ternary/conditional: `algo = secure ? "AES-256-GCM" : "AES-128-CBC"`
 *   - String concatenation: `"AES/" + mode` — extracts root algorithm
 *
 * Returns the resolved algorithm name or null if not found.
 *
 * @see docs/advanced-resolution-techniques.md — Phase 1B
 */
export function resolveVariableToAlgorithm(varName: string, lines: string[], matchLine: number): string | null {
  const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // ── Strategy 1: Direct assignment (±50 lines, backward-first priority) ──
  const assignmentPatterns = [
    // const/let/var/String algo = "VALUE"
    new RegExp(`(?:const|let|var|final|static|String|string)\\s+${escapedVar}\\s*[:=]\\s*["']([^"']+)["']`),
    // varName = "VALUE"  (simple assignment)
    new RegExp(`(?:^|\\s|;)${escapedVar}\\s*=\\s*["']([^"']+)["']`),
    // self.varName = "VALUE"  or this.varName = "VALUE"
    new RegExp(`(?:self|this)\\.${escapedVar}\\s*=\\s*["']([^"']+)["']`),
    // varName := "VALUE"  (Go)
    new RegExp(`${escapedVar}\\s*:=\\s*["']([^"']+)["']`),
    // #define VARNAME "VALUE"  (C/C++)
    new RegExp(`#define\\s+${escapedVar}\\s+"([^"]+)"`),
  ];

  // Backward search first (backward from call site is more likely to find the definition)
  const backwardStart = Math.max(0, matchLine - 100);
  for (let i = matchLine - 1; i >= backwardStart; i--) {
    for (const pattern of assignmentPatterns) {
      const m = lines[i].match(pattern);
      if (m) return m[1];
    }
  }

  // Forward search (for hoisted or later assignments in unusual patterns)
  const forwardEnd = Math.min(lines.length, matchLine + 50);
  for (let i = matchLine + 1; i < forwardEnd; i++) {
    for (const pattern of assignmentPatterns) {
      const m = lines[i].match(pattern);
      if (m) return m[1];
    }
  }

  // ── Strategy 2: Class-level constants / fields (full file scan) ──
  // Java: private static final String ALGO = "AES";
  // Python: ALGO = "SHA256" (module-level)
  // TS/JS: const ALGO = "RSA-OAEP" (module-level)
  const classFieldRe = new RegExp(
    `(?:private|public|protected|internal)?\\s*(?:static)?\\s*(?:final|readonly|const)?\\s*(?:String|string)?\\s*${escapedVar}\\s*[:=]\\s*["']([^"']+)["']`,
  );
  for (let i = 0; i < lines.length; i++) {
    if (i >= backwardStart && i < forwardEnd) continue; // Already scanned
    const m = lines[i].match(classFieldRe);
    if (m) return m[1];
  }

  // ── Strategy 3: Ternary / conditional (extract all possible values) ──
  const ternaryRe = new RegExp(
    `${escapedVar}\\s*=\\s*[^;]*\\?\\s*["']([^"']+)["']\\s*:\\s*["']([^"']+)["']`,
  );
  for (let i = Math.max(0, matchLine - 50); i < Math.min(lines.length, matchLine + 20); i++) {
    const m = lines[i].match(ternaryRe);
    if (m) {
      // Return the first option (most common path); both values are the same algorithm family
      return m[1];
    }
  }

  // ── Strategy 4: Enum mapping / switch-case ──
  // case "encrypt": return "AES-256-GCM";
  // "algo" => "SHA-256"
  const enumRe = /["']([A-Za-z0-9_/.\-+]+)["']\s*(?:=>|->|:)\s*["']([A-Za-z0-9_/.\-+]+)["']/;
  for (let i = Math.max(0, matchLine - 30); i < Math.min(lines.length, matchLine + 30); i++) {
    const m = lines[i].match(enumRe);
    if (m) {
      // Return the value side — likely the algorithm
      const val = m[2];
      if (/^[A-Z0-9].*(?:SHA|AES|RSA|EC|HMAC|MD|ChaCha|Blowfish|DES|Camellia)/i.test(val)) {
        return val;
      }
    }
  }

  // ── Strategy 5: Method parameter → call site resolution ──
  const methodCallRe = /function|def |private |public |protected |static |func /;
  for (let i = Math.max(0, matchLine - 5); i <= Math.min(lines.length - 1, matchLine + 5); i++) {
    const line = lines[i];
    if (methodCallRe.test(line) && line.includes(varName)) {
      const funcNameMatch = line.match(/(?:def\s+|function\s+|func\s+|(?:public|private|protected|static)\s+\S+\s+)(\w+)\s*\(/);
      if (funcNameMatch) {
        const funcName = funcNameMatch[1];
        // Find the parameter position
        const paramListMatch = line.match(/\(([^)]*)\)/);
        if (paramListMatch) {
          const params = paramListMatch[1].split(',').map(p => p.trim());
          const paramIdx = params.findIndex(p => p.includes(varName));

          for (const fileLine of lines) {
            // Match call site with positional argument
            const callMatch = fileLine.match(new RegExp(`${funcName}\\s*\\(([^)]*)\\)`));
            if (callMatch) {
              const args = callMatch[1].split(',').map(a => a.trim());
              const targetArg = paramIdx >= 0 ? args[paramIdx] : args[0];
              if (targetArg) {
                const literalMatch = targetArg.match(/["']([A-Za-z0-9_/.\-+]+)["']/);
                if (literalMatch) return literalMatch[1];
              }
            }
          }
        }
      }
    }
  }

  // ── Strategy 6: String concatenation — extract root algorithm ──
  // "AES/" + mode  → "AES"
  // algo = "AES" + "/CBC/" + padding  → "AES"
  const concatRe = new RegExp(`${escapedVar}\\s*=\\s*["']([A-Za-z0-9_-]+)["']\\s*\\+`);
  for (let i = Math.max(0, matchLine - 30); i < Math.min(lines.length, matchLine + 10); i++) {
    const m = lines[i].match(concatRe);
    if (m) return m[1]; // Return the root part before concatenation
  }

  // ── Strategy 7: Cross-file constant import resolution ──
  // import { ALGORITHM } from './constants';  → search full file for the constant
  const importRe = new RegExp(`import\\s+.*\\b${escapedVar}\\b.*from\\s+['"]([^'"]+)['"]`);
  for (const line of lines) {
    const m = line.match(importRe);
    if (m) {
      // We can't read another file here, but mark as "imported constant"
      // The cross-file enrichment step in scannerAggregator handles this
      break;
    }
  }

  return null;
}

/**
 * Enhanced backward variable resolution for the PQC parameter analyzer.
 *
 * Given a block of source context and a variable name, traces backward
 * through assignments, method parameters, and class fields to find
 * the concrete string value.
 *
 * This is a simplified "backward program slice" inspired by CryptoGuard's
 * inter-procedural backward slicing technique.
 *
 * @see docs/advanced-resolution-techniques.md — Phase 1B / CryptoGuard technique
 */
export function resolveVariableBackward(sourceContext: string, variableName: string): string | null {
  const lines = sourceContext.split('\n');
  const escaped = variableName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Strategy 1: Direct assignment patterns
  const patterns = [
    // Java: String algo = "SHA-256";
    new RegExp(`(?:final\\s+)?(?:String|string|var|const|let)\\s+${escaped}\\s*=\\s*["']([^"']+)["']`),
    // Python: algo = "SHA-256" or algo: str = "SHA-256"
    new RegExp(`${escaped}\\s*(?::\\s*str)?\\s*=\\s*["']([^"']+)["']`),
    // Go: algo := "SHA-256"
    new RegExp(`${escaped}\\s*:=\\s*["']([^"']+)["']`),
    // C#/Java field: private static final String ALGO = "AES";
    new RegExp(`(?:private|public|protected|internal)?\\s*(?:static)?\\s*(?:final|readonly|const)?\\s*\\S+\\s+${escaped}\\s*=\\s*["']([^"']+)["']`),
  ];

  // Scan backward (later matches override earlier — closest to usage wins)
  let result: string | null = null;
  for (const line of lines) {
    for (const pattern of patterns) {
      const m = line.match(pattern);
      if (m) {
        result = m[1];
      }
    }
  }

  if (result) return result;

  // Strategy 2: Config / properties file patterns
  const configPatterns = [
    // properties: algorithm=AES
    new RegExp(`${escaped}\\s*=\\s*([A-Za-z0-9_/.-]+)\\s*$`, 'm'),
    // YAML: algorithm: AES
    new RegExp(`${escaped}:\\s*([A-Za-z0-9_/.-]+)\\s*$`, 'm'),
    // JSON: "algorithm": "AES"
    new RegExp(`"${escaped}"\\s*:\\s*"([^"]+)"`),
  ];

  for (const pattern of configPatterns) {
    const m = sourceContext.match(pattern);
    if (m) return m[1];
  }

  return null;
}
