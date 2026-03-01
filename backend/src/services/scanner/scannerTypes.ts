/**
 * Scanner Types
 *
 * Shared type definitions for the regex-based crypto scanner.
 */
import { CryptoPrimitive, CryptoFunction, AssetType } from '../../types';

/**
 * Describes a single regex-based crypto detection pattern.
 */
export interface CryptoPattern {
  /** Regex to match against file content. Must use the `g` flag. */
  pattern: RegExp;
  /** Static algorithm name OR fallback when capture group is empty. */
  algorithm: string;
  /** The cryptographic primitive category. */
  primitive: CryptoPrimitive;
  /** The cryptographic function (encrypt, sign, hash, etc.). */
  cryptoFunction: CryptoFunction;
  /** CBOM asset type — defaults to ALGORITHM if omitted. */
  assetType?: AssetType;
  /** When true, prefer capture group 1 over the static `algorithm` field. */
  extractAlgorithm?: boolean;
  /** When true, capture group 1 is a variable name to resolve. */
  resolveVariable?: boolean;
  /** When true, scan nearby lines for algorithm context clues. */
  scanContext?: boolean;
}

/** File extensions the scanner will search, grouped by language. */
export const SCANNABLE_EXTENSIONS: Record<string, string[]> = {
  java:       ['.java'],
  python:     ['.py'],
  javascript: ['.js', '.jsx', '.ts', '.tsx'],
  cpp:        ['.cpp', '.cxx', '.cc', '.c', '.h', '.hpp', '.hxx'],
  csharp:     ['.cs'],
  go:         ['.go'],
  php:        ['.php'],
  rust:       ['.rs'],
};

/** All scannable file extensions as a flat set. */
export const ALL_EXTENSIONS = new Set(
  Object.values(SCANNABLE_EXTENSIONS).flat(),
);

/** Skip patterns for build artefacts and minified files. */
export const SKIP_FILE_PATTERNS: RegExp[] = [
  /\.min\.js$/,
  /\.chunk\.js$/,
  /\.bundle\.js$/,
  /\.[a-f0-9]{8,}\.js$/,
  /[\\/]static[\\/]js[\\/]/,
  /[\\/]resources[\\/]main[\\/]static[\\/]/,
  /[\\/]public[\\/]static[\\/]/,
  /[\\/]vendor[\\/]/,
  /[\\/]\.cache[\\/]/,
];
