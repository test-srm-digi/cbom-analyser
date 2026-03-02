/**
 * Utility functions for external tool integrations.
 */
import * as fs from 'fs';
import * as path from 'path';

/**
 * Recursively find files with a given extension.
 */
export function findFilesRecursive(dir: string, ext: string): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (/^(node_modules|\.git|target|build|dist|vendor)$/.test(entry.name)) continue;
        results.push(...findFilesRecursive(fullPath, ext));
      } else if (entry.name.endsWith(ext)) {
        results.push(fullPath);
      }
    }
  } catch { /* ignore permission errors */ }
  return results;
}

/**
 * Find compiled Java class directory for CryptoAnalysis.
 */
export function findBuildTarget(repoPath: string): string | null {
  const candidates = [
    'target/classes',
    'build/classes',
    'build/classes/java/main',
    'out/production',
  ];

  for (const candidate of candidates) {
    const fullPath = path.join(repoPath, candidate);
    if (fs.existsSync(fullPath)) return fullPath;
  }
  return null;
}
