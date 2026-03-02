/**
 * Analyzer Utilities
 *
 * Shared helpers used by parameter analyzers.
 */
import * as fs from 'fs';
import * as path from 'path';

/**
 * Extract surrounding source code context (±N lines around the detection).
 */
export function extractSourceContext(
  repoPath: string,
  fileName: string,
  lineNumber: number,
  contextLines: number = 15
): string | null {
  try {
    const fullPath = path.join(repoPath, fileName);
    if (!fs.existsSync(fullPath)) return null;

    const content = fs.readFileSync(fullPath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);
    return lines.slice(start, end).join('\n');
  } catch {
    return null;
  }
}
