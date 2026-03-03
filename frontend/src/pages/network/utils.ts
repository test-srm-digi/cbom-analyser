import type { CipherBreakdown } from '../../store/api';

/** Parse a JSON-encoded cipher breakdown, returning null on failure */
export function parseBreakdown(raw: string | null): CipherBreakdown | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
