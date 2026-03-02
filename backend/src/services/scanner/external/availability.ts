/**
 * External Tool Availability Detection
 *
 * Detects which cryptographic analysis tools are installed on the system.
 * Results are cached for the process lifetime.
 */
import { execSync } from 'child_process';
import type { ToolAvailability } from './types';

let cachedAvailability: ToolAvailability | null = null;

/** Reset the cached availability so that newly-installed tools are detected. */
export function resetToolAvailabilityCache(): void {
  cachedAvailability = null;
}

/** Check which external tools are available on the system. */
export async function checkToolAvailability(): Promise<ToolAvailability> {
  if (cachedAvailability) return cachedAvailability;

  const check = (cmd: string): boolean => {
    try {
      execSync(`which ${cmd} 2>/dev/null`, { encoding: 'utf-8' });
      return true;
    } catch {
      return false;
    }
  };

  cachedAvailability = {
    codeql: check('codeql'),
    cbomkitTheia: check('cbomkit-theia') || check('cbomkit'),
    keytool: check('keytool'),
    openssl: check('openssl'),
  };

  console.log('External tool availability:', JSON.stringify(cachedAvailability));
  return cachedAvailability;
}
