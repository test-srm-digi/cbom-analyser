/**
 * Combined crypto-pattern registry.
 *
 * Re-exports every language-specific pattern array and provides a single
 * `allCryptoPatterns` list for the scanner to iterate.
 */
export { javaPatterns }    from './javaPatterns';
export { pythonPatterns }  from './pythonPatterns';
export { jsPatterns }      from './jsPatterns';
export { cppPatterns }     from './cppPatterns';
export { csharpPatterns }  from './csharpPatterns';
export { goPatterns }      from './goPatterns';
export { phpPatterns }     from './phpPatterns';

import { javaPatterns }   from './javaPatterns';
import { pythonPatterns } from './pythonPatterns';
import { jsPatterns }     from './jsPatterns';
import { cppPatterns }    from './cppPatterns';
import { csharpPatterns } from './csharpPatterns';
import { goPatterns }     from './goPatterns';
import { phpPatterns }    from './phpPatterns';
import { CryptoPattern }  from '../scannerTypes';

/** Every known crypto pattern across all supported languages. */
export const allCryptoPatterns: CryptoPattern[] = [
  ...javaPatterns,
  ...pythonPatterns,
  ...jsPatterns,
  ...cppPatterns,
  ...csharpPatterns,
  ...goPatterns,
  ...phpPatterns,
];
