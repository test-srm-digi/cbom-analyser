/**
 * Types for the dependency scanner module.
 */
import { QuantumSafetyStatus } from '../../types';

/** Description of a known crypto library in a package manager ecosystem. */
export interface KnownCryptoLib {
  /** Display name */
  name: string;
  /** Algorithms this library is known to provide / use */
  algorithms: string[];
  /** Overall quantum safety — worst-case for the library's primary purpose */
  quantumSafety: QuantumSafetyStatus;
  /** Brief description */
  description: string;
}
