/**
 * PQC Risk Engine — Internal Types
 */
import { QuantumSafetyStatus } from '../../types';

export interface AlgorithmProfile {
  quantumSafety: QuantumSafetyStatus;
  recommendedPQC?: string;
  notes?: string;
  minSafeKeyLength?: number;
  /** Marks entries that are informational (e.g., provider registrations) — not actual algorithms.
   *  Informational entries are excluded from conditional/unknown counts but preserved in the CBOM
   *  for audit trail purposes. @see docs/advanced-resolution-techniques.md — Phase 1C */
  isInformational?: boolean;
}
