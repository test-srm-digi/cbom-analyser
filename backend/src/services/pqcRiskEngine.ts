/**
 * PQC Risk Engine — Re-export shim
 *
 * This file re-exports everything from the refactored `pqc/` module.
 * Kept for backward compatibility with existing imports.
 *
 * @see ./pqc/ for the actual implementation
 */
export {
  classifyAlgorithm,
  enrichAssetWithPQCData,
  syncQuantumSafetyWithVerdict,
  calculateReadinessScore,
  checkNISTPQCCompliance,
  getPQCAlgorithms,
  isInformationalAsset,
  filterInformationalAssets,
  ALGORITHM_DATABASE,
} from './pqc';

export type { AlgorithmProfile } from './pqc';
