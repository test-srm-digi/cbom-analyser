/**
 * PQC Parameter Analyzer — Re-export shim
 *
 * This file re-exports everything from the refactored `pqc/` module.
 * Kept for backward compatibility with existing imports.
 *
 * @see ./pqc/ for the actual implementation
 */
export {
  analyzeConditionalAsset,
  analyzeAllConditionalAssets,
} from './pqc';
