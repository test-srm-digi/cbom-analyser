/**
 * External Tool Integrations — Re-export shim
 *
 * This file re-exports everything from the refactored `external/` module.
 * Kept for backward compatibility with existing imports.
 *
 * @see ./external/ for the actual implementation
 */
export {
  checkToolAvailability,
  resetToolAvailabilityCache,
  runCodeQLAnalysis,
  CODEQL_QUERIES,
  runCbomkitTheia,
  runCryptoAnalysis,
  runExternalToolScans,
  deduplicateExternalAssets,
  findFilesRecursive,
  findBuildTarget,
} from './external';

export type {
  ToolAvailability,
  SARIFResult,
  SARIFRun,
  SARIFReport,
  CbomkitComponent,
  CbomkitOutput,
  CryptoAnalysisResult,
} from './external';
