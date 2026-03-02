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
  runCbomkitTheia,
  runExternalToolScans,
  deduplicateExternalAssets,
  findFilesRecursive,
  findBuildTarget,
} from './external';

export type {
  ToolAvailability,
  CbomkitComponent,
  CbomkitOutput,
} from './external';
