/**
 * Dependency Scanner — Re-export shim
 *
 * This file re-exports everything from the refactored `dependency/` module.
 * Kept for backward compatibility with existing imports.
 *
 * @see ./dependency/ for the actual implementation
 */
export { scanDependencies, cryptoLibToCBOMAssets } from './dependency';
