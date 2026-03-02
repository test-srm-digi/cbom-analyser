/**
 * Aggregator barrel — re-exports all public API from the aggregator module.
 */
export { createEmptyCBOM, parseCBOMFile, mergeCBOMs } from './cbomBuilder';
export { runSonarCryptoScan } from './sonarScanner';
export { runRegexCryptoScan } from './regexScanner';
export { runFullScan } from './fullScan';
