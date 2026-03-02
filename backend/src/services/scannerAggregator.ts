/**
 * Scanner Aggregator Service — thin re-export shim.
 *
 * Implementation has moved to the `aggregator/` module for cleaner separation.
 * This file preserves backward compatibility for all existing importers.
 */
export {
  createEmptyCBOM,
  parseCBOMFile,
  mergeCBOMs,
  runSonarCryptoScan,
  runRegexCryptoScan,
  runFullScan,
} from './aggregator';
