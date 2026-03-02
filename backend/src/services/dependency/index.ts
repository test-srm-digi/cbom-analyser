/**
 * Dependency Scanner Module — Barrel Exports
 */
export { scanDependencies, cryptoLibToCBOMAssets } from './scanner';
export type { KnownCryptoLib } from './types';
export {
  MAVEN_CRYPTO_LIBS,
  NPM_CRYPTO_LIBS,
  PIP_CRYPTO_LIBS,
  GO_CRYPTO_LIBS,
} from './cryptoLibDatabase';
export {
  parseMavenPom,
  parseGradleBuild,
  parsePackageJson,
  parseRequirementsTxt,
  parseSetupPy,
  parseGoMod,
} from './manifestParsers';
export { resolveMavenTransitive, resolveNpmTransitive } from './transitiveResolvers';
