/**
 * Manifest Parsers
 *
 * Parses project manifest files (pom.xml, build.gradle, package.json, etc.)
 * for known crypto library dependencies.
 */
import type { ThirdPartyCryptoLibrary } from '../../types';
import {
  MAVEN_CRYPTO_LIBS,
  NPM_CRYPTO_LIBS,
  PIP_CRYPTO_LIBS,
  GO_CRYPTO_LIBS,
} from './cryptoLibDatabase';

/**
 * Parse Maven pom.xml for known crypto dependencies.
 */
export function parseMavenPom(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];

  // Match <dependency><groupId>...</groupId><artifactId>...</artifactId><version>...</version></dependency>
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]*)<\/version>)?/gs;
  let match;

  while ((match = depRegex.exec(content)) !== null) {
    const groupId = match[1].trim();
    const artifactId = match[2].trim();
    const version = match[3]?.trim();
    const coordinate = `${groupId}:${artifactId}`;

    // Find the line number of this dependency in the manifest
    const matchOffset = match.index;
    const lineNumber = content.substring(0, matchOffset).split('\n').length;

    // Check against known crypto libs (prefix match)
    for (const [prefix, lib] of Object.entries(MAVEN_CRYPTO_LIBS)) {
      if (coordinate.startsWith(prefix) || coordinate.includes(prefix)) {
        results.push({
          name: lib.name,
          groupId,
          artifactId,
          version: version || undefined,
          packageManager: 'maven',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [artifactId],
          manifestFile,
          lineNumber,
        });
        break;
      }
    }
  }

  return results;
}

/**
 * Parse Gradle build.gradle / build.gradle.kts for known crypto dependencies.
 */
export function parseGradleBuild(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];

  // Match: implementation 'group:artifact:version'  or  implementation "group:artifact:version"
  // Also: api, compileOnly, runtimeOnly, testImplementation
  const depRegex = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\('"]([^:'"]+):([^:'"]+)(?::([^'")]+))?['")\s]/g;
  let match;

  while ((match = depRegex.exec(content)) !== null) {
    const groupId = match[1].trim();
    const artifactId = match[2].trim();
    const version = match[3]?.trim();
    const coordinate = `${groupId}:${artifactId}`;

    const matchOffset = match.index;
    const lineNumber = content.substring(0, matchOffset).split('\n').length;

    for (const [prefix, lib] of Object.entries(MAVEN_CRYPTO_LIBS)) {
      if (coordinate.startsWith(prefix) || coordinate.includes(prefix)) {
        results.push({
          name: lib.name,
          groupId,
          artifactId,
          version: version || undefined,
          packageManager: 'gradle',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [artifactId],
          manifestFile,
          lineNumber,
        });
        break;
      }
    }
  }

  return results;
}

/**
 * Parse npm package.json for known crypto dependencies.
 */
export function parsePackageJson(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];
  const lines = content.split('\n');

  try {
    const pkg = JSON.parse(content);
    const allDeps: Record<string, string> = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };

    for (const [name, version] of Object.entries(allDeps)) {
      if (NPM_CRYPTO_LIBS[name]) {
        const lib = NPM_CRYPTO_LIBS[name];
        const lineNumber = lines.findIndex(l => l.includes(`"${name}"`)) + 1 || undefined;
        results.push({
          name: lib.name,
          artifactId: name,
          version: version.replace(/^[\^~>=<]/, ''),
          packageManager: 'npm',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [name],
          manifestFile,
          lineNumber,
        });
      }
    }
  } catch {
    // Invalid package.json
  }

  return results;
}

/**
 * Parse pip requirements.txt for known crypto dependencies.
 */
export function parseRequirementsTxt(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;

    const pkgMatch = line.match(/^([a-zA-Z0-9_-]+)\s*([><=~!]+\s*[\d.]+)?/);
    if (!pkgMatch) continue;

    const pkgName = pkgMatch[1].toLowerCase().replace(/_/g, '-');
    const version = pkgMatch[2]?.replace(/[><=~!]/g, '').trim();

    for (const [key, lib] of Object.entries(PIP_CRYPTO_LIBS)) {
      if (pkgName === key || pkgName === key.replace(/-/g, '_')) {
        results.push({
          name: lib.name,
          artifactId: pkgName,
          version,
          packageManager: 'pip',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [pkgName],
          manifestFile,
          lineNumber: i + 1,
        });
        break;
      }
    }
  }

  return results;
}

/**
 * Parse setup.py install_requires for known crypto dependencies.
 */
export function parseSetupPy(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];

  const reqMatch = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (!reqMatch) return results;

  const reqBlock = reqMatch[1];
  const pkgPattern = /['"]([a-zA-Z0-9_-]+)\s*(?:[><=~!]+\s*[\d.]+)?['"]/g;
  let match;

  while ((match = pkgPattern.exec(reqBlock)) !== null) {
    const pkgName = match[1].toLowerCase().replace(/_/g, '-');
    const matchAbsOffset = (reqMatch?.index || 0) + match.index;
    const lineNumber = content.substring(0, matchAbsOffset).split('\n').length;
    for (const [key, lib] of Object.entries(PIP_CRYPTO_LIBS)) {
      if (pkgName === key || pkgName === key.replace(/-/g, '_')) {
        results.push({
          name: lib.name,
          artifactId: pkgName,
          packageManager: 'pip',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [pkgName],
          manifestFile,
          lineNumber,
        });
        break;
      }
    }
  }

  return results;
}

/**
 * Parse go.mod for known crypto dependencies.
 */
export function parseGoMod(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    const modMatch = line.match(/^(?:require\s+)?([a-zA-Z0-9._/:-]+)\s+v?([\d.]+\S*)/);
    if (!modMatch) continue;

    const modulePath = modMatch[1];
    const version = modMatch[2];

    for (const [prefix, lib] of Object.entries(GO_CRYPTO_LIBS)) {
      if (modulePath.startsWith(prefix)) {
        results.push({
          name: lib.name,
          artifactId: modulePath,
          version,
          packageManager: 'go',
          cryptoAlgorithms: lib.algorithms,
          quantumSafety: lib.quantumSafety,
          isDirectDependency: true,
          depth: 0,
          dependencyPath: [modulePath],
          manifestFile,
          lineNumber: i + 1,
        });
        break;
      }
    }
  }

  return results;
}
