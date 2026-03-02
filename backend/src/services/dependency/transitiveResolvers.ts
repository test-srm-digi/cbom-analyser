/**
 * Transitive Dependency Resolution
 *
 * Resolves transitive (indirect) crypto library dependencies using
 * package manager CLI tools (mvn dependency:tree, npm ls).
 */
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import type { ThirdPartyCryptoLibrary } from '../../types';
import { MAVEN_CRYPTO_LIBS, NPM_CRYPTO_LIBS } from './cryptoLibDatabase';

const execAsync = promisify(exec);

/**
 * Try to resolve transitive Maven dependencies using `mvn dependency:tree`.
 * Falls back gracefully if Maven is not installed.
 */
export async function resolveMavenTransitive(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
  const results: ThirdPartyCryptoLibrary[] = [];
  try {
    const pomPath = path.join(repoPath, 'pom.xml');
    if (!fs.existsSync(pomPath)) return results;

    const { stdout } = await execAsync(
      'mvn dependency:tree -DoutputType=text -q 2>/dev/null || true',
      { cwd: repoPath, timeout: 120000 }
    );

    // Parse tree output like:
    // [INFO] +- org.bouncycastle:bcprov-jdk18on:jar:1.78.1:compile
    // [INFO] |  +- other.dep:child:jar:1.0:compile
    const treeLineRegex = /\[INFO\]\s*([|+ \\-]+)\s*([^:]+):([^:]+):([^:]+):([^:]+):(\S+)/g;
    let match;

    while ((match = treeLineRegex.exec(stdout)) !== null) {
      const indent = match[1];
      const groupId = match[2].trim();
      const artifactId = match[3].trim();
      const _packaging = match[4];
      const version = match[5].trim();
      const _scope = match[6];

      // Calculate depth from indent
      const depth = Math.max(0, Math.floor((indent.replace(/[^|+-]/g, '').length - 1) / 1));
      const coordinate = `${groupId}:${artifactId}`;

      for (const [prefix, lib] of Object.entries(MAVEN_CRYPTO_LIBS)) {
        if (coordinate.startsWith(prefix) || coordinate.includes(prefix)) {
          // Skip if depth=0 — those are already captured by direct parsing
          if (depth > 0) {
            results.push({
              name: lib.name,
              groupId,
              artifactId,
              version,
              packageManager: 'maven',
              cryptoAlgorithms: lib.algorithms,
              quantumSafety: lib.quantumSafety,
              isDirectDependency: false,
              depth,
              dependencyPath: [artifactId],  // Could be enriched with full path
              manifestFile: 'pom.xml (transitive)',
            });
          }
          break;
        }
      }
    }
  } catch {
    // Maven not available or dependency:tree failed
  }
  return results;
}

/**
 * Try to resolve transitive npm dependencies by reading node_modules.
 */
export async function resolveNpmTransitive(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
  const results: ThirdPartyCryptoLibrary[] = [];
  const nodeModules = path.join(repoPath, 'node_modules');
  if (!fs.existsSync(nodeModules)) return results;

  try {
    // Use npm ls --json for full tree
    const { stdout } = await execAsync(
      'npm ls --json --all 2>/dev/null || true',
      { cwd: repoPath, timeout: 60000 }
    );

    const tree = JSON.parse(stdout);
    const visited = new Set<string>();

    function walkDeps(deps: Record<string, any>, depth: number, parentPath: string[]) {
      if (!deps || depth > 5) return; // Cap depth at 5

      for (const [name, info] of Object.entries(deps)) {
        const key = `${name}@${(info as any).version || '?'}`;
        if (visited.has(key)) continue;
        visited.add(key);

        if (NPM_CRYPTO_LIBS[name] && depth > 0) {
          const lib = NPM_CRYPTO_LIBS[name];
          results.push({
            name: lib.name,
            artifactId: name,
            version: (info as any).version,
            packageManager: 'npm',
            cryptoAlgorithms: lib.algorithms,
            quantumSafety: lib.quantumSafety,
            isDirectDependency: false,
            depth,
            dependencyPath: [...parentPath, name],
            manifestFile: 'package.json (transitive)',
          });
        }

        if ((info as any).dependencies) {
          walkDeps((info as any).dependencies, depth + 1, [...parentPath, name]);
        }
      }
    }

    if (tree.dependencies) {
      walkDeps(tree.dependencies, 0, []);
    }
  } catch {
    // npm ls failed
  }

  return results;
}
