/**
 * Third-Party Dependency Scanner
 *
 * Scans project manifest files (pom.xml, build.gradle, package.json, requirements.txt, go.mod)
 * for known crypto libraries and builds a dependency depth tree.
 *
 * Each detected library is classified with:
 *   - Quantum safety status
 *   - Known algorithms it provides
 *   - Dependency depth (direct vs transitive)
 *   - Full dependency path
 */
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';
import {
  ThirdPartyCryptoLibrary,
  CryptoAsset,
  AssetType,
  CryptoPrimitive,
  CryptoFunction,
  QuantumSafetyStatus,
} from '../types';
import { enrichAssetWithPQCData } from './pqcRiskEngine';

const execAsync = promisify(exec);

// ─── Known Crypto Library Database ──────────────────────────────────────────

interface KnownCryptoLib {
  /** Display name */
  name: string;
  /** Algorithms this library is known to provide / use */
  algorithms: string[];
  /** Overall quantum safety — worst-case for the library's primary purpose */
  quantumSafety: QuantumSafetyStatus;
  /** Brief description */
  description: string;
}

/**
 * Maven/Gradle (groupId:artifactId partial match)
 * Keys are `groupId:artifactId` prefixes — partial match is used.
 */
const MAVEN_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'org.bouncycastle:bcprov': {
    name: 'BouncyCastle Provider',
    algorithms: ['RSA', 'ECDSA', 'AES', 'SHA-256', 'SHA-512', 'PBKDF2', 'Ed25519', 'ML-KEM', 'ML-DSA'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Comprehensive JCE/JCA provider — supports both classical and PQC algorithms',
  },
  'org.bouncycastle:bcpkix': {
    name: 'BouncyCastle PKIX',
    algorithms: ['X.509', 'CMS', 'OCSP', 'TSP', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PKI utilities — certificates, CMS, OCSP. Uses classical signatures.',
  },
  'org.bouncycastle:bcpg': {
    name: 'BouncyCastle OpenPGP',
    algorithms: ['RSA', 'DSA', 'ElGamal', 'AES', 'CAST5'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'OpenPGP implementation — classical asymmetric crypto',
  },
  'org.bouncycastle:bcfips': {
    name: 'BouncyCastle FIPS',
    algorithms: ['AES', 'SHA-256', 'RSA', 'ECDSA', 'HMAC', 'DRBG'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'FIPS 140-2 certified provider',
  },
  'org.bouncycastle:bcpqc': {
    name: 'BouncyCastle PQC',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON', 'SPHINCS+', 'BIKE', 'HQC'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-Quantum Cryptography implementations',
  },
  'com.google.crypto.tink:tink': {
    name: 'Google Tink',
    algorithms: ['AES-GCM', 'AES-EAX', 'AES-CTR-HMAC', 'ECDSA', 'Ed25519', 'RSA-SSA-PKCS1', 'HKDF'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Google Tink crypto library — modern API, classical algorithms',
  },
  'org.conscrypt:conscrypt': {
    name: 'Conscrypt',
    algorithms: ['TLSv1.3', 'TLSv1.2', 'AES-GCM', 'ChaCha20-Poly1305', 'ECDHE', 'RSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Java Security Provider backed by BoringSSL — modern TLS, classical KEM',
  },
  'javax.xml.crypto:': {
    name: 'XML Digital Signatures',
    algorithms: ['RSA', 'DSA', 'ECDSA', 'SHA-256', 'HMAC-SHA256'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'XML-DSIG — classical signature algorithms',
  },
  'com.nimbusds:nimbus-jose-jwt': {
    name: 'Nimbus JOSE+JWT',
    algorithms: ['RSA', 'ECDSA', 'AES', 'HMAC-SHA256', 'Ed25519'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE/JWT/JWS/JWE library — classical crypto',
  },
  'io.jsonwebtoken:jjwt': {
    name: 'JJWT (Java JWT)',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA', 'Ed25519'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JSON Web Token library — classical signatures',
  },
  'org.apache.commons:commons-crypto': {
    name: 'Apache Commons Crypto',
    algorithms: ['AES', 'AES-CTR', 'AES-CBC'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Optimized AES with OpenSSL native binding — symmetric only',
  },
  'org.springframework.security:spring-security-crypto': {
    name: 'Spring Security Crypto',
    algorithms: ['PBKDF2', 'BCrypt', 'SCrypt', 'AES-GCM', 'Argon2'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Spring password encoders + encryption utilities',
  },
  'org.springframework.security:spring-security': {
    name: 'Spring Security',
    algorithms: ['RSA', 'ECDSA', 'AES', 'BCrypt', 'PBKDF2', 'TLSv1.2', 'TLSv1.3'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Full Spring Security framework — uses classical key exchange/signatures',
  },
  'commons-codec:commons-codec': {
    name: 'Apache Commons Codec',
    algorithms: ['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'HMAC-SHA1'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Hash + encoding utility — watch for MD5/SHA-1 usage',
  },
  'com.google.guava:guava': {
    name: 'Google Guava',
    algorithms: ['SHA-256', 'SHA-512', 'MD5', 'Murmur3', 'CRC32'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Contains Hashing utility class — some hashes are non-crypto',
  },
  'org.jasypt:jasypt': {
    name: 'Jasypt',
    algorithms: ['PBKDF2', 'AES', 'DES', '3DES', 'MD5'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Java Simplified Encryption — often uses weak defaults (DES, PBE)',
  },
  'de.mkammerer:argon2-jvm': {
    name: 'Argon2 JVM',
    algorithms: ['Argon2id', 'Argon2i', 'Argon2d'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing — quantum-resistant KDF',
  },
};

/**
 * npm (package name)
 */
const NPM_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'crypto-js': {
    name: 'CryptoJS',
    algorithms: ['AES', 'DES', '3DES', 'SHA-256', 'SHA-1', 'MD5', 'HMAC', 'PBKDF2', 'Rabbit', 'RC4'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'JavaScript crypto library — includes weak algorithms (DES, MD5, RC4)',
  },
  'node-forge': {
    name: 'Node Forge',
    algorithms: ['RSA', 'AES', 'DES', '3DES', 'SHA-256', 'MD5', 'HMAC', 'PBKDF2', 'X.509', 'TLS'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Pure JS TLS/PKI — classical asymmetric',
  },
  'tweetnacl': {
    name: 'TweetNaCl',
    algorithms: ['Curve25519', 'Ed25519', 'XSalsa20', 'Poly1305'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'NaCl-compatible library — classical ECC',
  },
  'libsodium-wrappers': {
    name: 'libsodium',
    algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'AES-256-GCM', 'Argon2id', 'BLAKE2b'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Sodium (libsodium) — modern crypto, but classical KEM/signatures',
  },
  'sodium-native': {
    name: 'sodium-native',
    algorithms: ['X25519', 'Ed25519', 'ChaCha20-Poly1305', 'Argon2id'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Native libsodium bindings',
  },
  'jsonwebtoken': {
    name: 'jsonwebtoken',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JWT library — classical signatures',
  },
  'jose': {
    name: 'jose',
    algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES-GCM', 'HMAC'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE/JWT/JWK library — classical crypto',
  },
  'bcrypt': {
    name: 'bcrypt',
    algorithms: ['BCrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'BCrypt password hashing — quantum-resistant KDF',
  },
  'argon2': {
    name: 'argon2',
    algorithms: ['Argon2id', 'Argon2i', 'Argon2d'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing — quantum-resistant KDF',
  },
  'scrypt': {
    name: 'scrypt',
    algorithms: ['scrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'scrypt KDF — quantum-resistant',
  },
  'elliptic': {
    name: 'elliptic',
    algorithms: ['ECDSA', 'ECDH', 'Ed25519', 'secp256k1'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'EC cryptography — quantum-vulnerable',
  },
  'openpgp': {
    name: 'OpenPGP.js',
    algorithms: ['RSA', 'ECDSA', 'ECDH', 'AES', 'SHA-256'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'OpenPGP implementation — classical asymmetric',
  },
  '@noble/curves': {
    name: '@noble/curves',
    algorithms: ['secp256k1', 'Ed25519', 'Ed448', 'P-256', 'P-384'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Noble curves — high-quality EC, but quantum-vulnerable',
  },
  '@noble/hashes': {
    name: '@noble/hashes',
    algorithms: ['SHA-256', 'SHA-512', 'SHA-3', 'BLAKE2', 'BLAKE3', 'RIPEMD-160'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Noble hashes — hash-only, quantum-resistant',
  },
  'pqcrypto': {
    name: 'pqcrypto',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-quantum crypto for Node.js',
  },
  'crystals-kyber': {
    name: 'crystals-kyber',
    algorithms: ['ML-KEM'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'CRYSTALS-Kyber (ML-KEM) implementation',
  },
};

/**
 * pip (package name)
 */
const PIP_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'cryptography': {
    name: 'cryptography',
    algorithms: ['RSA', 'ECDSA', 'Ed25519', 'AES', 'ChaCha20', 'SHA-256', 'HMAC', 'X.509', 'HKDF', 'PBKDF2'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python cryptography library — comprehensive, classical',
  },
  'pycryptodome': {
    name: 'PyCryptodome',
    algorithms: ['RSA', 'AES', 'DES', '3DES', 'ChaCha20', 'SHA-256', 'HMAC', 'PBKDF2', 'scrypt'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PyCryptodome — drop-in PyCrypto replacement',
  },
  'pycryptodomex': {
    name: 'PyCryptodomex',
    algorithms: ['RSA', 'AES', 'DES', 'SHA-256', 'HMAC'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'PyCryptodomex — side-by-side installable PyCryptodome',
  },
  'pynacl': {
    name: 'PyNaCl',
    algorithms: ['Curve25519', 'Ed25519', 'XSalsa20-Poly1305', 'BLAKE2b'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python binding to libsodium — classical ECC',
  },
  'pyopenssl': {
    name: 'pyOpenSSL',
    algorithms: ['RSA', 'ECDSA', 'TLS', 'X.509', 'AES'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Python OpenSSL wrapper',
  },
  'pyjwt': {
    name: 'PyJWT',
    algorithms: ['HMAC-SHA256', 'RSA', 'ECDSA'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JSON Web Token library',
  },
  'python-jose': {
    name: 'python-jose',
    algorithms: ['RSA', 'ECDSA', 'HMAC', 'AES'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'JOSE implementation for Python',
  },
  'passlib': {
    name: 'passlib',
    algorithms: ['BCrypt', 'SCrypt', 'Argon2', 'PBKDF2', 'SHA-512-Crypt'],
    quantumSafety: QuantumSafetyStatus.CONDITIONAL,
    description: 'Password hashing — mix of strong and legacy schemes',
  },
  'bcrypt': {
    name: 'bcrypt (Python)',
    algorithms: ['BCrypt'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'BCrypt password hashing',
  },
  'argon2-cffi': {
    name: 'argon2-cffi',
    algorithms: ['Argon2id', 'Argon2i'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Argon2 password hashing',
  },
  'pqcrypto': {
    name: 'pqcrypto (Python)',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'SPHINCS+'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Post-quantum crypto for Python',
  },
  'oqs': {
    name: 'liboqs-python',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Open Quantum Safe liboqs Python wrapper',
  },
};

/**
 * Go (module path prefix)
 */
const GO_CRYPTO_LIBS: Record<string, KnownCryptoLib> = {
  'golang.org/x/crypto': {
    name: 'golang.org/x/crypto',
    algorithms: ['ChaCha20-Poly1305', 'Curve25519', 'Ed25519', 'Argon2', 'BCrypt', 'scrypt', 'SSH', 'HKDF'],
    quantumSafety: QuantumSafetyStatus.NOT_QUANTUM_SAFE,
    description: 'Go extended crypto — classical ECC + modern KDFs',
  },
  'github.com/cloudflare/circl': {
    name: 'Cloudflare CIRCL',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'X25519', 'Ed448', 'HPKE'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Cloudflare cryptographic library — includes PQC',
  },
  'github.com/open-quantum-safe/liboqs-go': {
    name: 'liboqs-go',
    algorithms: ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'FALCON'],
    quantumSafety: QuantumSafetyStatus.QUANTUM_SAFE,
    description: 'Open Quantum Safe Go bindings',
  },
};

// ─── Manifest Parsers ───────────────────────────────────────────────────────

/**
 * Parse Maven pom.xml for known crypto dependencies.
 */
function parseMavenPom(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];
  const lines = content.split('\n');

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
function parseGradleBuild(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
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

    // Find the line number of this dependency in the manifest
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
function parsePackageJson(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
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
        // Find the line number where this dependency is declared
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
function parseRequirementsTxt(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;

    // Parse: package==version, package>=version, package~=version, or just package
    const pkgMatch = line.match(/^([a-zA-Z0-9_-]+)\s*([><=~!]+\s*[\d.]+)?/);
    if (!pkgMatch) continue;

    const pkgName = pkgMatch[1].toLowerCase().replace(/_/g, '-');
    const version = pkgMatch[2]?.replace(/[><=~!]/g, '').trim();

    // Check against known crypto libs (normalize names)
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
function parseSetupPy(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];

  // Extract install_requires=[...]
  const reqMatch = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (!reqMatch) return results;

  const reqBlock = reqMatch[1];
  const pkgPattern = /['"]([a-zA-Z0-9_-]+)\s*(?:[><=~!]+\s*[\d.]+)?['"]/g;
  let match;

  while ((match = pkgPattern.exec(reqBlock)) !== null) {
    const pkgName = match[1].toLowerCase().replace(/_/g, '-');
    // Find the line number of this match within the full content
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
function parseGoMod(content: string, manifestFile: string): ThirdPartyCryptoLibrary[] {
  const results: ThirdPartyCryptoLibrary[] = [];

  // Match: require ( ... ) block and single require lines
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Match: <module> <version> in require block or single require
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

// ─── Transitive Dependency Resolution ────────────────────────────────────────

/**
 * Try to resolve transitive Maven dependencies using `mvn dependency:tree`.
 * Falls back gracefully if Maven is not installed.
 */
async function resolveMavenTransitive(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
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
async function resolveNpmTransitive(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
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

// ─── Main Scanner ───────────────────────────────────────────────────────────

/**
 * Scan a repository for known third-party crypto libraries.
 * Returns both direct and (where possible) transitive dependencies.
 */
export async function scanDependencies(repoPath: string): Promise<ThirdPartyCryptoLibrary[]> {
  const allLibs: ThirdPartyCryptoLibrary[] = [];

  // Discover manifest files
  const manifestPatterns = [
    { glob: '**/pom.xml', parser: parseMavenPom },
    { glob: '**/build.gradle', parser: parseGradleBuild },
    { glob: '**/build.gradle.kts', parser: parseGradleBuild },
    { glob: '**/package.json', parser: parsePackageJson },
    { glob: '**/requirements.txt', parser: parseRequirementsTxt },
    { glob: '**/requirements-*.txt', parser: parseRequirementsTxt },
    { glob: '**/setup.py', parser: parseSetupPy },
    { glob: '**/go.mod', parser: parseGoMod },
  ];

  try {
    // Find all manifest files, excluding build/deps directories
    const { stdout } = await execAsync(
      `find "${repoPath}" -type d \\( ` +
        `-name node_modules -o -name .git -o -name target -o -name build ` +
        `-o -name dist -o -name .gradle -o -name __pycache__ -o -name vendor ` +
      `\\) -prune -o -type f \\( ` +
        `-name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" ` +
        `-o -name "package.json" -o -name "requirements.txt" -o -name "requirements-*.txt" ` +
        `-o -name "setup.py" -o -name "go.mod" ` +
      `\\) -print`,
      { timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);

    for (const filePath of files) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const relativePath = path.relative(repoPath, filePath);
        const fileName = path.basename(filePath);

        if (fileName === 'pom.xml') {
          allLibs.push(...parseMavenPom(content, relativePath));
        } else if (fileName.match(/build\.gradle(\.kts)?$/)) {
          allLibs.push(...parseGradleBuild(content, relativePath));
        } else if (fileName === 'package.json') {
          allLibs.push(...parsePackageJson(content, relativePath));
        } else if (fileName.match(/requirements.*\.txt$/)) {
          allLibs.push(...parseRequirementsTxt(content, relativePath));
        } else if (fileName === 'setup.py') {
          allLibs.push(...parseSetupPy(content, relativePath));
        } else if (fileName === 'go.mod') {
          allLibs.push(...parseGoMod(content, relativePath));
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch (error) {
    console.warn('Dependency file discovery failed:', (error as Error).message);
  }

  // Attempt transitive resolution (non-blocking)
  try {
    const [mavenTransitive, npmTransitive] = await Promise.all([
      resolveMavenTransitive(repoPath),
      resolveNpmTransitive(repoPath),
    ]);
    allLibs.push(...mavenTransitive, ...npmTransitive);
  } catch {
    // Transitive resolution is best-effort
  }

  // Deduplicate by groupId:artifactId (keep the one with lowest depth)
  const deduped = new Map<string, ThirdPartyCryptoLibrary>();
  for (const lib of allLibs) {
    const key = `${lib.groupId || ''}:${lib.artifactId || lib.name}:${lib.packageManager}`;
    const existing = deduped.get(key);
    if (!existing || lib.depth < existing.depth) {
      deduped.set(key, lib);
    }
  }

  return Array.from(deduped.values());
}

/**
 * Convert a third-party crypto library into CryptoAsset entries.
 * Each known algorithm from the library becomes a separate crypto asset.
 */
export function cryptoLibToCBOMAssets(lib: ThirdPartyCryptoLibrary): CryptoAsset[] {
  return lib.cryptoAlgorithms.map(alg => {
    // Determine a more specific asset type based on the algorithm
    let assetType = AssetType.ALGORITHM;
    if (['X.509', 'X509'].includes(alg)) assetType = AssetType.CERTIFICATE;
    else if (['TLS', 'SSL', 'DTLS'].includes(alg)) assetType = AssetType.PROTOCOL;
    else if (['RSA', 'ECDSA', 'Ed25519', 'DSA', 'ML-DSA', 'SLH-DSA'].includes(alg)) assetType = AssetType.ALGORITHM;

    const asset: CryptoAsset = {
      id: uuidv4(),
      name: alg,
      type: 'crypto-asset',
      version: lib.version,
      description: `Provided by ${lib.name} v${lib.version || 'unknown'} (${lib.packageManager}: ${lib.groupId ? lib.groupId + ':' : ''}${lib.artifactId}). ` +
        `Detected as a ${lib.isDirectDependency ? 'direct' : 'transitive'} dependency in ${lib.manifestFile}${lib.lineNumber ? ':' + lib.lineNumber : ''}.`,
      cryptoProperties: {
        assetType,
      },
      location: {
        fileName: lib.manifestFile,
        lineNumber: lib.lineNumber,
      },
      quantumSafety: QuantumSafetyStatus.UNKNOWN,
      provider: lib.name,
      detectionSource: 'dependency',
    };
    return enrichAssetWithPQCData(asset);
  });
}
