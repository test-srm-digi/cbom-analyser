/**
 * xBOM Merge Service
 *
 * Merges a Trivy-generated SBOM and a CBOM Analyser-generated CBOM into a
 * single unified xBOM (Extended Bill of Materials) document.
 *
 * The merge strategy:
 * 1. Takes the SBOM software components as-is
 * 2. Takes the CBOM crypto assets as-is
 * 3. Merges dependency graphs from both
 * 4. Builds cross-references: links each SBOM component to the CBOM crypto
 *    assets found in the same source files or declared via manifest dependencies
 * 5. Carries over Trivy vulnerabilities
 * 6. Produces combined metadata with both tools listed
 */

import { v4 as uuidv4 } from 'uuid';
import {
  CBOMDocument,
  CryptoAsset,
  QuantumReadinessScore,
  ComplianceSummary,
} from '../types/cbom.types';
import { SBOMDocument, SBOMComponent } from '../types/sbom.types';
import {
  XBOMDocument,
  XBOMMetadata,
  XBOMCrossReference,
  XBOMAnalytics,
  VulnerabilitySummary,
} from '../types/xbom.types';
import { calculateReadinessScore, checkNISTPQCCompliance } from '../services';

// ─── Merge SBOM + CBOM → xBOM ───────────────────────────────────────────────

export interface MergeOptions {
  /** Repository URL for metadata */
  repoUrl?: string;
  /** Branch name */
  branch?: string;
  /** CycloneDX spec version (default '1.6') */
  specVersion?: '1.6' | '1.7';
}

/**
 * Merge an SBOM document (from Trivy) and a CBOM document (from CBOM Analyser)
 * into a single xBOM document.
 */
export function mergeToXBOM(
  sbom: SBOMDocument | null,
  cbom: CBOMDocument | null,
  options: MergeOptions = {},
): XBOMDocument {
  if (!sbom && !cbom) {
    throw new Error('At least one of SBOM or CBOM must be provided');
  }

  const serialNumber = `urn:uuid:${uuidv4()}`;
  const timestamp = new Date().toISOString();

  // ── Build metadata ──
  const tools = buildToolsList(sbom, cbom);
  const metadata: XBOMMetadata = {
    timestamp,
    tools,
    component: extractRootComponent(sbom, cbom),
    repository: options.repoUrl
      ? { url: options.repoUrl, branch: options.branch }
      : cbom?.metadata?.repository ?? undefined,
  };

  // ── Software components from SBOM ──
  const components: SBOMComponent[] = sbom?.components ?? [];

  // ── Crypto assets from CBOM ──
  const cryptoAssets: CryptoAsset[] = cbom?.cryptoAssets ?? [];

  // ── Merged dependencies ──
  const sbomDeps = sbom?.dependencies ?? [];
  const cbomDeps = cbom?.dependencies ?? [];
  const dependencies = [...sbomDeps, ...cbomDeps];

  // ── Vulnerabilities from SBOM (Trivy) ──
  const vulnerabilities = sbom?.vulnerabilities ?? [];

  // ── Cross-references ──
  const crossReferences = buildCrossReferences(components, cryptoAssets, cbom);

  // ── Third-party libraries from CBOM ──
  const thirdPartyLibraries = cbom?.thirdPartyLibraries ?? undefined;

  const xbom: XBOMDocument = {
    bomFormat: 'CycloneDX',
    specVersion: options.specVersion ?? '1.6',
    serialNumber,
    version: 1,
    metadata,
    components,
    cryptoAssets,
    dependencies,
    vulnerabilities,
    crossReferences,
    thirdPartyLibraries,
  };

  return xbom;
}

// ─── Build analytics from xBOM ───────────────────────────────────────────────

export function computeXBOMAnalytics(xbom: XBOMDocument): XBOMAnalytics {
  const quantumReadiness: QuantumReadinessScore = calculateReadinessScore(xbom.cryptoAssets);
  const compliance: ComplianceSummary = checkNISTPQCCompliance(xbom.cryptoAssets);
  const vulnerabilitySummary = computeVulnSummary(xbom);

  return {
    quantumReadiness,
    compliance,
    vulnerabilitySummary,
    totalSoftwareComponents: xbom.components.length,
    totalCryptoAssets: xbom.cryptoAssets.length,
    totalCrossReferences: xbom.crossReferences.length,
  };
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function buildToolsList(sbom: SBOMDocument | null, cbom: CBOMDocument | null) {
  const tools: { vendor: string; name: string; version: string }[] = [];

  // Add Trivy from SBOM metadata
  if (sbom?.metadata?.tools) {
    const sbomTools = Array.isArray(sbom.metadata.tools)
      ? sbom.metadata.tools
      : (sbom.metadata.tools as { components?: { vendor?: string; name: string; version?: string }[] }).components ?? [];

    for (const t of sbomTools) {
      tools.push({
        vendor: t.vendor ?? 'Aqua Security',
        name: t.name,
        version: t.version ?? 'unknown',
      });
    }
  }

  // Add CBOM Analyser tools
  if (cbom?.metadata?.tools && Array.isArray(cbom.metadata.tools)) {
    for (const t of cbom.metadata.tools) {
      tools.push({ vendor: t.vendor, name: t.name, version: t.version });
    }
  }

  // Ensure at least the merge tool is listed
  tools.push({
    vendor: 'QuantumGuard',
    name: 'xBOM Merge Service',
    version: '1.0.0',
  });

  return tools;
}

function extractRootComponent(sbom: SBOMDocument | null, cbom: CBOMDocument | null) {
  // Prefer SBOM's root component (has more package info)
  const sbomComp = sbom?.metadata?.component;
  if (sbomComp) {
    return {
      name: sbomComp.name,
      version: sbomComp.version,
      type: sbomComp.type,
      group: sbomComp.group,
      purl: sbomComp.purl,
    };
  }

  const cbomComp = cbom?.metadata?.component;
  if (cbomComp) {
    return {
      name: cbomComp.name,
      version: cbomComp.version,
      type: cbomComp.type,
      group: cbomComp.group,
      purl: cbomComp.purl,
    };
  }

  return undefined;
}

/**
 * Build cross-references between SBOM components and CBOM crypto assets.
 *
 * Linking strategies:
 * 1. **Manifest match**: if a CBOM third-party library's groupId:artifactId
 *    matches an SBOM component's purl, link all its crypto algorithms.
 * 2. **File co-location**: if a crypto asset's source file is inside a
 *    component's package path, link them.
 * 3. **Dependency graph**: if the CBOM dependency graph connects a crypto
 *    asset ref to a component ref, link them.
 */
function buildCrossReferences(
  components: SBOMComponent[],
  cryptoAssets: CryptoAsset[],
  cbom: CBOMDocument | null,
): XBOMCrossReference[] {
  const refs: XBOMCrossReference[] = [];
  const componentBomRefs = new Set(components.map(c => c['bom-ref']).filter(Boolean));

  // Strategy 1: Match third-party crypto libraries to SBOM components via purl
  if (cbom?.thirdPartyLibraries) {
    for (const lib of cbom.thirdPartyLibraries) {
      // Find matching SBOM component by purl substring or name
      const matchingComponent = components.find(c => {
        if (!c.purl) return false;
        // Check group:artifact match in purl
        if (lib.groupId && lib.artifactId) {
          return c.purl.includes(`${lib.groupId}/${lib.artifactId}`) ||
                 c.purl.includes(`${lib.groupId}%2F${lib.artifactId}`);
        }
        // Fallback: name match
        return c.purl.includes(lib.name) || c.name === lib.name;
      });

      if (matchingComponent?.['bom-ref']) {
        // Find crypto assets that mention algorithms from this library
        const matchingCryptoRefs = cryptoAssets
          .filter(asset => lib.cryptoAlgorithms.some(alg =>
            asset.name.toLowerCase().includes(alg.toLowerCase()) ||
            alg.toLowerCase().includes(asset.name.toLowerCase())
          ))
          .map(a => a.id);

        if (matchingCryptoRefs.length > 0) {
          refs.push({
            softwareRef: matchingComponent['bom-ref'],
            cryptoRefs: matchingCryptoRefs,
            linkMethod: 'dependency-manifest',
          });
        }
      }
    }
  }

  // Strategy 2: File co-location — match crypto assets to components by source path
  const componentsByPath = new Map<string, string>();
  for (const comp of components) {
    if (comp['bom-ref'] && comp.properties) {
      const srcProp = comp.properties.find(p =>
        p.name === 'aquasecurity:trivy:FilePath' || p.name.includes('path')
      );
      if (srcProp?.value) {
        componentsByPath.set(srcProp.value, comp['bom-ref']);
      }
    }
  }

  if (componentsByPath.size > 0) {
    for (const asset of cryptoAssets) {
      if (asset.location?.fileName) {
        // Check if the crypto asset's file is inside any component's path
        for (const [compPath, compRef] of componentsByPath) {
          if (asset.location.fileName.includes(compPath) || compPath.includes(asset.location.fileName)) {
            const existing = refs.find(r => r.softwareRef === compRef);
            if (existing) {
              if (!existing.cryptoRefs.includes(asset.id)) {
                existing.cryptoRefs.push(asset.id);
              }
            } else {
              refs.push({
                softwareRef: compRef,
                cryptoRefs: [asset.id],
                linkMethod: 'file-co-location',
              });
            }
          }
        }
      }
    }
  }

  // Strategy 3: CBOM dependency graph cross-links
  if (cbom?.dependencies) {
    for (const dep of cbom.dependencies) {
      if (componentBomRefs.has(dep.ref)) {
        // This CBOM dependency ref matches an SBOM component
        const cryptoRefs = dep.dependsOn.filter(d =>
          cryptoAssets.some(a => a.id === d)
        );
        if (cryptoRefs.length > 0) {
          const existing = refs.find(r => r.softwareRef === dep.ref);
          if (existing) {
            for (const cr of cryptoRefs) {
              if (!existing.cryptoRefs.includes(cr)) {
                existing.cryptoRefs.push(cr);
              }
            }
          } else {
            refs.push({
              softwareRef: dep.ref,
              cryptoRefs,
              linkMethod: 'dependency-manifest',
            });
          }
        }
      }
    }
  }

  return refs;
}

function computeVulnSummary(xbom: XBOMDocument): VulnerabilitySummary {
  const summary: VulnerabilitySummary = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const vuln of xbom.vulnerabilities) {
    summary.total++;

    // Get the highest severity from ratings
    const severity = getHighestSeverity(vuln.ratings?.map(r => r.severity).filter(Boolean) as string[] ?? []);
    switch (severity) {
      case 'critical': summary.critical++; break;
      case 'high': summary.high++; break;
      case 'medium': summary.medium++; break;
      case 'low': summary.low++; break;
      case 'info':
      case 'none':
        summary.info++; break;
    }
  }

  return summary;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown'];

function getHighestSeverity(severities: string[]): string {
  if (severities.length === 0) return 'unknown';
  return severities.reduce((highest, current) => {
    const hIdx = SEVERITY_ORDER.indexOf(highest);
    const cIdx = SEVERITY_ORDER.indexOf(current);
    return cIdx < hIdx ? current : highest;
  }, 'unknown');
}
