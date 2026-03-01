/**
 * Trivy-generated CycloneDX SBOM type definitions.
 *
 * Trivy outputs CycloneDX 1.5/1.6 JSON with software components,
 * dependency trees, and vulnerabilities (CVEs).
 *
 * @see https://aquasecurity.github.io/trivy
 * @see https://cyclonedx.org/docs/1.6/json/
 */

// ─── SBOM Component ──────────────────────────────────────────────────────────

export type SBOMComponentType =
  | 'application'
  | 'framework'
  | 'library'
  | 'container'
  | 'operating-system'
  | 'device'
  | 'firmware'
  | 'file';

export interface SBOMExternalReference {
  type: string;
  url: string;
  comment?: string;
}

export interface SBOMComponentLicense {
  license?: {
    id?: string;
    name?: string;
    url?: string;
  };
  expression?: string;
}

export interface SBOMComponentProperty {
  name: string;
  value: string;
}

export interface SBOMComponent {
  'bom-ref'?: string;
  type: SBOMComponentType;
  name: string;
  version?: string;
  group?: string;
  purl?: string;
  description?: string;
  scope?: 'required' | 'optional' | 'excluded';
  hashes?: { alg: string; content: string }[];
  licenses?: SBOMComponentLicense[];
  externalReferences?: SBOMExternalReference[];
  properties?: SBOMComponentProperty[];
  supplier?: { name: string; url?: string[] };
  publisher?: string;
}

// ─── SBOM Dependency ─────────────────────────────────────────────────────────

export interface SBOMDependency {
  ref: string;
  dependsOn?: string[];
}

// ─── Trivy Vulnerability ─────────────────────────────────────────────────────

export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' | 'unknown';

export interface VulnerabilityRating {
  source?: { name: string; url?: string };
  score?: number;
  severity?: VulnerabilitySeverity;
  method?: string;
  vector?: string;
}

export interface VulnerabilityAdvisory {
  title?: string;
  url: string;
}

export interface VulnerabilityAffect {
  ref: string;
  versions?: { version: string; status: 'affected' | 'unaffected' }[];
}

export interface SBOMVulnerability {
  id: string;
  source?: { name: string; url?: string };
  ratings?: VulnerabilityRating[];
  cwes?: number[];
  description?: string;
  detail?: string;
  recommendation?: string;
  advisories?: VulnerabilityAdvisory[];
  created?: string;
  published?: string;
  updated?: string;
  affects?: VulnerabilityAffect[];
  properties?: SBOMComponentProperty[];
}

// ─── Full Trivy CycloneDX SBOM Document ──────────────────────────────────────

export interface SBOMMetadata {
  timestamp?: string;
  tools?: SBOMTool[] | { components?: SBOMTool[] };
  component?: SBOMComponent;
  properties?: SBOMComponentProperty[];
}

export interface SBOMTool {
  vendor?: string;
  name: string;
  version?: string;
}

export interface SBOMDocument {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber?: string;
  version?: number;
  metadata?: SBOMMetadata;
  components?: SBOMComponent[];
  dependencies?: SBOMDependency[];
  vulnerabilities?: SBOMVulnerability[];
}
