/**
 * xBOM — Unified Extended Bill of Materials
 *
 * Merges SBOM (software components + vulnerabilities from Trivy)
 * with CBOM (cryptographic assets from the CBOM Analyser) into a
 * single CycloneDX-aligned document with relational cross-references.
 *
 * The xBOM retains full CycloneDX compatibility while adding a
 * `cryptoAssets` convenience array and `crossReferences` to link
 * software components to the crypto primitives they use.
 */

import { CryptoAsset, CryptoDependency, ThirdPartyCryptoLibrary, QuantumReadinessScore, ComplianceSummary } from './cbom.types';
import { SBOMComponent, SBOMDependency, SBOMVulnerability, VulnerabilitySeverity } from './sbom.types';

// ─── Cross-reference: links an SBOM component to its CBOM crypto assets ─────

export interface XBOMCrossReference {
  /** bom-ref of the SBOM software component */
  softwareRef: string;
  /** bom-refs of the CBOM crypto assets used by this software */
  cryptoRefs: string[];
  /** How the link was established */
  linkMethod: 'dependency-manifest' | 'code-scan' | 'file-co-location' | 'manual';
}

// ─── xBOM Metadata ───────────────────────────────────────────────────────────

export interface XBOMTool {
  vendor: string;
  name: string;
  version: string;
}

export interface XBOMMetadata {
  timestamp: string;
  tools: XBOMTool[];
  component?: {
    name: string;
    version?: string;
    type: string;
    group?: string;
    purl?: string;
  };
  repository?: {
    url: string;
    branch?: string;
  };
}

// ─── Vulnerability summary ───────────────────────────────────────────────────

export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ─── Full xBOM Document ─────────────────────────────────────────────────────

export interface XBOMDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.6' | '1.7';
  serialNumber: string;
  version: number;
  metadata: XBOMMetadata;

  /** SBOM — software components from Trivy */
  components: SBOMComponent[];

  /** CBOM — cryptographic assets from CBOM Analyser */
  cryptoAssets: CryptoAsset[];

  /** Merged dependency graph (SBOM deps + CBOM deps) */
  dependencies: (SBOMDependency | CryptoDependency)[];

  /** Trivy-detected CVEs */
  vulnerabilities: SBOMVulnerability[];

  /** Links between SBOM components and CBOM crypto assets */
  crossReferences: XBOMCrossReference[];

  /** Third-party crypto libraries detected from manifests */
  thirdPartyLibraries?: ThirdPartyCryptoLibrary[];
}

// ─── Aggregated Analytics ────────────────────────────────────────────────────

export interface XBOMAnalytics {
  /** PQC readiness breakdown */
  quantumReadiness: QuantumReadinessScore;

  /** NIST PQC compliance check */
  compliance: ComplianceSummary;

  /** Vulnerability severity breakdown */
  vulnerabilitySummary: VulnerabilitySummary;

  /** Total software components */
  totalSoftwareComponents: number;

  /** Total cryptographic assets */
  totalCryptoAssets: number;

  /** Number of cross-references established */
  totalCrossReferences: number;
}

// ─── API Request / Response ──────────────────────────────────────────────────

export interface XBOMGenerateRequest {
  /** Path to the repository / folder to scan */
  repoPath: string;
  /** Optional: only generate SBOM, CBOM, or both */
  mode?: 'full' | 'sbom-only' | 'cbom-only';
  /** Glob patterns to exclude from crypto scanning */
  excludePatterns?: string[];
  /** Repository URL for metadata */
  repoUrl?: string;
  /** Branch name */
  branch?: string;
  /** CycloneDX spec version ('1.6' or '1.7', default '1.6') */
  specVersion?: '1.6' | '1.7';
  /** Skip Trivy if SBOM JSON is supplied directly */
  sbomJson?: string;
  /** Skip CBOM scan if CBOM JSON is supplied directly */
  cbomJson?: string;
  /** External tool configuration (CodeQL, cbomkit-theia, CryptoAnalysis) */
  externalTools?: import('./cbom.types').ExternalToolOptions;
}

export interface XBOMResponse {
  success: boolean;
  message: string;
  xbom?: XBOMDocument;
  analytics?: XBOMAnalytics;
  error?: string;
}
